//! Console authentication middleware and handlers.
//!
//! Provides session-based authentication for the admin console using
//! argon2 password hashing and secure session tokens.

use std::sync::Arc;

use askama::Template;
use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use rand::Rng;
use tracing::warn;

use chalk_core::cookies::{clear_cookie, set_cookie, CookieAttrs, SameSite};
use chalk_core::http::extract_client_ip;
use chalk_core::models::audit::AdminSession;

use crate::AppState;

const SESSION_COOKIE_NAME: &str = "chalk_session";
const SESSION_DURATION_HOURS: i64 = 24;

/// Paths that bypass authentication.
const PUBLIC_PATHS: &[&str] = &["/health", "/login", "/set-password", "/api/"];

/// Check if a path should bypass authentication.
fn is_public_path(path: &str) -> bool {
    PUBLIC_PATHS.iter().any(|p| path.starts_with(p))
}

/// Extract session token from cookie header.
fn extract_session_token(req: &Request<Body>) -> Option<String> {
    let cookie_header = req.headers().get(header::COOKIE)?;
    let cookie_str = cookie_header.to_str().ok()?;
    for cookie in cookie_str.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
            return Some(value.to_string());
        }
    }
    None
}

/// Authentication middleware that checks for valid session cookie.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    // Skip auth for public paths
    if is_public_path(&path) {
        return next.run(req).await;
    }

    // Skip auth if no admin password is configured
    if state.config.chalk.admin_password_hash.is_none() {
        return next.run(req).await;
    }

    // Check for valid session
    if let Some(token) = extract_session_token(&req) {
        if let Ok(Some(session)) = state.repo.get_admin_session(&token).await {
            if session.expires_at > Utc::now() {
                return next.run(req).await;
            }
            // Expired session - clean it up
            let _ = state.repo.delete_admin_session(&token).await;
        }
    }

    // Redirect to login
    Redirect::to("/login").into_response()
}

/// Generate a random session token (64 hex characters).
fn generate_session_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    hex::encode(&bytes)
}

/// Encode bytes as hex string.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Hash a password using argon2 (re-exported from `chalk_core::auth`).
pub use chalk_core::auth::hash_password;

/// Verify a password against a hash.
///
/// Returns `false` for both mismatch and an unparseable stored hash so that
/// existing callers can keep their boolean check.
fn verify_password(password: &str, hash: &str) -> bool {
    chalk_core::auth::verify_password(hash, password).unwrap_or(false)
}

/// Extract client IP from request headers.
fn client_ip(req: &Request<Body>) -> Option<String> {
    extract_client_ip(
        req.headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok()),
    )
}

// -- Templates --

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "set_password.html")]
pub struct SetPasswordTemplate {
    pub reset_token: String,
    pub error: Option<String>,
}

// -- Handlers --

#[derive(serde::Deserialize, Default)]
pub struct LoginQuery {
    pub reset_token: Option<String>,
}

/// GET /login - Show login form, or redirect to set-password flow if a
/// `reset_token` query parameter is present.
pub async fn login_page(Query(q): Query<LoginQuery>) -> Response {
    if let Some(token) = q.reset_token.as_deref().filter(|t| !t.is_empty()) {
        let encoded = urlencoding::encode(token);
        return Redirect::to(&format!("/set-password?reset_token={encoded}")).into_response();
    }
    LoginTemplate { error: None }.into_response()
}

#[derive(serde::Deserialize)]
pub struct LoginForm {
    pub password: String,
}

/// POST /login - Process login form.
pub async fn login_submit(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let ip = client_ip(&req);

    // Extract form body
    let body_bytes = match axum::body::to_bytes(req.into_body(), 1024 * 16).await {
        Ok(b) => b,
        Err(_) => {
            return LoginTemplate {
                error: Some("Invalid request".to_string()),
            }
            .into_response();
        }
    };

    let form: LoginForm = match serde_urlencoded::from_bytes(&body_bytes) {
        Ok(f) => f,
        Err(_) => {
            return LoginTemplate {
                error: Some("Invalid form data".to_string()),
            }
            .into_response();
        }
    };

    // Resolve a hash to verify against. Preference order:
    //   1. config.chalk.admin_password_hash — the OSS chalk.toml shared admin
    //      secret. This is the canonical path for self-hosted deployments.
    //   2. Per-user `users.password_hash` for an Administrator user. Hosted
    //      deployments bootstrap a per-tenant admin user (no chalk.toml) and
    //      the reset-token flow writes the chosen password into that row, so
    //      we accept the per-user hash as an admin login. The OSS surface
    //      remains unchanged for installs that set admin_password_hash.
    let password_hash = match &state.config.chalk.admin_password_hash {
        Some(h) => h.clone(),
        None => {
            let admins = state
                .repo
                .list_users(&chalk_core::models::sync::UserFilter {
                    role: Some(chalk_core::models::common::RoleType::Administrator),
                    ..Default::default()
                })
                .await
                .unwrap_or_default();
            let mut found: Option<String> = None;
            for u in &admins {
                if let Ok(Some(h)) = state.repo.get_password_hash(&u.sourced_id).await {
                    if !h.is_empty() {
                        found = Some(h);
                        break;
                    }
                }
            }
            match found {
                Some(h) => h,
                None => {
                    return LoginTemplate {
                        error: Some("No admin password configured".to_string()),
                    }
                    .into_response();
                }
            }
        }
    };

    // Argon2 verify is CPU-bound (~100ms); offload to a blocking thread so
    // we don't starve the tokio runtime under concurrent login pressure.
    let verify_input_pwd = form.password.clone();
    let verify_input_hash = password_hash.clone();
    let valid = match tokio::task::spawn_blocking(move || {
        verify_password(&verify_input_pwd, &verify_input_hash)
    })
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("password verify task panicked: {e}");
            return LoginTemplate {
                error: Some("Internal error".to_string()),
            }
            .into_response();
        }
    };

    if !valid {
        warn!("Failed login attempt from {:?}", ip);
        let _ = state
            .repo
            .log_admin_action("login_failed", None, ip.as_deref())
            .await;
        return LoginTemplate {
            error: Some("Invalid password".to_string()),
        }
        .into_response();
    }

    // Create session
    let token = generate_session_token();
    let session = AdminSession {
        token: token.clone(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(SESSION_DURATION_HOURS),
        ip_address: ip.clone(),
    };

    if let Err(e) = state.repo.create_admin_session(&session).await {
        warn!("Failed to create session: {}", e);
        return LoginTemplate {
            error: Some("Internal error".to_string()),
        }
        .into_response();
    }

    let _ = state
        .repo
        .log_admin_action("login", Some("Admin logged in"), ip.as_deref())
        .await;

    // Set session cookie and redirect to dashboard
    let cookie = set_cookie(
        SESSION_COOKIE_NAME,
        &token,
        &CookieAttrs {
            same_site: SameSite::Strict,
            http_only: true,
            secure: state.config.chalk.cookies_secure(),
            path: "/",
            max_age_secs: Some(SESSION_DURATION_HOURS * 3600),
        },
    );

    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, "/".to_string()),
        ],
    )
        .into_response()
}

// -- Password reset (set-password) flow --

#[derive(serde::Deserialize, Default)]
pub struct SetPasswordQuery {
    pub reset_token: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct SetPasswordForm {
    pub reset_token: String,
    pub password: String,
    pub confirm: String,
}

/// GET /set-password?reset_token=... - Render the set-password form.
///
/// We do NOT consume the reset token here — that happens atomically inside
/// the POST handler so a refresh of this page does not invalidate the token.
pub async fn set_password_page(Query(q): Query<SetPasswordQuery>) -> Response {
    let token = match q.reset_token.as_deref().filter(|t| !t.is_empty()) {
        Some(t) => t.to_string(),
        None => return Redirect::to("/login").into_response(),
    };
    Html(
        SetPasswordTemplate {
            reset_token: token,
            error: None,
        }
        .render()
        .unwrap_or_default(),
    )
    .into_response()
}

/// POST /set-password - Atomically consume the reset token, hash the new
/// password (off-thread), persist it, and redirect to /login.
pub async fn set_password_submit(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    let body_bytes = match axum::body::to_bytes(req.into_body(), 1024 * 16).await {
        Ok(b) => b,
        Err(_) => {
            return Html(render_set_password_error("", "Invalid request")).into_response();
        }
    };
    let form: SetPasswordForm = match serde_urlencoded::from_bytes(&body_bytes) {
        Ok(f) => f,
        Err(_) => {
            return Html(render_set_password_error("", "Invalid form data")).into_response();
        }
    };

    if form.password.len() < 12 {
        return Html(render_set_password_error(
            &form.reset_token,
            "Password must be at least 12 characters",
        ))
        .into_response();
    }
    if form.password != form.confirm {
        return Html(render_set_password_error(
            &form.reset_token,
            "Passwords do not match",
        ))
        .into_response();
    }

    let user_id = match state.repo.consume_reset_token(&form.reset_token).await {
        Ok(Some(uid)) => uid,
        Ok(None) => {
            return Html(render_set_password_error(
                "",
                "Reset link is invalid, expired, or already used",
            ))
            .into_response();
        }
        Err(e) => {
            warn!("consume_reset_token failed: {e}");
            return Html(render_set_password_error(
                &form.reset_token,
                "Internal error",
            ))
            .into_response();
        }
    };

    // Argon2 hash is CPU-bound — offload so the runtime keeps serving.
    let pwd = form.password.clone();
    let hash_result = tokio::task::spawn_blocking(move || hash_password(&pwd)).await;
    let hash = match hash_result {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            warn!("hash_password failed: {e}");
            return Html(render_set_password_error("", "Internal error")).into_response();
        }
        Err(e) => {
            warn!("hash task panicked: {e}");
            return Html(render_set_password_error("", "Internal error")).into_response();
        }
    };

    if let Err(e) = state.repo.set_password_hash(&user_id, &hash).await {
        warn!("set_password_hash failed: {e}");
        return Html(render_set_password_error("", "Internal error")).into_response();
    }

    let _ = state
        .repo
        .log_admin_action(
            "password_set_via_reset",
            Some(&format!("user={user_id}")),
            None,
        )
        .await;

    Redirect::to("/login").into_response()
}

fn render_set_password_error(reset_token: &str, msg: &str) -> String {
    SetPasswordTemplate {
        reset_token: reset_token.to_string(),
        error: Some(msg.to_string()),
    }
    .render()
    .unwrap_or_default()
}

/// POST /logout - Delete session and redirect to login.
pub async fn logout(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let ip = client_ip(&req);

    if let Some(token) = extract_session_token(&req) {
        let _ = state.repo.delete_admin_session(&token).await;
    }

    let _ = state
        .repo
        .log_admin_action("logout", None, ip.as_deref())
        .await;

    // Clear cookie
    let cookie = clear_cookie(
        SESSION_COOKIE_NAME,
        &CookieAttrs {
            same_site: SameSite::Strict,
            http_only: true,
            secure: state.config.chalk.cookies_secure(),
            path: "/",
            max_age_secs: None,
        },
    );

    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, "/login".to_string()),
        ],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_password() {
        let hash = hash_password("my-secret-password").unwrap();
        assert!(verify_password("my-secret-password", &hash));
        assert!(!verify_password("wrong-password", &hash));
    }

    #[test]
    fn verify_password_with_invalid_hash() {
        assert!(!verify_password("password", "not-a-valid-hash"));
    }

    #[test]
    fn generate_session_token_is_64_hex_chars() {
        let token = generate_session_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_session_token_is_unique() {
        let t1 = generate_session_token();
        let t2 = generate_session_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn is_public_path_returns_true_for_health() {
        assert!(is_public_path("/health"));
    }

    #[test]
    fn is_public_path_returns_true_for_login() {
        assert!(is_public_path("/login"));
    }

    #[test]
    fn is_public_path_returns_true_for_api() {
        assert!(is_public_path("/api/v1/something"));
    }

    #[test]
    fn is_public_path_returns_false_for_dashboard() {
        assert!(!is_public_path("/"));
    }

    #[test]
    fn is_public_path_returns_false_for_settings() {
        assert!(!is_public_path("/settings"));
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex::encode(&[0x00, 0xff, 0x0a]), "00ff0a");
        assert_eq!(hex::encode(&[]), "");
    }

    #[test]
    fn extract_session_token_from_cookie() {
        let req = Request::builder()
            .header(header::COOKIE, "chalk_session=abc123; other=value")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_session_token(&req), Some("abc123".to_string()));
    }

    #[test]
    fn extract_session_token_missing_cookie() {
        let req = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(extract_session_token(&req), None);
    }

    #[test]
    fn extract_session_token_no_matching_cookie() {
        let req = Request::builder()
            .header(header::COOKIE, "other=value; another=thing")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_session_token(&req), None);
    }
}
