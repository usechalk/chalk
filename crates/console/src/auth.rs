//! Console authentication middleware and handlers.
//!
//! Provides session-based authentication for the admin console using
//! argon2 password hashing and secure session tokens.

use std::sync::Arc;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use askama::Template;
use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use rand::Rng;
use tracing::warn;

use chalk_core::db::repository::{AdminAuditRepository, AdminSessionRepository};
use chalk_core::http::extract_client_ip;
use chalk_core::models::audit::AdminSession;

use crate::AppState;

const SESSION_COOKIE_NAME: &str = "chalk_session";
const SESSION_DURATION_HOURS: i64 = 24;

/// Paths that bypass authentication.
const PUBLIC_PATHS: &[&str] = &["/health", "/login", "/api/"];

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

/// Hash a password using argon2.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = argon2::password_hash::SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("password hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a password against a hash.
fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
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

// -- Handlers --

/// GET /login - Show login form.
pub async fn login_page() -> LoginTemplate {
    LoginTemplate { error: None }
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

    let password_hash = match &state.config.chalk.admin_password_hash {
        Some(h) => h.clone(),
        None => {
            return LoginTemplate {
                error: Some("No admin password configured".to_string()),
            }
            .into_response();
        }
    };

    if !verify_password(&form.password, &password_hash) {
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
    let cookie = format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        SESSION_DURATION_HOURS * 3600
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
    let cookie = format!("{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");

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
