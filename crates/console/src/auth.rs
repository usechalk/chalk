//! Console authentication middleware and handlers.
//!
//! Provides session-based authentication for the admin console using
//! argon2 password hashing and secure session tokens.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use askama::Template;
use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use parking_lot::Mutex;
use rand::Rng;
use tracing::warn;

use chalk_core::cookies::{clear_cookie, set_cookie, CookieAttrs, SameSite};
use chalk_core::http::extract_client_ip;
use chalk_core::models::audit::AdminSession;

use crate::AppState;

const SESSION_COOKIE_NAME: &str = "chalk_session";
const SESSION_DURATION_HOURS: i64 = 24;

/// Paths that bypass session authentication entirely.
///
/// Previously this was `&["/health", "/login", "/set-password", "/api/"]` — the
/// blanket `/api/` prefix exempted every `/api/*` route, including the OneRoster
/// REST API which had no auth at all. Each API surface now declares its own
/// auth: `/api/oneroster/*` requires a bearer token (see
/// `oneroster_bearer_middleware`), and `/api/signup*` stays public by design.
const PUBLIC_PATHS: &[&str] = &[
    "/health",
    "/login",
    "/set-password",
    "/api/signup",
    "/api/oneroster/", // unauthed at the session-middleware layer; the bearer
    // middleware enforces the actual gate further down the
    // stack so OneRoster handlers never run without a valid
    // token.
    "/static/", // self-hosted assets (htmx bundle) — needed before
                // auth so the login page can load them.
];

/// Check if a path should bypass session authentication.
fn is_public_path(path: &str) -> bool {
    PUBLIC_PATHS.iter().any(|p| path.starts_with(p))
}

/// SHA-256 hex of a string. Used both at token-mint time and at verification
/// time. Plaintext tokens are never compared directly — we only ever see the
/// digest server-side.
fn hash_token(plaintext: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    let bytes = hasher.finalize();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Extract a `Bearer <token>` header value. Returns the token portion only.
fn extract_bearer_token(req: &Request<Body>) -> Option<String> {
    let auth = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

/// Per-request carrier for an authenticated token's read scope, stashed in the
/// request extensions by [`oneroster_bearer_middleware`] and read by the
/// OneRoster handlers. `None` means unrestricted (the OSS default). Wrapping
/// `Option` in a named type lets handlers extract it via `Extension` while
/// distinguishing "no scope" from "extension absent" (e.g. in unit tests that
/// don't run the middleware).
#[derive(Clone, Debug, Default)]
pub struct ScopeContext(pub Option<chalk_core::models::token_scope::TokenScope>);

/// Middleware that enforces a valid (unrevoked) API token on
/// `/api/oneroster/*`. Returns `401 Unauthorized` on missing, malformed, or
/// unknown tokens. On success the request proceeds with the token's read scope
/// inserted into the request extensions; `last_used_at` is updated
/// fire-and-forget so the authenticated request never blocks on the DB write.
pub async fn oneroster_bearer_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let plaintext = match extract_bearer_token(&req) {
        Some(t) if !t.is_empty() => t,
        _ => return unauthorized_response("missing or malformed Authorization header"),
    };

    let hash = hash_token(&plaintext);
    let token = match state.repo.find_active_api_token_by_hash(&hash).await {
        Ok(Some(t)) => t,
        Ok(None) => return unauthorized_response("invalid or revoked token"),
        Err(e) => {
            warn!("api token lookup failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"error":"server_error"}"#.to_string(),
            )
                .into_response();
        }
    };

    // Make the token's scope available to the OneRoster handlers downstream.
    req.extensions_mut()
        .insert(ScopeContext(token.scope.clone()));

    // Fire-and-forget: update `last_used_at`. Failures are logged but never
    // block the request.
    let repo = state.repo.clone();
    let token_id = token.id.clone();
    tokio::spawn(async move {
        if let Err(e) = repo.touch_api_token(&token_id).await {
            warn!("touch_api_token({token_id}) failed: {e}");
        }
    });

    next.run(req).await
}

fn unauthorized_response(reason: &str) -> Response {
    let body = format!(r#"{{"error":"invalid_token","error_description":"{reason}"}}"#);
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::WWW_AUTHENTICATE, r#"Bearer realm="oneroster""#),
            (header::CONTENT_TYPE, "application/json"),
        ],
        body,
    )
        .into_response()
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

    // Skip auth ONLY in the OSS local-dev shortcut: no admin password set AND
    // magic-link login not enabled. When magic-link is on (hosted cloud), the
    // session is always enforced — this closes the "no chalk.toml password =>
    // open console" gap for hosted tenants.
    if state.config.chalk.admin_password_hash.is_none() && !state.magic_login_enabled() {
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

// -- Login rate limiter (per-IP token bucket) --
//
// Best-effort, in-memory defense in depth against password spraying on
// `POST /login`. The real backstop is the argon2 work factor + account
// lockout; this just blunts trivial scripted attacks. Single-process: in
// multi-replica deployments each replica enforces its own budget.

/// Capacity and refill rate for the login bucket: 5 attempts per 60 seconds.
const LOGIN_BUCKET_CAPACITY: u32 = 5;
const LOGIN_BUCKET_WINDOW_SECS: u64 = 60;

/// Idle entries older than this are evicted on each `check_and_consume` so
/// the map can't grow unboundedly under sustained scanning. Two windows is
/// long enough to be conservative (a legitimate user retrying after a
/// rejection still has a fully-refilled bucket waiting for them).
const LOGIN_BUCKET_EVICT_AFTER: StdDuration = StdDuration::from_secs(LOGIN_BUCKET_WINDOW_SECS * 2);

/// Trait for "what time is it" — exists purely so unit tests can advance
/// time without `tokio::time::sleep`.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> Instant;
}

/// Real-wall-clock implementation used in production.
#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// One token bucket per IP. `tokens` is stored as a float so a partial
/// refill across the window boundary doesn't get silently rounded away.
#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn full(now: Instant) -> Self {
        Self {
            tokens: f64::from(LOGIN_BUCKET_CAPACITY),
            last_refill: now,
        }
    }

    /// Refill the bucket based on elapsed time since `last_refill`, then
    /// return `true` if a token can be consumed (and consume it). Returns
    /// the number of whole seconds the caller should wait before the next
    /// attempt is permitted, if rejected.
    fn try_consume(&mut self, now: Instant) -> Result<(), u64> {
        // Refill: `LOGIN_BUCKET_CAPACITY` tokens per `LOGIN_BUCKET_WINDOW_SECS`
        // seconds, computed as a float so we don't drop sub-second fractions
        // on tick boundaries.
        let elapsed = now.saturating_duration_since(self.last_refill);
        let rate_per_sec = f64::from(LOGIN_BUCKET_CAPACITY) / (LOGIN_BUCKET_WINDOW_SECS as f64);
        let refill = elapsed.as_secs_f64() * rate_per_sec;
        if refill > 0.0 {
            self.tokens = (self.tokens + refill).min(f64::from(LOGIN_BUCKET_CAPACITY));
            self.last_refill = now;
        }

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Seconds until one full token is available again. Round up so
            // we never under-report and let the client retry too early.
            let deficit = 1.0 - self.tokens;
            let secs = (deficit / rate_per_sec).ceil() as u64;
            Err(secs.max(1))
        }
    }
}

/// Per-IP token-bucket rate limiter. Cheap to construct (`Default`) and
/// safe to share via `Arc`.
pub struct LoginRateLimiter {
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
    clock: Box<dyn Clock>,
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            clock: Box::new(SystemClock),
        }
    }
}

impl LoginRateLimiter {
    /// Build with a caller-supplied clock. Used by tests; production calls
    /// `Default::default()`.
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Attempt to consume one token for `ip`. Returns `Ok(())` if allowed;
    /// `Err(retry_after_secs)` if the bucket is empty.
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let now = self.clock.now();
        let mut guard = self.buckets.lock();

        // Evict stale entries opportunistically. Cheap: only fires when a
        // new request lands on the limiter at all.
        guard
            .retain(|_, b| now.saturating_duration_since(b.last_refill) < LOGIN_BUCKET_EVICT_AFTER);

        let bucket = guard.entry(ip).or_insert_with(|| TokenBucket::full(now));
        bucket.try_consume(now)
    }

    /// Test-only: how many IPs are currently tracked.
    #[cfg(test)]
    fn tracked_ips(&self) -> usize {
        self.buckets.lock().len()
    }
}

/// Build the `429 Too Many Requests` response sent when an IP exceeds its
/// login budget. Includes `Retry-After` (seconds) per RFC 6585.
fn too_many_login_attempts(retry_after_secs: u64) -> Response {
    let body = format!(r#"{{"error":"too_many_requests","retry_after":{retry_after_secs}}}"#);
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::RETRY_AFTER, retry_after_secs.to_string()),
            (header::CONTENT_TYPE, "application/json".to_string()),
        ],
        body,
    )
        .into_response()
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

#[derive(Template)]
#[template(path = "login_magic.html")]
pub struct MagicLoginTemplate {
    pub error: Option<String>,
    /// When set, shows the post-submit "check your email" confirmation instead
    /// of the email form.
    pub notice: Option<String>,
}

// -- Handlers --

#[derive(serde::Deserialize, Default)]
pub struct LoginQuery {
    pub reset_token: Option<String>,
}

/// GET /login - Show login form, or redirect to set-password flow if a
/// `reset_token` query parameter is present. In magic-link mode, renders the
/// email form instead of the password form.
pub async fn login_page(
    State(state): State<Arc<AppState>>,
    Query(q): Query<LoginQuery>,
) -> Response {
    if let Some(token) = q.reset_token.as_deref().filter(|t| !t.is_empty()) {
        let encoded = urlencoding::encode(token);
        return Redirect::to(&format!("/set-password?reset_token={encoded}")).into_response();
    }
    if state.magic_login_enabled() {
        return MagicLoginTemplate {
            error: None,
            notice: None,
        }
        .into_response();
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

    // Per-IP rate limit. Only applies to POST (the limiter is only invoked
    // here, never on GET /login). If the IP header parses to an `IpAddr`,
    // consume a token from its bucket; on miss return 429 with Retry-After.
    // If the header is missing or unparseable we fail open — this is best-
    // effort defense in depth, not the primary control.
    if let Some(parsed) = ip.as_deref().and_then(|s| s.parse::<IpAddr>().ok()) {
        if let Err(retry_after) = state.login_limiter.check(parsed) {
            warn!("login rate-limit hit for {parsed} (retry_after={retry_after}s)");
            let _ = state
                .repo
                .log_admin_action("login_rate_limited", None, ip.as_deref())
                .await;
            return too_many_login_attempts(retry_after);
        }
    }

    // Magic-link mode: the body is an email, not a password. Email a one-time
    // link to a matching Administrator and show a neutral confirmation.
    if state.magic_login_enabled() {
        return magic_login_submit(state, req, ip).await;
    }

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

// -- Magic-link (passwordless) login --

#[derive(serde::Deserialize)]
struct MagicLoginForm {
    email: String,
}

/// How long a magic-link login token is valid.
const MAGIC_LINK_TTL_MINUTES: i64 = 15;

/// POST /login in magic-link mode. Looks up an Administrator by email, mints a
/// one-time token, emails the link, and always returns a neutral confirmation
/// (no account enumeration).
async fn magic_login_submit(
    state: Arc<AppState>,
    req: Request<Body>,
    ip: Option<String>,
) -> Response {
    let body_bytes = match axum::body::to_bytes(req.into_body(), 1024 * 16).await {
        Ok(b) => b,
        Err(_) => {
            return MagicLoginTemplate {
                error: Some("Invalid request".to_string()),
                notice: None,
            }
            .into_response()
        }
    };
    let form: MagicLoginForm = match serde_urlencoded::from_bytes(&body_bytes) {
        Ok(f) => f,
        Err(_) => {
            return MagicLoginTemplate {
                error: Some("Enter a valid email".to_string()),
                notice: None,
            }
            .into_response()
        }
    };
    let email = form.email.trim().to_ascii_lowercase();

    // Find an Administrator with this email (the allowlist is "is a provisioned
    // admin of this tenant"). Failures are swallowed into the neutral response.
    let admins = state
        .repo
        .list_users(&chalk_core::models::sync::UserFilter {
            role: Some(chalk_core::models::common::RoleType::Administrator),
            ..Default::default()
        })
        .await
        .unwrap_or_default();
    let user = admins
        .into_iter()
        .find(|u| u.email.as_deref().map(|e| e.eq_ignore_ascii_case(&email)) == Some(true));

    if let Some(user) = user {
        let raw = generate_session_token();
        let token_hash = hash_token(&raw);
        let expires = Utc::now() + Duration::minutes(MAGIC_LINK_TTL_MINUTES);
        if let Err(e) = state
            .repo
            .create_magic_login_token(&user.sourced_id, &token_hash, expires)
            .await
        {
            warn!("create_magic_login_token failed: {e}");
        } else if let Some(mailer) = state.magic_login.clone() {
            let base = state.config.chalk.public_url.clone().unwrap_or_default();
            let link = format!("{base}/login/verify?token={raw}");
            let to = user.email.clone().unwrap_or_default();
            tokio::spawn(async move {
                if let Err(e) = mailer.send_login_link(&to, &link).await {
                    warn!("magic login email send failed: {e}");
                }
            });
        }
    }
    let _ = state
        .repo
        .log_admin_action("magic_login_requested", None, ip.as_deref())
        .await;

    MagicLoginTemplate {
        error: None,
        notice: Some(
            "If that email belongs to an admin, a one-time sign-in link is on its way. \
             It expires in 15 minutes."
                .to_string(),
        ),
    }
    .into_response()
}

/// GET /login/verify?token=... — redeem a magic-link token and start a session.
pub async fn login_verify(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    // Only valid in magic mode; otherwise behave like /login.
    if !state.magic_login_enabled() {
        return Redirect::to("/login").into_response();
    }
    let token = match req
        .uri()
        .query()
        .and_then(|qs| {
            serde_urlencoded::from_str::<std::collections::HashMap<String, String>>(qs).ok()
        })
        .and_then(|m| m.get("token").cloned())
    {
        Some(t) if !t.is_empty() => t,
        _ => {
            return MagicLoginTemplate {
                error: Some("Invalid or expired link".to_string()),
                notice: None,
            }
            .into_response();
        }
    };

    let user_id = match state.repo.consume_magic_login_token(&token).await {
        Ok(Some(uid)) => uid,
        Ok(None) => {
            return MagicLoginTemplate {
                error: Some("This sign-in link is invalid, expired, or already used.".to_string()),
                notice: None,
            }
            .into_response()
        }
        Err(e) => {
            warn!("consume_magic_login_token failed: {e}");
            return MagicLoginTemplate {
                error: Some("Internal error".to_string()),
                notice: None,
            }
            .into_response();
        }
    };

    // Defense in depth: only Administrators may start a console session.
    match state.repo.get_user(&user_id).await {
        Ok(Some(u)) if u.role == chalk_core::models::common::RoleType::Administrator => {}
        _ => {
            return MagicLoginTemplate {
                error: Some("This account can't access the admin console.".to_string()),
                notice: None,
            }
            .into_response()
        }
    }

    let ip = client_ip(&req);
    let token = generate_session_token();
    let session = AdminSession {
        token: token.clone(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(SESSION_DURATION_HOURS),
        ip_address: ip.clone(),
    };
    if let Err(e) = state.repo.create_admin_session(&session).await {
        warn!("create_admin_session failed: {e}");
        return MagicLoginTemplate {
            error: Some("Internal error".to_string()),
            notice: None,
        }
        .into_response();
    }
    let _ = state
        .repo
        .log_admin_action(
            "magic_login",
            Some("Admin logged in via magic link"),
            ip.as_deref(),
        )
        .await;

    let cookie = set_cookie(
        SESSION_COOKIE_NAME,
        &token,
        &CookieAttrs {
            same_site: SameSite::Lax,
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
    fn is_public_path_returns_true_for_signup_api() {
        // Apex signup endpoint is intentionally unauthenticated.
        assert!(is_public_path("/api/signup"));
        assert!(is_public_path("/api/signup/verify"));
    }

    #[test]
    fn is_public_path_returns_true_for_oneroster_prefix() {
        // The session middleware skips OneRoster — the bearer-token middleware
        // gates it instead.
        assert!(is_public_path("/api/oneroster/v1p1/users"));
    }

    #[test]
    fn is_public_path_does_not_blanket_exempt_api() {
        // Regression: the previous "/api/" blanket exemption left OneRoster
        // open. Any future `/api/*` route must declare itself public here
        // (or be guarded by its own middleware).
        assert!(!is_public_path("/api/admin/things"));
        assert!(!is_public_path("/api/v1/something"));
    }

    #[test]
    fn hash_token_is_deterministic_and_hex() {
        let h1 = hash_token("chk_abcd1234");
        let h2 = hash_token("chk_abcd1234");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_token_differs_for_different_inputs() {
        assert_ne!(hash_token("chk_aaaaaaaa"), hash_token("chk_bbbbbbbb"));
    }

    #[test]
    fn extract_bearer_token_from_header() {
        let req = Request::builder()
            .header(header::AUTHORIZATION, "Bearer chk_abc123")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), Some("chk_abc123".to_string()));
    }

    #[test]
    fn extract_bearer_token_missing_header() {
        let req = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(extract_bearer_token(&req), None);
    }

    #[test]
    fn extract_bearer_token_wrong_scheme() {
        let req = Request::builder()
            .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), None);
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

    // -- Rate limiter tests --
    //
    // We drive a `FakeClock` instead of `tokio::time::sleep` so the tests
    // are deterministic and run in microseconds.

    use std::sync::Mutex as StdMutex;

    struct FakeClock {
        // Tracked as an offset from a fixed origin so we can advance the
        // clock without dealing with `Instant::checked_add` edge cases.
        origin: Instant,
        offset: StdMutex<StdDuration>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                origin: Instant::now(),
                offset: StdMutex::new(StdDuration::ZERO),
            }
        }

        fn advance(&self, by: StdDuration) {
            let mut guard = self.offset.lock().expect("fake clock poisoned");
            *guard += by;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            let off = *self.offset.lock().expect("fake clock poisoned");
            self.origin + off
        }
    }

    fn test_ip() -> IpAddr {
        "10.1.2.3".parse().expect("valid test IP")
    }

    #[test]
    fn rate_limiter_allows_first_five_attempts() {
        let limiter = LoginRateLimiter::with_clock(Box::new(FakeClock::new()));
        let ip = test_ip();
        for i in 0..LOGIN_BUCKET_CAPACITY {
            assert!(
                limiter.check(ip).is_ok(),
                "attempt {} should be allowed",
                i + 1
            );
        }
    }

    #[test]
    fn rate_limiter_rejects_sixth_attempt() {
        let limiter = LoginRateLimiter::with_clock(Box::new(FakeClock::new()));
        let ip = test_ip();
        for _ in 0..LOGIN_BUCKET_CAPACITY {
            limiter.check(ip).expect("within capacity");
        }
        let err = limiter.check(ip).expect_err("sixth must be rejected");
        // Retry-After should be a positive integer < window.
        assert!(err >= 1, "retry-after must be >= 1 second");
        assert!(
            err <= LOGIN_BUCKET_WINDOW_SECS,
            "retry-after must be <= window"
        );
    }

    #[test]
    fn rate_limiter_resets_after_window() {
        let clock = Arc::new(FakeClock::new());
        // We share the FakeClock between the limiter and the test by
        // wrapping it in an Arc adapter.
        struct ArcClock(Arc<FakeClock>);
        impl Clock for ArcClock {
            fn now(&self) -> Instant {
                self.0.now()
            }
        }

        let limiter = LoginRateLimiter::with_clock(Box::new(ArcClock(Arc::clone(&clock))));
        let ip = test_ip();

        for _ in 0..LOGIN_BUCKET_CAPACITY {
            limiter.check(ip).expect("within capacity");
        }
        assert!(limiter.check(ip).is_err(), "exhausted");

        // Advance past the window — the bucket should refill to capacity.
        clock.advance(StdDuration::from_secs(LOGIN_BUCKET_WINDOW_SECS + 1));
        for i in 0..LOGIN_BUCKET_CAPACITY {
            assert!(
                limiter.check(ip).is_ok(),
                "post-refill attempt {} should be allowed",
                i + 1
            );
        }
    }

    #[test]
    fn rate_limiter_partial_refill_does_not_drop_fractions() {
        let clock = Arc::new(FakeClock::new());
        struct ArcClock(Arc<FakeClock>);
        impl Clock for ArcClock {
            fn now(&self) -> Instant {
                self.0.now()
            }
        }

        let limiter = LoginRateLimiter::with_clock(Box::new(ArcClock(Arc::clone(&clock))));
        let ip = test_ip();

        for _ in 0..LOGIN_BUCKET_CAPACITY {
            limiter.check(ip).expect("within capacity");
        }
        // After ~12 seconds (1/5 of the window) exactly one token should
        // be available again (5 tokens per 60s = 1 token per 12s).
        clock.advance(StdDuration::from_secs(12));
        assert!(
            limiter.check(ip).is_ok(),
            "12s should refill one full token"
        );
        // ...and the bucket should be empty again immediately after.
        assert!(limiter.check(ip).is_err(), "only one token was available");
    }

    #[test]
    fn rate_limiter_buckets_are_per_ip() {
        let limiter = LoginRateLimiter::with_clock(Box::new(FakeClock::new()));
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..LOGIN_BUCKET_CAPACITY {
            limiter.check(ip_a).expect("a within capacity");
        }
        assert!(limiter.check(ip_a).is_err(), "a is exhausted");
        // ip_b must be unaffected.
        for _ in 0..LOGIN_BUCKET_CAPACITY {
            limiter.check(ip_b).expect("b has its own bucket");
        }
        assert_eq!(limiter.tracked_ips(), 2);
    }

    #[test]
    fn rate_limiter_evicts_idle_entries() {
        let clock = Arc::new(FakeClock::new());
        struct ArcClock(Arc<FakeClock>);
        impl Clock for ArcClock {
            fn now(&self) -> Instant {
                self.0.now()
            }
        }
        let limiter = LoginRateLimiter::with_clock(Box::new(ArcClock(Arc::clone(&clock))));

        let ip_old: IpAddr = "10.0.0.9".parse().unwrap();
        limiter.check(ip_old).expect("first attempt allowed");
        assert_eq!(limiter.tracked_ips(), 1);

        // Advance well past the eviction threshold, then touch a different
        // IP — the stale entry should be cleared.
        clock.advance(LOGIN_BUCKET_EVICT_AFTER + StdDuration::from_secs(1));
        let ip_new: IpAddr = "10.0.0.10".parse().unwrap();
        limiter.check(ip_new).expect("new ip allowed");
        assert_eq!(limiter.tracked_ips(), 1, "stale entry should be evicted");
    }

    #[test]
    fn too_many_login_attempts_sets_retry_after_and_429() {
        let resp = too_many_login_attempts(42);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry = resp
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After header set");
        assert_eq!(retry.to_str().unwrap(), "42");
    }
}
