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
    http::{header, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use parking_lot::Mutex;
use rand::RngExt;
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
    "/share/dashboard/",
    "/login",
    "/set-password",
    "/api/signup",
    "/api/oneroster/", // unauthed at the session-middleware layer; the bearer
    // middleware enforces the actual gate further down the
    // stack so OneRoster handlers never run without a valid
    // token.
    "/static/", // self-hosted assets (htmx bundle) — needed before
    // auth so the login page can load them.
    "/inbound/", // inbound mail webhooks. A provider cannot present a session;
    // `inbound::receive` checks a shared secret in constant time
    // and 404s when the feature is not configured at all.
    "/attachments/", // ticket attachments. Both a technician and a requester
    // follow the same link, so this cannot sit behind the
    // admin session — `ticket_files::download` asks which
    // session is present and whether it may see the ticket
    // the file hangs off.
    "/help", // the staff help portal. Exempt from the *admin* session because
    // its audience is a teacher, never an administrator; every handler
    // there checks a portal session of its own and redirects to
    // /help/signin without one. Requiring an admin session would make
    // the portal reachable only by the people it is not for.
    "/csat/", // one-click satisfaction ratings from a resolved-ticket email.
    "/attest/", // custody self-attestation answers from a campaign email.
              // The unguessable token in the path is the whole credential —
              // the requester clicking from their inbox has no session of any
              // kind, and only the first response is recorded.
];

/// Check if a path should bypass session authentication.
fn is_public_path(path: &str) -> bool {
    PUBLIC_PATHS.iter().any(|p| path.starts_with(p))
}

/// SHA-256 hex of a string. Used both at token-mint time and at verification
/// time. Plaintext tokens are never compared directly — we only ever see the
/// digest server-side.
pub(crate) fn hash_token(plaintext: &str) -> String {
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
/// Whether this request carries a valid administrator session.
///
/// Lives beside [`auth_middleware`] because it must agree with it, including
/// the local-development shortcut: in a console with no password and no
/// magic-link, every request is already admin-authenticated, and a handler
/// that decided otherwise would refuse the operator on their own machine.
pub async fn has_admin_session(state: &Arc<AppState>, headers: &HeaderMap) -> bool {
    if state.config.chalk.admin_password_hash.is_none() && !state.magic_login_enabled() {
        return true;
    }
    let Some(raw) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(token) = raw
        .split(';')
        .map(str::trim)
        .find_map(|c| c.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")))
    else {
        return false;
    };
    matches!(
        state.repo.get_admin_session(token).await,
        Ok(Some(s)) if s.expires_at > Utc::now()
    )
}

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
        // No session, so no per-person identity: the open console acts as the
        // anonymous administrator, which is what attribution falls back to.
        let actor = chalk_core::models::console_user::Actor::shared_admin();
        let mut req = req;
        req.extensions_mut()
            .insert(crate::authz::Principal::unrestricted(actor.clone()));
        req.extensions_mut().insert(actor);
        return next.run(req).await;
    }

    // Check for valid session
    if let Some(token) = extract_session_token(&req) {
        if let Ok(Some(session)) = state.repo.get_admin_session(&token).await {
            if session.expires_at > Utc::now() {
                let actor = session.actor();

                // Permission enforcement, before the handler runs (GP-2).
                // Resolved live, not from the session, so a revocation bites
                // on the next request rather than the next login. The shared
                // password and magic-link have no console-user row and
                // resolve to unrestricted, so self-host is unaffected.
                let principal = state.resolve_principal(&actor).await;
                let matched = req
                    .extensions()
                    .get::<axum::extract::MatchedPath>()
                    .map(|m| m.as_str().to_owned());
                use crate::authz::RouteAuthz;
                match matched
                    .as_deref()
                    .and_then(|m| crate::authz::route_authz(req.method(), m))
                {
                    Some(RouteAuthz::Public) | Some(RouteAuthz::SelfService) => {}
                    Some(RouteAuthz::Read(p)) | Some(RouteAuthz::Write(p)) => {
                        if !principal.allows(p) {
                            return forbidden("Your account does not have access to this.");
                        }
                    }
                    // FAIL CLOSED: a mutating route nobody declared is a
                    // route nobody decided about. The lint catches this at
                    // build time; this catches whatever slips past it.
                    None if is_mutating(req.method()) => {
                        return forbidden("This action has no declared permission.");
                    }
                    // Undeclared reads stay open — the pre-GP-2 contract —
                    // and row-level scoping still filters what they show.
                    None => {}
                }

                // Product analytics (hosted-only): the sink is absent on
                // self-host, and the event type has no field that could
                // carry PII — route template + method + role, nothing else.
                if let Some(sink) = &state.analytics {
                    if let Some(m) = matched.as_deref() {
                        sink.capture(chalk_core::analytics::AnalyticsEvent {
                            name: if is_mutating(req.method()) {
                                "console_action"
                            } else {
                                "console_pageview"
                            },
                            route: m.to_string(),
                            method: req.method().to_string(),
                            role: actor.role.as_str().to_string(),
                        });
                    }
                }

                // Hand the handler the identity captured at login, so audit
                // events and ticket comments name a real person, plus the
                // resolved principal for row-level scope decisions.
                let mut req = req;
                req.extensions_mut().insert(principal);
                req.extensions_mut().insert(actor);
                return next.run(req).await;
            }
            // Expired session - clean it up
            let _ = state.repo.delete_admin_session(&token).await;
        }
    }

    // Redirect to login
    Redirect::to("/login").into_response()
}

/// A method that changes state. GET/HEAD/OPTIONS are reads; everything else a
/// read-only account is refused.
fn is_mutating(method: &axum::http::Method) -> bool {
    !matches!(
        *method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    )
}

/// `message` is always a fixed literal from this module, so it needs no
/// escaping. Kept as a parameter only so the two call sites read clearly.
fn forbidden(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Html(format!(
            "<!doctype html><meta charset=utf-8><title>Not allowed</title>\
             <p>{message}</p><p><a href=\"/\">Back</a></p>"
        )),
    )
        .into_response()
}

/// The identity for the current request, for handlers that attribute an action.
///
/// Reads the [`Actor`](chalk_core::models::console_user::Actor) that
/// [`auth_middleware`] attached. Absent only on paths that never run behind the
/// middleware; those fall back to the anonymous administrator, which is the
/// honest answer when there is no session to name.
pub fn request_actor(ext: &axum::http::Extensions) -> chalk_core::models::console_user::Actor {
    ext.get::<chalk_core::models::console_user::Actor>()
        .cloned()
        .unwrap_or_else(chalk_core::models::console_user::Actor::shared_admin)
}

/// Generate a random session token (64 hex characters).
pub(crate) fn generate_session_token() -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.random()).collect();
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

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub sso: bool,
    pub error: Option<String>,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "set_password.html")]
pub struct SetPasswordTemplate {
    pub reset_token: String,
    pub error: Option<String>,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "login_magic.html")]
pub struct MagicLoginTemplate {
    pub sso: bool,
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
            sso: state.console_sso.is_some(),
            error: None,
            notice: None,
        }
        .into_response();
    }
    LoginTemplate {
        sso: state.console_sso.is_some(),
        error: None,
    }
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct LoginForm {
    /// A console user's email. Empty means the shared-password path (the
    /// self-host default, and every install that predates console accounts).
    #[serde(default)]
    pub email: String,
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
                sso: false,
                error: Some("Invalid request".to_string()),
            }
            .into_response();
        }
    };

    let form: LoginForm = match serde_urlencoded::from_bytes(&body_bytes) {
        Ok(f) => f,
        Err(_) => {
            return LoginTemplate {
                sso: false,
                error: Some("Invalid form data".to_string()),
            }
            .into_response();
        }
    };

    // Resolve a hash to verify against, and the identity to act as.
    //
    // If an email was given, this is a per-person console-account login: match
    // it, and fail closed if it does not resolve rather than silently falling
    // through to the shared password — an explicit wrong email is a failed
    // login, not an anonymous attempt.
    //
    // Otherwise the shared-password path, whose preference order is unchanged:
    //   1. config.chalk.admin_password_hash — the OSS chalk.toml shared secret.
    //   2. Per-user `users.password_hash` for a roster Administrator (hosted
    //      bootstraps one and the reset-token flow writes into it).
    // The shared path has no per-person identity, so its actor is None, which
    // resolves to the anonymous "Administrator" — self-host unchanged.
    let email = form.email.trim().to_ascii_lowercase();
    let (password_hash, actor): (String, Option<chalk_core::models::console_user::Actor>) =
        if !email.is_empty() {
            let user = match &state.console_users {
                Some(repo) => repo.get_console_user_by_email(&email).await.ok().flatten(),
                None => None,
            };
            match user {
                Some(u) if u.is_active() && u.password_hash.is_some() => {
                    let actor = chalk_core::models::console_user::Actor::from_console_user(&u);
                    (u.password_hash.clone().unwrap(), Some(actor))
                }
                _ => {
                    // Unknown email, disabled account, or no password set. Same
                    // generic message as a wrong password, so the form never
                    // reveals which console emails exist.
                    warn!("console-account login failed for an unmatched email");
                    let _ = state
                        .repo
                        .log_admin_action("login_failed", None, ip.as_deref())
                        .await;
                    return LoginTemplate {
                        sso: false,
                        error: Some("Invalid email or password".to_string()),
                    }
                    .into_response();
                }
            }
        } else {
            let hash = match &state.config.chalk.admin_password_hash {
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
                                sso: false,
                                error: Some("No admin password configured".to_string()),
                            }
                            .into_response();
                        }
                    }
                }
            };
            (hash, None)
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
                sso: false,
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
            sso: false,
            error: Some("Invalid password".to_string()),
        }
        .into_response();
    }

    // Password verified. A console account with confirmed 2FA does not get a
    // session yet — it gets a short-lived challenge and the code form. The
    // challenge token is the only thing tying step two to the verified
    // password, and it redeems exactly once.
    if let (Some(actor_ref), Some(users)) = (actor.as_ref(), state.console_users.as_ref()) {
        if let Ok(Some(u)) = users
            .get_console_user(actor_ref.console_user_id().unwrap_or_default())
            .await
        {
            if u.totp_confirmed {
                let challenge = generate_session_token();
                if let Err(e) = users
                    .create_totp_challenge(&challenge, &u.id, Utc::now() + Duration::minutes(5))
                    .await
                {
                    warn!("could not create a totp challenge: {e}");
                    return LoginTemplate {
                        sso: false,
                        error: Some("Internal error".to_string()),
                    }
                    .into_response();
                }
                return LoginTotpTemplate {
                    challenge,
                    error: None,
                }
                .into_response();
            }
        }
    }

    // Create session, stamping the identity captured above so attribution
    // needs no join. A shared-password login leaves these None.
    let token = generate_session_token();
    let session = AdminSession {
        token: token.clone(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(SESSION_DURATION_HOURS),
        ip_address: ip.clone(),
        actor_id: actor.as_ref().map(|a| a.id.clone()),
        actor_label: actor.as_ref().map(|a| a.label.clone()),
        actor_role: actor.as_ref().map(|a| a.role.as_str().to_string()),
    };

    if let Err(e) = state.repo.create_admin_session(&session).await {
        warn!("Failed to create session: {}", e);
        return LoginTemplate {
            sso: false,
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
                sso: false,
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
                sso: false,
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
            // Absent means no scheme and no host, which a mail client cannot
            // open — the message arrives, looks right, and does nothing.
            // Better to send none and say why in the log.
            match state.config.chalk.absolute_url_base() {
                Some(base) => {
                    let link = format!("{base}/login/verify?token={raw}");
                    let to = user.email.clone().unwrap_or_default();
                    tokio::spawn(async move {
                        if let Err(e) = mailer.send_login_link(&to, &link).await {
                            warn!("magic login email send failed: {e}");
                        }
                    });
                }
                None => warn!(
                    "chalk.public_url is not set, so a magic-link login mail would \
                     contain a link with no host. No mail was sent."
                ),
            }
        }
    }
    let _ = state
        .repo
        .log_admin_action("magic_login_requested", None, ip.as_deref())
        .await;

    MagicLoginTemplate {
        sso: false,
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
                sso: false,
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
                sso: false,
                error: Some("This sign-in link is invalid, expired, or already used.".to_string()),
                notice: None,
            }
            .into_response()
        }
        Err(e) => {
            warn!("consume_magic_login_token failed: {e}");
            return MagicLoginTemplate {
                sso: false,
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
                sso: false,
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
        actor_id: None,
        actor_label: None,
        actor_role: None,
    };
    if let Err(e) = state.repo.create_admin_session(&session).await {
        warn!("create_admin_session failed: {e}");
        return MagicLoginTemplate {
            sso: false,
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

// ---------------------------------------------------------------------------
// Login step two: TOTP (SS-3)
// ---------------------------------------------------------------------------

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "login_totp.html")]
pub struct LoginTotpTemplate {
    pub challenge: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct TotpLoginForm {
    pub challenge: String,
    pub code: String,
}

/// `POST /login/totp` — redeem the challenge with a 6-digit code or a
/// recovery code. A failed attempt burns the challenge (single use), sending
/// the person back to the password step rather than giving a guesser a
/// stationary target.
pub async fn login_totp_submit(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<TotpLoginForm>,
) -> Response {
    let Some(users) = state.console_users.clone() else {
        return LoginTemplate {
            sso: false,
            error: Some("Invalid email or password".to_string()),
        }
        .into_response();
    };
    let user_id = match users.take_totp_challenge(form.challenge.trim()).await {
        Ok(Some(id)) => id,
        _ => {
            return LoginTemplate {
                sso: false,
                error: Some("That sign-in attempt expired — start again.".to_string()),
            }
            .into_response();
        }
    };
    let Ok(Some(user)) = users.get_console_user(&user_id).await else {
        return LoginTemplate {
            sso: false,
            error: Some("Invalid email or password".to_string()),
        }
        .into_response();
    };
    let Some(secret) = user.totp_secret.clone() else {
        return LoginTemplate {
            sso: false,
            error: Some("Invalid email or password".to_string()),
        }
        .into_response();
    };

    let code = form.code.trim();
    let now = Utc::now().timestamp() as u64;
    let mut ok = chalk_core::totp::verify_code(&secret, code, now);
    if !ok {
        // Not a valid TOTP — maybe a recovery code. Burn it on use.
        if let Some(recovery_json) = user.totp_recovery.clone() {
            let normalized = code.replace('-', "").to_ascii_uppercase();
            let digest = hash_token(&normalized);
            if let Ok(mut hashes) = serde_json::from_str::<Vec<String>>(&recovery_json) {
                if let Some(pos) = hashes.iter().position(|h| h == &digest) {
                    hashes.remove(pos);
                    let remaining = serde_json::to_string(&hashes).unwrap_or_default();
                    let _ = users.set_totp_recovery(&user.id, &remaining).await;
                    ok = true;
                }
            }
        }
    }
    if !ok {
        warn!("totp verification failed for a console account");
        let _ = state
            .repo
            .log_admin_action("login_failed", Some("totp"), None)
            .await;
        return LoginTemplate {
            sso: false,
            error: Some("That code did not verify — sign in again.".to_string()),
        }
        .into_response();
    }

    let actor = chalk_core::models::console_user::Actor::from_console_user(&user);
    finish_login(&state, Some(actor), None).await
}

/// Session creation + cookie + redirect, shared by the one-step and two-step
/// login paths so the two can never drift.
async fn finish_login(
    state: &Arc<AppState>,
    actor: Option<chalk_core::models::console_user::Actor>,
    ip: Option<String>,
) -> Response {
    let token = generate_session_token();
    let session = AdminSession {
        token: token.clone(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(SESSION_DURATION_HOURS),
        ip_address: ip.clone(),
        actor_id: actor.as_ref().map(|a| a.id.clone()),
        actor_label: actor.as_ref().map(|a| a.label.clone()),
        actor_role: actor.as_ref().map(|a| a.role.as_str().to_string()),
    };
    if let Err(e) = state.repo.create_admin_session(&session).await {
        warn!("Failed to create session: {}", e);
        return LoginTemplate {
            sso: false,
            error: Some("Internal error".to_string()),
        }
        .into_response();
    }
    let _ = state
        .repo
        .log_admin_action("login", Some("Admin logged in"), ip.as_deref())
        .await;
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

// ---------------------------------------------------------------------------
// Console sign-in via Chalk's own IdP (SS-6)
// ---------------------------------------------------------------------------

/// Ten minutes of validity for the OAuth `state` nonce cookie — the whole
/// flow is seconds; anything older is a replay or a bookmark.
const SSO_STATE_COOKIE: &str = "chalk_sso_state";

/// `GET /login/sso` — bounce to Chalk's own authorize endpoint with a fresh
/// `state` nonce pinned in a cookie.
pub async fn login_sso_start(State(state): State<Arc<AppState>>) -> Response {
    let Some(sso) = state.console_sso.clone() else {
        return Redirect::to("/login").into_response();
    };
    let nonce = generate_session_token();
    let authorize = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email&state={}",
        sso.authorize_url,
        urlencoding::encode(&sso.client_id),
        urlencoding::encode(&sso.redirect_uri),
        nonce,
    );
    let cookie = set_cookie(
        SSO_STATE_COOKIE,
        &nonce,
        &CookieAttrs {
            // Lax, not Strict: the callback arrives as a cross-page redirect
            // from the authorize endpoint, and a Strict cookie would not
            // accompany it.
            same_site: SameSite::Lax,
            http_only: true,
            secure: state.config.chalk.cookies_secure(),
            path: "/login",
            max_age_secs: Some(600),
        },
    );
    (
        StatusCode::SEE_OTHER,
        [(header::SET_COOKIE, cookie), (header::LOCATION, authorize)],
    )
        .into_response()
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct SsoCallbackQuery {
    pub code: String,
    pub state: String,
    pub error: String,
}

fn sso_fail(message: &str) -> Response {
    LoginTemplate {
        sso: true,
        error: Some(message.to_string()),
    }
    .into_response()
}

/// `GET /login/sso/callback` — redeem the code with our own token endpoint,
/// read the email from userinfo, and sign the matching console account in.
/// 2FA still interposes: the IdP proved who they are, the authenticator
/// proves it twice, exactly as a password would have.
pub async fn login_sso_callback(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(q): Query<SsoCallbackQuery>,
) -> Response {
    let Some(sso) = state.console_sso.clone() else {
        return Redirect::to("/login").into_response();
    };
    if !q.error.is_empty() {
        return sso_fail("Sign-in was cancelled.");
    }
    // The state nonce must match the cookie set at /login/sso — a code
    // arriving without it was not requested by this browser.
    let cookie_state = crate::csrf::csrf_named_cookie(&headers, SSO_STATE_COOKIE);
    if q.state.is_empty() || cookie_state.as_deref() != Some(q.state.as_str()) {
        warn!("sso callback with a mismatched state nonce");
        return sso_fail("That sign-in attempt expired — start again.");
    }
    if q.code.is_empty() {
        return sso_fail("That sign-in attempt expired — start again.");
    }

    // Code → tokens, against our own token endpoint.
    #[derive(serde::Deserialize)]
    struct TokenResponse {
        access_token: String,
    }
    let http = reqwest::Client::new();
    let token: TokenResponse = match http
        .post(&sso.token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", q.code.as_str()),
            ("redirect_uri", sso.redirect_uri.as_str()),
            ("client_id", sso.client_id.as_str()),
            ("client_secret", sso.client_secret.as_str()),
        ])
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => match r.json().await {
            Ok(t) => t,
            Err(e) => {
                warn!("sso token response unreadable: {e}");
                return sso_fail("Sign-in failed — try again.");
            }
        },
        Ok(r) => {
            warn!("sso token exchange refused ({})", r.status());
            return sso_fail("Sign-in failed — try again.");
        }
        Err(e) => {
            warn!("sso token exchange failed: {e}");
            return sso_fail("Sign-in failed — try again.");
        }
    };

    // Access token → userinfo → email. The round trip to our own server is
    // what makes the claim authoritative without JWKS plumbing here.
    #[derive(serde::Deserialize)]
    struct UserInfo {
        email: Option<String>,
    }
    let info: UserInfo = match http
        .get(&sso.userinfo_url)
        .bearer_auth(&token.access_token)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => match r.json().await {
            Ok(i) => i,
            Err(e) => {
                warn!("sso userinfo unreadable: {e}");
                return sso_fail("Sign-in failed — try again.");
            }
        },
        _ => return sso_fail("Sign-in failed — try again."),
    };
    let Some(email) = info.email.map(|e| e.trim().to_ascii_lowercase()) else {
        return sso_fail("Your account has no email address to match on.");
    };

    // Email is the bridge between the roster namespace the IdP authenticated
    // and the console-account namespace this session lives in.
    let Some(users) = state.console_users.clone() else {
        return sso_fail("Console accounts are not set up here.");
    };
    let user = match users.get_console_user_by_email(&email).await {
        Ok(Some(u)) if u.is_active() => u,
        _ => {
            // Same generic wording as a wrong password: the form never
            // reveals which console emails exist.
            warn!("sso sign-in for an email with no active console account");
            let _ = state
                .repo
                .log_admin_action("login_failed", Some("sso"), None)
                .await;
            return sso_fail("No console account matches that sign-in.");
        }
    };

    // 2FA interposes exactly as it would after a password.
    if user.totp_confirmed {
        let challenge = generate_session_token();
        if users
            .create_totp_challenge(&challenge, &user.id, Utc::now() + Duration::minutes(5))
            .await
            .is_err()
        {
            return sso_fail("Sign-in failed — try again.");
        }
        return LoginTotpTemplate {
            challenge,
            error: None,
        }
        .into_response();
    }

    let actor = chalk_core::models::console_user::Actor::from_console_user(&user);
    finish_login(&state, Some(actor), None).await
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

    // -----------------------------------------------------------------------
    // Console SSO via the local IdP (SS-6)
    // -----------------------------------------------------------------------

    mod sso {
        use super::super::*;
        use crate::{router, AppState, ConsoleSso};
        use axum::body::Body;
        use axum::http::Request;
        use chalk_core::config::ChalkConfig;
        use chalk_core::db::repository::{ChalkRepository, ConsoleUserRepository};
        use chalk_core::db::sqlite::SqliteRepository;
        use chalk_core::db::DatabasePool;
        use chalk_core::models::console_user::{ConsoleRole, ConsoleUser, ConsoleUserStatus};
        use tower::ServiceExt;
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        async fn fixture(idp: &MockServer) -> (Arc<AppState>, Arc<SqliteRepository>) {
            let pool = DatabasePool::new_sqlite_memory().await.unwrap();
            let repo = match pool {
                DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
                DatabasePool::Postgres(_) => unreachable!(),
            };
            repo.create_console_user(&ConsoleUser {
                id: "cu-1".into(),
                email: "maya.chen@district.test".into(),
                display_name: "Maya Chen".into(),
                password_hash: None, // SSO-only technician: no password at all
                role: ConsoleRole::Technician,
                status: ConsoleUserStatus::Active,
                totp_secret: None,
                totp_confirmed: false,
                totp_recovery: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .await
            .unwrap();
            let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
            let users: Arc<dyn ConsoleUserRepository> = repo.clone();
            let mut config = ChalkConfig::generate_default();
            config.chalk.admin_password_hash = Some(hash_password("unused").unwrap());
            let sso = Arc::new(ConsoleSso {
                client_id: "chalk-console".into(),
                client_secret: "boot-secret".into(),
                authorize_url: format!("{}/idp/oidc/authorize", idp.uri()),
                token_url: format!("{}/idp/oidc/token", idp.uri()),
                userinfo_url: format!("{}/idp/oidc/userinfo", idp.uri()),
                redirect_uri: "http://console.test/login/sso/callback".into(),
            });
            let state = Arc::new(
                AppState::new(chalk_repo, config)
                    .with_console_users(users)
                    .with_console_sso(sso),
            );
            (state, repo)
        }

        async fn mount_happy_idp(idp: &MockServer, email: &str) {
            Mock::given(method("POST"))
                .and(path("/idp/oidc/token"))
                .and(body_string_contains("boot-secret"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "at-1", "token_type": "Bearer", "id_token": "unused"
                })))
                .mount(idp)
                .await;
            Mock::given(method("GET"))
                .and(path("/idp/oidc/userinfo"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "sub": "user-1", "email": email
                })))
                .mount(idp)
                .await;
        }

        async fn callback(
            state: Arc<AppState>,
            qs: &str,
            cookie: &str,
        ) -> axum::response::Response {
            router(state)
                .oneshot(
                    Request::builder()
                        .uri(format!("/login/sso/callback?{qs}"))
                        .header("cookie", cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        }

        fn session_cookie(res: &axum::response::Response) -> Option<String> {
            res.headers()
                .get_all(axum::http::header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .find(|c| c.starts_with("chalk_session="))
                .map(str::to_string)
        }

        /// The magic-link login page — the one hosted tenants actually see —
        /// carries the SSO button exactly when console SSO is configured.
        /// (v1.39.0 put the button only on the password template, so hosted
        /// shipped a working flow with an invisible entry point.)
        #[tokio::test]
        async fn magic_login_page_shows_the_sso_button_exactly_when_configured() {
            let idp = MockServer::start().await;
            for want_button in [true, false] {
                let pool = DatabasePool::new_sqlite_memory().await.unwrap();
                let repo = match pool {
                    DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
                    DatabasePool::Postgres(_) => unreachable!(),
                };
                let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
                let mut config = ChalkConfig::generate_default();
                config.chalk.admin_password_hash = Some(hash_password("unused").unwrap());
                let mut state = AppState::new(chalk_repo, config)
                    .with_magic_login(Arc::new(chalk_core::mail::LoggingMailer));
                if want_button {
                    state = state.with_console_sso(Arc::new(ConsoleSso {
                        client_id: "chalk-console".into(),
                        client_secret: "boot-secret".into(),
                        authorize_url: format!("{}/idp/oidc/authorize", idp.uri()),
                        token_url: format!("{}/idp/oidc/token", idp.uri()),
                        userinfo_url: format!("{}/idp/oidc/userinfo", idp.uri()),
                        redirect_uri: "http://console.test/login/sso/callback".into(),
                    }));
                }
                let res = router(Arc::new(state))
                    .oneshot(
                        Request::builder()
                            .uri("/login")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(res.status(), StatusCode::OK);
                let body = axum::body::to_bytes(res.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let html = String::from_utf8_lossy(&body);
                assert!(
                    html.contains("email"),
                    "the magic-link form itself must still render"
                );
                assert_eq!(
                    html.contains("Sign in with Chalk SSO"),
                    want_button,
                    "sso configured: {want_button}"
                );
            }
        }

        /// The start leg sets the state cookie and points at authorize with
        /// the registered redirect.
        #[tokio::test]
        async fn start_sets_the_nonce_and_redirects_to_authorize() {
            let idp = MockServer::start().await;
            let (state, _) = fixture(&idp).await;
            let res = router(state)
                .oneshot(
                    Request::builder()
                        .uri("/login/sso")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::SEE_OTHER);
            let loc = res.headers().get("location").unwrap().to_str().unwrap();
            assert!(loc.starts_with(&format!("{}/idp/oidc/authorize", idp.uri())));
            assert!(loc.contains("client_id=chalk-console"));
            let cookies: Vec<_> = res
                .headers()
                .get_all(axum::http::header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            assert!(cookies.iter().any(|c| c.starts_with("chalk_sso_state=")));
        }

        /// Happy path: code + matching state → token exchange → userinfo →
        /// email matches the passwordless console account → session.
        #[tokio::test]
        async fn a_full_sso_login_issues_a_session() {
            let idp = MockServer::start().await;
            mount_happy_idp(&idp, "maya.chen@district.test").await;
            let (state, _) = fixture(&idp).await;
            let res = callback(state, "code=c-1&state=n-1", "chalk_sso_state=n-1").await;
            assert_eq!(res.status(), StatusCode::SEE_OTHER);
            assert!(session_cookie(&res).is_some(), "session issued");
        }

        /// A mismatched or missing state nonce refuses before any token
        /// exchange — the code was not requested by this browser.
        #[tokio::test]
        async fn a_mismatched_state_refuses_without_touching_the_idp() {
            let idp = MockServer::start().await;
            let (state, _) = fixture(&idp).await;
            let res = callback(state, "code=c-1&state=evil", "chalk_sso_state=n-1").await;
            assert_eq!(res.status(), StatusCode::OK, "login page with the error");
            assert!(session_cookie(&res).is_none());
            assert!(
                idp.received_requests().await.unwrap().is_empty(),
                "no token exchange happened"
            );
        }

        /// An authenticated roster user with no console account is refused
        /// with the same generic wording as a wrong password.
        #[tokio::test]
        async fn an_unknown_email_is_refused_generically() {
            let idp = MockServer::start().await;
            mount_happy_idp(&idp, "stranger@district.test").await;
            let (state, _) = fixture(&idp).await;
            let res = callback(state, "code=c-1&state=n-1", "chalk_sso_state=n-1").await;
            assert!(session_cookie(&res).is_none());
        }

        /// A disabled console account cannot ride SSO back in.
        #[tokio::test]
        async fn a_disabled_account_is_refused() {
            let idp = MockServer::start().await;
            mount_happy_idp(&idp, "maya.chen@district.test").await;
            let (state, repo) = fixture(&idp).await;
            let mut u = repo.get_console_user("cu-1").await.unwrap().unwrap();
            u.status = ConsoleUserStatus::Disabled;
            repo.update_console_user(&u).await.unwrap();
            let res = callback(state, "code=c-1&state=n-1", "chalk_sso_state=n-1").await;
            assert!(session_cookie(&res).is_none());
        }

        /// 2FA interposes after SSO exactly as it would after a password.
        #[tokio::test]
        async fn totp_still_interposes_after_sso() {
            let idp = MockServer::start().await;
            mount_happy_idp(&idp, "maya.chen@district.test").await;
            let (state, repo) = fixture(&idp).await;
            let secret = chalk_core::totp::generate_secret();
            repo.set_totp("cu-1", &secret, "[]").await.unwrap();
            repo.confirm_totp("cu-1").await.unwrap();
            let res = callback(state, "code=c-1&state=n-1", "chalk_sso_state=n-1").await;
            assert_eq!(res.status(), StatusCode::OK);
            assert!(session_cookie(&res).is_none(), "no session before the code");
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap();
            let html = String::from_utf8_lossy(&bytes);
            assert!(html.contains("/login/totp"), "the code form renders");
        }
    }
}
