//! Self-serve signup endpoint mounted on the apex.
//!
//! Flow:
//! 1. POST `/api/signup` with `{slug, admin_email, admin_name, district_name,
//!    captcha_token}`. We validate the slug + email, verify Cloudflare
//!    Turnstile (skipped in dev when `TURNSTILE_SECRET` is unset), insert a
//!    row into `_meta.signup_pending` with a 24h-expiring UUID token, and
//!    email a verification link via Postmark (or log it to stdout in dev).
//! 2. GET `/api/signup/verify?token=...` looks up the pending row, runs the
//!    shared `provision::activate_tenant` pipeline (which seals per-tenant
//!    keys + bootstraps the admin user), deletes the pending row, and
//!    redirects the user to `https://<slug>.<apex>/login?reset_token=<...>`.
//!
//! Per-IP rate limiting on POST is provided by `governor` via a tiny
//! tower-style layer below — we keep the dependency surface small rather
//! than pulling tower-governor.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use governor::{
    clock::DefaultClock, middleware::NoOpMiddleware, state::keyed::DefaultKeyedStateStore, Quota,
    RateLimiter,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use crate::commands::provision;
use crate::keys::MasterKey;
use crate::tenant::TenantRegistry;
use crate::{is_valid_slug, RESERVED_SLUGS};

/// Cloudflare Turnstile siteverify endpoint.
const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
/// Postmark transactional-email endpoint.
const POSTMARK_API_URL: &str = "https://api.postmarkapp.com/email";

/// State for signup routes (separate from the per-tenant cache because
/// signup runs on the apex host and never resolves a tenant context).
#[derive(Clone)]
pub struct SignupState {
    pub registry: Arc<TenantRegistry>,
    pub master_key: Arc<MasterKey>,
    pub apex: String,
    pub postgres_url: String,
    /// Scheme used in verification email links and the post-activation redirect.
    pub public_scheme: String,
    /// Optional port appended to verification + activation URLs.
    pub public_port: Option<u16>,
    pub limiter:
        Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock, NoOpMiddleware>>,
}

impl SignupState {
    pub fn new(
        registry: Arc<TenantRegistry>,
        master_key: Arc<MasterKey>,
        apex: String,
        postgres_url: String,
        public_scheme: String,
        public_port: Option<u16>,
    ) -> Self {
        // 3 successful signup POSTs per IP per hour.
        let quota = Quota::with_period(Duration::from_secs(3600 / 3))
            .expect("non-zero period")
            .allow_burst(NonZeroU32::new(3).expect("non-zero burst"));
        let limiter = Arc::new(RateLimiter::keyed(quota));
        Self {
            registry,
            master_key,
            apex,
            postgres_url,
            public_scheme,
            public_port,
            limiter,
        }
    }
}

pub fn router(state: SignupState) -> Router {
    Router::<SignupState>::new()
        .route("/api/signup", post(signup_post))
        .route("/api/signup/verify", get(signup_verify))
        .with_state(state)
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub slug: String,
    pub admin_email: String,
    pub admin_name: String,
    pub district_name: String,
    pub captcha_token: Option<String>,
    /// Optional SIS-provider choice from the signup chooser. Accepts the
    /// snake_case strings the OSS `SisProvider` serde wire format emits
    /// (`powerschool`, `infinite_campus`, `skyward`, `oneroster_csv`). An
    /// empty string or `None` means "I'll set this up later" and is stored
    /// as NULL in `_meta.signup_pending.sis_provider`.
    #[serde(default)]
    pub sis_provider: Option<String>,
}

/// Allowed `sis_provider` values on the signup form. Kept as a free string
/// in the API surface (rather than parsing into `SisProvider`) so the hosted
/// crate doesn't grow a dependency on the OSS enum just for validation.
/// `activate_tenant` will eventually hand this off to Phase 1/3/4 code that
/// writes the per-tenant `tenant_config_sis` row.
const ALLOWED_SIS_PROVIDERS: &[&str] =
    &["powerschool", "infinite_campus", "skyward", "oneroster_csv"];

fn normalize_sis_provider(raw: Option<&str>) -> Result<Option<String>, SignupError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) if ALLOWED_SIS_PROVIDERS.contains(&s) => Ok(Some(s.to_string())),
        Some(_) => Err(SignupError::InvalidSisProvider),
    }
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub status: &'static str,
    pub email_sent: bool,
}

#[derive(Debug)]
pub enum SignupError {
    InvalidSlug,
    ReservedSlug,
    SlugTaken,
    InvalidEmail,
    InvalidName,
    InvalidSisProvider,
    CaptchaFailed,
    RateLimited,
    Internal(String),
}

impl IntoResponse for SignupError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            SignupError::InvalidSlug => (StatusCode::BAD_REQUEST, "invalid slug"),
            SignupError::ReservedSlug => (StatusCode::BAD_REQUEST, "reserved slug"),
            SignupError::SlugTaken => (StatusCode::CONFLICT, "slug already taken"),
            SignupError::InvalidEmail => (StatusCode::BAD_REQUEST, "invalid email"),
            SignupError::InvalidName => (StatusCode::BAD_REQUEST, "invalid name"),
            SignupError::InvalidSisProvider => (StatusCode::BAD_REQUEST, "invalid sis_provider"),
            SignupError::CaptchaFailed => (StatusCode::BAD_REQUEST, "captcha failed"),
            SignupError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate limited"),
            SignupError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
        if let SignupError::Internal(ref e) = self {
            warn!("signup internal error: {e}");
        }
        (status, Json(serde_json::json!({"error": msg}))).into_response()
    }
}

/// Lightweight email-format check: contains '@', no spaces, has TLD-looking
/// suffix, length <= 254.
pub fn is_valid_email(email: &str) -> bool {
    if email.len() > 254 || email.contains(' ') {
        return false;
    }
    let (local, domain) = match email.split_once('@') {
        Some(p) => p,
        None => return false,
    };
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if !domain.contains('.') {
        return false;
    }
    let tld = domain.rsplit('.').next().unwrap_or("");
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    true
}

/// Extract the client IP, preferring `X-Forwarded-For` (first hop) then
/// `X-Real-IP`, then the connection peer.
fn client_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    if let Some(v) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
        if let Some(first) = v.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    if let Some(v) = headers.get("x-real-ip").and_then(|h| h.to_str().ok()) {
        if let Ok(ip) = v.trim().parse::<IpAddr>() {
            return ip;
        }
    }
    peer
}

async fn signup_post(
    State(state): State<SignupState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<SignupRequest>,
) -> Result<Json<SignupResponse>, SignupError> {
    let ip = client_ip(&headers, peer.ip());
    state
        .limiter
        .check_key(&ip)
        .map_err(|_| SignupError::RateLimited)?;

    if RESERVED_SLUGS.contains(&req.slug.as_str()) {
        return Err(SignupError::ReservedSlug);
    }
    if !is_valid_slug(&req.slug) {
        return Err(SignupError::InvalidSlug);
    }
    if !is_valid_email(&req.admin_email) {
        return Err(SignupError::InvalidEmail);
    }
    let admin_name = req.admin_name.trim().to_string();
    if admin_name.is_empty() || admin_name.len() > 200 {
        return Err(SignupError::InvalidName);
    }
    let district_name = req.district_name.trim().to_string();
    if district_name.is_empty() || district_name.len() > 200 {
        return Err(SignupError::InvalidName);
    }

    let sis_provider = normalize_sis_provider(req.sis_provider.as_deref())?;

    verify_turnstile(req.captcha_token.as_deref(), &ip.to_string())
        .await
        .map_err(|_| SignupError::CaptchaFailed)?;

    let existing = state
        .registry
        .get(&req.slug)
        .await
        .map_err(|e| SignupError::Internal(e.to_string()))?;
    if existing.is_some() {
        return Err(SignupError::SlugTaken);
    }

    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + ChronoDuration::hours(24);
    insert_pending(
        state.registry.pool(),
        &token,
        &req.slug,
        &req.admin_email,
        &admin_name,
        &district_name,
        sis_provider.as_deref(),
        expires_at,
    )
    .await
    .map_err(|e| SignupError::Internal(e.to_string()))?;

    // Hand the email send to a background task so the HTTP handler returns
    // immediately. The pending row already holds the token, so a transient
    // Postmark failure is recoverable from the operator's logs in dev and
    // (eventually) a resend endpoint in prod.
    let verify_url = format!(
        "{}/api/signup/verify?token={}",
        crate::public_url(&state.public_scheme, None, &state.apex, state.public_port),
        token
    );
    let email_to = req.admin_email.clone();
    tokio::spawn(async move {
        match send_verification_email(&email_to, &verify_url).await {
            Ok(true) => {}
            Ok(false) => {
                // Dev fallback already logged the URL in `send_verification_email`.
            }
            Err(e) => {
                warn!("postmark send failed for {email_to}: {e}");
            }
        }
    });

    Ok(Json(SignupResponse {
        status: "pending",
        // Best-effort: the send is now spawned, so we report `true` once
        // dispatched. Failures surface via `tracing::warn!` in the spawned task.
        email_sent: true,
    }))
}

async fn signup_verify(
    Query(params): Query<VerifyParams>,
    State(state): State<SignupState>,
) -> Response {
    match verify_inner(&state, &params.token).await {
        Ok(redirect) => redirect.into_response(),
        Err((status, html)) => (status, html).into_response(),
    }
}

#[derive(Deserialize)]
struct VerifyParams {
    token: String,
}

async fn verify_inner(
    state: &SignupState,
    token: &str,
) -> Result<Redirect, (StatusCode, Html<String>)> {
    let row = take_pending(state.registry.pool(), token)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(format!("<h1>Internal error</h1><p>{e}</p>")),
            )
        })?;
    let row = match row {
        Some(r) => r,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Html(
                    "<h1>Invalid or expired link</h1><p>Please request a new signup email.</p>"
                        .to_string(),
                ),
            ));
        }
    };
    if row.expires_at < Utc::now() {
        return Err((
            StatusCode::BAD_REQUEST,
            Html("<h1>Link expired</h1><p>Please request a new signup email.</p>".to_string()),
        ));
    }

    // Log the chosen provider for operator visibility. Phase 3/4 will use
    // this to seed `tenant_config_sis` from the per-tenant repo Phase 1 is
    // creating. We deliberately don't fail activation when the provider is
    // None — that just means "I'll set it up later" from the chooser.
    info!(
        slug = %row.slug,
        sis_provider = row.sis_provider.as_deref().unwrap_or("(none)"),
        "activating tenant"
    );

    let outcome = provision::activate_tenant(
        &state.postgres_url,
        &row.slug,
        &row.display_name,
        &row.admin_email,
        &row.admin_name,
        &state.master_key,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(format!("<h1>Activation failed</h1><pre>{e}</pre>")),
        )
    })?;

    let url = format!(
        "{}/login?reset_token={}",
        crate::public_url(
            &state.public_scheme,
            Some(&outcome.slug),
            &state.apex,
            state.public_port,
        ),
        outcome.admin.reset_token
    );
    Ok(Redirect::to(&url))
}

struct PendingRow {
    slug: String,
    admin_email: String,
    admin_name: String,
    display_name: String,
    sis_provider: Option<String>,
    expires_at: DateTime<Utc>,
}

#[allow(clippy::too_many_arguments)]
async fn insert_pending(
    pool: &PgPool,
    token: &str,
    slug: &str,
    admin_email: &str,
    admin_name: &str,
    display_name: &str,
    sis_provider: Option<&str>,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO _meta.signup_pending \
         (token, slug, admin_email, admin_name, display_name, sis_provider, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(token)
    .bind(slug)
    .bind(admin_email)
    .bind(admin_name)
    .bind(display_name)
    .bind(sis_provider)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Tuple shape returned by the `DELETE ... RETURNING` query in
/// `take_pending`. Aliased so clippy's `type_complexity` lint stays happy
/// without an `#[allow]`.
type PendingRowTuple = (
    String,
    String,
    String,
    String,
    Option<String>,
    DateTime<Utc>,
);

async fn take_pending(pool: &PgPool, token: &str) -> Result<Option<PendingRow>> {
    // Atomically delete-and-return the matching row so that even concurrent
    // verify clicks can't double-activate.
    let row: Option<PendingRowTuple> = sqlx::query_as(
        "DELETE FROM _meta.signup_pending WHERE token = $1 \
             RETURNING slug, admin_email, admin_name, display_name, sis_provider, expires_at",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(slug, admin_email, admin_name, display_name, sis_provider, expires_at)| PendingRow {
            slug,
            admin_email,
            admin_name,
            display_name,
            sis_provider,
            expires_at,
        },
    ))
}

/// Verify a Turnstile token if `TURNSTILE_SECRET` is configured. In dev (no
/// secret) this is a no-op that emits a warn log.
async fn verify_turnstile(token: Option<&str>, remote_ip: &str) -> Result<()> {
    let secret = match std::env::var("TURNSTILE_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            warn!("TURNSTILE_SECRET unset — skipping captcha (dev only)");
            return Ok(());
        }
    };
    let token = token.ok_or_else(|| anyhow!("missing captcha token"))?;
    let resp = reqwest::Client::new()
        .post(TURNSTILE_VERIFY_URL)
        .form(&[
            ("secret", secret.as_str()),
            ("response", token),
            ("remoteip", remote_ip),
        ])
        .send()
        .await?
        .json::<TurnstileResponse>()
        .await?;
    if !resp.success {
        return Err(anyhow!(
            "turnstile rejected: {:?}",
            resp.error_codes.unwrap_or_default()
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct TurnstileResponse {
    success: bool,
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<String>>,
}

/// Send the verification email via Postmark. If `POSTMARK_TOKEN` is unset we
/// log the URL to stdout as a dev fallback and return `Ok(false)`.
async fn send_verification_email(to: &str, url: &str) -> Result<bool> {
    let token = match std::env::var("POSTMARK_TOKEN") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            info!(target: "chalk_hosted::signup", "DEV verification url for {to}: {url}");
            return Ok(false);
        }
    };
    let from = std::env::var("POSTMARK_FROM").unwrap_or_else(|_| "noreply@chalk.app".to_string());
    let body = serde_json::json!({
        "From": from,
        "To": to,
        "Subject": "Verify your Chalk signup",
        "TextBody": format!("Click to verify and activate your tenant:\n\n{url}\n\nThis link expires in 24 hours."),
        "MessageStream": "outbound",
    });
    let resp = reqwest::Client::new()
        .post(POSTMARK_API_URL)
        .header("X-Postmark-Server-Token", token)
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        return Err(anyhow!("postmark error {status}: {txt}"));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sis_provider_normalize_empty_is_none() {
        assert!(normalize_sis_provider(None).unwrap().is_none());
        assert!(normalize_sis_provider(Some("")).unwrap().is_none());
        assert!(normalize_sis_provider(Some("   ")).unwrap().is_none());
    }

    #[test]
    fn sis_provider_normalize_accepts_known() {
        for p in ["powerschool", "infinite_campus", "skyward", "oneroster_csv"] {
            assert_eq!(normalize_sis_provider(Some(p)).unwrap().as_deref(), Some(p));
        }
    }

    #[test]
    fn sis_provider_normalize_rejects_unknown() {
        assert!(matches!(
            normalize_sis_provider(Some("acme")),
            Err(SignupError::InvalidSisProvider)
        ));
    }

    #[test]
    fn email_validation() {
        assert!(is_valid_email("a@b.co"));
        assert!(is_valid_email("first.last+tag@example.org"));
        assert!(!is_valid_email("no-at-sign"));
        assert!(!is_valid_email("@nolocal.com"));
        assert!(!is_valid_email("nolocal@"));
        assert!(!is_valid_email("a@b"));
        assert!(!is_valid_email("a b@c.de"));
        assert!(!is_valid_email("a@b.1"));
    }
}
