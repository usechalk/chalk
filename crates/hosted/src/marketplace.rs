//! Marketplace application endpoint mounted on the apex.
//!
//! POST `/api/marketplace/apply` accepts the marketing form payload, validates
//! it, and emails the contents to `MARKETPLACE_APPLY_RECIPIENT` via Postmark.
//! Per-IP rate limiting matches signup (3/hour).
//!
//! Recipient address is read from env so the public chalk repo doesn't bake
//! in a business email. If the env var is unset, the endpoint returns 503 and
//! the form-submit client falls back to its `data-fallback-email` mailto link.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use governor::{
    clock::DefaultClock, middleware::NoOpMiddleware, state::keyed::DefaultKeyedStateStore, Quota,
    RateLimiter,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

const POSTMARK_API_URL: &str = "https://api.postmarkapp.com/email";

#[derive(Clone)]
pub struct MarketplaceState {
    limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock, NoOpMiddleware>>,
}

impl Default for MarketplaceState {
    fn default() -> Self {
        Self::new()
    }
}

impl MarketplaceState {
    pub fn new() -> Self {
        let quota = Quota::with_period(Duration::from_secs(3600 / 3))
            .expect("non-zero period")
            .allow_burst(NonZeroU32::new(3).expect("non-zero burst"));
        Self {
            limiter: Arc::new(RateLimiter::keyed(quota)),
        }
    }
}

pub fn router(state: MarketplaceState) -> Router {
    Router::<MarketplaceState>::new()
        .route("/api/marketplace/apply", post(apply_post))
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum StringOrVec {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
pub struct ApplyRequest {
    pub company_name: String,
    pub contact_name: String,
    pub contact_email: String,
    pub company_website: String,
    /// Number arrives as a string from FormData JSON serialization.
    pub schools_served: String,
    #[serde(default)]
    pub integration_types: Option<StringOrVec>,
    pub description: String,
}

#[derive(Serialize)]
pub struct ApplyResponse {
    pub status: &'static str,
}

#[derive(Debug)]
pub enum ApplyError {
    InvalidEmail,
    InvalidField(&'static str),
    RateLimited,
    NotConfigured,
    SendFailed,
}

impl IntoResponse for ApplyError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            Self::InvalidEmail => (StatusCode::BAD_REQUEST, "invalid email"),
            Self::InvalidField(f) => (StatusCode::BAD_REQUEST, f),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate limited"),
            Self::NotConfigured => (StatusCode::SERVICE_UNAVAILABLE, "not configured"),
            Self::SendFailed => (StatusCode::BAD_GATEWAY, "send failed"),
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

async fn apply_post(
    State(state): State<MarketplaceState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<ApplyRequest>,
) -> Result<Json<ApplyResponse>, ApplyError> {
    if state.limiter.check_key(&addr.ip()).is_err() {
        return Err(ApplyError::RateLimited);
    }
    validate(&req)?;

    let recipient = std::env::var("MARKETPLACE_APPLY_RECIPIENT")
        .ok()
        .filter(|s| !s.is_empty());
    let Some(recipient) = recipient else {
        warn!("MARKETPLACE_APPLY_RECIPIENT unset — refusing to send");
        return Err(ApplyError::NotConfigured);
    };
    let token = std::env::var("POSTMARK_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    let Some(token) = token else {
        warn!("POSTMARK_TOKEN unset — refusing to send");
        return Err(ApplyError::NotConfigured);
    };
    let from = std::env::var("POSTMARK_FROM").unwrap_or_else(|_| "noreply@chalk.app".to_string());

    let body = format_email(&req);
    let subject = format!("[Marketplace] Application from {}", req.company_name);

    if let Err(e) = send_via_postmark(
        &token,
        &from,
        &recipient,
        &subject,
        &body,
        &req.contact_email,
    )
    .await
    {
        warn!("postmark marketplace apply send failed: {e}");
        return Err(ApplyError::SendFailed);
    }
    Ok(Json(ApplyResponse { status: "received" }))
}

fn validate(req: &ApplyRequest) -> Result<(), ApplyError> {
    if !is_valid_email(&req.contact_email) {
        return Err(ApplyError::InvalidEmail);
    }
    if req.company_name.trim().is_empty() || req.company_name.len() > 200 {
        return Err(ApplyError::InvalidField("company_name"));
    }
    if req.contact_name.trim().is_empty() || req.contact_name.len() > 120 {
        return Err(ApplyError::InvalidField("contact_name"));
    }
    if !req.company_website.starts_with("http://") && !req.company_website.starts_with("https://") {
        return Err(ApplyError::InvalidField("company_website"));
    }
    if req.schools_served.parse::<u32>().is_err() {
        return Err(ApplyError::InvalidField("schools_served"));
    }
    if req.description.trim().is_empty() || req.description.len() > 1000 {
        return Err(ApplyError::InvalidField("description"));
    }
    Ok(())
}

fn is_valid_email(e: &str) -> bool {
    let Some((local, domain)) = e.split_once('@') else {
        return false;
    };
    if local.is_empty() || local.contains(' ') {
        return false;
    }
    let Some(tld_dot) = domain.rfind('.') else {
        return false;
    };
    let tld = &domain[tld_dot + 1..];
    if tld.is_empty() || tld.chars().any(|c| c.is_ascii_digit()) || tld.len() < 2 {
        return false;
    }
    !domain[..tld_dot].is_empty()
}

fn format_email(req: &ApplyRequest) -> String {
    let integrations = req
        .integration_types
        .as_ref()
        .map(|v| match v {
            StringOrVec::One(s) => s.clone(),
            StringOrVec::Many(vs) => vs.join(", "),
        })
        .unwrap_or_else(|| "(none selected)".to_string());

    format!(
        "New marketplace application\n\n\
         Company:       {company}\n\
         Website:       {website}\n\
         Contact:       {contact} <{email}>\n\
         Schools served:{schools}\n\
         Integration:   {integrations}\n\n\
         Description:\n{description}\n",
        company = req.company_name,
        website = req.company_website,
        contact = req.contact_name,
        email = req.contact_email,
        schools = req.schools_served,
        integrations = integrations,
        description = req.description,
    )
}

async fn send_via_postmark(
    token: &str,
    from: &str,
    to: &str,
    subject: &str,
    text_body: &str,
    reply_to: &str,
) -> Result<()> {
    let body = serde_json::json!({
        "From": from,
        "To": to,
        "ReplyTo": reply_to,
        "Subject": subject,
        "TextBody": text_body,
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_req() -> ApplyRequest {
        ApplyRequest {
            company_name: "Acme".into(),
            contact_name: "Jane".into(),
            contact_email: "jane@acme.io".into(),
            company_website: "https://acme.io".into(),
            schools_served: "50".into(),
            integration_types: Some(StringOrVec::Many(vec!["roster".into(), "sso".into()])),
            description: "We do classroom apps.".into(),
        }
    }

    #[test]
    fn accepts_well_formed() {
        assert!(validate(&ok_req()).is_ok());
    }

    #[test]
    fn rejects_bad_email() {
        let mut r = ok_req();
        r.contact_email = "not-an-email".into();
        assert!(matches!(validate(&r), Err(ApplyError::InvalidEmail)));
    }

    #[test]
    fn rejects_non_http_website() {
        let mut r = ok_req();
        r.company_website = "acme.io".into();
        assert!(matches!(
            validate(&r),
            Err(ApplyError::InvalidField("company_website"))
        ));
    }

    #[test]
    fn rejects_non_numeric_schools() {
        let mut r = ok_req();
        r.schools_served = "many".into();
        assert!(matches!(
            validate(&r),
            Err(ApplyError::InvalidField("schools_served"))
        ));
    }

    #[test]
    fn rejects_oversize_description() {
        let mut r = ok_req();
        r.description = "x".repeat(1001);
        assert!(matches!(
            validate(&r),
            Err(ApplyError::InvalidField("description"))
        ));
    }

    #[test]
    fn format_includes_all_fields() {
        let body = format_email(&ok_req());
        assert!(body.contains("Acme"));
        assert!(body.contains("jane@acme.io"));
        assert!(body.contains("https://acme.io"));
        assert!(body.contains("50"));
        assert!(body.contains("roster, sso"));
        assert!(body.contains("classroom apps"));
    }
}
