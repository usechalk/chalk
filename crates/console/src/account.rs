//! The signed-in person's own security page (SS-3): TOTP enrollment.
//!
//! Enrollment is self-service and per-person: generate a secret, scan the QR,
//! prove possession with one code, and from then on login demands a code.
//! Recovery codes are shown exactly once, stored only as digests.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use chalk_core::models::console_user::Actor;
use chalk_core::totp;
use chrono::Utc;
use serde::Deserialize;

use crate::auth::hash_token;
use crate::AppState;

pub const SECURITY_PATH: &str = "/account/security";

/// How many one-time recovery codes an enrollment mints.
pub const RECOVERY_CODES: usize = 8;

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "account_security.html")]
pub struct SecurityTemplate {
    pub nav: crate::nav::Nav,
    /// False for the shared-password admin, who has no per-person row to
    /// hang a secret on.
    pub has_account: bool,
    pub enrolled: bool,
    /// Set only in the reply to "start": the QR and codes render once.
    pub qr_svg: String,
    pub recovery_codes: Vec<String>,
    pub pending_confirm: bool,
    pub notice: String,
    pub csrf_token: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SecurityNoticeQuery {
    pub notice: String,
}

fn notice_message(notice: &str) -> String {
    match notice {
        "enabled" => "Two-factor auth is on. From now on, sign-in asks for a code.".into(),
        "disabled" => "Two-factor auth is off.".into(),
        "bad_code" => "That code did not verify — check the app and try again.".into(),
        "failed" => "That did not work — try again.".into(),
        _ => String::new(),
    }
}

async fn render(
    state: &Arc<AppState>,
    actor: &Actor,
    csrf: String,
    notice: &str,
    fresh: Option<(String, Vec<String>)>,
) -> Response {
    let (has_account, enrolled, pending_confirm) = match state.console_users.as_ref() {
        Some(users) => match users
            .get_console_user(actor.console_user_id().unwrap_or_default())
            .await
        {
            Ok(Some(u)) => (
                true,
                u.totp_confirmed,
                u.totp_secret.is_some() && !u.totp_confirmed,
            ),
            _ => (false, false, false),
        },
        None => (false, false, false),
    };
    let (qr_svg, recovery_codes) = fresh.unwrap_or_default();
    SecurityTemplate {
        nav: crate::nav::Nav::new(&state.config, "settings"),
        has_account,
        enrolled,
        qr_svg,
        recovery_codes,
        pending_confirm,
        notice: notice_message(notice),
        csrf_token: csrf,
    }
    .into_response()
}

/// `GET /account/security`
pub async fn security_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    axum::Extension(actor): axum::Extension<Actor>,
    axum::extract::Query(q): axum::extract::Query<SecurityNoticeQuery>,
) -> Response {
    render(&state, &actor, csrf.0, &q.notice, None).await
}

/// One human-friendly recovery code: `XXXX-XXXX` over an unambiguous
/// alphabet.
fn generate_recovery_code() -> String {
    use rand::RngExt;
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rng();
    let mut pick = |n: usize| {
        (0..n)
            .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
            .collect::<String>()
    };
    format!("{}-{}", pick(4), pick(4))
}

/// `POST /account/security/totp/start` — mint the secret and the recovery
/// codes, unconfirmed, and show the QR exactly once.
pub async fn totp_start(
    State(state): State<Arc<AppState>>,
    axum::Extension(actor): axum::Extension<Actor>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(users) = state.console_users.clone() else {
        return Redirect::to(&format!("{SECURITY_PATH}?notice=failed")).into_response();
    };
    let Ok(Some(user)) = users
        .get_console_user(actor.console_user_id().unwrap_or_default())
        .await
    else {
        return Redirect::to(&format!("{SECURITY_PATH}?notice=failed")).into_response();
    };

    let secret = totp::generate_secret();
    let codes: Vec<String> = (0..RECOVERY_CODES)
        .map(|_| generate_recovery_code())
        .collect();
    let digests: Vec<String> = codes
        .iter()
        .map(|c| hash_token(&c.replace('-', "").to_ascii_uppercase()))
        .collect();
    let recovery_json = serde_json::to_string(&digests).unwrap_or_default();
    if users
        .set_totp(&user.id, &secret, &recovery_json)
        .await
        .is_err()
    {
        return Redirect::to(&format!("{SECURITY_PATH}?notice=failed")).into_response();
    }

    let url = totp::otpauth_url("Chalk", &user.email, &secret);
    let qr_svg = qrcode::QrCode::new(url.as_bytes())
        .map(|code| {
            code.render::<qrcode::render::svg::Color>()
                .quiet_zone(false)
                .build()
        })
        .unwrap_or_default();

    // Render directly (not a redirect): the QR and the plaintext recovery
    // codes exist only in this one response. The echoed CSRF token must be
    // the one the cookie already holds, or the confirm step would 403.
    let csrf = crate::csrf::csrf_from_headers(&headers).unwrap_or_default();
    render(&state, &actor, csrf, "", Some((qr_svg, codes))).await
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CodeForm {
    pub code: String,
}

/// `POST /account/security/totp/confirm` — prove possession, arm the gate.
pub async fn totp_confirm(
    State(state): State<Arc<AppState>>,
    axum::Extension(actor): axum::Extension<Actor>,
    axum::Form(form): axum::Form<CodeForm>,
) -> Response {
    let Some(users) = state.console_users.clone() else {
        return Redirect::to(&format!("{SECURITY_PATH}?notice=failed")).into_response();
    };
    let Ok(Some(user)) = users
        .get_console_user(actor.console_user_id().unwrap_or_default())
        .await
    else {
        return Redirect::to(&format!("{SECURITY_PATH}?notice=failed")).into_response();
    };
    let Some(secret) = user.totp_secret.clone() else {
        return Redirect::to(&format!("{SECURITY_PATH}?notice=failed")).into_response();
    };
    let now = Utc::now().timestamp() as u64;
    if !totp::verify_code(&secret, form.code.trim(), now) {
        return Redirect::to(&format!("{SECURITY_PATH}?notice=bad_code")).into_response();
    }
    let _ = users.confirm_totp(&user.id).await;
    Redirect::to(&format!("{SECURITY_PATH}?notice=enabled")).into_response()
}

/// `POST /account/security/totp/disable` — requires a current code, so a
/// walked-away-from session cannot silently strip the account's 2FA.
pub async fn totp_disable(
    State(state): State<Arc<AppState>>,
    axum::Extension(actor): axum::Extension<Actor>,
    axum::Form(form): axum::Form<CodeForm>,
) -> Response {
    let Some(users) = state.console_users.clone() else {
        return Redirect::to(&format!("{SECURITY_PATH}?notice=failed")).into_response();
    };
    let Ok(Some(user)) = users
        .get_console_user(actor.console_user_id().unwrap_or_default())
        .await
    else {
        return Redirect::to(&format!("{SECURITY_PATH}?notice=failed")).into_response();
    };
    let Some(secret) = user.totp_secret.clone() else {
        return Redirect::to(&format!("{SECURITY_PATH}?notice=failed")).into_response();
    };
    let now = Utc::now().timestamp() as u64;
    if !totp::verify_code(&secret, form.code.trim(), now) {
        return Redirect::to(&format!("{SECURITY_PATH}?notice=bad_code")).into_response();
    }
    let _ = users.clear_totp(&user.id).await;
    Redirect::to(&format!("{SECURITY_PATH}?notice=disabled")).into_response()
}

#[cfg(test)]
mod tests;
