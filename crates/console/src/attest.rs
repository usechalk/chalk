//! Custody self-attestation campaigns (SS-2).
//!
//! The scan audit covers what is in the building; this covers what went
//! home. A campaign creates one ask per open loan and emails each holder a
//! tokenized link; the public form takes one answer — *do you still have it,
//! and what shape is it in* — and "no" is the finding the whole surface
//! exists to produce.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::models::attestation::{AttestCondition, Attestation};
use chrono::Utc;
use serde::Deserialize;

use crate::AppState;
use chalk_core::models::console_user::Actor;

pub const ATTESTATIONS_PATH: &str = "/devices/attestations";

// ---------------------------------------------------------------------------
// Console: campaign page + start + resend
// ---------------------------------------------------------------------------

/// One ask as the campaign table shows it.
pub struct AttestRow {
    pub holder: String,
    pub device: String,
    pub asset_id: String,
    pub requested: String,
    pub answered: bool,
    pub has_item: Option<bool>,
    pub condition: String,
    pub note: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/attestations.html")]
pub struct AttestationsTemplate {
    pub nav: crate::nav::Nav,
    pub rows: Vec<AttestRow>,
    pub outstanding: usize,
    pub missing_count: usize,
    pub open_loans: usize,
    pub can_send: bool,
    pub notice: String,
    pub csrf_token: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AttestNoticeQuery {
    pub notice: String,
}

fn notice_message(notice: &str) -> String {
    match notice {
        "started" => "Campaign started — every open loan without a pending ask was emailed.".into(),
        "resent" => "Reminders sent to everyone who has not answered.".into(),
        "nothing" => "Nothing to ask — no open loans without a pending ask.".into(),
        "no_mailer" => "No mail server is configured, so nothing could be sent.".into(),
        "failed" => "That did not work — try again.".into(),
        _ => String::new(),
    }
}

/// `GET /devices/attestations` — the campaign table.
pub async fn attestations_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    axum::extract::Query(q): axum::extract::Query<AttestNoticeQuery>,
) -> Response {
    let (Some(attest), Some(custody), Some(assets)) = (
        state.attestations.clone(),
        state.custody.clone(),
        state.assets.clone(),
    ) else {
        return not_configured();
    };
    let all = attest.list_attestations().await.unwrap_or_default();
    let open_loans = custody.list_open_custody().await.unwrap_or_default().len();

    let mut rows = Vec::with_capacity(all.len());
    for a in &all {
        // Small campaigns, per-row lookups — the circulation page precedent.
        let (holder, device, asset_id) = match custody.get_custody(&a.custody_id).await {
            Ok(Some(c)) => {
                let holder = match state.repo.get_user(&c.user_sourced_id).await {
                    Ok(Some(u)) => format!("{}, {}", u.family_name, u.given_name),
                    _ => c.user_sourced_id.clone(),
                };
                let device = match assets.get_asset(&c.asset_id).await {
                    Ok(Some(asset)) => asset
                        .asset_tag
                        .or(asset.serial_number)
                        .unwrap_or_else(|| c.asset_id.clone()),
                    _ => c.asset_id.clone(),
                };
                (holder, device, c.asset_id.clone())
            }
            _ => ("—".into(), a.custody_id.clone(), String::new()),
        };
        rows.push(AttestRow {
            holder,
            device,
            asset_id,
            requested: a.requested_at.format("%Y-%m-%d").to_string(),
            answered: a.answered(),
            has_item: a.has_item,
            condition: a
                .condition
                .map(|c| c.as_str().to_string())
                .unwrap_or_default(),
            note: a.note.clone().unwrap_or_default(),
        });
    }
    let outstanding = rows.iter().filter(|r| !r.answered).count();
    let missing_count = rows.iter().filter(|r| r.has_item == Some(false)).count();

    AttestationsTemplate {
        nav: crate::nav::Nav::new(&state.config, "devices"),
        rows,
        outstanding,
        missing_count,
        open_loans,
        can_send: state.mailer.is_some(),
        notice: notice_message(&q.notice),
        csrf_token: csrf.0,
    }
    .into_response()
}

/// Send (or re-send) the ask email for one attestation. Quietly skips holders
/// with no email — the campaign table still shows the ask, so nobody is
/// silently uncovered.
async fn send_ask(state: &Arc<AppState>, a: &Attestation) {
    let Some(mailer) = state.mailer.clone() else {
        return;
    };
    let Some(custody) = state.custody.clone() else {
        return;
    };
    let Some(base) = state.config.chalk.absolute_url_base() else {
        return;
    };
    let Ok(Some(c)) = custody.get_custody(&a.custody_id).await else {
        return;
    };
    let Ok(Some(user)) = state.repo.get_user(&c.user_sourced_id).await else {
        return;
    };
    let Some(email) = user.email.clone().filter(|e| !e.trim().is_empty()) else {
        return;
    };
    let device = match state.assets.clone() {
        Some(assets) => match assets.get_asset(&c.asset_id).await {
            Ok(Some(asset)) => asset
                .asset_tag
                .or(asset.serial_number)
                .unwrap_or_else(|| "your device".to_string()),
            _ => "your device".to_string(),
        },
        None => "your device".to_string(),
    };
    let body = format!(
        "Hi {},\n\n\
         Quick check from the technology office: do you still have {device}?\n\n\
         One minute, one link — it just asks whether you have it and what\n\
         shape it is in:\n\n  {base}/attest/{}\n\n\
         Thank you!",
        user.given_name, a.token
    );
    let message = chalk_core::mail::EmailMessage::new(
        email.clone(),
        format!("Do you still have {device}?"),
        body,
    );
    if let Err(e) = mailer.send_email(&message).await {
        tracing::error!("could not send an attestation ask to {email}: {e}");
    }
}

/// `POST /devices/attestations/start` — one ask per open loan that does not
/// already have a pending one.
pub async fn start_campaign(
    State(state): State<Arc<AppState>>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> Response {
    let (Some(attest), Some(custody)) = (state.attestations.clone(), state.custody.clone()) else {
        return back("failed");
    };
    if state.mailer.is_none() {
        return back("no_mailer");
    }
    let open = custody.list_open_custody().await.unwrap_or_default();
    let mut created = 0usize;
    for loan in &open {
        let a = Attestation {
            id: uuid::Uuid::new_v4().to_string(),
            custody_id: loan.id.clone(),
            token: uuid::Uuid::new_v4().to_string(),
            requested_at: Utc::now(),
            responded_at: None,
            has_item: None,
            condition: None,
            note: None,
            actor: actor.audit_actor(),
        };
        match attest.create_attestation(&a).await {
            Ok(true) => {
                created += 1;
                send_ask(&state, &a).await;
            }
            Ok(false) => {} // already pending — the resend button covers it
            Err(e) => tracing::error!("could not create an attestation: {e}"),
        }
    }
    back(if created > 0 { "started" } else { "nothing" })
}

/// `POST /devices/attestations/resend` — nag everyone who has not answered.
pub async fn resend_outstanding(State(state): State<Arc<AppState>>) -> Response {
    let Some(attest) = state.attestations.clone() else {
        return back("failed");
    };
    if state.mailer.is_none() {
        return back("no_mailer");
    }
    let all = attest.list_attestations().await.unwrap_or_default();
    for a in all.iter().filter(|a| !a.answered()) {
        send_ask(&state, a).await;
    }
    back("resent")
}

fn back(notice: &str) -> Response {
    Redirect::to(&format!("{ATTESTATIONS_PATH}?notice={notice}")).into_response()
}

// ---------------------------------------------------------------------------
// Public: the answer form
// ---------------------------------------------------------------------------

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "attest_form.html")]
pub struct AttestFormTemplate {
    pub token: String,
    pub device: String,
    pub csrf_token: String,
}

/// `GET /attest/{token}` — the one-question form. An unknown or answered
/// token ends politely; an email link must never dead-end the person who
/// clicked it.
pub async fn attest_form(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Path(token): Path<String>,
) -> Response {
    let Some(attest) = state.attestations.clone() else {
        return page("This link is not active here.");
    };
    let a = match attest.get_attestation_by_token(&token).await {
        Ok(Some(a)) => a,
        _ => return page("This link is no longer active."),
    };
    if a.answered() {
        return page("Already answered — thank you!");
    }
    let device = device_label(&state, &a).await;
    AttestFormTemplate {
        token,
        device,
        csrf_token: csrf.0,
    }
    .into_response()
}

async fn device_label(state: &Arc<AppState>, a: &Attestation) -> String {
    let (Some(custody), Some(assets)) = (state.custody.clone(), state.assets.clone()) else {
        return "your device".to_string();
    };
    let Ok(Some(c)) = custody.get_custody(&a.custody_id).await else {
        return "your device".to_string();
    };
    match assets.get_asset(&c.asset_id).await {
        Ok(Some(asset)) => asset
            .asset_tag
            .or(asset.serial_number)
            .unwrap_or_else(|| "your device".to_string()),
        _ => "your device".to_string(),
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AttestAnswerForm {
    /// `"yes"` or `"no"`.
    pub have: String,
    pub condition: String,
    pub note: String,
    pub csrf_token: String,
}

/// `POST /attest/{token}` — record the one answer. First answer wins.
pub async fn attest_submit(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    axum::Form(form): axum::Form<AttestAnswerForm>,
) -> Response {
    let Some(attest) = state.attestations.clone() else {
        return page("This link is not active here.");
    };
    let has_item = match form.have.as_str() {
        "yes" => true,
        "no" => false,
        _ => return page("Pick yes or no — that is the whole question."),
    };
    let Some(condition) = AttestCondition::parse(form.condition.trim()) else {
        return page("Pick a condition from the list.");
    };
    let note = {
        let n = form.note.trim();
        (!n.is_empty()).then(|| n.chars().take(500).collect::<String>())
    };
    match attest
        .respond_attestation(&token, has_item, condition, note.as_deref())
        .await
    {
        Ok(true) => page("Recorded — thank you!"),
        Ok(false) => page("Already answered — thank you!"),
        Err(e) => {
            tracing::error!("could not record an attestation answer: {e}");
            page("Something went wrong on our side — try the link again.")
        }
    }
}

/// The same minimal standalone page CSAT uses: a sentence, no console chrome.
fn page(message: &str) -> Response {
    Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>Device check</title></head>\
         <body style=\"font-family: system-ui, sans-serif; display: grid; place-items: center; min-height: 90vh;\">\
         <p style=\"font-size: 1.2rem;\">{message}</p></body></html>"
    ))
    .into_response()
}

fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Attestations are not available here.</h1>".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
