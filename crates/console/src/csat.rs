//! CSAT — the survey sent when a ticket is resolved, and the public endpoint
//! its one-click rating links land on (WS-11).
//!
//! The email carries five links, one per score, each authenticated by nothing
//! but an unguessable token — the requester is in their inbox, not in any
//! session. Only the first response is recorded, so a forwarded email or a
//! prefetching mail client cannot rewrite the score, and clicking twice shows
//! "already recorded" rather than an error.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Response};
use chalk_core::mail::EmailMessage;
use chalk_core::models::csat::{valid_score, CsatResponse, CSAT_MAX, CSAT_MIN};
use chrono::Utc;

use crate::AppState;

/// Send the survey for a resolved ticket, once.
///
/// Quietly does nothing when any prerequisite is missing — no CSAT repository,
/// no mailer, no public URL, no reachable requester — and when a survey was
/// already sent for this ticket. Resolving is the trigger, but a re-resolve
/// must not be a second ask.
pub async fn send_survey_on_resolve(state: &Arc<AppState>, ticket_id: &str) {
    let (Some(csat), Some(mailer), Some(tickets)) = (
        state.csat.clone(),
        state.mailer.clone(),
        state.tickets.clone(),
    ) else {
        return;
    };
    let Some(base) = state.config.chalk.absolute_url_base() else {
        return;
    };
    let Ok(Some(ticket)) = tickets.get_ticket(ticket_id).await else {
        return;
    };

    // The requester's address: the one on the ticket, else their roster email —
    // the same resolution the reply notification uses.
    let to = match &ticket.requester_email {
        Some(e) if !e.trim().is_empty() => Some(e.clone()),
        _ => match &ticket.requester_user_sourced_id {
            Some(sid) => match state.repo.get_user(sid).await {
                Ok(Some(u)) => u.email,
                _ => None,
            },
            None => None,
        },
    };
    let Some(to) = to else { return };

    let survey = CsatResponse {
        id: uuid::Uuid::new_v4().to_string(),
        ticket_id: ticket.id.clone(),
        token: crate::csrf::generate_csrf_token(),
        score: None,
        sent_at: Utc::now(),
        responded_at: None,
    };
    match csat.create_csat(&survey).await {
        Ok(true) => {}
        // Already surveyed (re-resolve) — one ask per ticket.
        Ok(false) => return,
        Err(e) => {
            tracing::error!("could not create CSAT survey for ticket {ticket_id}: {e}");
            return;
        }
    }

    let mut lines = vec![
        format!(
            "Your ticket #{} ({}) has been resolved.",
            ticket.number, ticket.subject
        ),
        String::new(),
        "How did we do? One click records your answer:".to_string(),
        String::new(),
    ];
    for score in CSAT_MIN..=CSAT_MAX {
        lines.push(format!(
            "  {score} — {}: {base}/csat/{}/{score}",
            score_word(score),
            survey.token
        ));
    }
    lines.push(String::new());
    lines.push("Thank you — it helps us do better.".to_string());

    let message = EmailMessage::new(
        to.clone(),
        format!("[#{}] How did we do?", ticket.number),
        lines.join("\n"),
    );
    if let Err(e) = mailer.send_email(&message).await {
        tracing::error!("could not send CSAT survey for ticket {ticket_id} to {to}: {e}");
    }
}

fn score_word(score: i64) -> &'static str {
    match score {
        1 => "Very unhappy",
        2 => "Unhappy",
        3 => "Okay",
        4 => "Happy",
        _ => "Very happy",
    }
}

/// `GET /csat/{token}/{score}` — record a rating and say thanks.
///
/// A GET with a side effect, deliberately: it must work as a bare link in any
/// mail client. The damage a prefetcher can do is bounded — first response
/// only, idempotent after that — which is the standard shape of email rating
/// links everywhere.
pub async fn rate(
    State(state): State<Arc<AppState>>,
    Path((token, score)): Path<(String, i64)>,
) -> Response {
    let Some(csat) = state.csat.clone() else {
        return page("Ratings are not available here.", "");
    };
    if !valid_score(score) {
        return page("That is not a valid rating.", "");
    }
    // Unknown token and already-answered both end politely — an email link
    // must never dead-end the person who clicked it.
    match csat.record_csat_score(&token, score).await {
        Ok(true) => page(
            "Thank you — your rating was recorded.",
            "You can close this page.",
        ),
        Ok(false) => match csat.get_csat_by_token(&token).await {
            Ok(Some(_)) => page(
                "Your rating was already recorded.",
                "Only the first answer counts — thanks again.",
            ),
            _ => page("That rating link is no longer valid.", ""),
        },
        Err(e) => {
            tracing::error!("could not record CSAT for token: {e}");
            page("Something went wrong recording that.", "Please try again.")
        }
    }
}

/// A minimal, self-contained confirmation page. No console shell — the person
/// reading it is a requester in their mail client, not a technician.
fn page(title: &str, body: &str) -> Response {
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title>\
         <style>body{{font-family:system-ui,sans-serif;display:grid;place-items:center;\
         min-height:90vh;margin:0;background:#fafafa;color:#1a1a2e}}\
         main{{text-align:center;padding:2rem}}h1{{font-size:1.4rem}}</style></head>\
         <body><main><h1>{title}</h1><p>{body}</p></main></body></html>"
    ))
    .into_response()
}

#[cfg(test)]
mod tests;
