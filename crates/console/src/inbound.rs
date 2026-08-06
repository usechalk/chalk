//! The endpoint a mail provider POSTs to.
//!
//! # Why this is not behind a session
//!
//! Postmark cannot present one. The endpoint is authenticated by a shared
//! secret instead, which is the mechanism inbound webhooks actually support:
//! the URL is configured once in the provider's dashboard and never seen by a
//! person. It stays closed until both a provider and a secret are configured,
//! because an open one lets anybody on the internet file tickets in a
//! district's queue.
//!
//! # Why it almost always answers 200
//!
//! Providers re-deliver on any non-2xx, and Postmark keeps retrying for hours.
//! So a message Chalk *decides* not to act on — an auto-reply, something with
//! no `Message-ID` — is a success: it was handled, and handling it meant
//! dropping it. Only a genuinely unreadable body or a failed write earns a
//! non-2xx, because those are the cases where retrying might work.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chalk_core::inbound_email::{providers, EmailIngestor, Ingested};
use chalk_core::ticket_service::TicketService;
use serde::Deserialize;

use crate::AppState;

pub const INBOUND_PATH: &str = "/inbound/email";

/// Header alternative to `?secret=`, for relays that would rather not put it
/// in a URL that ends up in logs.
const SECRET_HEADER: &str = "x-chalk-inbound-secret";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct InboundQuery {
    pub secret: String,
}

/// `POST /inbound/email`
pub async fn receive(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<InboundQuery>,
    body: Bytes,
) -> Response {
    let config = &state.config.helpdesk.inbound;
    let (Some(provider), Some(expected)) = (config.provider.as_deref(), config.secret.as_deref())
    else {
        // Never configured. Not an error to report in detail — an unconfigured
        // endpoint should look the same as one that does not exist.
        return StatusCode::NOT_FOUND.into_response();
    };

    let presented = if !query.secret.is_empty() {
        query.secret.clone()
    } else {
        headers
            .get(SECRET_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    if !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        // Deliberately terse. A wrong secret gets nothing to calibrate against.
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let Some(parser) = providers::parser_for(provider) else {
        tracing::error!(
            "helpdesk.inbound.provider is {provider:?}, which Chalk does not know; \
             expected one of {:?}",
            providers::PROVIDERS
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let message = match parser.parse(&body) {
        Ok(m) => m,
        Err(e) => {
            // A body we cannot read will not become readable on retry, so this
            // is a 400 — telling the provider to stop rather than hammer.
            tracing::warn!("could not read an inbound message from {provider}: {e}");
            return (StatusCode::BAD_REQUEST, "unreadable payload").into_response();
        }
    };

    let Some(tickets) = state.tickets.clone() else {
        tracing::error!("inbound mail arrived but the helpdesk is not wired");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    // Resolve an address to a roster user. Loaded once per message rather than
    // per lookup, and only consulted when the provider vouched for the sender.
    let roster = state
        .repo
        .list_users(&chalk_core::models::sync::UserFilter::search(
            chalk_core::email::address_from_header(&message.from),
            25,
        ))
        .await
        .unwrap_or_default();

    let mut message = message;
    let attachments = std::mem::take(&mut message.attachments);
    let ingestor = EmailIngestor::new(
        tickets,
        TicketService::new(state.config.helpdesk.clone(), state.assets.clone()),
        Box::new(move |email| {
            roster
                .iter()
                .find(|u| {
                    u.email
                        .as_deref()
                        .is_some_and(|e| e.eq_ignore_ascii_case(email))
                })
                .cloned()
        }),
    );

    match ingestor.ingest(message).await {
        Ok(Ingested::Raised(id)) | Ok(Ingested::Replied(id)) => {
            store_attachments(&state, &id, attachments).await;
            StatusCode::OK.into_response()
        }
        // Already handled. Emphatically a success — anything else and the
        // provider retries forever.
        Ok(Ingested::AlreadySeen(id)) => {
            tracing::debug!("inbound message already ingested as ticket {id}");
            StatusCode::OK.into_response()
        }
        Ok(Ingested::Dropped(reason)) => {
            tracing::info!("dropped an inbound message: {}", reason.as_str());
            StatusCode::OK.into_response()
        }
        Err(e) => {
            // A write failed. This one *is* worth retrying.
            tracing::error!("could not ingest an inbound message: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn store_attachments(
    state: &Arc<AppState>,
    ticket_id: &str,
    attachments: Vec<chalk_core::inbound_email::InboundAttachment>,
) {
    if attachments.is_empty() {
        return;
    }
    let files: Vec<crate::ticket_files::Incoming> = attachments
        .into_iter()
        // The same size and count limits as an upload. A mail provider will
        // happily forward a 30 MB attachment.
        .filter(|a| chalk_core::attachments::check(&a.bytes, 0).is_ok())
        .take(chalk_core::attachments::MAX_ATTACHMENTS_PER_MESSAGE)
        .map(|a| crate::ticket_files::Incoming {
            filename: a.filename,
            bytes: a.bytes,
        })
        .collect();
    crate::ticket_files::store_all(state, ticket_id, None, files).await;
}

/// Compare two secrets without leaking their length or contents through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests;
