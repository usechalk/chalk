//! Uploading and serving what is attached to a ticket.
//!
//! # One download route, two audiences
//!
//! A technician and a requester both follow the same link. Rather than two
//! handlers with two nearly-identical authorisation checks — the arrangement
//! that eventually grows a difference nobody notices — there is one handler
//! that asks a single question: *does whoever this is get to see the ticket
//! this file hangs off?* An administrator gets to see every ticket; a
//! requester gets to see their own. Both answers come from the session that is
//! actually present.
//!
//! # Serving files a stranger uploaded
//!
//! The bytes are attacker-controlled, so the response says as much:
//!
//! - the content type comes from [`chalk_core::attachments::sniff`], never
//!   from the upload;
//! - `X-Content-Type-Options: nosniff`, so a browser cannot decide it knows
//!   better and execute it;
//! - `Content-Security-Policy: default-src 'none'; sandbox`, so even if
//!   something scriptable were served it has no origin to act in;
//! - only image formats that cannot carry script are `inline`; everything else
//!   downloads.

use std::sync::Arc;

use axum::extract::{Multipart, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use chalk_core::attachments::{
    check, content_disposition, digest, safe_filename, sniff, UploadError,
};
use chalk_core::models::ticket::TicketAttachment;
use chalk_core::models::user::User;
use chrono::Utc;

use crate::AppState;

/// A file pulled out of a multipart body, already checked.
pub struct Incoming {
    pub filename: String,
    pub bytes: Vec<u8>,
}

/// Read every `file` part of a multipart body.
///
/// Returns the files and, separately, the ordinary text fields — a caller
/// needs both, and reading the body twice is not possible.
pub async fn read_multipart(
    mut multipart: Multipart,
) -> Result<(Vec<(String, String)>, Vec<Incoming>), UploadError> {
    let mut fields = Vec::new();
    let mut files = Vec::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or_default().to_string();
        let filename = field.file_name().map(str::to_string);
        let Ok(bytes) = field.bytes().await else {
            continue;
        };

        match filename {
            // A file input that was left empty still arrives, with a blank
            // name and no bytes. That is not an error, it is somebody not
            // attaching anything.
            Some(f) if !f.trim().is_empty() && !bytes.is_empty() => {
                check(&bytes, files.len())?;
                files.push(Incoming {
                    filename: safe_filename(&f),
                    bytes: bytes.to_vec(),
                });
            }
            Some(_) => {}
            None => fields.push((name, String::from_utf8_lossy(&bytes).to_string())),
        }
    }
    Ok((fields, files))
}

/// Store each file and record it against `ticket_id`.
///
/// Bytes are written before the row, so a crash between the two leaves an
/// orphaned file rather than a row pointing at nothing — the first is
/// invisible to a person, the second is a broken link on a page.
pub async fn store_all(
    state: &Arc<AppState>,
    ticket_id: &str,
    comment_id: Option<i64>,
    files: Vec<Incoming>,
) -> usize {
    let (Some(store), Some(tickets)) = (state.attachments.as_ref(), state.tickets.as_ref()) else {
        if !files.is_empty() {
            tracing::warn!(
                "{} file(s) were uploaded but no attachment store is configured; \
                 they were discarded",
                files.len()
            );
        }
        return 0;
    };

    let mut stored = 0;
    for file in files {
        let id = uuid::Uuid::new_v4().to_string();
        let kind = sniff(&file.bytes);
        let size = file.bytes.len() as i64;
        let sha = digest(&file.bytes);

        let key = match store.put(&id, &file.bytes).await {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("could not store an attachment: {e}");
                continue;
            }
        };

        let row = TicketAttachment {
            id,
            ticket_id: ticket_id.to_string(),
            comment_id,
            // Sanitised here rather than only at the multipart reader, because
            // this is the function that writes the row and the guarantee
            // belongs with the write. Email ingestion calls it with a filename
            // from a MIME part that no browser ever touched.
            filename: safe_filename(&file.filename),
            // What the bytes are, not what the browser claimed.
            content_type: kind.content_type.to_string(),
            size_bytes: size,
            sha256: sha,
            storage_key: key.clone(),
            created_at: Utc::now(),
        };
        if let Err(e) = tickets.add_attachment(&row).await {
            tracing::error!("could not record an attachment: {e}");
            let _ = store.delete(&key).await;
            continue;
        }
        stored += 1;
    }
    stored
}

/// `GET /attachments/{id}` — the one download route.
///
/// Not under `/tickets/`, which requires an administrator session: a requester
/// following a link from their own page would be bounced to a login form for a
/// console they are not allowed into. It is exempt from that middleware and
/// does its own check for both audiences.
pub async fn download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (Some(store), Some(tickets)) = (state.attachments.clone(), state.tickets.clone()) else {
        return not_found();
    };
    let Ok(Some(attachment)) = tickets.get_attachment(&id).await else {
        return not_found();
    };

    if !may_see(&state, &headers, &attachment.ticket_id).await {
        // Not found, never forbidden: "you may not have this" confirms the id
        // is real, which is the whole of what an enumeration attack wants.
        return not_found();
    }

    let bytes = match store.get(&attachment.storage_key).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("attachment {id} is recorded but unreadable: {e}");
            return not_found();
        }
    };

    // Sniffed again at serve time rather than trusted from the row. The column
    // was written by this code, but a value that decides whether a browser
    // executes something should be derived from the bytes being served, not
    // from a string alongside them.
    let kind = sniff(&bytes);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, kind.content_type.to_string()),
            (
                header::CONTENT_DISPOSITION,
                content_disposition(&attachment.filename, kind.inline),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; sandbox".to_string(),
            ),
            (header::CACHE_CONTROL, "private, max-age=300".to_string()),
        ],
        bytes,
    )
        .into_response()
}

/// Whether the caller may see the ticket this file belongs to.
///
/// An administrator session sees everything. Otherwise a portal session must
/// belong to the requester — the same rule the thread uses, asked once.
async fn may_see(state: &Arc<AppState>, headers: &HeaderMap, ticket_id: &str) -> bool {
    if crate::auth::has_admin_session(state, headers).await {
        return true;
    }
    let Some(user) = crate::help::signed_in_user(state, headers).await else {
        return false;
    };
    let Some(tickets) = state.tickets.as_ref() else {
        return false;
    };
    let Ok(Some(ticket)) = tickets.get_ticket(ticket_id).await else {
        return false;
    };
    owns(&ticket, &user)
}

/// The single definition of "this ticket is yours".
pub fn owns(ticket: &chalk_core::models::ticket::Ticket, user: &User) -> bool {
    let by_roster = ticket.requester_user_sourced_id.as_deref() == Some(&user.sourced_id);
    let by_email = match (&ticket.requester_email, &user.email) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    };
    by_roster || by_email
}

pub fn upload_refused(id: &str, base: &str, e: UploadError) -> Response {
    let code = match e {
        UploadError::Empty => "file_empty",
        UploadError::TooLarge => "file_large",
        UploadError::TooMany => "file_many",
    };
    Redirect::to(&format!("{base}/{id}?notice={code}")).into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not found").into_response()
}

#[cfg(test)]
mod tests;
