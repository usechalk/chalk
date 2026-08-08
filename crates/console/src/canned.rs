//! Canned responses — the settings page that manages shared reply templates,
//! and the helper the ticket thread uses to offer them (WS-11).
//!
//! The templates are district-wide and small, so this is a plain list with an
//! add form and a delete button — no paging, no search. The reply box on a
//! ticket fills from them client-side; nothing here touches a ticket.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::models::canned_response::CannedResponse;
use serde::Deserialize;

use crate::AppState;

pub const CANNED_PATH: &str = "/settings/canned-responses";

/// One template as the reply picker needs it: a title to choose by and the body
/// to paste. Kept tiny so the ticket page can embed the whole library.
pub struct CannedOption {
    pub id: String,
    pub title: String,
    pub body: String,
}

/// Every canned response, or empty when the feature is not wired. Shared by the
/// settings page and the ticket-thread picker.
pub async fn canned_options(state: &Arc<AppState>) -> Vec<CannedOption> {
    let Some(repo) = state.canned_responses.as_ref() else {
        return Vec::new();
    };
    repo.list_canned_responses()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| CannedOption {
            id: c.id,
            title: c.title,
            body: c.body,
        })
        .collect()
}

struct Flash {
    kind: String,
    message: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "settings/canned_responses.html")]
struct CannedTemplate {
    nav: crate::nav::Nav,
    responses: Vec<CannedOption>,
    flash: Option<Flash>,
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct FlashQuery {
    #[serde(default)]
    ok: Option<String>,
    #[serde(default)]
    err: Option<String>,
}

fn not_available() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Canned responses are not available on this build.</h1>".to_string()),
    )
        .into_response()
}

/// `GET /settings/canned-responses`
pub async fn page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Query(flash_q): Query<FlashQuery>,
) -> Response {
    if state.canned_responses.is_none() {
        return not_available();
    }
    let flash = flash_q
        .ok
        .map(|m| Flash {
            kind: "success".to_string(),
            message: m,
        })
        .or_else(|| {
            flash_q.err.map(|m| Flash {
                kind: "warning".to_string(),
                message: m,
            })
        });
    CannedTemplate {
        nav: crate::nav::Nav::new(&state.config, "canned_responses"),
        responses: canned_options(&state).await,
        flash,
        csrf_token: csrf.0,
    }
    .into_response()
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct CreateForm {
    title: String,
    body: String,
}

/// `POST /settings/canned-responses`
pub async fn create(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<CreateForm>,
) -> Response {
    let Some(repo) = state.canned_responses.clone() else {
        return not_available();
    };
    let title = form.title.trim();
    let body = form.body.trim();
    if title.is_empty() || body.is_empty() {
        return Redirect::to(&format!(
            "{CANNED_PATH}?err=A+title+and+a+body+are+both+required."
        ))
        .into_response();
    }
    let response = CannedResponse::new(uuid::Uuid::new_v4().to_string(), title, body);
    match repo.create_canned_response(&response).await {
        Ok(()) => Redirect::to(&format!("{CANNED_PATH}?ok=Saved.")).into_response(),
        Err(e) => {
            tracing::error!("could not save canned response: {e}");
            Redirect::to(&format!("{CANNED_PATH}?err=That+could+not+be+saved.")).into_response()
        }
    }
}

/// `POST /settings/canned-responses/{id}/delete`
pub async fn delete(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some(repo) = state.canned_responses.clone() else {
        return not_available();
    };
    match repo.delete_canned_response(&id).await {
        Ok(()) => Redirect::to(&format!("{CANNED_PATH}?ok=Deleted.")).into_response(),
        Err(e) => {
            tracing::error!("could not delete canned response {id}: {e}");
            Redirect::to(&format!("{CANNED_PATH}?err=That+could+not+be+deleted.")).into_response()
        }
    }
}

#[cfg(test)]
mod tests;
