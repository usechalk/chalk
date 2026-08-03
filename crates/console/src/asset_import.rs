//! Importing devices from a CSV (A2).
//!
//! # This screen does not change anything
//!
//! It reads a file and produces a *proposal*. The operator lands on the same
//! diff preview a bulk edit produces, sees every row with its old and new
//! values, and can strike individual ones out before committing. A spreadsheet
//! is the highest-leverage and least-reviewed input a district has — someone
//! sorts one column without extending the selection and the file still looks
//! fine — so it gets the same gate every other fleet-wide write gets.
//!
//! That is the third entry point ARCHITECTURE §6.4 anticipated, and it needed
//! no new preview surface.
//!
//! # Why the upload page explains the columns
//!
//! The export writes exactly the columns the import reads, so the shortest
//! path to a good file is "export, edit, import back". The page says so and
//! links to the export, because an operator who builds a file from scratch is
//! the one who ends up with a rejected column list.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Multipart, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::asset_csv::{self, IMPORTABLE_COLUMNS, REFERENCE_COLUMNS};
use chalk_core::csv_import::plan_csv_import;
use serde::Deserialize;

use crate::AppState;

pub const IMPORT_PATH: &str = "/devices/import";

/// Actor recorded on everything an import writes, matching what the rest of
/// the console records so history reads consistently.
const ACTOR: &str = "console:admin";

/// Largest file the upload will read.
///
/// 8 MB is roughly 60,000 rows of this schema — comfortably more than one plan
/// may carry, so the ceiling an operator actually hits is the plan's, which is
/// reported per-file rather than as a rejected upload.
pub const MAX_UPLOAD_BYTES: usize = crate::csrf::MULTIPART_BODY_LIMIT;

/// The CSRF middleware buffers the body before this route's limit applies, so
/// a limit above its cap would reject at 400 without the handler running.
const _: () = assert!(MAX_UPLOAD_BYTES <= crate::csrf::MULTIPART_BODY_LIMIT);

// ---------------------------------------------------------------------------
// The upload page
// ---------------------------------------------------------------------------

pub struct ImportView {
    pub importable: Vec<&'static str>,
    pub reference: Vec<&'static str>,
    pub error: String,
    pub csrf_token: String,
}

impl ImportView {
    pub fn has_error(&self) -> bool {
        !self.error.is_empty()
    }
}

#[derive(Template)]
#[template(path = "devices/import.html")]
pub struct ImportTemplate {
    pub view: ImportView,
    pub nav: crate::nav::Nav,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ErrQuery {
    pub err: String,
}

impl ErrQuery {
    /// A closed set of codes rather than reflected text — the same rule every
    /// other device screen follows, so a crafted link cannot put arbitrary
    /// words on a page about to change a fleet.
    fn message(&self) -> String {
        match self.err.as_str() {
            "nofile" => "Choose a CSV file to import.".to_string(),
            "empty" => "That file has no rows to import.".to_string(),
            "toobig" => format!(
                "That file is larger than {} MB. Split it and import in parts.",
                MAX_UPLOAD_BYTES / (1024 * 1024)
            ),
            "notutf8" => "That file is not text Chalk can read. Save it as CSV \
                          (UTF-8) and try again."
                .to_string(),
            "unreadable" => "That file could not be read as a CSV.".to_string(),
            "failed" => "Could not work out what the file would change.".to_string(),
            _ => String::new(),
        }
    }
}

/// `GET /devices/import`
pub async fn import_form(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ErrQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Response {
    render(ImportTemplate {
        view: ImportView {
            importable: IMPORTABLE_COLUMNS.to_vec(),
            reference: REFERENCE_COLUMNS.to_vec(),
            error: q.message(),
            csrf_token: csrf.0,
        },
        nav: crate::nav::Nav::new(&state.config, "devices"),
    })
}

// ---------------------------------------------------------------------------
// The upload
// ---------------------------------------------------------------------------

/// `POST /devices/import` — read the file, plan it, and show the preview.
///
/// Nothing is written here. On success the operator is redirected to the diff
/// preview, which is where the decision actually gets made.
pub async fn import_submit(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Response {
    let (Some(assets), Some(sets)) = (state.assets.clone(), state.change_sets.clone()) else {
        return not_configured();
    };

    let bytes = match read_upload(&mut multipart).await {
        Ok(Some(b)) => b,
        Ok(None) => return back("nofile"),
        Err(code) => return back(code),
    };
    if bytes.is_empty() {
        return back("empty");
    }
    // Rejected before parsing rather than after: the CSV reader would happily
    // treat a spreadsheet or a PDF as one enormous single-column row and
    // report four thousand unmatched lines instead of "this is not a CSV".
    if std::str::from_utf8(&bytes).is_err() {
        return back("notutf8");
    }

    let (rows, mut errors) = asset_csv::parse(&bytes);
    if rows.is_empty() && errors.is_empty() {
        return back("empty");
    }

    // D8, the second of three doors. A row whose type this plan does not cover
    // is rejected **by line**, alongside every other unusable row, rather than
    // failing the whole file: a district on the free tier uploading a mixed
    // inventory should get their Chromebooks and a list of what was left out.
    let modules = &state.config.modules;
    let (rows, refused): (Vec<_>, Vec<_>) = rows
        .into_iter()
        .partition(|r| r.asset_type.is_none_or(|t| modules.allows_asset_type(t)));
    for row in refused {
        let t = row.asset_type.unwrap_or_default();
        errors.push(chalk_core::asset_csv::CsvRowError {
            line: row.line,
            message: modules.asset_type_refusal(t),
        });
    }

    match plan_csv_import(&assets, &sets, &rows, &errors, ACTOR).await {
        Ok(plan) => {
            tracing::info!(
                "csv import planned {} items ({} new, {} updated, {} rejected)",
                plan.item_count,
                plan.created_count,
                plan.updated_count,
                plan.rejected.len()
            );
            Redirect::to(&format!(
                "{}/{}",
                crate::preview::PREVIEW_PATH,
                plan.change_set_id
            ))
            .into_response()
        }
        Err(e) => {
            tracing::error!("could not plan a CSV import: {e}");
            back("failed")
        }
    }
}

/// Pull the first file field out of the upload.
///
/// Returns `Ok(None)` when the form arrived with no file at all, which is what
/// a browser sends when the operator submits an empty picker.
async fn read_upload(multipart: &mut Multipart) -> Result<Option<Vec<u8>>, &'static str> {
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        tracing::warn!("csv upload could not be read: {e}");
        // Axum's own body limit surfaces here, and it is the likely reason a
        // real upload fails — say so rather than "unreadable".
        "toobig"
    })? {
        if field.name() != Some("file") {
            continue;
        }
        let data = field.bytes().await.map_err(|e| {
            tracing::warn!("csv upload body could not be read: {e}");
            "toobig"
        })?;
        if data.is_empty() {
            return Ok(None);
        }
        return Ok(Some(data.to_vec()));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

fn back(code: &str) -> Response {
    Redirect::to(&format!("{IMPORT_PATH}?err={code}")).into_response()
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!("import render failed: {e}");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>Devices</h1><p>The import page could not be loaded.</p>".to_string()),
            )
                .into_response()
        }
    }
}

fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Devices</h1><p>Importing is not enabled here.</p>".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
