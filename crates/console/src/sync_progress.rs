//! First sync — progress, not a spinner (C2).
//!
//! # Why this is not an indicator
//!
//! A twenty-thousand-device fleet is roughly a hundred requests to Google:
//! minutes, not seconds. The console already contains the counter-example —
//! the SIS "Running…" indicator displays only while the ~10ms POST is in
//! flight, so it vanishes before the sync it describes has really begun. That
//! is worse than showing nothing, because it actively asserts the work is
//! over.
//!
//! So this polls the real run row and shows real counters. The engine updates
//! them mid-run, which is what makes progress genuine rather than a bar that
//! jumps from 0 to 100.
//!
//! # The result is framed as the win
//!
//! Not "sync complete, 5,000 records processed" but *"4,812 of 5,000 devices
//! matched to students"*. That sentence is the entire product argument, and
//! this is the moment it is true for the first time on a district's own data.
//!
//! # Triggering is enqueueing
//!
//! The console does not run syncs. It writes a `jobs` row and the worker in the
//! server binary picks it up — which is why this module needs no knowledge of
//! `chalk-devices`, Google, or credentials.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::models::device_sync::{DeviceSyncRun, DeviceSyncRunStatus};
use chalk_core::models::job::{JobFilter, JobKind, JobStatus, NewJob};
use chalk_core::models::page::PageRequest;
use chrono::{Duration, Utc};

use crate::AppState;

pub const SYNC_PATH: &str = "/devices/sync";

/// How many past runs the history shows.
pub const HISTORY_LIMIT: i64 = 10;

/// A run still `running` with no `completed_at` after this long is reported as
/// interrupted rather than in progress.
///
/// Matches the job runner's own liveness window: a device sync only exists
/// because a worker claimed a job, so if that worker is gone the run row is
/// never going to be closed by anyone. Without this the page would show a
/// spinner forever on a sync whose process died — the exact failure this
/// module exists not to imitate.
pub const LIVENESS: Duration = Duration::minutes(30);

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

/// One run, formatted for display.
pub struct RunView {
    pub id: i64,
    pub started: String,
    pub finished: String,
    pub status_label: String,
    pub status_class: String,
    pub seen: i64,
    pub created: i64,
    pub updated: i64,
    pub matched: i64,
    pub unmatched: i64,
    pub api_calls: i64,
    pub throttle_events: i64,
    pub dry_run: bool,
    pub error: String,
    /// Live, so the fragment keeps polling.
    pub in_progress: bool,
}

impl RunView {
    pub fn new(run: &DeviceSyncRun, now: chrono::DateTime<Utc>) -> Self {
        let interrupted = run.is_running() && now - run.started_at > LIVENESS;
        let (status_label, status_class) = match run.status {
            _ if interrupted => ("Interrupted", "badge badge--warning"),
            DeviceSyncRunStatus::Running => ("Running", "badge badge--info"),
            DeviceSyncRunStatus::Succeeded => ("Finished", "badge badge--success"),
            DeviceSyncRunStatus::Failed => ("Failed", "badge badge--danger"),
            DeviceSyncRunStatus::Cancelled => ("Cancelled", "badge badge--neutral"),
        };
        let c = &run.counters;
        Self {
            id: run.id,
            started: run.started_at.format("%Y-%m-%d %H:%M").to_string(),
            finished: run
                .completed_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "—".to_string()),
            status_label: status_label.to_string(),
            status_class: status_class.to_string(),
            seen: c.devices_seen,
            created: c.devices_created,
            updated: c.devices_updated,
            matched: c.devices_matched,
            unmatched: c.devices_unmatched,
            api_calls: c.api_calls,
            throttle_events: c.throttle_events,
            dry_run: run.dry_run,
            error: run.error_message.clone().unwrap_or_default(),
            in_progress: run.is_running() && !interrupted,
        }
    }

    pub fn has_error(&self) -> bool {
        !self.error.is_empty()
    }

    /// The sentence the whole module exists to produce.
    ///
    /// Says *matched to students*, not "processed": the count that matters is
    /// the one a device-only asset tracker cannot produce at all.
    pub fn headline(&self) -> String {
        if self.seen == 0 {
            return "No devices seen yet.".to_string();
        }
        format!(
            "{} of {} devices matched to students",
            crate::table::thousands(self.matched),
            crate::table::thousands(self.seen)
        )
    }

    /// Surfaced because §5.3 requires recording throttling, and this is where
    /// "why was the sync slow" becomes answerable instead of a mystery.
    pub fn was_throttled(&self) -> bool {
        self.throttle_events > 0
    }
}

pub struct SyncView {
    pub latest: Option<RunView>,
    pub history: Vec<RunView>,
    /// A sync is queued or running, so the button must not offer another.
    pub work_pending: bool,
    /// Device sync is configured well enough to run at all.
    pub configured: bool,
    pub flash: String,
    pub csrf_token: String,
}

impl SyncView {
    pub fn has_latest(&self) -> bool {
        self.latest.is_some()
    }

    pub fn has_history(&self) -> bool {
        !self.history.is_empty()
    }

    /// Announced after each poll. Under 120 characters per §5.12, and stating
    /// the result rather than the process.
    pub fn announcement(&self) -> String {
        match &self.latest {
            None if self.work_pending => "Sync queued.".to_string(),
            None => "No sync has run yet.".to_string(),
            Some(r) if r.in_progress => {
                format!("Sync running. {} devices seen so far.", r.seen)
            }
            Some(r) => r.headline(),
        }
    }
}

#[derive(Template)]
#[template(path = "devices/sync.html")]
pub struct SyncPageTemplate {
    pub view: SyncView,
    pub nav: crate::nav::Nav,
}

#[derive(Template)]
#[template(path = "devices/sync_status.html")]
pub struct SyncStatusTemplate {
    pub view: SyncView,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// A one-shot message after a trigger.
///
/// Carried as a **code**, not as text. Reflecting a message through the query
/// string would let any crafted link render arbitrary words in this page's
/// status area — escaped, so not script injection, but a ready-made way to
/// tell a signed-in administrator something untrue about their fleet. The set
/// is closed and the text lives here.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct NoticeQuery {
    pub notice: String,
}

impl NoticeQuery {
    fn message(&self) -> String {
        match self.notice.as_str() {
            "queued" => "Sync queued. It starts within a few seconds.".to_string(),
            "already" => "A sync is already queued or running.".to_string(),
            "disabled" => "Device sync is not enabled. Connect Google Workspace first.".to_string(),
            "checkfailed" => "Could not check whether a sync is already running.".to_string(),
            "failed" => "Could not queue the sync. Check the server log.".to_string(),
            _ => String::new(),
        }
    }
}

/// `GET /devices/sync` — the sync page.
pub async fn sync_page(
    State(state): State<Arc<AppState>>,
    Query(notice): Query<NoticeQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Response {
    match build_view(&state, notice.message(), csrf.0).await {
        Ok(view) => render(SyncPageTemplate {
            view,
            nav: crate::nav::Nav::new(&state.config, "devices"),
        }),
        Err(e) => e,
    }
}

/// `GET /devices/sync/status` — the polled fragment.
pub async fn sync_status(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    _headers: HeaderMap,
) -> Response {
    match build_view(&state, String::new(), csrf.0).await {
        Ok(view) => render(SyncStatusTemplate { view }),
        Err(e) => e,
    }
}

/// `POST /devices/sync` — ask for a sync.
///
/// Enqueues; it does not run. Refuses to queue a second one while work is
/// pending, because two concurrent full syncs would race on the same cursor
/// and each would see the other's partial writes.
pub async fn sync_trigger(State(state): State<Arc<AppState>>) -> Response {
    let (Some(jobs), Some(_runs)) = (state.jobs.clone(), state.device_runs.clone()) else {
        return not_configured();
    };

    if !state.config.device_sync.enabled && state.tenant_config.is_none() {
        return back_with("disabled");
    }

    match pending_work(&state).await {
        Ok(true) => return back_with("already"),
        Ok(false) => {}
        Err(e) => {
            tracing::error!("could not check for pending sync jobs: {e}");
            return back_with("checkfailed");
        }
    }

    match jobs.enqueue(&NewJob::now(JobKind::GoogleDeviceSync)).await {
        Ok(job) => {
            tracing::info!("queued device sync job {}", job.id);
            back_with("queued")
        }
        Err(e) => {
            tracing::error!("could not queue a device sync: {e}");
            back_with("failed")
        }
    }
}

/// True when a device-sync job is queued or already running.
async fn pending_work(state: &AppState) -> chalk_core::error::Result<bool> {
    let Some(jobs) = state.jobs.clone() else {
        return Ok(false);
    };
    for status in [JobStatus::Queued, JobStatus::Running] {
        let page = jobs
            .list_jobs(
                &JobFilter {
                    kind: Some(JobKind::GoogleDeviceSync),
                    status: Some(status),
                },
                PageRequest::new(1, 0),
            )
            .await?;
        if page.total > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn build_view(
    state: &Arc<AppState>,
    flash: String,
    csrf_token: String,
) -> Result<SyncView, Response> {
    let Some(runs) = state.device_runs.clone() else {
        return Err(not_configured());
    };

    let page = runs
        .list_runs(PageRequest::new(HISTORY_LIMIT, 0))
        .await
        .map_err(|e| {
            tracing::error!("could not read device sync runs: {e}");
            load_failed()
        })?;

    let now = Utc::now();
    let mut views: Vec<RunView> = page.items.iter().map(|r| RunView::new(r, now)).collect();
    // `list_runs` is newest-first, so the head is the current or most recent
    // run and the tail is history.
    let latest = if views.is_empty() {
        None
    } else {
        Some(views.remove(0))
    };

    // Configured enough to run: either TOML says so, or a stored config does.
    let configured = state.config.device_sync.enabled
        || match &state.tenant_config {
            Some(repo) => repo
                .get_device_config()
                .await
                .ok()
                .flatten()
                .map(|c| c.enabled && c.service_account_key.is_some())
                .unwrap_or(false),
            None => false,
        };

    let work_pending = pending_work(state).await.unwrap_or(false)
        || latest.as_ref().map(|r| r.in_progress).unwrap_or(false);

    Ok(SyncView {
        latest,
        history: views,
        work_pending,
        configured,
        flash,
        csrf_token,
    })
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/// Redirect back with a notice **code**. See [`NoticeQuery`].
fn back_with(code: &str) -> Response {
    Redirect::to(&format!("{SYNC_PATH}?notice={code}")).into_response()
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!("sync page render failed: {e}");
            load_failed()
        }
    }
}

fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html(
            "<h1>Devices</h1><p>The device inventory is not enabled on this \
             installation.</p>"
                .to_string(),
        ),
    )
        .into_response()
}

fn load_failed() -> Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Html("<h1>Devices</h1><p>Sync status could not be loaded.</p>".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
