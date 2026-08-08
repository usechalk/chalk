//! The diff preview (C4, DESIGN_SYSTEM.md §5.13).
//!
//! # What this screen is for
//!
//! It is the thing standing between "act on all 400 devices matching this
//! filter" and the 400 writes. The operator sees the actual rows, the actual
//! old and new values, and can strike individual devices out. Nothing has
//! happened yet when this page renders — the change set is a proposal.
//!
//! That is what makes filter-scoped selection defensible rather than reckless,
//! and it is why the plan explicitly refuses to let the two ship apart.
//!
//! # One component, three futures
//!
//! It renders from `change_set_items` and knows nothing about where they came
//! from, so the same screen serves a bulk edit today and a sync dry-run or a
//! CSV import later without being rewritten.
//!
//! # Destructive changes get a second gate
//!
//! A deprovision returns the licence and drops the device out of management;
//! re-enrolling is a physical act at the device. So a change set containing one
//! cannot be committed by pressing a button — the operator types the number of
//! devices, and the server checks it. The consequence is stated first, in the
//! plainest wording available, and there is deliberately no "do not ask again".
//!
//! The gate is here, at commit, rather than at plan time: planning is safe, and
//! a confirmation attached to a harmless step teaches people to click through
//! it before it ever guards anything.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::change_plan::{plan_change, PlannedChange, MAX_PLAN_ITEMS};
use chalk_core::models::asset::{AssetStatus, MatchState};
use chalk_core::models::change_set::{
    ChangeSetItem, ChangeSetItemStatus, ChangeSetOp, ChangeSetStatus, RemoteTarget,
};
use chalk_core::models::device_action::{ChangeStatusAction, DeprovisionReason};
use chalk_core::models::job::{JobKind, NewJob};
use chalk_core::models::page::PageRequest;
use serde::Deserialize;

use crate::devices::DevicesQuery;
use crate::AppState;

pub const PREVIEW_PATH: &str = "/devices/changes";

/// Items rendered on one preview page.
///
/// Generous, because the point is to *see* the change. Paging a preview into
/// forty screens would defeat it; the plan's own ceiling is what bounds the
/// total.
pub const PREVIEW_PAGE_SIZE: i64 = 250;

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/// The bulk action an operator asked for, from the inventory's toolbar.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PlanForm {
    /// `assign` | `unassign` | `status` | `shared`
    pub action: String,
    /// For `assign`: the roster user. For `status`: the lifecycle value.
    pub value: String,
    /// Asset ids the operator unticked before planning.
    #[serde(default)]
    pub exclude: String,
    /// For `move_ou`: the destination org unit. Its own field rather than
    /// sharing `value`, because two controls with one name in the same form
    /// send whichever the browser felt like.
    #[serde(default)]
    pub ou_path: String,
    /// For `deprovision`: the reason Google requires.
    #[serde(default)]
    pub reason: String,
}

impl PlanForm {
    /// Translate the form into a planned change, or say why it cannot be.
    ///
    /// An unknown action is refused rather than defaulted. Defaulting a bulk
    /// write to *anything* is how a mistyped request becomes a fleet-wide
    /// surprise.
    fn to_change(&self) -> Result<PlannedChange, String> {
        match self.action.as_str() {
            "assign" => {
                let user = self.value.trim();
                if user.is_empty() {
                    return Err("Pick a person to attach these devices to.".into());
                }
                Ok(PlannedChange::Assign {
                    user_sourced_id: user.to_string(),
                })
            }
            "unassign" => Ok(PlannedChange::Unassign),
            "status" => AssetStatus::parse(self.value.trim())
                .map(|status| PlannedChange::SetStatus { status })
                .map_err(|_| format!("{:?} is not a device status.", self.value)),
            "shared" => Ok(PlannedChange::SetMatchState {
                match_state: MatchState::Ignored,
            }),
            "move_ou" => {
                let path = self.ou_path.trim();
                if path.is_empty() {
                    return Err("Type the org unit to move these devices into.".into());
                }
                // Google org unit paths are absolute. A relative one is
                // accepted by nothing and produces a 400 that reads as a
                // Chalk fault, so it is refused here where it can be fixed.
                if !path.starts_with('/') {
                    return Err(format!(
                        "{path:?} is not an org unit path — it has to start with a slash, \
                         like /Students/HS."
                    ));
                }
                Ok(PlannedChange::MoveOu {
                    org_unit_path: path.to_string(),
                })
            }
            "disable" => Ok(PlannedChange::ChangeStatus {
                action: ChangeStatusAction::Disable,
            }),
            "reenable" => Ok(PlannedChange::ChangeStatus {
                action: ChangeStatusAction::Reenable,
            }),
            // The emails map is filled by the handler — building it needs the
            // roster, and this parser stays synchronous.
            "annotate" => Ok(PlannedChange::SyncAnnotations {
                emails: Default::default(),
            }),
            "deprovision" => {
                // Google rejects a deprovision without a reason, and the type
                // makes one unrepresentable — so the failure has to be caught
                // here, with wording that says what to do.
                let reason = DeprovisionReason::parse(self.reason.trim()).map_err(|_| {
                    "Choose why these devices are being deprovisioned — Google requires \
                     a reason and will not accept the change without one."
                        .to_string()
                })?;
                Ok(PlannedChange::ChangeStatus {
                    action: ChangeStatusAction::Deprovision(reason),
                })
            }
            other => Err(format!("{other:?} is not an action this page offers.")),
        }
    }

    fn excluded(&self) -> Vec<String> {
        self.exclude
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }
}

/// `POST /devices/changes` — plan a bulk change and redirect to its preview.
///
/// Takes the inventory's own query string as the selection scope, so what is
/// planned is exactly what the operator was looking at. Nothing is applied.
pub async fn plan(
    State(state): State<Arc<AppState>>,
    Query(devices_query): Query<DevicesQuery>,
    axum::Form(form): axum::Form<PlanForm>,
) -> Response {
    let (Some(assets), Some(sets)) = (state.assets.clone(), state.change_sets.clone()) else {
        return not_configured();
    };

    let mut change = match form.to_change() {
        Ok(c) => c,
        Err(message) => return back_to_inventory(&message),
    };
    if let PlannedChange::SyncAnnotations { emails } = &mut change {
        // sourcedId → email for every roster user, one query — the planner
        // needs to name each device's assigned student by email.
        let users = state
            .repo
            .list_users(&chalk_core::models::sync::UserFilter::default())
            .await
            .unwrap_or_default();
        *emails = users
            .into_iter()
            .filter_map(|u| u.email.map(|e| (u.sourced_id, e)))
            .collect();
    }

    match plan_change(
        &assets,
        &sets,
        &devices_query.to_asset_filter(),
        &change,
        &form.excluded(),
        ACTOR,
    )
    .await
    {
        Ok(plan) => Redirect::to(&format!("{PREVIEW_PATH}/{}", plan.change_set_id)).into_response(),
        Err(e) => {
            tracing::error!("could not plan a bulk change: {e}");
            back_to_inventory("Could not work out what would change.")
        }
    }
}

// ---------------------------------------------------------------------------
// The preview
// ---------------------------------------------------------------------------

pub struct ItemView {
    pub id: i64,
    /// Asset tag or serial — what a technician reads off the sticker.
    pub device: String,
    pub asset_id: String,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
    pub op: String,
    /// Excluded by the operator, so it will not be applied.
    pub skipped: bool,
    /// Needs a Google write, which this release cannot perform.
    pub needs_google: bool,
    /// Brings a device into existence rather than changing one.
    pub is_create: bool,
}

impl ItemView {
    fn new(item: &ChangeSetItem) -> Self {
        // A create's `new_value` is the whole asset as JSON — the commit path's
        // payload, not something to put in a table cell. What the operator
        // needs to read is that a device will be added, and which one.
        let is_create = item.op == ChangeSetOp::Create;
        Self {
            id: item.id,
            device: item
                .target_ref
                .clone()
                .or_else(|| item.asset_id.clone())
                .unwrap_or_else(|| "—".to_string()),
            asset_id: item.asset_id.clone().unwrap_or_default(),
            field: if is_create {
                "the whole device".to_string()
            } else {
                item.field.clone().unwrap_or_default()
            },
            // An absent value is a clear, and must read as one rather than as
            // an empty cell a reader takes for a rendering fault.
            old_value: if is_create {
                "not in Chalk".to_string()
            } else {
                item.old_value.clone().unwrap_or_else(|| "—".to_string())
            },
            new_value: if is_create {
                "will be added".to_string()
            } else {
                // A status action is stored in its wire form so the item stays
                // self-describing and the plan hash covers the reason. That
                // encoding is for the commit path, not for a person: an
                // operator approving a fleet-wide deprovision should be reading
                // "Retiring from the fleet", not `deprovision:retiring_device`.
                item.new_value
                    .as_deref()
                    .filter(|_| item.op == ChangeSetOp::ChangeStatus)
                    .and_then(|v| ChangeStatusAction::parse_item_value(v).ok())
                    .map(|a| a.label())
                    .or_else(|| item.new_value.clone())
                    .unwrap_or_else(|| "(cleared)".to_string())
            },
            op: item.op.as_str().to_string(),
            skipped: item.status == ChangeSetItemStatus::Skipped,
            needs_google: item.remote_target == RemoteTarget::Google,
            is_create,
        }
    }
}

/// A row the import could not use, named so it can be fixed.
pub struct RejectedRow {
    pub line: i64,
    pub message: String,
}

pub struct PreviewView {
    pub change_set_id: String,
    pub status: String,
    pub created_by: String,
    pub created_at: String,
    pub items: Vec<ItemView>,
    /// Items that will actually be applied — total minus struck-out.
    pub will_apply: i64,
    pub skipped: i64,
    pub total: i64,
    /// Devices in scope that were already in the requested state.
    pub unchanged: i64,
    /// Devices the *file* would bring into existence. A plan-time fact about
    /// the upload, phrased as one — it does not move when the operator strikes
    /// rows out, and the copy says "this file adds" rather than "will add" so
    /// it stays true either way. Only a CSV import produces these.
    pub created: i64,
    /// Rows an import could not use. Carried on the change set rather than
    /// flashed on a redirect, so they survive a reload and sit beside what
    /// *will* happen instead of in a message the operator has to remember.
    pub rejected: Vec<RejectedRow>,
    pub truncated: bool,
    /// More items exist than this page shows.
    pub has_more: bool,
    pub flash: String,
    pub csrf_token: String,
    /// Already committed or discarded, so the actions are gone.
    pub is_settled: bool,
    /// Devices that would be deprovisioned. Non-zero turns the commit button
    /// into a typed confirmation.
    pub destructive_count: i64,
    /// What the destructive rows would do, in the operator's words.
    pub destructive_summary: String,
}

impl PreviewView {
    pub fn has_items(&self) -> bool {
        !self.items.is_empty()
    }

    pub fn is_empty_plan(&self) -> bool {
        self.total == 0
    }

    pub fn has_rejected(&self) -> bool {
        !self.rejected.is_empty()
    }

    /// The summary strip. States what will happen, in the operator's terms.
    pub fn summary(&self) -> String {
        if self.total == 0 {
            return "Nothing would change.".to_string();
        }
        // Deliberately one number, not "added + changed". Those two are
        // plan-time facts about the file; this line has to stay true after the
        // operator strikes rows out, and a breakdown that drifts from the
        // button underneath it is worse than no breakdown.
        let mut parts = vec![format!(
            "{} change{} will apply",
            crate::table::thousands(self.will_apply),
            if self.will_apply == 1 { "" } else { "s" }
        )];
        if self.skipped > 0 {
            parts.push(format!(
                "{} struck out",
                crate::table::thousands(self.skipped)
            ));
        }
        if self.unchanged > 0 {
            parts.push(format!(
                "{} already correct",
                crate::table::thousands(self.unchanged)
            ));
        }
        parts.join(" · ")
    }

    pub fn any_needs_google(&self) -> bool {
        self.items.iter().any(|i| i.needs_google)
    }

    /// True when committing this set cannot be undone from Chalk.
    pub fn is_destructive(&self) -> bool {
        self.destructive_count > 0
    }
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/preview.html")]
pub struct PreviewTemplate {
    pub view: PreviewView,
    pub nav: crate::nav::Nav,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NoticeQuery {
    pub notice: String,
}

impl NoticeQuery {
    /// Closed set of codes, not reflected text — a crafted link must not be
    /// able to put arbitrary words on a page about to change a fleet.
    fn message(&self) -> String {
        match self.notice.as_str() {
            "committed" => "Applying the changes. This page shows progress.".to_string(),
            "discarded" => "Discarded. Nothing was changed.".to_string(),
            "stale" => "The devices changed since this was planned, so nothing was applied. \
                        Plan it again to see what is different."
                .to_string(),
            "settled" => "That change set has already been decided.".to_string(),
            "failed" => "Could not apply the changes. Check the server log.".to_string(),
            "unconfirmed" => "Nothing was applied. Type the number of devices to \
                              confirm a deprovision — it releases the licences and \
                              cannot be undone from Chalk."
                .to_string(),
            _ => String::new(),
        }
    }
}

/// `GET /devices/changes/{id}` — the preview.
pub async fn preview(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(notice): Query<NoticeQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Response {
    let Some(sets) = state.change_sets.clone() else {
        return not_configured();
    };

    let Ok(Some(set)) = sets.get_change_set(&id).await else {
        return not_found();
    };
    let page = match sets
        .list_items(&id, None, PageRequest::new(PREVIEW_PAGE_SIZE, 0))
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("could not read change set {id}: {e}");
            return load_failed();
        }
    };
    let counts = sets.item_status_counts(&id).await.unwrap_or_default();

    // Counted from the stored items, not from the summary: what makes a commit
    // irreversible is what is actually still pending, and an operator may have
    // struck rows out since the plan was written.
    let destructive: Vec<&ChangeSetItem> = page
        .items
        .iter()
        .filter(|i| i.status != ChangeSetItemStatus::Skipped)
        .filter(|i| {
            i.op == ChangeSetOp::ChangeStatus
                && i.new_value
                    .as_deref()
                    .and_then(|v| ChangeStatusAction::parse_item_value(v).ok())
                    .is_some_and(|a| a.is_destructive())
        })
        .collect();
    let destructive_summary = destructive
        .first()
        .and_then(|i| i.new_value.as_deref())
        .and_then(|v| ChangeStatusAction::parse_item_value(v).ok())
        .map(|a| a.label())
        .unwrap_or_default();

    let items: Vec<ItemView> = page.items.iter().map(ItemView::new).collect();
    let view = PreviewView {
        change_set_id: set.id.clone(),
        status: set.status.as_str().to_string(),
        created_by: set.created_by.clone(),
        created_at: set.created_at.format("%Y-%m-%d %H:%M").to_string(),
        will_apply: page.total - counts.skipped,
        skipped: counts.skipped,
        total: page.total,
        unchanged: set.summary["unchangedCount"].as_i64().unwrap_or(0),
        created: set.summary["createdCount"].as_i64().unwrap_or(0),
        rejected: set.summary["rejectedRows"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .map(|r| RejectedRow {
                        line: r["line"].as_i64().unwrap_or(0),
                        message: r["message"].as_str().unwrap_or_default().to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        truncated: set.summary["truncated"].as_bool().unwrap_or(false),
        has_more: page.total > items.len() as i64,
        items,
        flash: notice.message(),
        csrf_token: csrf.0,
        is_settled: set.status != ChangeSetStatus::Planned,
        destructive_count: destructive.len() as i64,
        destructive_summary,
    };

    render(PreviewTemplate {
        view,
        nav: crate::nav::Nav::new(&state.config, "devices"),
    })
}

/// The commit form. `confirm` is the device count typed back for a
/// destructive change set, and is ignored for every other kind.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CommitForm {
    pub confirm: String,
}

/// How many still-pending items would deprovision a device.
///
/// Read from the repository at commit time rather than carried in the form:
/// a count the browser supplied is a count the browser could have chosen.
async fn destructive_count(
    sets: &Arc<dyn chalk_core::db::repository::ChangeSetRepository>,
    id: &str,
) -> Result<i64, chalk_core::error::ChalkError> {
    let page = sets
        .list_items(id, None, PageRequest::new(MAX_PLAN_ITEMS, 0))
        .await?;
    Ok(page
        .items
        .iter()
        .filter(|i| i.status != ChangeSetItemStatus::Skipped)
        .filter(|i| {
            i.op == ChangeSetOp::ChangeStatus
                && i.new_value
                    .as_deref()
                    .and_then(|v| ChangeStatusAction::parse_item_value(v).ok())
                    .is_some_and(|a| a.is_destructive())
        })
        .count() as i64)
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ExcludeForm {
    pub item_id: i64,
}

/// `POST /devices/changes/{id}/exclude` — strike one row out of the plan.
///
/// Marks the item `skipped` rather than deleting it: the change set is the
/// record of what was proposed, and a row silently removed would make the
/// preview disagree with the history of the decision.
pub async fn exclude(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<ExcludeForm>,
) -> Response {
    let Some(sets) = state.change_sets.clone() else {
        return not_configured();
    };
    match sets.get_change_set(&id).await {
        Ok(Some(set)) if set.status == ChangeSetStatus::Planned => {}
        Ok(Some(_)) => return back_to_preview(&id, "settled"),
        _ => return not_found(),
    }

    if let Err(e) = sets
        .mark_item_outcome(form.item_id, ChangeSetItemStatus::Skipped, None)
        .await
    {
        tracing::error!("could not exclude item {}: {e}", form.item_id);
        return back_to_preview(&id, "failed");
    }
    Redirect::to(&format!("{PREVIEW_PATH}/{id}")).into_response()
}

/// `POST /devices/changes/{id}/commit` — apply what is left.
///
/// Enqueues a `change_set_commit` job. The console does not apply changes any
/// more than it runs syncs; the worker owns that, which keeps one path for
/// every long operation and one place where at-most-once is enforced.
pub async fn commit(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<CommitForm>,
) -> Response {
    let (Some(sets), Some(jobs)) = (state.change_sets.clone(), state.jobs.clone()) else {
        return not_configured();
    };

    let Ok(Some(set)) = sets.get_change_set(&id).await else {
        return not_found();
    };
    if set.status != ChangeSetStatus::Planned {
        return back_to_preview(&id, "settled");
    }

    // The typed confirmation is checked here, not in the browser. A disabled
    // button is a hint; this is the gate. Recounted from the stored items so a
    // set that changed since the page rendered cannot be committed against a
    // number the operator typed for a different set.
    match destructive_count(&sets, &id).await {
        Ok(0) => {}
        Ok(expected) => {
            if form.confirm.trim() != expected.to_string() {
                return back_to_preview(&id, "unconfirmed");
            }
        }
        Err(e) => {
            tracing::error!("could not count destructive items for {id}: {e}");
            return back_to_preview(&id, "failed");
        }
    }

    match jobs
        .enqueue(
            &NewJob::now(JobKind::ChangeSetCommit).with_payload(serde_json::json!({
                "changeSetId": set.id,
                // Carried so the worker can re-check the plan is still the one that
                // was approved, rather than trusting the id alone.
                "planHash": set.plan_hash,
                "expectedItemCount": set.expected_item_count,
            })),
        )
        .await
    {
        Ok(job) => {
            tracing::info!("queued commit job {} for change set {id}", job.id);
            back_to_preview(&id, "committed")
        }
        Err(e) => {
            tracing::error!("could not queue a commit for change set {id}: {e}");
            back_to_preview(&id, "failed")
        }
    }
}

/// `POST /devices/changes/{id}/discard`
pub async fn discard(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some(sets) = state.change_sets.clone() else {
        return not_configured();
    };
    match sets.get_change_set(&id).await {
        Ok(Some(set)) if set.status == ChangeSetStatus::Planned => {}
        Ok(Some(_)) => return back_to_preview(&id, "settled"),
        _ => return not_found(),
    }
    if let Err(e) = sets.discard_change_set(&id).await {
        tracing::error!("could not discard change set {id}: {e}");
        return back_to_preview(&id, "failed");
    }
    back_to_preview(&id, "discarded")
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/// The console authenticates one admin rather than individual staff accounts,
/// so this is what the audit trail can honestly record. Matching the value the
/// unmatched queue writes, so history reads consistently.
const ACTOR: &str = "console:admin";

fn back_to_preview(id: &str, code: &str) -> Response {
    Redirect::to(&format!("{PREVIEW_PATH}/{id}?notice={code}")).into_response()
}

/// Back to the inventory with a reason.
///
/// The message is a fixed string chosen here, never operator input reflected
/// back — the same rule the queue and the sync page follow.
fn back_to_inventory(message: &str) -> Response {
    Redirect::to(&format!(
        "{}?planerr={}",
        crate::devices::DEVICES_PATH,
        urlencoding::encode(message)
    ))
    .into_response()
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!("preview render failed: {e}");
            load_failed()
        }
    }
}

fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Devices</h1><p>Bulk changes are not enabled here.</p>".to_string()),
    )
        .into_response()
}

fn not_found() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html(
            "<h1>No such change set</h1><p><a href=\"/devices\">Back to \
             devices</a></p>"
                .to_string(),
        ),
    )
        .into_response()
}

fn load_failed() -> Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Html("<h1>Devices</h1><p>The preview could not be loaded.</p>".to_string()),
    )
        .into_response()
}

/// Plan ceiling, surfaced for the template's copy.
pub const PLAN_CEILING: i64 = MAX_PLAN_ITEMS;

#[cfg(test)]
mod tests;
