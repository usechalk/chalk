//! The circulation desk — device check-out and check-in (WS-12).
//!
//! # Custody drives assignment, not the other way round
//!
//! Checking a device out writes two things in strict order: the custody record
//! (when, to whom, due when, in what condition, agreement acknowledged) and
//! then the asset's `assigned_user` through `apply_patch_with_event`, so the
//! device history shows the assignment with the same audit trail every other
//! assignment gets. Check-in is the mirror image. The custody table is the
//! story; the FK on the asset is just its last line.
//!
//! # One open loan per device
//!
//! Enforced by a partial unique index, and checked here first so the desk gets
//! "already checked out to X" rather than a constraint error.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::response::{Redirect, Response};
use chalk_core::models::asset::{ActorKind, AssetPatch, MatchState, NewAssetEvent, Patch};
use chalk_core::models::console_user::Actor;
use chalk_core::models::custody::CustodyRecord;
use chrono::Utc;
use serde::Deserialize;

use crate::AppState;

pub const CIRCULATION_PATH: &str = "/devices/circulation";

fn back(asset_id: &str, notice: &str) -> Response {
    Redirect::to(&format!("/devices/{asset_id}?notice={notice}")).into_response()
}

/// Resolve what the desk typed — an email or a roster id — to a user.
///
/// Exact matches only. A circulation desk moves fast, and handing a device to
/// the wrong "close enough" student is the failure mode speed invites.
async fn resolve_user(
    state: &Arc<AppState>,
    input: &str,
) -> Option<chalk_core::models::user::User> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    if let Ok(Some(u)) = state.repo.get_user(input).await {
        return Some(u);
    }
    // By email, exact.
    let candidates = state
        .repo
        .list_users(&chalk_core::models::sync::UserFilter::search(
            input.to_string(),
            10,
        ))
        .await
        .unwrap_or_default();
    candidates.into_iter().find(|u| {
        u.email
            .as_deref()
            .is_some_and(|e| e.eq_ignore_ascii_case(input))
    })
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CheckOutForm {
    /// Roster sourced_id or exact email.
    pub user: String,
    /// `YYYY-MM-DD`, optional — empty means kept all year.
    pub due: String,
    pub condition: String,
    /// `"1"` records that the device agreement was acknowledged.
    pub agreement: String,
    /// `"1"` marks a temporary swap (loaner).
    pub loaner: String,
}

/// `POST /devices/{id}/checkout`
pub async fn check_out(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Extension(actor): axum::Extension<Actor>,
    axum::Form(form): axum::Form<CheckOutForm>,
) -> Response {
    let (Some(custody), Some(assets)) = (state.custody.clone(), state.assets.clone()) else {
        return back(&id, "failed");
    };
    // The device must exist.
    match assets.get_asset(&id).await {
        Ok(Some(_)) => {}
        _ => return back(&id, "failed"),
    }
    // One open loan per device, said in words before the index says it in SQL.
    if let Ok(Some(_)) = custody.open_custody_for_asset(&id).await {
        return back(&id, "custody_open");
    }
    let Some(user) = resolve_user(&state, &form.user).await else {
        return back(&id, "custody_no_user");
    };

    let due_at = {
        let d = form.due.trim();
        if d.is_empty() {
            None
        } else {
            match chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d") {
                // Due at end of that day, UTC — a date, not a deadline hour.
                Ok(date) => date.and_hms_opt(23, 59, 59).map(|dt| dt.and_utc()),
                Err(_) => return back(&id, "custody_bad_date"),
            }
        }
    };

    let record = CustodyRecord {
        id: uuid::Uuid::new_v4().to_string(),
        asset_id: id.clone(),
        user_sourced_id: user.sourced_id.clone(),
        checked_out_at: Utc::now(),
        due_at,
        checked_in_at: None,
        condition_out: {
            let c = form.condition.trim();
            (!c.is_empty()).then(|| c.to_string())
        },
        condition_in: None,
        agreement_acknowledged: form.agreement.trim() == "1",
        actor: actor.audit_actor(),
        loaner: form.loaner.trim() == "1",
    };
    if let Err(e) = custody.create_custody(&record).await {
        tracing::error!("could not open custody for {id}: {e}");
        return back(&id, "failed");
    }

    // Custody first, then the assignment — in the audited path, so the device
    // history shows who handed it out.
    let patch = AssetPatch {
        assigned_user_sourced_id: Patch::Set(user.sourced_id.clone()),
        // A desk hand-out is a human decision a sync must not undo.
        match_state: Some(MatchState::Manual),
        ..Default::default()
    };
    let event = NewAssetEvent {
        asset_id: id.clone(),
        actor: record.actor.clone(),
        actor_kind: console_actor_kind(&actor),
        event_type: chalk_core::models::asset::AssetEventType::Assigned,
        payload: Some(serde_json::json!({
            "custody": record.id,
            "userSourcedId": user.sourced_id,
            "dueAt": record.due_at,
            "agreementAcknowledged": record.agreement_acknowledged,
        })),
    };
    match assets.apply_patch_with_event(&id, &patch, &event).await {
        Ok(true) => {
            crate::fees::notify_family(
                &state,
                &user.sourced_id,
                &format!(
                    "A device was checked out to you{}",
                    if record.loaner { " (loaner)" } else { "" }
                ),
                &match record.due_at {
                    Some(due) => format!(
                        "You have been issued a device. It is due back on {}.",
                        due.format("%Y-%m-%d")
                    ),
                    None => "You have been issued a device for the year.".to_string(),
                },
            )
            .await;
            back(&id, "checked_out")
        }
        _ => {
            tracing::error!("custody opened for {id} but the assignment write failed");
            back(&id, "failed")
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CheckInForm {
    pub condition: String,
}

/// `POST /devices/{id}/checkin`
pub async fn check_in(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Extension(actor): axum::Extension<Actor>,
    axum::Form(form): axum::Form<CheckInForm>,
) -> Response {
    let (Some(custody), Some(assets)) = (state.custody.clone(), state.assets.clone()) else {
        return back(&id, "failed");
    };
    let Ok(Some(open)) = custody.open_custody_for_asset(&id).await else {
        return back(&id, "custody_none");
    };
    let condition = {
        let c = form.condition.trim();
        (!c.is_empty()).then(|| c.to_string())
    };
    match custody
        .close_custody(&open.id, condition.as_deref(), &actor.audit_actor())
        .await
    {
        Ok(true) => {}
        _ => return back(&id, "failed"),
    }

    let patch = AssetPatch {
        assigned_user_sourced_id: Patch::Clear,
        ..Default::default()
    };
    let event = NewAssetEvent {
        asset_id: id.clone(),
        actor: actor.audit_actor(),
        actor_kind: console_actor_kind(&actor),
        event_type: chalk_core::models::asset::AssetEventType::Unassigned,
        payload: Some(serde_json::json!({
            "custody": open.id,
            "userSourcedId": open.user_sourced_id,
            "conditionIn": condition,
        })),
    };
    match assets.apply_patch_with_event(&id, &patch, &event).await {
        Ok(true) => back(&id, "checked_in"),
        _ => {
            tracing::error!("custody closed for {id} but the unassignment write failed");
            back(&id, "failed")
        }
    }
}

pub(crate) fn console_actor_kind(actor: &Actor) -> ActorKind {
    use chalk_core::models::console_user::ConsoleRole;
    match actor.role {
        ConsoleRole::Admin => ActorKind::Admin,
        _ => ActorKind::Technician,
    }
}

// ---------------------------------------------------------------------------
// The circulation view
// ---------------------------------------------------------------------------

pub struct LoanRow {
    pub asset_id: String,
    pub device: String,
    pub holder: String,
    pub checked_out: String,
    pub due: String,
    pub overdue: bool,
    pub agreement: bool,
    pub loaner: bool,
}

#[derive(askama::Template, askama_web::WebTemplate)]
#[template(path = "devices/circulation.html")]
struct CirculationTemplate {
    nav: crate::nav::Nav,
    loans: Vec<LoanRow>,
    overdue_count: usize,
}

/// `GET /devices/circulation` — every open loan, soonest due first, overdue
/// called out. The year-end collection list.
pub async fn circulation(State(state): State<Arc<AppState>>) -> Response {
    let (Some(custody), Some(assets)) = (state.custody.clone(), state.assets.clone()) else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::response::Html("<h1>Circulation is not available here.</h1>".to_string()),
        )
            .into_response();
    };
    let open = custody.list_open_custody().await.unwrap_or_default();
    let now = Utc::now();

    let mut loans = Vec::with_capacity(open.len());
    for r in &open {
        // A page of loans is at most a screen; per-row lookups are fine and
        // keep this free of a bespoke join.
        let device = match assets.get_asset(&r.asset_id).await {
            Ok(Some(a)) => a
                .asset_tag
                .or(a.serial_number)
                .unwrap_or_else(|| r.asset_id.clone()),
            _ => r.asset_id.clone(),
        };
        let holder = match state.repo.get_user(&r.user_sourced_id).await {
            Ok(Some(u)) => format!("{}, {}", u.family_name, u.given_name),
            _ => r.user_sourced_id.clone(),
        };
        loans.push(LoanRow {
            asset_id: r.asset_id.clone(),
            device,
            holder,
            checked_out: r.checked_out_at.format("%Y-%m-%d").to_string(),
            due: r
                .due_at
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "—".to_string()),
            overdue: r.is_overdue(now),
            agreement: r.agreement_acknowledged,
            loaner: r.loaner,
        });
    }
    let overdue_count = loans.iter().filter(|l| l.overdue).count();

    CirculationTemplate {
        nav: crate::nav::Nav::new(&state.config, "devices"),
        loans,
        overdue_count,
    }
    .into_response()
}

#[cfg(test)]
mod tests;
