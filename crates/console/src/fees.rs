//! Repairs and fees — the F3 charges ledger, surfaced (WS-12).
//!
//! # Assessment only, forever
//!
//! Chalk records that a district assessed a fee, waived it, or saw it settled
//! in the district's own payment system. There is no gateway, no card entry,
//! and no balance a family can pay *here* — that is decision D14/D22, and it
//! is what keeps "Chalk does not take payment-card details" true.
//!
//! # Corrections are new rows
//!
//! A charge's amount is immutable once recorded (the repository offers no way
//! to change it). A mistake is corrected by waiving the wrong charge and
//! assessing the right one, so the ledger reads like a ledger.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use chalk_core::models::asset::{AssetPatch, AssetStatus, NewAssetEvent};
use chalk_core::models::charge::{ChargeKind, ChargeStatus, NewCharge};
use chalk_core::models::console_user::Actor;
use chalk_core::models::repair::RepairRecord;
use chrono::Utc;
use serde::Deserialize;

use crate::AppState;

fn back(asset_id: &str, notice: &str) -> Response {
    Redirect::to(&format!("/devices/{asset_id}?notice={notice}")).into_response()
}

/// `"129.99"` → `12999`. Whole dollars, or dollars-dot-cents; nothing else.
///
/// Deliberately strict: money typed at a desk should either parse exactly or
/// be retyped, because "close enough" on a fee becomes a phone call from a
/// parent.
pub fn parse_dollars_to_cents(input: &str) -> Option<i64> {
    let s = input.trim().trim_start_matches('$').replace(',', "");
    if s.is_empty() {
        return None;
    }
    match s.split_once('.') {
        None => s.parse::<i64>().ok().map(|d| d * 100),
        Some((dollars, cents)) => {
            if cents.len() != 2 {
                return None;
            }
            let d = dollars.parse::<i64>().ok()?;
            let c = cents.parse::<i64>().ok()?;
            Some(d * 100 + c)
        }
    }
}

/// Cents → `"$129.99"`.
pub fn format_cents(cents: i64) -> String {
    format!("${}.{:02}", cents / 100, (cents % 100).abs())
}

// ---------------------------------------------------------------------------
// Repairs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OpenRepairForm {
    pub description: String,
    pub vendor: String,
}

/// `POST /devices/{id}/repairs` — open a repair and put the device in the
/// Repair status through the audited path.
pub async fn open_repair(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Extension(actor): axum::Extension<Actor>,
    axum::Form(form): axum::Form<OpenRepairForm>,
) -> Response {
    let (Some(repairs), Some(assets)) = (state.repairs.clone(), state.assets.clone()) else {
        return back(&id, "failed");
    };
    let description = form.description.trim();
    if description.is_empty() {
        return back(&id, "repair_no_description");
    }
    if let Ok(Some(_)) = repairs.open_repair_for_asset(&id).await {
        return back(&id, "repair_open");
    }
    match assets.get_asset(&id).await {
        Ok(Some(_)) => {}
        _ => return back(&id, "failed"),
    }

    let record = RepairRecord {
        id: uuid::Uuid::new_v4().to_string(),
        asset_id: id.clone(),
        ticket_id: None,
        description: description.to_string(),
        vendor: {
            let v = form.vendor.trim();
            (!v.is_empty()).then(|| v.to_string())
        },
        opened_at: Utc::now(),
        closed_at: None,
        cost_cents: None,
        actor: actor.audit_actor(),
    };
    if let Err(e) = repairs.create_repair(&record).await {
        tracing::error!("could not open repair for {id}: {e}");
        return back(&id, "failed");
    }

    let patch = AssetPatch {
        status: Some(AssetStatus::Repair),
        ..Default::default()
    };
    let event = NewAssetEvent {
        asset_id: id.clone(),
        actor: record.actor.clone(),
        actor_kind: crate::custody::console_actor_kind(&actor),
        event_type: chalk_core::models::asset::AssetEventType::StatusChanged,
        payload: Some(serde_json::json!({
            "field": "status",
            "new": "repair",
            "repair": record.id,
        })),
    };
    match assets.apply_patch_with_event(&id, &patch, &event).await {
        Ok(true) => back(&id, "repair_opened"),
        _ => back(&id, "failed"),
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CloseRepairForm {
    /// Dollars, e.g. `129.99`. Optional — a warranty repair costs nothing.
    pub cost: String,
    /// `"1"` also assesses the cost as a repair fee to the current holder.
    pub assess: String,
    /// `"1"` marks the assessed fee insurance-applied.
    pub insurance: String,
}

/// `POST /devices/{id}/repairs/close` — close the open repair with its final
/// cost, return the device to Active, and optionally assess the cost as a fee
/// to whoever holds the device.
pub async fn close_repair(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Extension(actor): axum::Extension<Actor>,
    axum::Form(form): axum::Form<CloseRepairForm>,
) -> Response {
    let (Some(repairs), Some(assets)) = (state.repairs.clone(), state.assets.clone()) else {
        return back(&id, "failed");
    };
    let Ok(Some(open)) = repairs.open_repair_for_asset(&id).await else {
        return back(&id, "repair_none");
    };
    let cost_cents = {
        let c = form.cost.trim();
        if c.is_empty() {
            None
        } else {
            match parse_dollars_to_cents(c) {
                Some(v) if v >= 0 => Some(v),
                _ => return back(&id, "bad_amount"),
            }
        }
    };
    match repairs.close_repair(&open.id, cost_cents).await {
        Ok(true) => {}
        _ => return back(&id, "failed"),
    }

    // Optionally assess the cost to the holder — refused in words when there
    // is no cost or nobody holds the device.
    let mut notice = "repair_closed";
    if form.assess.trim() == "1" {
        match (cost_cents, state.charges.clone()) {
            (Some(cents), Some(charges)) if cents > 0 => {
                let holder = assets
                    .get_asset(&id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|a| a.assigned_user_sourced_id);
                match holder {
                    Some(user) => {
                        let charge = NewCharge {
                            asset_id: Some(id.clone()),
                            user_sourced_id: Some(user),
                            ticket_id: open.ticket_id.clone(),
                            kind: ChargeKind::RepairFee,
                            amount_cents: cents,
                            status: ChargeStatus::Assessed,
                            insurance_applied: form.insurance.trim() == "1",
                            reason: Some(open.description.clone()),
                            actor: actor.audit_actor(),
                        };
                        if let Err(e) = charges.create_charge(&charge).await {
                            tracing::error!("repair closed but the fee failed: {e}");
                            notice = "fee_failed";
                        } else {
                            notice = "repair_closed_fee";
                        }
                    }
                    None => notice = "fee_no_holder",
                }
            }
            _ => notice = "fee_no_cost",
        }
    }

    let patch = AssetPatch {
        status: Some(AssetStatus::Active),
        ..Default::default()
    };
    let event = NewAssetEvent {
        asset_id: id.clone(),
        actor: actor.audit_actor(),
        actor_kind: crate::custody::console_actor_kind(&actor),
        event_type: chalk_core::models::asset::AssetEventType::Repaired,
        payload: Some(serde_json::json!({
            "repair": open.id,
            "costCents": cost_cents,
        })),
    };
    let _ = assets.apply_patch_with_event(&id, &patch, &event).await;
    back(&id, notice)
}

// ---------------------------------------------------------------------------
// Fees
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AssessForm {
    pub kind: String,
    /// Dollars.
    pub amount: String,
    /// Roster sourced_id; empty means the device's current holder.
    pub user: String,
    pub reason: String,
    pub insurance: String,
}

/// `POST /devices/{id}/charges` — assess a fee against a person for this
/// device. Assessment only: recording that the district is owed, never taking
/// the money.
pub async fn assess_charge(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Extension(actor): axum::Extension<Actor>,
    axum::Form(form): axum::Form<AssessForm>,
) -> Response {
    let (Some(charges), Some(assets)) = (state.charges.clone(), state.assets.clone()) else {
        return back(&id, "failed");
    };
    let Some(cents) = parse_dollars_to_cents(&form.amount) else {
        return back(&id, "bad_amount");
    };
    if cents <= 0 {
        return back(&id, "bad_amount");
    }
    let kind = ChargeKind::parse(form.kind.trim()).unwrap_or(ChargeKind::Other);

    let user = {
        let u = form.user.trim();
        if u.is_empty() {
            assets
                .get_asset(&id)
                .await
                .ok()
                .flatten()
                .and_then(|a| a.assigned_user_sourced_id)
        } else {
            Some(u.to_string())
        }
    };
    let Some(user) = user else {
        return back(&id, "fee_no_holder");
    };

    let charge = NewCharge {
        asset_id: Some(id.clone()),
        user_sourced_id: Some(user),
        ticket_id: None,
        kind,
        amount_cents: cents,
        status: ChargeStatus::Assessed,
        insurance_applied: form.insurance.trim() == "1",
        reason: {
            let r = form.reason.trim();
            (!r.is_empty()).then(|| r.to_string())
        },
        actor: actor.audit_actor(),
    };
    match charges.create_charge(&charge).await {
        Ok(_) => back(&id, "fee_assessed"),
        Err(e) => {
            tracing::error!("could not assess a fee on {id}: {e}");
            back(&id, "failed")
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DispositionForm {
    /// Where to land afterwards — the user page that showed the button.
    pub user: String,
}

/// `POST /charges/{id}/waive`
pub async fn waive_charge(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<DispositionForm>,
) -> Response {
    set_disposition(state, id, ChargeStatus::Waived, form.user).await
}

/// `POST /charges/{id}/settle` — settled in the district's own system, not
/// paid to Chalk. The name is the boundary.
pub async fn settle_charge(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<DispositionForm>,
) -> Response {
    set_disposition(state, id, ChargeStatus::SettledExternally, form.user).await
}

async fn set_disposition(
    state: Arc<AppState>,
    id: String,
    status: ChargeStatus,
    user: String,
) -> Response {
    let Some(charges) = state.charges.clone() else {
        return Redirect::to("/").into_response();
    };
    // Insurance flag is preserved: read the charge, write back its own value.
    let insurance = charges
        .get_charge(&id)
        .await
        .ok()
        .flatten()
        .map(|c| c.insurance_applied)
        .unwrap_or(false);
    if let Err(e) = charges.update_charge_status(&id, status, insurance).await {
        tracing::error!("could not update charge {id}: {e}");
    }
    let user = user.trim();
    if user.is_empty() {
        Redirect::to("/").into_response()
    } else {
        Redirect::to(&format!("/users/{user}")).into_response()
    }
}

#[cfg(test)]
mod tests;
