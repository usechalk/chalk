//! The plan phase of diff-preview-then-commit (ARCHITECTURE.md §6.4).
//!
//! # What planning is
//!
//! Pure read. It walks the assets an operator selected, works out what *would*
//! change, and writes a `change_sets` row plus one `change_set_items` row per
//! affected device. Nothing is applied and nothing is touched — the change set
//! is a proposal.
//!
//! # Why this is what makes filter-scoped selection safe
//!
//! The inventory lets an operator act on "all 400 devices matching this
//! filter" rather than the hundred on screen. That is the right shape — it is
//! what a technician means — but it is only defensible because a plan stands
//! between the filter and the write. The operator sees the actual 400 rows,
//! with the actual old and new values, and can strike individual ones out
//! before anything happens.
//!
//! Without this step, "act on everything matching" is a blind write.
//!
//! # Why it lives in core
//!
//! Planning needs `AssetRepository` and `ChangeSetRepository` and nothing else.
//! No Google client, no credentials. Putting it here means the console can plan
//! without depending on `chalk-devices`, the same property that keeps the job
//! queue clean.
//!
//! # Items with nothing to change are not planned
//!
//! A device already in the requested state produces no item. That is not an
//! optimisation: a preview padded with two hundred no-op rows makes the twelve
//! real changes impossible to find, and an operator who cannot see what will
//! happen has not been shown a preview.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::db::repository::{AssetRepository, ChangeSetRepository};
use crate::error::Result;
use crate::models::asset::{Asset, AssetFilter, AssetStatus, MatchState};
use crate::models::change_set::{
    ChangeSet, ChangeSetKind, ChangeSetOp, NewChangeSetItem, RemoteTarget,
};
use crate::models::device_action::ChangeStatusAction;
use crate::models::page::PageRequest;

/// How many assets one plan may cover.
///
/// A ceiling rather than a page: a change set is previewed in one screen and
/// committed as one unit, and a plan over a hundred thousand devices is not a
/// thing an operator can meaningfully review. Hitting it is reported, never
/// silently truncated — a preview that quietly covers less than it says is the
/// exact failure this whole phase exists to prevent.
pub const MAX_PLAN_ITEMS: i64 = 5_000;

/// What the operator asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedChange {
    /// Attach every selected device to one roster user.
    Assign { user_sourced_id: String },
    /// Detach every selected device from whoever holds it.
    Unassign,
    /// Set the lifecycle status.
    SetStatus { status: AssetStatus },
    /// Mark devices as shared, so the unmatched queue stops asking about them.
    SetMatchState { match_state: MatchState },
    /// Move devices into a Google org unit. Written to Google, then mirrored.
    MoveOu { org_unit_path: String },
    /// Deprovision, disable or re-enable in Google.
    ChangeStatus { action: ChangeStatusAction },
}

impl PlannedChange {
    fn op(&self) -> ChangeSetOp {
        match self {
            PlannedChange::Assign { .. } => ChangeSetOp::Assign,
            PlannedChange::Unassign => ChangeSetOp::Unassign,
            PlannedChange::SetStatus { .. } => ChangeSetOp::ChangeStatus,
            PlannedChange::SetMatchState { .. } => ChangeSetOp::UpdateField,
            PlannedChange::MoveOu { .. } => ChangeSetOp::MoveOu,
            PlannedChange::ChangeStatus { .. } => ChangeSetOp::ChangeStatus,
        }
    }

    /// The column this change writes, as it appears in the preview.
    fn field(&self) -> &'static str {
        match self {
            PlannedChange::Assign { .. } | PlannedChange::Unassign => "assigned_user_sourced_id",
            PlannedChange::SetStatus { .. } => "status",
            PlannedChange::SetMatchState { .. } => "match_state",
            PlannedChange::MoveOu { .. } => "org_unit_path",
            // Not `status`: this is Google's device state, which is a different
            // thing from the lifecycle status a technician sets by hand. Naming
            // them the same in a preview would suggest one column.
            PlannedChange::ChangeStatus { .. } => "google_status",
        }
    }

    /// Which side has to perform the change.
    ///
    /// Only the two Google operations are remote. Everything else is a local
    /// edit to Chalk's own records, and marking one `Google` would send a
    /// device id to the Directory API for a field Google does not own.
    fn remote_target(&self) -> RemoteTarget {
        match self {
            PlannedChange::MoveOu { .. } | PlannedChange::ChangeStatus { .. } => {
                RemoteTarget::Google
            }
            _ => RemoteTarget::Local,
        }
    }

    /// The value this change would write, or `None` for a clear.
    fn new_value(&self) -> Option<String> {
        match self {
            PlannedChange::Assign { user_sourced_id } => Some(user_sourced_id.clone()),
            PlannedChange::Unassign => None,
            PlannedChange::SetStatus { status } => Some(status.as_str().to_string()),
            PlannedChange::SetMatchState { match_state } => Some(match_state.as_str().to_string()),
            PlannedChange::MoveOu { org_unit_path } => Some(org_unit_path.clone()),
            PlannedChange::ChangeStatus { action } => Some(action.as_item_value()),
        }
    }

    /// The value this asset holds today, for the old→new column.
    fn old_value(&self, asset: &Asset) -> Option<String> {
        match self {
            PlannedChange::Assign { .. } | PlannedChange::Unassign => {
                asset.assigned_user_sourced_id.clone()
            }
            PlannedChange::SetStatus { .. } => Some(asset.status.as_str().to_string()),
            PlannedChange::SetMatchState { .. } => Some(asset.match_state.as_str().to_string()),
            PlannedChange::MoveOu { .. } => asset.org_unit_path.clone(),
            // Deliberately unknown. Chalk stores a *lifecycle* status a
            // technician sets by hand; Google's device state is a different
            // thing it never syncs. Showing the lifecycle value here would put
            // a number in the "now" column that is not the value being
            // changed — and an operator would reasonably read it as one.
            PlannedChange::ChangeStatus { .. } => None,
        }
    }

    /// True when this asset is already in the requested state.
    ///
    /// A status change can never be one, and that falls out of the data rather
    /// than needing a special case: [`old_value`](Self::old_value) is `None`
    /// for a status change because Chalk does not store Google's device state,
    /// and the new value is always `Some`. Dropping such a row as "already
    /// done" would silently discard a device the operator selected; Google
    /// answers a redundant change with 412, which the commit path already
    /// reads as already-applied.
    fn is_noop_for(&self, asset: &Asset) -> bool {
        self.old_value(asset) == self.new_value()
    }
}

/// The outcome of planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub change_set_id: String,
    /// Rows that would actually change.
    pub item_count: i64,
    /// Selected devices already in the requested state, so nothing was planned
    /// for them. Reported rather than hidden: "400 selected, 12 will change"
    /// is the sentence that stops an operator expecting 400.
    pub unchanged_count: i64,
    /// True when the selection was larger than [`MAX_PLAN_ITEMS`] and the plan
    /// covers only the first slice. Never silent.
    pub truncated: bool,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.item_count == 0
    }
}

/// Plan a change over every asset matching `filter`.
///
/// `excluded` are asset ids the operator struck out before planning — the
/// checkbox path from a page of results. They are dropped here rather than
/// after, so an excluded device never appears in the preview at all.
pub async fn plan_change(
    assets: &Arc<dyn AssetRepository>,
    change_sets: &Arc<dyn ChangeSetRepository>,
    filter: &AssetFilter,
    change: &PlannedChange,
    excluded: &[String],
    created_by: &str,
) -> Result<Plan> {
    let page = assets
        .list_assets(filter, PageRequest::new(MAX_PLAN_ITEMS + 1, 0))
        .await?;
    let truncated = page.items.len() as i64 > MAX_PLAN_ITEMS;
    let considered: Vec<&Asset> = page
        .items
        .iter()
        .take(MAX_PLAN_ITEMS as usize)
        .filter(|a| !excluded.iter().any(|e| e == &a.id))
        .collect();

    let mut items = Vec::new();
    let mut unchanged = 0i64;
    for asset in considered {
        if change.is_noop_for(asset) {
            unchanged += 1;
            continue;
        }
        items.push(NewChangeSetItem {
            asset_id: Some(asset.id.clone()),
            // Denormalised so the item still names a real device after the
            // asset row is gone — `asset_id` is ON DELETE SET NULL, which would
            // otherwise erase what an applied item actually did.
            target_ref: asset
                .asset_tag
                .clone()
                .or_else(|| asset.serial_number.clone()),
            google_device_id: asset.google_device_id.clone(),
            op: change.op(),
            field: Some(change.field().to_string()),
            old_value: change.old_value(asset),
            new_value: change.new_value(),
            remote_target: change.remote_target(),
        });
    }

    let id = uuid::Uuid::new_v4().to_string();
    let item_count = items.len() as i64;
    let mut set = ChangeSet::planned(
        &id,
        ChangeSetKind::BulkEdit,
        created_by,
        plan_hash(&items),
        item_count,
    );
    set.summary = serde_json::json!({
        "op": change.op().as_str(),
        "field": change.field(),
        "itemCount": item_count,
        "unchangedCount": unchanged,
        "truncated": truncated,
    });

    change_sets.create_change_set(&set, &items).await?;

    Ok(Plan {
        change_set_id: id,
        item_count,
        unchanged_count: unchanged,
        truncated,
    })
}

/// A digest over exactly what was planned.
///
/// Compared at commit time against a freshly computed hash, so a change set
/// whose rows were altered between preview and commit is refused rather than
/// applied. It covers each item's identity *and* both values: an item whose
/// target moved, or whose old value drifted because something else edited the
/// device, must not pass as the plan the operator approved.
///
/// Order-independent by construction — items are hashed individually and the
/// digests sorted — because the repository makes no ordering promise and a
/// plan that failed to commit purely because rows came back in another order
/// would be maddening and wrong.
pub fn plan_hash(items: &[NewChangeSetItem]) -> String {
    let mut digests: Vec<String> = items
        .iter()
        .map(|i| {
            let mut h = Sha256::new();
            h.update(i.asset_id.as_deref().unwrap_or("-").as_bytes());
            h.update(b"\x1f");
            h.update(i.op.as_str().as_bytes());
            h.update(b"\x1f");
            h.update(i.field.as_deref().unwrap_or("-").as_bytes());
            h.update(b"\x1f");
            h.update(i.old_value.as_deref().unwrap_or("\x00").as_bytes());
            h.update(b"\x1f");
            h.update(i.new_value.as_deref().unwrap_or("\x00").as_bytes());
            hex::encode(h.finalize())
        })
        .collect();
    digests.sort();

    let mut outer = Sha256::new();
    for d in &digests {
        outer.update(d.as_bytes());
    }
    hex::encode(outer.finalize())
}

#[cfg(test)]
mod tests;
