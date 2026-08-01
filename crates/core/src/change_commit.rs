//! The commit phase of diff-preview-then-commit (ARCHITECTURE.md §6.3, §6.4).
//!
//! # What commit guarantees
//!
//! **Nothing is applied that the operator did not approve.** The claim compares
//! the plan hash and item count against what was previewed, so a change set
//! whose rows drifted — because a sync ran, or someone edited a device in
//! another tab — is refused rather than applied. A diff nobody looked at is
//! never written.
//!
//! **Each item's outcome is persisted before the next one is attempted.**
//! `mark_item_applied` is a single transaction over the asset write, its audit
//! event, and the item's status. There is no state where a device changed but
//! its history disagrees, and a process killed mid-commit leaves per-item truth
//! rather than a set anyone has to guess about.
//!
//! # Google items are refused, not skipped quietly
//!
//! Write-back does not exist yet. An item targeting Google is left `pending`
//! with an explicit reason rather than marked applied or silently dropped —
//! the operator can see exactly which rows are waiting on a capability the
//! product does not have. Marking them `failed` would be worse: it would
//! suggest something went wrong, when nothing was attempted.

use std::sync::Arc;

use crate::db::repository::ChangeSetRepository;
use crate::error::Result;
use crate::models::asset::{ActorKind, AssetPatch, AssetStatus, MatchState, NewAssetEvent, Patch};
use crate::models::change_set::{
    ChangeSetItem, ChangeSetItemStatus, ChangeSetOp, CommitClaim, RemoteTarget,
};
use crate::models::page::PageRequest;

/// How many items one commit pass reads at a time.
const BATCH: i64 = 500;

/// What a commit did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommitOutcome {
    pub applied: i64,
    pub skipped: i64,
    /// Left alone because they need a Google write this release cannot make.
    pub deferred: i64,
    pub failed: i64,
}

impl CommitOutcome {
    pub fn total(&self) -> i64 {
        self.applied + self.skipped + self.deferred + self.failed
    }
}

/// Why a commit could not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitRefusal {
    NotFound,
    AlreadySettled {
        status: String,
    },
    /// The devices moved under the preview. Reported with both sides so an
    /// operator is told what changed rather than merely that something did.
    Stale {
        expected_items: i64,
        actual_items: i64,
    },
}

/// Apply a planned change set.
///
/// `actor` is recorded on every audit event this writes.
pub async fn commit_change_set(
    sets: &Arc<dyn ChangeSetRepository>,
    change_set_id: &str,
    expected_plan_hash: &str,
    expected_item_count: i64,
    actor: &str,
) -> Result<std::result::Result<CommitOutcome, CommitRefusal>> {
    // Read before claiming, purely so the audit trail can say which entry
    // point produced this — "via csv_import" and "via bulk_edit" answer very
    // different questions six months later.
    let kind = sets
        .get_change_set(change_set_id)
        .await?
        .map(|s| s.kind.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // The staleness guard. One conditional claim, so two commits of the same
    // set cannot both proceed.
    match sets
        .claim_for_commit(change_set_id, expected_plan_hash, expected_item_count)
        .await?
    {
        CommitClaim::Claimed => {}
        CommitClaim::NotFound => return Ok(Err(CommitRefusal::NotFound)),
        CommitClaim::NotPlanned { status } => {
            return Ok(Err(CommitRefusal::AlreadySettled {
                status: status.as_str().to_string(),
            }))
        }
        CommitClaim::Stale {
            expected_item_count,
            actual_item_count,
            ..
        } => {
            return Ok(Err(CommitRefusal::Stale {
                expected_items: expected_item_count,
                actual_items: actual_item_count,
            }))
        }
    }

    let mut outcome = CommitOutcome::default();
    let mut offset = 0i64;
    loop {
        let page = sets
            .list_items(change_set_id, None, PageRequest::new(BATCH, offset))
            .await?;
        if page.items.is_empty() {
            break;
        }
        for item in &page.items {
            match apply_one(sets, item, actor, &kind).await {
                Ok(ItemResult::Applied) => outcome.applied += 1,
                Ok(ItemResult::Skipped) => outcome.skipped += 1,
                Ok(ItemResult::Deferred) => outcome.deferred += 1,
                Err(e) => {
                    // Recorded against the item, not raised — one device that
                    // cannot be written must not abandon the other 399.
                    tracing::error!("change set {change_set_id} item {} failed: {e}", item.id);
                    sets.mark_item_outcome(
                        item.id,
                        ChangeSetItemStatus::Failed,
                        Some(&e.to_string()),
                    )
                    .await?;
                    outcome.failed += 1;
                }
            }
        }
        offset += page.items.len() as i64;
    }

    sets.finish_commit(change_set_id).await?;
    Ok(Ok(outcome))
}

enum ItemResult {
    Applied,
    Skipped,
    Deferred,
}

async fn apply_one(
    sets: &Arc<dyn ChangeSetRepository>,
    item: &ChangeSetItem,
    actor: &str,
    kind: &str,
) -> Result<ItemResult> {
    // Already decided — struck out at preview, or applied by an earlier pass
    // that was interrupted. Re-applying would double-write.
    if item.status != ChangeSetItemStatus::Pending {
        return Ok(ItemResult::Skipped);
    }

    if item.remote_target == RemoteTarget::Google {
        // Left `pending` on purpose. `failed` would say something went wrong
        // when nothing was attempted, and `skipped` would say the operator
        // chose this. Neither is true.
        return Ok(ItemResult::Deferred);
    }

    // A create carries its whole asset, id and all, so the row an operator
    // approved in the preview is exactly the row that gets written.
    if item.op == ChangeSetOp::Create {
        let raw = item.new_value.as_deref().unwrap_or_default();
        let asset: crate::models::asset::Asset = serde_json::from_str(raw).map_err(|e| {
            crate::error::ChalkError::Sync(format!(
                "change set item {} is not an asset: {e}",
                item.id
            ))
        })?;
        let event = NewAssetEvent {
            asset_id: asset.id.clone(),
            actor: actor.to_string(),
            actor_kind: ActorKind::Admin,
            event_type: crate::models::asset::AssetEventType::Imported,
            payload: Some(serde_json::json!({
                "assetTag": asset.asset_tag,
                "serialNumber": asset.serial_number,
                "source": asset.source.as_str(),
                "via": kind,
                "changeSetId": item.change_set_id,
            })),
        };
        sets.mark_item_created(item.id, &asset, &event).await?;
        return Ok(ItemResult::Applied);
    }

    let Some(asset_id) = item.asset_id.as_deref() else {
        return Ok(ItemResult::Skipped);
    };

    let patch = patch_for(item)?;
    let event = NewAssetEvent {
        asset_id: asset_id.to_string(),
        actor: actor.to_string(),
        actor_kind: ActorKind::Admin,
        event_type: event_type_for(item.op),
        payload: Some(serde_json::json!({
            "field": item.field,
            "old": item.old_value,
            "new": item.new_value,
            "via": kind,
            "changeSetId": item.change_set_id,
        })),
    };

    // The atom: asset write, audit row and item status in one transaction.
    // No `AssetRepository` is needed here — `mark_item_applied` owns the whole
    // write, which is exactly why it exists.
    sets.mark_item_applied(item.id, Some(&patch), &event)
        .await?;
    Ok(ItemResult::Applied)
}

/// Turn one item into the patch that applies it.
///
/// Values are re-parsed from the stored strings rather than trusted, so a row
/// hand-edited in the database cannot write a status the enum does not have.
fn patch_for(item: &ChangeSetItem) -> Result<AssetPatch> {
    let new = item.new_value.as_deref();
    Ok(match item.op {
        ChangeSetOp::Assign => AssetPatch {
            assigned_user_sourced_id: match new {
                Some(v) if !v.is_empty() => Patch::Set(v.to_string()),
                _ => Patch::Clear,
            },
            // An operator's decision outranks the matcher, and must survive the
            // next sync — which refuses to touch `manual` rows.
            match_state: Some(MatchState::Manual),
            ..Default::default()
        },
        ChangeSetOp::Unassign => AssetPatch {
            assigned_user_sourced_id: Patch::Clear,
            match_state: Some(MatchState::Manual),
            ..Default::default()
        },
        ChangeSetOp::ChangeStatus => AssetPatch {
            status: Some(AssetStatus::parse(new.unwrap_or_default())?),
            ..Default::default()
        },
        ChangeSetOp::UpdateField => match item.field.as_deref() {
            Some("match_state") => AssetPatch {
                match_state: Some(MatchState::parse(new.unwrap_or_default())?),
                ..Default::default()
            },
            // The CSV-importable columns. A CSV cannot clear a field — an empty
            // cell means "unchanged" — so every one of these is a `Set`.
            Some("asset_tag") => AssetPatch {
                asset_tag: text(new),
                ..Default::default()
            },
            Some("serial_number") => AssetPatch {
                serial_number: text(new),
                ..Default::default()
            },
            Some("asset_type") => AssetPatch {
                asset_type: Some(crate::models::asset::AssetType::parse(
                    new.unwrap_or_default(),
                )?),
                ..Default::default()
            },
            Some("make") => AssetPatch {
                make: text(new),
                ..Default::default()
            },
            Some("model") => AssetPatch {
                model: text(new),
                ..Default::default()
            },
            Some("location") => AssetPatch {
                location: text(new),
                ..Default::default()
            },
            Some("funding_source") => AssetPatch {
                funding_source: text(new),
                ..Default::default()
            },
            Some("notes") => AssetPatch {
                notes: text(new),
                ..Default::default()
            },
            Some("purchase_date") => AssetPatch {
                purchase_date: date(new)?,
                ..Default::default()
            },
            Some("warranty_expires") => AssetPatch {
                warranty_expires: date(new)?,
                ..Default::default()
            },
            other => {
                return Err(crate::error::ChalkError::Sync(format!(
                    "no commit rule for field {other:?}"
                )))
            }
        },
        other => {
            return Err(crate::error::ChalkError::Sync(format!(
                "no commit rule for op {}",
                other.as_str()
            )))
        }
    })
}

/// A stored string as a nullable text column. An absent value is a clear —
/// which the CSV path never produces, but the bulk-edit path may.
fn text(new: Option<&str>) -> Patch<String> {
    match new {
        Some(v) if !v.is_empty() => Patch::Set(v.to_string()),
        _ => Patch::Clear,
    }
}

/// A stored string as a date, re-parsed rather than trusted so a row
/// hand-edited in the database cannot write a value the column cannot hold.
fn date(new: Option<&str>) -> Result<Patch<chrono::NaiveDate>> {
    let Some(v) = new.filter(|v| !v.is_empty()) else {
        return Ok(Patch::Clear);
    };
    chrono::NaiveDate::parse_from_str(v, "%Y-%m-%d")
        .map(Patch::Set)
        .map_err(|_| crate::error::ChalkError::Sync(format!("{v:?} is not a date")))
}

fn event_type_for(op: ChangeSetOp) -> crate::models::asset::AssetEventType {
    use crate::models::asset::AssetEventType as E;
    match op {
        ChangeSetOp::Assign => E::Assigned,
        ChangeSetOp::Unassign => E::Unassigned,
        ChangeSetOp::ChangeStatus => E::StatusChanged,
        ChangeSetOp::MoveOu => E::MovedOu,
        _ => E::FieldChanged,
    }
}

#[cfg(test)]
mod tests;
