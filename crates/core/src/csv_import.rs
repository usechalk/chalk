//! Planning a CSV import as a change set (ARCHITECTURE.md §6.4).
//!
//! # Why an import is a plan, not a write
//!
//! A spreadsheet is the highest-leverage and least reviewed input a district
//! has. Someone sorts a column without extending the selection, or pastes four
//! hundred rows one cell to the left, and the file still looks fine. Applying
//! it directly is how an inventory gets quietly rewritten.
//!
//! So an import compiles to the same object a bulk edit does: a change set the
//! operator previews row by row, with old and new values side by side, and can
//! strike individual rows out of before anything happens. This is the third
//! entry point §6.4 anticipated, and it needed no new preview surface.
//!
//! # An empty cell means "unchanged", never "clear this"
//!
//! A file with only `serial_number,status` is a perfectly good bulk status
//! update, and it must not erase every note and location in the fleet. There
//! is deliberately no way to clear a field from a CSV — that is what the edit
//! form is for, one device at a time, where the intent is unambiguous.
//!
//! # Matching, and refusing to guess
//!
//! Serial first, then asset tag ([`AssetCsvRow::match_key`]). Serials carry a
//! unique index; asset tags do not, because districts reuse them across
//! refresh cycles. A tag matching two devices is genuinely ambiguous and the
//! row is reported rather than written to whichever row came back first.
//!
//! A row matching nothing **creates** a device, marked `source = csv`. That is
//! the feature — it is how a district's existing inventory gets in — and it is
//! safe only because the preview shows every create before it happens.

use std::collections::HashSet;
use std::sync::Arc;

use crate::asset_csv::{AssetCsvRow, CsvRowError};
use crate::change_plan::{plan_hash, MAX_PLAN_ITEMS};
use crate::db::repository::{AssetRepository, ChangeSetRepository};
use crate::error::Result;
use crate::models::asset::{Asset, AssetSource};
use crate::models::change_set::{ChangeSet, ChangeSetKind, ChangeSetOp, NewChangeSetItem};

/// What an import would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvImportPlan {
    pub change_set_id: String,
    /// Change set items — one per changed field, plus one per new device.
    pub item_count: i64,
    /// Rows that would bring a new device into existence.
    pub created_count: i64,
    /// Rows that would change an existing device.
    pub updated_count: i64,
    /// Rows that matched a device and had nothing to say that was different.
    /// Reported rather than hidden: a re-import of an unedited export is
    /// *supposed* to be a no-op, and seeing that is how an operator learns to
    /// trust the round trip.
    pub unchanged_count: i64,
    /// Rows that could not be read or could not be matched, each naming its
    /// line. Carried into the change set's summary so the preview can show
    /// them beside what will happen.
    pub rejected: Vec<CsvRowError>,
    /// The file had more to change than one plan may carry.
    pub truncated: bool,
}

impl CsvImportPlan {
    pub fn is_empty(&self) -> bool {
        self.item_count == 0
    }
}

/// Plan an import.
///
/// `parse_errors` are the rows [`crate::asset_csv::parse`] could not read at
/// all. They are folded into the same `rejected` list so the operator gets one
/// account of everything the file did not do, rather than two half-lists in
/// different places.
pub async fn plan_csv_import(
    assets: &Arc<dyn AssetRepository>,
    change_sets: &Arc<dyn ChangeSetRepository>,
    rows: &[AssetCsvRow],
    parse_errors: &[CsvRowError],
    created_by: &str,
) -> Result<CsvImportPlan> {
    let mut items: Vec<NewChangeSetItem> = Vec::new();
    let mut rejected: Vec<CsvRowError> = parse_errors.to_vec();
    let mut created = 0i64;
    let mut updated = 0i64;
    let mut unchanged = 0i64;
    let mut truncated = false;
    // Match keys already consumed by an earlier row. Two rows claiming the
    // same device is a file the operator has to fix — applying both would make
    // the outcome depend on row order, and for a create it would try to make
    // the same device twice.
    let mut seen: HashSet<String> = HashSet::new();

    for row in rows {
        if items.len() as i64 >= MAX_PLAN_ITEMS {
            truncated = true;
            break;
        }

        let Some((key_field, key_value)) = row.match_key() else {
            // `parse` already rejects these; belt and braces for a caller that
            // builds rows some other way.
            rejected.push(CsvRowError {
                line: row.line,
                message: "no serial number or asset tag, so this row cannot be matched \
                          to a device"
                    .into(),
            });
            continue;
        };

        let dedupe = format!("{key_field}={}", key_value.to_ascii_lowercase());
        if !seen.insert(dedupe) {
            rejected.push(CsvRowError {
                line: row.line,
                message: format!(
                    "{key_value:?} already appeared earlier in this file — \
                     two rows cannot describe the same device"
                ),
            });
            continue;
        }

        let matches = match key_field {
            "serial_number" => assets
                .get_asset_by_serial(key_value)
                .await?
                .into_iter()
                .collect(),
            _ => assets.find_assets_by_asset_tag(key_value).await?,
        };

        match matches.len() {
            0 => {
                items.push(create_item(row));
                created += 1;
            }
            1 => {
                let before = items.len();
                items.extend(update_items(row, &matches[0]));
                if items.len() == before {
                    unchanged += 1;
                } else {
                    updated += 1;
                }
            }
            n => rejected.push(CsvRowError {
                line: row.line,
                message: format!(
                    "asset tag {key_value:?} is on {n} devices, so this row is ambiguous — \
                     give it a serial number instead"
                ),
            }),
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    let item_count = items.len() as i64;
    let mut set = ChangeSet::planned(
        &id,
        ChangeSetKind::CsvImport,
        created_by,
        plan_hash(&items),
        item_count,
    );
    set.summary = serde_json::json!({
        "itemCount": item_count,
        "createdCount": created,
        "updatedCount": updated,
        "unchangedCount": unchanged,
        "truncated": truncated,
        "rejectedRows": rejected
            .iter()
            .map(|e| serde_json::json!({ "line": e.line, "message": e.message }))
            .collect::<Vec<_>>(),
    });

    change_sets.create_change_set(&set, &items).await?;

    Ok(CsvImportPlan {
        change_set_id: id,
        item_count,
        created_count: created,
        updated_count: updated,
        unchanged_count: unchanged,
        rejected,
        truncated,
    })
}

/// The field a create item's `new_value` carries: the whole asset, as JSON.
///
/// The id is fixed here rather than at commit time on purpose. A commit that
/// somehow ran twice collides on the primary key and fails loudly, instead of
/// creating the device a second time — and the id is inside the plan hash, so
/// the row an operator approved is the row that gets written.
fn create_item(row: &AssetCsvRow) -> NewChangeSetItem {
    let mut asset = Asset::new(uuid::Uuid::new_v4().to_string());
    asset.source = AssetSource::Csv;
    asset.asset_tag = row.asset_tag.clone();
    asset.serial_number = row.serial_number.clone();
    if let Some(v) = row.asset_type {
        asset.asset_type = v;
    }
    if let Some(v) = row.status {
        asset.status = v;
    }
    asset.make = row.make.clone();
    asset.model = row.model.clone();
    asset.location = row.location.clone();
    asset.funding_source = row.funding_source.clone();
    asset.purchase_date = row.purchase_date;
    asset.warranty_expires = row.warranty_expires;
    asset.notes = row.notes.clone();

    NewChangeSetItem {
        asset_id: None,
        target_ref: row.asset_tag.clone().or_else(|| row.serial_number.clone()),
        google_device_id: None,
        op: ChangeSetOp::Create,
        field: None,
        old_value: None,
        new_value: Some(serde_json::to_string(&asset).unwrap_or_default()),
        remote_target: Default::default(),
    }
}

/// One item per field this row would actually change.
///
/// Per field, not per row, because that is what the preview renders: a
/// technician looking at "location: Room 12 → Room 14" can strike out that one
/// column without abandoning the status change beside it.
fn update_items(row: &AssetCsvRow, asset: &Asset) -> Vec<NewChangeSetItem> {
    let mut out = Vec::new();
    let mut push = |field: &'static str, op: ChangeSetOp, old: Option<String>, new: String| {
        if old.as_deref() == Some(new.as_str()) {
            return;
        }
        out.push(NewChangeSetItem {
            asset_id: Some(asset.id.clone()),
            // Denormalised so an applied item still names a real device after
            // the asset row is gone — `asset_id` is ON DELETE SET NULL.
            target_ref: asset
                .asset_tag
                .clone()
                .or_else(|| asset.serial_number.clone()),
            google_device_id: asset.google_device_id.clone(),
            op,
            field: Some(field.to_string()),
            old_value: old,
            new_value: Some(new),
            remote_target: Default::default(),
        });
    };

    let f = ChangeSetOp::UpdateField;
    if let Some(v) = &row.asset_tag {
        push("asset_tag", f, asset.asset_tag.clone(), v.clone());
    }
    if let Some(v) = &row.serial_number {
        push("serial_number", f, asset.serial_number.clone(), v.clone());
    }
    if let Some(v) = row.asset_type {
        push(
            "asset_type",
            f,
            Some(asset.asset_type.as_str().to_string()),
            v.as_str().to_string(),
        );
    }
    if let Some(v) = &row.make {
        push("make", f, asset.make.clone(), v.clone());
    }
    if let Some(v) = &row.model {
        push("model", f, asset.model.clone(), v.clone());
    }
    if let Some(v) = row.status {
        push(
            "status",
            ChangeSetOp::ChangeStatus,
            Some(asset.status.as_str().to_string()),
            v.as_str().to_string(),
        );
    }
    if let Some(v) = &row.location {
        push("location", f, asset.location.clone(), v.clone());
    }
    if let Some(v) = &row.funding_source {
        push("funding_source", f, asset.funding_source.clone(), v.clone());
    }
    if let Some(v) = row.purchase_date {
        push(
            "purchase_date",
            f,
            asset.purchase_date.map(|d| d.to_string()),
            v.to_string(),
        );
    }
    if let Some(v) = row.warranty_expires {
        push(
            "warranty_expires",
            f,
            asset.warranty_expires.map(|d| d.to_string()),
            v.to_string(),
        );
    }
    if let Some(v) = &row.notes {
        push("notes", f, asset.notes.clone(), v.clone());
    }

    out
}

#[cfg(test)]
mod tests;
