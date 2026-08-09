//! Procurement records (GP-3, migration 048).
//!
//! Deliberately light. TIPWeb builds a full receive-against-PO warehouse
//! workflow; what districts actually need first is (a) a managed list of
//! funding sources so ESSER/Title/E-rate tracking stops being a free-text
//! spelling contest, and (b) a PO record an asset can name, so "what did we
//! buy on PO 2026-114 and where is it" is one filtered inventory view.
//! Receiving happens through the existing CSV import diff preview with the
//! PO's number in the po_number column — no second import pipeline.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// One managed funding source ("ESSER III", "Title I", "E-rate", "Bond 2024").
///
/// The `assets.funding_source` column stays plain text — history and CSV
/// imports keep working unchanged — this list feeds the edit form's choices
/// and gives reports a canonical set to group by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FundingSource {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// A purchase order, matched to assets by `po_number`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PurchaseOrder {
    pub id: String,
    /// The district's own PO number — unique, and the join key assets carry.
    pub po_number: String,
    pub vendor: Option<String>,
    pub funding_source: Option<String>,
    pub po_date: Option<NaiveDate>,
    pub notes: String,
    pub created_at: DateTime<Utc>,
}

/// A purchase order joined with how many assets name it — the list row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurchaseOrderRow {
    pub po: PurchaseOrder,
    /// Devices whose `po_number` matches. "Received" in the light model.
    pub asset_count: i64,
}
