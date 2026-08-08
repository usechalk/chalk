//! Repair records (migration 038).
//!
//! "Repair" was only an asset status; this is the story behind it — what
//! broke, who is fixing it, when it went out and came back, and what it cost.
//! The cost is what a district reports on and what a fee can be assessed from,
//! through the charges ledger.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One repair of one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepairRecord {
    /// UUID.
    pub id: String,
    pub asset_id: String,
    /// The ticket that reported it, when there is one.
    pub ticket_id: Option<String>,
    pub description: String,
    pub vendor: Option<String>,
    pub opened_at: DateTime<Utc>,
    /// `None` while the repair is in progress.
    pub closed_at: Option<DateTime<Utc>>,
    /// Recorded at close. Cents, same idiom as `purchase_cost_cents`.
    pub cost_cents: Option<i64>,
    pub actor: String,
}

impl RepairRecord {
    pub fn is_open(&self) -> bool {
        self.closed_at.is_none()
    }
}
