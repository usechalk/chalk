//! Custody records — the 1:1 circulation loop (migration 037).
//!
//! The asset's `assigned_user_sourced_id` says who holds a device *now*. A
//! custody record is the story around it: when they took it, when it is due
//! back, what condition it left in, whether the device agreement was
//! acknowledged, and — once checked in — when it returned and in what shape.
//! At most one open record per asset, enforced by a partial unique index.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One loan of one device to one person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustodyRecord {
    /// UUID.
    pub id: String,
    pub asset_id: String,
    pub user_sourced_id: String,
    pub checked_out_at: DateTime<Utc>,
    /// `None` means no return date was set — a 1:1 device kept all year.
    pub due_at: Option<DateTime<Utc>>,
    /// `None` while the loan is open.
    pub checked_in_at: Option<DateTime<Utc>>,
    /// Free text, as the desk described it at hand-out.
    pub condition_out: Option<String>,
    /// Free text at return. `None` until checked in.
    pub condition_in: Option<String>,
    /// The device agreement was acknowledged at checkout.
    pub agreement_acknowledged: bool,
    /// Who ran the desk — an audit actor string, same convention as asset
    /// events.
    pub actor: String,
    /// A temporary swap: the holder keeps their primary device assignment on
    /// the broken machine while carrying this one.
    pub loaner: bool,
}

impl CustodyRecord {
    pub fn is_open(&self) -> bool {
        self.checked_in_at.is_none()
    }

    /// Open and past its due date.
    pub fn is_overdue(&self, now: DateTime<Utc>) -> bool {
        self.is_open() && self.due_at.is_some_and(|due| due < now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> CustodyRecord {
        CustodyRecord {
            id: "c-1".into(),
            asset_id: "a-1".into(),
            user_sourced_id: "u-1".into(),
            checked_out_at: Utc::now(),
            due_at: None,
            checked_in_at: None,
            condition_out: None,
            condition_in: None,
            agreement_acknowledged: true,
            actor: "console:admin".into(),
            loaner: false,
        }
    }

    #[test]
    fn overdue_needs_an_open_loan_and_a_past_due_date() {
        let now = Utc::now();
        let mut r = record();
        assert!(!r.is_overdue(now), "no due date, never overdue");

        r.due_at = Some(now - chrono::Duration::days(1));
        assert!(r.is_overdue(now), "open and past due");

        r.checked_in_at = Some(now);
        assert!(!r.is_overdue(now), "returned late is history, not overdue");
    }
}
