//! Fees and fines assessed against a device or a student (migration 028, F3).
//!
//! **Assessment and record only.** There is no payment row, no gateway, no card
//! handling here (decision D14/D22). A charge is *money owed, recorded*;
//! marking it settled means it was paid somewhere the district already collects
//! money, not through Chalk. Amounts are integer cents, never floats.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::str_enum::str_enum;

str_enum! {
    /// Why money is owed.
    pub enum ChargeKind {
        /// A repair the family is billed for (negligent or repeat damage).
        RepairFee => "repair_fee",
        /// A fine for damage, distinct from the repair cost.
        DamageFine => "damage_fine",
        /// Replacing a device that was lost or never returned.
        LossReplacement => "loss_replacement",
        #[default]
        Other => "other",
    }
    with_default
}

str_enum! {
    /// Where a charge stands. Only `Assessed` counts toward a balance.
    pub enum ChargeStatus {
        /// Owed and outstanding.
        #[default]
        Assessed => "assessed",
        /// Forgiven — a one-time accident, or covered by a protection plan.
        Waived => "waived",
        /// Recorded as paid through the district's own system. Chalk took no
        /// money; this is a bookkeeping note, not a transaction.
        SettledExternally => "settled_externally",
    }
    with_default
}

impl ChargeStatus {
    /// Whether a charge in this status still contributes to what a family owes.
    /// Only an outstanding (`Assessed`) charge does.
    pub fn is_outstanding(&self) -> bool {
        matches!(self, ChargeStatus::Assessed)
    }
}

/// One assessed fee or fine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Charge {
    pub id: String,
    pub asset_id: Option<String>,
    pub user_sourced_id: Option<String>,
    pub ticket_id: Option<String>,
    pub kind: ChargeKind,
    pub amount_cents: i64,
    pub status: ChargeStatus,
    /// Whether a protection plan reduced or removed this charge, kept so "why is
    /// this waived / $0" has a recorded answer.
    pub insurance_applied: bool,
    pub reason: Option<String>,
    pub actor: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// What a person owes: the sum of their outstanding charges. Waived and
/// externally-settled charges are excluded because they are no longer owed.
///
/// This is the number a family balance view shows and an export reports. It is
/// deliberately a pure function of a charge list, so it is trivial to check
/// against an independent hand-calculation and cannot disagree with itself
/// across the two database drivers.
pub fn outstanding_balance_cents(charges: &[Charge]) -> i64 {
    charges
        .iter()
        .filter(|c| c.status.is_outstanding())
        .map(|c| c.amount_cents)
        .sum()
}

/// A new charge to record. `id`/`created_at`/`updated_at` are the database's.
#[derive(Debug, Clone)]
pub struct NewCharge {
    pub asset_id: Option<String>,
    pub user_sourced_id: Option<String>,
    pub ticket_id: Option<String>,
    pub kind: ChargeKind,
    pub amount_cents: i64,
    pub status: ChargeStatus,
    pub insurance_applied: bool,
    pub reason: Option<String>,
    pub actor: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn charge(amount: i64, status: ChargeStatus) -> Charge {
        Charge {
            id: "c".into(),
            asset_id: None,
            user_sourced_id: Some("u-1".into()),
            ticket_id: None,
            kind: ChargeKind::RepairFee,
            amount_cents: amount,
            status,
            insurance_applied: false,
            reason: None,
            actor: "console:admin".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// The balance is only what is still owed. An independent hand-calc: a
    /// $50.00 assessed repair, a $30.00 fine waived under a protection plan, and
    /// a $20.00 replacement already paid at the front office → the family still
    /// owes exactly the $50.00. Waived and settled must not count.
    #[test]
    fn balance_counts_only_outstanding_charges() {
        let charges = vec![
            charge(5000, ChargeStatus::Assessed),
            charge(3000, ChargeStatus::Waived),
            charge(2000, ChargeStatus::SettledExternally),
        ];
        assert_eq!(outstanding_balance_cents(&charges), 5000);
    }

    #[test]
    fn a_person_with_no_outstanding_charges_owes_nothing() {
        assert_eq!(outstanding_balance_cents(&[]), 0);
        let all_settled = vec![
            charge(9900, ChargeStatus::Waived),
            charge(100, ChargeStatus::SettledExternally),
        ];
        assert_eq!(outstanding_balance_cents(&all_settled), 0);
    }

    #[test]
    fn outstanding_status_is_assessed_only() {
        assert!(ChargeStatus::Assessed.is_outstanding());
        assert!(!ChargeStatus::Waived.is_outstanding());
        assert!(!ChargeStatus::SettledExternally.is_outstanding());
    }
}
