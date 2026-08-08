//! Custody self-attestation (SS-2): the periodic "do you still have it?"
//!
//! A technician walking rooms with a scanner covers what is in the building;
//! this covers what went home. Each row is one ask against one open loan,
//! answered once through a tokenized public link — the token is the whole
//! credential, exactly like CSAT.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The holder's answer about the item's condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestCondition {
    Good,
    Fair,
    Poor,
    Broken,
}

impl AttestCondition {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttestCondition::Good => "good",
            AttestCondition::Fair => "fair",
            AttestCondition::Poor => "poor",
            AttestCondition::Broken => "broken",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "good" => Some(AttestCondition::Good),
            "fair" => Some(AttestCondition::Fair),
            "poor" => Some(AttestCondition::Poor),
            "broken" => Some(AttestCondition::Broken),
            _ => None,
        }
    }
}

/// One attestation ask, and eventually its answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// UUID.
    pub id: String,
    /// The open loan being attested.
    pub custody_id: String,
    /// The public answer link's credential. Unique, unguessable.
    pub token: String,
    pub requested_at: DateTime<Utc>,
    /// `None` until the holder answers; an attestation answers once.
    pub responded_at: Option<DateTime<Utc>>,
    /// `None` until answered. `false` is the finding a campaign exists for.
    pub has_item: Option<bool>,
    pub condition: Option<AttestCondition>,
    /// Free text from the holder ("charger is missing").
    pub note: Option<String>,
    /// Who launched the campaign.
    pub actor: String,
}

impl Attestation {
    pub fn answered(&self) -> bool {
        self.responded_at.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions_round_trip_and_junk_is_refused() {
        for c in [
            AttestCondition::Good,
            AttestCondition::Fair,
            AttestCondition::Poor,
            AttestCondition::Broken,
        ] {
            assert_eq!(AttestCondition::parse(c.as_str()), Some(c));
        }
        assert_eq!(AttestCondition::parse("exploded"), None);
    }
}
