//! Device actions an operator can ask for, and the reasons they carry.
//!
//! # Why these live in core rather than beside the Google client
//!
//! Three places need them and only one of those may depend on
//! `chalk-google-sync`: the change-set planner, the commit path
//! (`change_commit`, which is in this crate precisely so it needs no Google
//! client), and the console's typed-confirmation form. Google's *wire*
//! constants stay with the Google client — that mapping is Google's business,
//! not the domain's.
//!
//! # A deprovision cannot lose its reason
//!
//! Google rejects a deprovision without one, so the reason travels inside the
//! [`ChangeStatusAction::Deprovision`] variant rather than beside it as an
//! `Option`. The invalid state is not representable, which is stronger than
//! validating for it.

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Why a device is being deprovisioned.
///
/// Google **requires** a reason when the action is deprovision, so the reason
/// travels inside the [`ChangeStatusAction::Deprovision`] variant rather than
/// beside it as an `Option` — a deprovision without one is not representable.
///
/// Only the four reasons a district can legitimately choose are modelled.
/// Google's enum also carries `UNSPECIFIED`, four values marked deprecated
/// (`UPGRADE`, `DOMAIN_MOVE`, `SERVICE_EXPIRATION`, `OTHER`), `NOT_REQUIRED`,
/// and `REPAIR_CENTER` — the last settable only by a repair centre during an
/// RMA. Offering any of those would be offering a choice that fails or means
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeprovisionReason {
    /// RMA or warranty swap for the same model.
    SameModelReplacement,
    /// Replaced with an upgraded or newer model.
    DifferentModelReplacement,
    /// Donated, discarded, or otherwise removed from the fleet.
    RetiringDevice,
    /// A ChromeOS Flex device being replaced with a Chromebook within a year.
    UpgradeTransfer,
}

impl DeprovisionReason {
    /// The stable short value stored in a change set and posted by a form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SameModelReplacement => "same_model_replacement",
            Self::DifferentModelReplacement => "different_model_replacement",
            Self::RetiringDevice => "retiring_device",
            Self::UpgradeTransfer => "upgrade_transfer",
        }
    }

    /// Wording an operator picks from. Google's own phrasing, shortened.
    pub fn label(&self) -> &'static str {
        match self {
            Self::SameModelReplacement => "Replacing with the same model (RMA or warranty)",
            Self::DifferentModelReplacement => "Replacing with a different or newer model",
            Self::RetiringDevice => "Retiring from the fleet (donated or discarded)",
            Self::UpgradeTransfer => "ChromeOS Flex device replaced by a Chromebook",
        }
    }

    /// Every reason, in the order the confirmation form offers them.
    pub const ALL: &'static [DeprovisionReason] = &[
        Self::RetiringDevice,
        Self::SameModelReplacement,
        Self::DifferentModelReplacement,
        Self::UpgradeTransfer,
    ];

    pub fn parse(raw: &str) -> Result<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|r| r.as_str() == raw)
            .ok_or_else(|| {
                crate::error::ChalkError::Sync(format!("{raw:?} is not a deprovision reason"))
            })
    }
}

/// A status change to apply to a batch of devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeStatusAction {
    /// Release the licence and remove the device from management. The reason
    /// is carried here because Google rejects a deprovision without one.
    Deprovision(DeprovisionReason),
    /// Block the device from signing in, reversibly.
    Disable,
    /// Undo a disable.
    Reenable,
}

impl ChangeStatusAction {
    /// True when this cannot be undone from Chalk. Deprovision returns the
    /// licence; re-enrolling is a physical act at the device.
    pub fn is_destructive(&self) -> bool {
        matches!(self, Self::Deprovision(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only reasons a district can legitimately pick are offered. Google's enum
    /// also carries `UNSPECIFIED`, four deprecated values, `NOT_REQUIRED`, and
    /// `REPAIR_CENTER` — the last settable only by a repair centre during an
    /// RMA. Offering any of them is offering a choice that fails or means
    /// nothing, and this is the list a confirmation form renders from.
    #[test]
    fn every_offered_reason_round_trips_and_reads_as_a_sentence() {
        assert_eq!(DeprovisionReason::ALL.len(), 4);
        for r in DeprovisionReason::ALL {
            assert_eq!(
                DeprovisionReason::parse(r.as_str()).unwrap(),
                *r,
                "{} does not round trip",
                r.as_str()
            );
            assert!(
                r.label().len() > 20,
                "{} needs wording an operator can choose between, not a token",
                r.as_str()
            );
        }
    }

    /// A stored value that is not a reason is refused rather than defaulted.
    /// Defaulting would let a hand-edited change set deprovision devices under
    /// a reason nobody chose.
    #[test]
    fn an_unknown_reason_is_refused_rather_than_defaulted() {
        assert!(DeprovisionReason::parse("").is_err());
        assert!(DeprovisionReason::parse("retiring").is_err());
        assert!(DeprovisionReason::parse("DEPROVISION_REASON_OTHER").is_err());
    }

    /// The type makes the invalid state unrepresentable: there is no way to
    /// build a deprovision without the reason Google requires.
    #[test]
    fn only_a_deprovision_is_destructive_and_it_always_carries_a_reason() {
        let d = ChangeStatusAction::Deprovision(DeprovisionReason::RetiringDevice);
        assert!(
            d.is_destructive(),
            "a released licence is not undoable here"
        );
        assert!(!ChangeStatusAction::Disable.is_destructive());
        assert!(!ChangeStatusAction::Reenable.is_destructive());

        match d {
            ChangeStatusAction::Deprovision(r) => {
                assert_eq!(r, DeprovisionReason::RetiringDevice)
            }
            _ => panic!("wrong variant"),
        }
    }
}
