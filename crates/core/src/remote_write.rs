//! The seam between committing a change set and writing to Google.
//!
//! # Why this trait exists
//!
//! [`crate::change_commit`] lives in this crate specifically so it needs no
//! Google client — that is what keeps `chalk-core` a leaf and lets the console
//! plan and commit without depending on `chalk-devices`. But a change set can
//! contain items that only Google can apply, and something has to apply them.
//!
//! So the commit path calls a `RemoteWriter` it knows nothing about.
//! `chalk-devices` implements it over the ChromeOS client; tests implement it
//! in thirty lines. The dependency arrow never reverses.
//!
//! # Per device, not per call
//!
//! The writer answers for *devices*, not for requests. Chunking — Google's
//! fifty-device ceiling, which chunk failed, which one timed out — is entirely
//! the implementation's business, because the commit loop's job is to record
//! what happened to each device, and it cannot do that if it is handed a single
//! verdict for a batch.
//!
//! # Three outcomes, never two
//!
//! [`RemoteResult`] has no boolean form. `moveDevicesToOu` is chunk-granular:
//! fifty devices share one answer, and a timeout says nothing about any of
//! them individually. Collapsing that into "failed" would tell an operator
//! their devices did not move when some of them may have — the half-applied
//! batch with no record of which rows landed that ARCHITECTURE §6.3 exists to
//! prevent. `Indeterminate` is the honest third answer, and the UI says "may
//! have applied — verify" rather than guessing.

use async_trait::async_trait;

use crate::models::device_action::ChangeStatusAction;

/// What happened to one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteResult {
    /// Google confirmed it.
    Applied,
    /// Google refused before touching anything. The device provably did not
    /// change, so re-arming this item is safe.
    Failed { message: String },
    /// The outcome is unknown — a timeout, or a failure after the request was
    /// sent. Never retried automatically; a human re-arms it.
    Indeterminate { detail: String },
}

/// One device and what happened to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOutcome {
    /// The Directory API `deviceId`, matching the item's `google_device_id`.
    pub device_id: String,
    pub result: RemoteResult,
}

impl RemoteOutcome {
    pub fn applied(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            result: RemoteResult::Applied,
        }
    }
}

/// Applies the parts of a change set that only Google can apply.
#[async_trait]
pub trait RemoteWriter: Send + Sync {
    /// Move every device into `org_unit_path`.
    async fn move_to_ou(&self, org_unit_path: &str, device_ids: &[String]) -> Vec<RemoteOutcome>;

    /// Apply one status change to every device.
    async fn change_status(
        &self,
        action: ChangeStatusAction,
        device_ids: &[String],
    ) -> Vec<RemoteOutcome>;

    /// Write one annotated metadata field to every device.
    ///
    /// `field` is Chalk's column name (`annotated_user`, `annotated_asset_id`,
    /// `annotated_location`, `notes`); an empty `value` clears the annotation
    /// in the console. A writer that does not recognize `field` must fail the
    /// devices with a message, never guess.
    async fn write_field(
        &self,
        field: &str,
        value: &str,
        device_ids: &[String],
    ) -> Vec<RemoteOutcome>;
}

/// A writer that refuses everything, with a reason an operator can act on.
///
/// This is what a deployment without Google write access gets, and it is
/// deliberately not "silently do nothing": every item comes back `failed` with
/// a message naming the missing capability, so the change set records why
/// rather than appearing to succeed.
pub struct UnavailableWriter {
    reason: String,
}

impl UnavailableWriter {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    fn refuse(&self, device_ids: &[String]) -> Vec<RemoteOutcome> {
        device_ids
            .iter()
            .map(|id| RemoteOutcome {
                device_id: id.clone(),
                result: RemoteResult::Failed {
                    message: self.reason.clone(),
                },
            })
            .collect()
    }
}

#[async_trait]
impl RemoteWriter for UnavailableWriter {
    async fn move_to_ou(&self, _org_unit_path: &str, device_ids: &[String]) -> Vec<RemoteOutcome> {
        self.refuse(device_ids)
    }

    async fn change_status(
        &self,
        _action: ChangeStatusAction,
        device_ids: &[String],
    ) -> Vec<RemoteOutcome> {
        self.refuse(device_ids)
    }

    async fn write_field(
        &self,
        _field: &str,
        _value: &str,
        device_ids: &[String],
    ) -> Vec<RemoteOutcome> {
        self.refuse(device_ids)
    }
}

#[cfg(test)]
mod tests;
