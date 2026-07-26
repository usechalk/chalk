//! Diff-preview-then-commit staging (migration 022).
//!
//! Google write-back, CSV re-import and bulk edits all compile to the same
//! two-phase object: **plan** (pure read, insert `change_sets` +
//! `change_set_items`), **preview** (render, exclude items), **commit** (apply
//! item by item, persisting each outcome before the next remote call).
//!
//! Two things here are not in ARCHITECTURE §4.7 as originally written, and
//! both are load-bearing:
//!
//! 1. [`ChangeSet::plan_hash`] and [`ChangeSet::expected_item_count`] are
//!    columns, not `summary` JSON keys, because the commit path compares them
//!    against the live plan to reject a stale commit.
//! 2. `change_sets.status` has no `partial` value. §6.3 assumed a crashed
//!    process would write one — nothing can, and there is no sweeper. Display
//!    status is *derived* at read time from item counts
//!    ([`ChangeSetProgress::display_status`]), and a `committing` row past a
//!    liveness window reports as [`ChangeSetDisplayStatus::Interrupted`].

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::str_enum::str_enum;

/// How long a `committing` change set may go without reaching `committed`
/// before it is displayed as interrupted. Matches the job-claim liveness
/// window in ARCHITECTURE §6.2.
pub const COMMIT_LIVENESS_WINDOW_MINUTES: i64 = 30;

str_enum! {
    /// Which entry point produced this change set.
    pub enum ChangeSetKind {
        GoogleWriteback => "google_writeback",
        CsvImport => "csv_import",
        BulkEdit => "bulk_edit",
    }
}

str_enum! {
    /// Stored status. See the module docs for why `partial` is absent.
    pub enum ChangeSetStatus {
        /// The plan exists, nothing has been touched.
        #[default]
        Planned => "planned",
        /// A commit has claimed this set.
        Committing => "committing",
        /// The commit loop ran to completion. Individual items may still be
        /// `failed` or `indeterminate`.
        Committed => "committed",
        /// Abandoned without committing.
        Discarded => "discarded",
    }
    with_default
}

str_enum! {
    /// Per-item outcome. Four states, not two.
    pub enum ChangeSetItemStatus {
        /// Not yet attempted.
        #[default]
        Pending => "pending",
        /// Confirmed applied. `applied_at` is set.
        Applied => "applied",
        /// Confirmed NOT applied. Safe to retry.
        Failed => "failed",
        /// The remote call's outcome is unknown, so the UI says "may have
        /// applied — verify" rather than "failed". This exists because
        /// `moveDevicesToOu` is chunk-granular: 50 items share one outcome and
        /// a chunk timeout says nothing about any individual device.
        Indeterminate => "indeterminate",
        /// Excluded by the operator at preview time.
        Skipped => "skipped",
    }
    with_default
}

impl ChangeSetItemStatus {
    /// Statuses a "retry failed items" pass re-arms. `Applied` is excluded
    /// (already done) and so is `Skipped` (a human said no).
    pub const RETRYABLE: &'static [ChangeSetItemStatus] = &[
        ChangeSetItemStatus::Pending,
        ChangeSetItemStatus::Failed,
        ChangeSetItemStatus::Indeterminate,
    ];

    /// True when the item has reached a state the commit loop will not revisit.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ChangeSetItemStatus::Applied | ChangeSetItemStatus::Skipped
        )
    }

    pub fn is_retryable(&self) -> bool {
        Self::RETRYABLE.contains(self)
    }
}

str_enum! {
    /// The operation an item performs.
    pub enum ChangeSetOp {
        UpdateField => "update_field",
        MoveOu => "move_ou",
        ChangeStatus => "change_status",
        Create => "create",
        Assign => "assign",
        Unassign => "unassign",
    }
}

str_enum! {
    /// Whether applying the item requires a remote call.
    pub enum RemoteTarget {
        /// Writes to the Google Admin SDK. At-most-once, no auto-retry.
        Google => "google",
        /// Local database only. Safe inside a transaction.
        #[default]
        Local => "local",
    }
    with_default
}

/// A row of `change_sets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeSet {
    /// UUID.
    pub id: String,
    pub kind: ChangeSetKind,
    pub status: ChangeSetStatus,
    /// `users.sourced_id` or an API token prefix.
    pub created_by: String,
    /// Hash over the planned items, compared at commit time.
    pub plan_hash: String,
    /// Item count at plan time, compared at commit time.
    pub expected_item_count: i64,
    /// JSON: counts per op type, source file hash, etc.
    pub summary: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub committed_at: Option<DateTime<Utc>>,
}

impl ChangeSet {
    /// A freshly planned change set.
    pub fn planned(
        id: impl Into<String>,
        kind: ChangeSetKind,
        created_by: impl Into<String>,
        plan_hash: impl Into<String>,
        expected_item_count: i64,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            status: ChangeSetStatus::Planned,
            created_by: created_by.into(),
            plan_hash: plan_hash.into(),
            expected_item_count,
            summary: serde_json::json!({}),
            created_at: Utc::now(),
            committed_at: None,
        }
    }

    /// True when this set was claimed for commit and never finished within the
    /// liveness window. Such a set is reported as interrupted and is **never**
    /// auto-resumed: per-item truth already records what landed, and a retry
    /// is an explicit human re-arm.
    pub fn is_interrupted(&self, now: DateTime<Utc>) -> bool {
        self.status == ChangeSetStatus::Committing
            && self.committed_at.is_none()
            && now - self.created_at > Duration::minutes(COMMIT_LIVENESS_WINDOW_MINUTES)
    }
}

/// A change set item to insert. No `id` — the database assigns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewChangeSetItem {
    /// `None` for a `Create` op, which has no asset yet.
    pub asset_id: Option<String>,
    /// Denormalized asset identity (serial or tag). Survives `asset_id` being
    /// nulled by `ON DELETE SET NULL`, which would otherwise destroy the audit
    /// truth of an already-applied item.
    pub target_ref: Option<String>,
    /// Denormalized Directory API `deviceId`, for the same reason.
    pub google_device_id: Option<String>,
    pub op: ChangeSetOp,
    pub field: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub remote_target: RemoteTarget,
}

impl NewChangeSetItem {
    /// A local field update on an existing asset.
    pub fn update_field(
        asset_id: impl Into<String>,
        field: impl Into<String>,
        old_value: Option<String>,
        new_value: Option<String>,
    ) -> Self {
        Self {
            asset_id: Some(asset_id.into()),
            target_ref: None,
            google_device_id: None,
            op: ChangeSetOp::UpdateField,
            field: Some(field.into()),
            old_value,
            new_value,
            remote_target: RemoteTarget::Local,
        }
    }

    /// An OU move, which always writes to Google.
    pub fn move_ou(
        asset_id: impl Into<String>,
        google_device_id: impl Into<String>,
        old_path: Option<String>,
        new_path: impl Into<String>,
    ) -> Self {
        Self {
            asset_id: Some(asset_id.into()),
            target_ref: None,
            google_device_id: Some(google_device_id.into()),
            op: ChangeSetOp::MoveOu,
            field: Some("org_unit_path".to_string()),
            old_value: old_path,
            new_value: Some(new_path.into()),
            remote_target: RemoteTarget::Google,
        }
    }
}

/// A row of `change_set_items`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeSetItem {
    pub id: i64,
    pub change_set_id: String,
    pub asset_id: Option<String>,
    pub target_ref: Option<String>,
    pub google_device_id: Option<String>,
    pub op: ChangeSetOp,
    pub field: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub remote_target: RemoteTarget,
    pub status: ChangeSetItemStatus,
    pub error: Option<String>,
    pub applied_at: Option<DateTime<Utc>>,
}

/// Filters for listing change sets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ChangeSetFilter {
    pub kind: Option<ChangeSetKind>,
    pub status: Option<ChangeSetStatus>,
    pub created_by: Option<String>,
}

/// Item counts for one change set, grouped by status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ChangeSetProgress {
    pub pending: i64,
    pub applied: i64,
    pub failed: i64,
    pub indeterminate: i64,
    pub skipped: i64,
}

impl ChangeSetProgress {
    pub fn total(&self) -> i64 {
        self.pending + self.applied + self.failed + self.indeterminate + self.skipped
    }

    /// Items a retry pass would re-arm.
    pub fn retryable(&self) -> i64 {
        self.pending + self.failed + self.indeterminate
    }

    /// Add one item's status to the tally.
    pub fn record(&mut self, status: ChangeSetItemStatus) {
        match status {
            ChangeSetItemStatus::Pending => self.pending += 1,
            ChangeSetItemStatus::Applied => self.applied += 1,
            ChangeSetItemStatus::Failed => self.failed += 1,
            ChangeSetItemStatus::Indeterminate => self.indeterminate += 1,
            ChangeSetItemStatus::Skipped => self.skipped += 1,
        }
    }

    /// The status to show a human, derived from the stored status plus these
    /// counts. This is the *only* place `Partial` comes from — the column
    /// never holds it.
    pub fn display_status(&self, set: &ChangeSet, now: DateTime<Utc>) -> ChangeSetDisplayStatus {
        match set.status {
            ChangeSetStatus::Planned => ChangeSetDisplayStatus::Planned,
            ChangeSetStatus::Discarded => ChangeSetDisplayStatus::Discarded,
            ChangeSetStatus::Committing => {
                if set.is_interrupted(now) {
                    ChangeSetDisplayStatus::Interrupted
                } else {
                    ChangeSetDisplayStatus::Committing
                }
            }
            ChangeSetStatus::Committed => {
                if self.failed > 0 || self.indeterminate > 0 || self.pending > 0 {
                    ChangeSetDisplayStatus::Partial
                } else {
                    ChangeSetDisplayStatus::Committed
                }
            }
        }
    }
}

/// What the console shows. Derived, never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeSetDisplayStatus {
    Planned,
    Committing,
    Committed,
    /// Committed, but some items failed, are indeterminate, or never ran.
    Partial,
    /// Claimed for commit and never finished within the liveness window. Never
    /// auto-resumed.
    Interrupted,
    Discarded,
}

/// Outcome of claiming a change set for commit.
///
/// Returned by
/// [`ChangeSetRepository::claim_for_commit`](crate::db::repository::ChangeSetRepository::claim_for_commit),
/// which is a conditional `UPDATE` — exactly one caller can win.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "outcome")]
pub enum CommitClaim {
    /// This caller owns the commit.
    Claimed,
    /// No change set with that id.
    NotFound,
    /// Already `committing`, `committed` or `discarded`.
    NotPlanned { status: ChangeSetStatus },
    /// The plan changed underneath the preview the operator approved. The
    /// commit is refused rather than applying a diff nobody looked at.
    Stale {
        expected_plan_hash: String,
        actual_plan_hash: String,
        expected_item_count: i64,
        actual_item_count: i64,
    },
}

impl CommitClaim {
    pub fn is_claimed(&self) -> bool {
        matches!(self, CommitClaim::Claimed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_with(status: ChangeSetStatus, created_at: DateTime<Utc>) -> ChangeSet {
        let mut s = ChangeSet::planned("cs-1", ChangeSetKind::GoogleWriteback, "user-1", "h", 3);
        s.status = status;
        s.created_at = created_at;
        s
    }

    #[test]
    fn every_enum_round_trips() {
        for v in ChangeSetKind::ALL {
            assert_eq!(&ChangeSetKind::parse(v.as_str()).unwrap(), v);
        }
        for v in ChangeSetStatus::ALL {
            assert_eq!(&ChangeSetStatus::parse(v.as_str()).unwrap(), v);
        }
        for v in ChangeSetItemStatus::ALL {
            assert_eq!(&ChangeSetItemStatus::parse(v.as_str()).unwrap(), v);
        }
        for v in ChangeSetOp::ALL {
            assert_eq!(&ChangeSetOp::parse(v.as_str()).unwrap(), v);
        }
        for v in RemoteTarget::ALL {
            assert_eq!(&RemoteTarget::parse(v.as_str()).unwrap(), v);
        }
    }

    #[test]
    fn stored_status_has_no_partial_value() {
        assert!(
            ChangeSetStatus::parse("partial").is_err(),
            "partial is a derived display status only — nothing may write it"
        );
        assert!(!ChangeSetStatus::ALL.iter().any(|s| s.as_str() == "partial"));
    }

    #[test]
    fn item_status_keeps_the_ambiguous_case() {
        assert_eq!(ChangeSetItemStatus::Indeterminate.as_str(), "indeterminate");
        assert!(ChangeSetItemStatus::Indeterminate.is_retryable());
        assert!(!ChangeSetItemStatus::Indeterminate.is_terminal());
    }

    #[test]
    fn retryable_excludes_applied_and_skipped() {
        assert!(!ChangeSetItemStatus::Applied.is_retryable());
        assert!(!ChangeSetItemStatus::Skipped.is_retryable());
        assert!(ChangeSetItemStatus::Pending.is_retryable());
        assert!(ChangeSetItemStatus::Failed.is_retryable());
    }

    #[test]
    fn progress_tallies_and_totals() {
        let mut p = ChangeSetProgress::default();
        for s in [
            ChangeSetItemStatus::Applied,
            ChangeSetItemStatus::Applied,
            ChangeSetItemStatus::Failed,
            ChangeSetItemStatus::Indeterminate,
            ChangeSetItemStatus::Skipped,
            ChangeSetItemStatus::Pending,
        ] {
            p.record(s);
        }
        assert_eq!(p.total(), 6);
        assert_eq!(p.applied, 2);
        assert_eq!(p.retryable(), 3);
    }

    #[test]
    fn committed_with_clean_items_displays_committed() {
        let set = set_with(ChangeSetStatus::Committed, Utc::now());
        let p = ChangeSetProgress {
            applied: 5,
            skipped: 1,
            ..Default::default()
        };
        assert_eq!(
            p.display_status(&set, Utc::now()),
            ChangeSetDisplayStatus::Committed
        );
    }

    #[test]
    fn committed_with_failures_displays_partial() {
        let set = set_with(ChangeSetStatus::Committed, Utc::now());
        for p in [
            ChangeSetProgress {
                applied: 5,
                failed: 1,
                ..Default::default()
            },
            ChangeSetProgress {
                applied: 5,
                indeterminate: 1,
                ..Default::default()
            },
            ChangeSetProgress {
                applied: 5,
                pending: 1,
                ..Default::default()
            },
        ] {
            assert_eq!(
                p.display_status(&set, Utc::now()),
                ChangeSetDisplayStatus::Partial
            );
        }
    }

    #[test]
    fn committing_within_the_window_is_not_interrupted() {
        let now = Utc::now();
        let set = set_with(ChangeSetStatus::Committing, now - Duration::minutes(5));
        assert!(!set.is_interrupted(now));
        assert_eq!(
            ChangeSetProgress::default().display_status(&set, now),
            ChangeSetDisplayStatus::Committing
        );
    }

    #[test]
    fn committing_past_the_window_is_interrupted() {
        let now = Utc::now();
        let set = set_with(
            ChangeSetStatus::Committing,
            now - Duration::minutes(COMMIT_LIVENESS_WINDOW_MINUTES + 1),
        );
        assert!(set.is_interrupted(now));
        assert_eq!(
            ChangeSetProgress::default().display_status(&set, now),
            ChangeSetDisplayStatus::Interrupted
        );
    }

    #[test]
    fn a_committed_set_is_never_interrupted() {
        let now = Utc::now();
        let mut set = set_with(ChangeSetStatus::Committed, now - Duration::days(7));
        set.committed_at = Some(now - Duration::days(7));
        assert!(!set.is_interrupted(now));
    }

    #[test]
    fn move_ou_items_target_google() {
        let item = NewChangeSetItem::move_ou("a-1", "dev-1", Some("/old".into()), "/new");
        assert_eq!(item.remote_target, RemoteTarget::Google);
        assert_eq!(item.google_device_id.as_deref(), Some("dev-1"));
        assert_eq!(item.op, ChangeSetOp::MoveOu);
    }

    #[test]
    fn update_field_items_stay_local() {
        let item = NewChangeSetItem::update_field("a-1", "notes", None, Some("hi".into()));
        assert_eq!(item.remote_target, RemoteTarget::Local);
    }

    #[test]
    fn commit_claim_reports_staleness_detail() {
        let claim = CommitClaim::Stale {
            expected_plan_hash: "a".into(),
            actual_plan_hash: "b".into(),
            expected_item_count: 3,
            actual_item_count: 4,
        };
        assert!(!claim.is_claimed());
        assert!(CommitClaim::Claimed.is_claimed());
    }
}
