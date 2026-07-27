//! Background jobs (`jobs`, migration 023).
//!
//! The queue is a table. A district's whole install is one binary, so there is
//! no Redis and no broker — a worker claims rows with a conditional `UPDATE`
//! and runs them. See `crate::jobs` for the runner and ARCHITECTURE.md §6 for
//! the semantics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::str_enum::str_enum;

str_enum! {
    /// Lifecycle of one job.
    pub enum JobStatus {
        #[default]
        Queued => "queued",
        Running => "running",
        Succeeded => "succeeded",
        Failed => "failed",
        Cancelled => "cancelled",
    }
    with_default
}

str_enum! {
    /// What a job does.
    ///
    /// A closed enum rather than a free string: the runner dispatches on it,
    /// and an unregistered kind sitting in the table forever is a silent
    /// backlog. Adding a kind here without registering a handler is caught by
    /// [`crate::jobs::JobRunner`]'s own test.
    ///
    /// The strings are persisted. Never change one — a queued row written by
    /// the previous release is read with it.
    pub enum JobKind {
        /// Pull the ChromeOS fleet from Google. Read-only, so it may retry.
        #[default]
        GoogleDeviceSync => "google_device_sync",
        /// Apply a planned change set. Writes to Google, so `max_attempts = 1`.
        ChangeSetCommit => "change_set_commit",
    }
    with_default
}

impl JobKind {
    /// Whether a failed job of this kind may be retried automatically.
    ///
    /// The rule is not "is it important" but **"can it write to something
    /// outside this database"**. A device sync only reads Google and writes
    /// our own rows, so re-running it converges. A change-set commit mutates a
    /// district's live fleet, and a retry could re-apply a partially-applied
    /// batch — so it is at-most-once and a human re-arms it, choosing which
    /// items to retry. ARCHITECTURE §6.3.
    pub fn default_max_attempts(&self) -> i64 {
        match self {
            JobKind::GoogleDeviceSync => 3,
            JobKind::ChangeSetCommit => 1,
        }
    }
}

/// A row of `jobs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    /// UUID.
    pub id: String,
    pub kind: JobKind,
    pub status: JobStatus,
    /// Job-kind specific JSON. The change-set id for a commit lives here
    /// rather than in a column, which is what keeps `jobs` free of a foreign
    /// key to `change_sets`.
    pub payload: serde_json::Value,
    /// Earliest time a worker may claim this. `None` means as soon as one is
    /// free.
    pub run_after: Option<DateTime<Utc>>,
    pub attempt: i64,
    pub max_attempts: i64,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Job {
    /// True when a failure leaves attempts on the clock.
    pub fn may_retry(&self) -> bool {
        self.attempt < self.max_attempts
    }

    /// True when this job has stopped moving, whatever the outcome.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            JobStatus::Succeeded | JobStatus::Failed | JobStatus::Cancelled
        )
    }
}

/// A job to enqueue. Has no `id`, no `attempt` and no timestamps — the
/// repository owns all of them, which is what stops a caller from enqueueing a
/// row that claims to have already run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewJob {
    pub kind: JobKind,
    pub payload: serde_json::Value,
    pub run_after: Option<DateTime<Utc>>,
    /// Defaults to [`JobKind::default_max_attempts`] when `None`.
    pub max_attempts: Option<i64>,
}

impl NewJob {
    /// Run as soon as a worker is free.
    pub fn now(kind: JobKind) -> Self {
        Self {
            kind,
            payload: serde_json::json!({}),
            run_after: None,
            max_attempts: None,
        }
    }

    pub fn with_payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = payload;
        self
    }

    pub fn run_after(mut self, at: DateTime<Utc>) -> Self {
        self.run_after = Some(at);
        self
    }

    /// The attempts this job should get, honouring the kind's default.
    pub fn resolved_max_attempts(&self) -> i64 {
        self.max_attempts
            .unwrap_or_else(|| self.kind.default_max_attempts())
            .max(1)
    }
}

/// Filters for listing jobs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobFilter {
    pub kind: Option<JobKind>,
    pub status: Option<JobStatus>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_strings_are_stable() {
        // These are persisted. A queued row written by the previous release is
        // read with them, so a rename is a data migration, not a refactor.
        assert_eq!(JobKind::GoogleDeviceSync.as_str(), "google_device_sync");
        assert_eq!(JobKind::ChangeSetCommit.as_str(), "change_set_commit");
        for s in ["queued", "running", "succeeded", "failed", "cancelled"] {
            assert_eq!(JobStatus::parse(s).unwrap().as_str(), s);
        }
    }

    /// The rule is "can it write outside this database", not "is it
    /// important". Getting this backwards would let a retry re-apply a
    /// partially-applied fleet-wide mutation.
    #[test]
    fn only_read_only_jobs_retry() {
        assert_eq!(JobKind::ChangeSetCommit.default_max_attempts(), 1);
        assert!(JobKind::GoogleDeviceSync.default_max_attempts() > 1);
    }

    #[test]
    fn max_attempts_defaults_per_kind_and_never_falls_below_one() {
        assert_eq!(
            NewJob::now(JobKind::ChangeSetCommit).resolved_max_attempts(),
            1
        );
        assert_eq!(
            NewJob::now(JobKind::GoogleDeviceSync).resolved_max_attempts(),
            3
        );

        // An explicit override wins...
        let capped = NewJob {
            max_attempts: Some(7),
            ..NewJob::now(JobKind::ChangeSetCommit)
        };
        assert_eq!(capped.resolved_max_attempts(), 7);

        // ...but zero or negative would mean a job no worker may ever run,
        // which is a silent backlog rather than an error.
        let zero = NewJob {
            max_attempts: Some(0),
            ..NewJob::now(JobKind::GoogleDeviceSync)
        };
        assert_eq!(zero.resolved_max_attempts(), 1);
    }

    fn job(attempt: i64, max_attempts: i64, status: JobStatus) -> Job {
        Job {
            id: "j-1".into(),
            kind: JobKind::GoogleDeviceSync,
            status,
            payload: serde_json::json!({}),
            run_after: None,
            attempt,
            max_attempts,
            started_at: None,
            finished_at: None,
            last_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn retry_budget_counts_attempts_already_spent() {
        assert!(job(0, 3, JobStatus::Failed).may_retry());
        assert!(job(2, 3, JobStatus::Failed).may_retry());
        assert!(
            !job(3, 3, JobStatus::Failed).may_retry(),
            "the third of three attempts exhausts the budget"
        );
        assert!(!job(1, 1, JobStatus::Failed).may_retry());
    }

    #[test]
    fn terminal_states_are_the_ones_a_worker_never_picks_up_again() {
        assert!(!job(0, 1, JobStatus::Queued).is_terminal());
        assert!(!job(1, 1, JobStatus::Running).is_terminal());
        assert!(job(1, 1, JobStatus::Succeeded).is_terminal());
        assert!(job(1, 1, JobStatus::Failed).is_terminal());
        assert!(job(0, 1, JobStatus::Cancelled).is_terminal());
    }
}
