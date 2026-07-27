//! The background job runner (ARCHITECTURE.md §6).
//!
//! # Why a table and not a queue
//!
//! A district's whole install is one binary. There is no Redis to run, no
//! broker to operate, and an IT department that already runs a SIS is not
//! going to accept a second daemon. So `jobs` is the queue, a worker claims
//! rows with a conditional `UPDATE`, and the correctness argument is in
//! [`JobRepository::claim`] rather than in a lock manager.
//!
//! # Why handlers are registered rather than matched
//!
//! `chalk-core` is the leaf crate: it cannot depend on `chalk-devices`, and it
//! must not, or every crate in the workspace ends up depending on the Google
//! client. So the runner owns the loop, the claim protocol and the retry
//! policy, while **the binary supplies the handlers** through [`JobHandler`].
//!
//! ```text
//! console ──enqueue──▶ jobs ◀──claim── JobRunner ──dispatch──▶ JobHandler
//!  (JobRepository)                      (here)                 (registered
//!                                                               by the binary)
//! ```
//!
//! That indirection is what lets the console request a device sync while
//! knowing nothing about `chalk-devices`.
//!
//! # Concurrency is one
//!
//! Deliberately, in v1. SQLite has a single writer anyway, and a single worker
//! keeps the ordering of Google writes trivial to reason about. The claim
//! protocol is already safe for more than one worker — that is a property of
//! the `UPDATE`, not of the count — so raising it later is a config change and
//! not a redesign.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{Duration, Utc};

use crate::db::repository::JobRepository;
use crate::error::Result;
use crate::models::job::{Job, JobKind, JobStatus};

/// How long a `running` job may go unfinished before startup recovery decides
/// its worker is gone.
///
/// Generous on purpose: a full ChromeOS sync of a large district is minutes,
/// and the cost of sweeping a live job is worse than the cost of leaving a
/// dead one visible a little longer. This is only consulted at startup, when
/// by definition no worker of ours is running.
pub const DEFAULT_LIVENESS: Duration = Duration::minutes(30);

/// How long the worker sleeps when it finds nothing to do.
pub const DEFAULT_POLL_INTERVAL: StdDuration = StdDuration::from_secs(2);

/// Executes one kind of job.
///
/// Implemented outside `chalk-core` — by the binary that owns the dependencies
/// a given job needs. The device-sync handler lives in the CLI because that is
/// where `chalk-devices` is already a dependency.
#[async_trait]
pub trait JobHandler: Send + Sync {
    /// The kind this handles. One handler per kind.
    fn kind(&self) -> JobKind;

    /// Do the work. Returning `Err` fails the attempt; whether that is
    /// terminal depends on the job's remaining budget, which the runner owns.
    ///
    /// A handler is given the whole [`Job`] rather than just its payload so it
    /// can see `attempt` — a retry may reasonably behave differently from a
    /// first try.
    async fn run(&self, job: &Job) -> Result<()>;
}

/// What one tick of the worker did. Returned so a caller — a test, or a
/// future metrics hook — can see progress without reading the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Nothing was claimable.
    Idle,
    /// A job ran and succeeded.
    Succeeded,
    /// A job ran, failed, and has attempts left.
    Requeued,
    /// A job ran, failed, and is out of attempts.
    Failed,
    /// A job was claimable but its kind has no registered handler.
    Unhandled,
    /// Another worker won the race for the job this one selected.
    Lost,
}

/// The worker loop.
pub struct JobRunner {
    repo: Arc<dyn JobRepository>,
    handlers: HashMap<JobKind, Arc<dyn JobHandler>>,
    liveness: Duration,
    poll_interval: StdDuration,
    /// Delay applied when a failed job is returned to the queue. Fixed rather
    /// than exponential in v1: the retryable kinds are read-only syncs whose
    /// usual failure is a transient network error, and the backoff that
    /// matters for Google rate limits already lives inside the client.
    retry_delay: Duration,
}

impl JobRunner {
    pub fn new(repo: Arc<dyn JobRepository>) -> Self {
        Self {
            repo,
            handlers: HashMap::new(),
            liveness: DEFAULT_LIVENESS,
            poll_interval: DEFAULT_POLL_INTERVAL,
            retry_delay: Duration::seconds(30),
        }
    }

    /// Register a handler. A second handler for the same kind replaces the
    /// first — the registry is a map, and silently running two handlers for
    /// one job would be worse than the last-wins surprise.
    pub fn register(mut self, handler: Arc<dyn JobHandler>) -> Self {
        self.handlers.insert(handler.kind(), handler);
        self
    }

    pub fn with_poll_interval(mut self, interval: StdDuration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn with_liveness(mut self, liveness: Duration) -> Self {
        self.liveness = liveness;
        self
    }

    pub fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = delay;
        self
    }

    /// Kinds with no registered handler.
    ///
    /// A job of an unregistered kind is not an error the worker can fix: it
    /// will be claimed, found unhandled, and failed, once per attempt. Better
    /// to say so at startup than to discover it as a stalled queue.
    pub fn unhandled_kinds(&self) -> Vec<JobKind> {
        JobKind::ALL
            .iter()
            .copied()
            .filter(|k| !self.handlers.contains_key(k))
            .collect()
    }

    /// Fail every job whose worker died. Call once, before the loop starts.
    ///
    /// Returns how many were swept. See [`JobRepository::fail_abandoned`] for
    /// why these are failed rather than re-queued.
    pub async fn recover_abandoned(&self) -> Result<u64> {
        let cutoff = Utc::now() - self.liveness;
        let swept = self.repo.fail_abandoned(cutoff).await?;
        if swept > 0 {
            tracing::warn!(
                "failed {swept} job(s) left running by a previous process; they were not \
                 re-queued, because a job that writes to Google may have applied part of \
                 its work"
            );
        }
        Ok(swept)
    }

    /// Claim and run at most one job.
    ///
    /// Separate from [`run_forever`](Self::run_forever) so the whole protocol
    /// is testable without a clock or a spawned task.
    pub async fn tick(&self) -> Result<Tick> {
        let now = Utc::now();
        let Some(job) = self.repo.next_claimable(now).await? else {
            return Ok(Tick::Idle);
        };

        // Another worker may take it between the select and the claim. That is
        // the race the conditional UPDATE exists for, and losing it is normal.
        if !self.repo.claim(&job.id, now).await? {
            return Ok(Tick::Lost);
        }

        let Some(handler) = self.handlers.get(&job.kind) else {
            tracing::error!(
                "job {} is of kind {} with no registered handler",
                job.id,
                job.kind.as_str()
            );
            self.repo
                .finish(
                    &job.id,
                    JobStatus::Failed,
                    Some("no handler registered for this job kind"),
                )
                .await?;
            return Ok(Tick::Unhandled);
        };

        // Re-read: `claim` incremented `attempt`, and the retry decision below
        // depends on the value *after* this attempt was spent.
        let claimed = self.repo.get_job(&job.id).await?.unwrap_or(job);

        match handler.run(&claimed).await {
            Ok(()) => {
                self.repo
                    .finish(&claimed.id, JobStatus::Succeeded, None)
                    .await?;
                Ok(Tick::Succeeded)
            }
            Err(e) => {
                let message = e.to_string();
                if claimed.may_retry() {
                    tracing::warn!(
                        "job {} failed on attempt {} of {}, retrying: {message}",
                        claimed.id,
                        claimed.attempt,
                        claimed.max_attempts
                    );
                    self.repo
                        .requeue(&claimed.id, Some(Utc::now() + self.retry_delay), &message)
                        .await?;
                    Ok(Tick::Requeued)
                } else {
                    tracing::error!(
                        "job {} failed permanently after {} attempt(s): {message}",
                        claimed.id,
                        claimed.attempt
                    );
                    self.repo
                        .finish(&claimed.id, JobStatus::Failed, Some(&message))
                        .await?;
                    Ok(Tick::Failed)
                }
            }
        }
    }

    /// Recover, then poll forever. Intended for `tokio::spawn`.
    ///
    /// A failure inside one tick is logged and the loop continues: a worker
    /// that exits on the first database blip stops every scheduled sync in the
    /// install, which is a far worse outcome than a retried tick.
    pub async fn run_forever(self) {
        if let Err(e) = self.recover_abandoned().await {
            tracing::error!("job recovery failed at startup: {e}");
        }
        for kind in self.unhandled_kinds() {
            tracing::warn!(
                "no handler registered for job kind {} — jobs of that kind will fail",
                kind.as_str()
            );
        }

        loop {
            match self.tick().await {
                // Work found: go straight round again rather than sleeping, so
                // a backlog drains at the speed of the work and not of the
                // poll interval.
                Ok(Tick::Succeeded) | Ok(Tick::Requeued) | Ok(Tick::Failed)
                | Ok(Tick::Unhandled) | Ok(Tick::Lost) => continue,
                Ok(Tick::Idle) => {}
                Err(e) => {
                    tracing::error!("job worker tick failed: {e}");
                }
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

#[cfg(test)]
mod tests;
