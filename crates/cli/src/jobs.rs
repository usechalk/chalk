//! Job handlers, and the runner the server spawns.
//!
//! Handlers live here rather than in `chalk-core` because this is the crate
//! that already depends on `chalk-devices`. `chalk-core` is the leaf and must
//! stay that way — if the runner matched on job kind itself, every crate in
//! the workspace would inherit a dependency on the Google client.
//!
//! The payoff is that `chalk-console` needs none of it. The console enqueues a
//! row through `JobRepository`, and this module is what turns that row into
//! work.

use std::sync::Arc;

use async_trait::async_trait;
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::JobRepository;
use chalk_core::error::{ChalkError, Result};
use chalk_core::jobs::{JobHandler, JobRunner};
use chalk_core::models::job::{Job, JobKind};
use tracing::info;

use crate::commands::devices::{build_engine, DeviceSyncRepos};

/// Runs a ChromeOS device sync.
///
/// Read-only against Google, which is why [`JobKind::GoogleDeviceSync`] is
/// allowed more than one attempt: re-running it converges rather than
/// double-applying anything.
pub struct DeviceSyncHandler {
    config: ChalkConfig,
    repos: DeviceSyncRepos,
}

impl DeviceSyncHandler {
    pub fn new(config: ChalkConfig, repos: DeviceSyncRepos) -> Arc<Self> {
        Arc::new(Self { config, repos })
    }
}

#[async_trait]
impl JobHandler for DeviceSyncHandler {
    fn kind(&self) -> JobKind {
        JobKind::GoogleDeviceSync
    }

    async fn run(&self, job: &Job) -> Result<()> {
        // Refused here rather than at enqueue time. A district can disable
        // device sync between a job being queued and a worker reaching it —
        // by turning the module off, or by restarting into a changed config —
        // and running anyway would be ignoring the operator's most recent
        // instruction.
        if !self.config.device_sync.enabled {
            return Err(ChalkError::Sync(
                "device sync is disabled in configuration".into(),
            ));
        }

        // A dry run plans without writing, matching `chalk devices sync
        // --dry-run`. Absent or malformed, it is a real run: defaulting a
        // *write* to "pretend" would silently do nothing on a job an operator
        // asked for.
        let dry_run = job
            .payload
            .get("dryRun")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        info!(
            job_id = job.id,
            attempt = job.attempt,
            dry_run,
            "running ChromeOS device sync from a job"
        );

        let engine = build_engine(&self.config, self.repos.clone())
            .map_err(|e| ChalkError::Sync(format!("could not build the device sync: {e}")))?;

        let summary = engine.run_sync(dry_run).await?;
        let c = summary.counters;
        info!(
            job_id = job.id,
            seen = c.devices_seen,
            created = c.devices_created,
            updated = c.devices_updated,
            matched = c.devices_matched,
            unmatched = c.devices_unmatched,
            api_calls = c.api_calls,
            throttled = c.throttle_events,
            "ChromeOS device sync finished"
        );
        Ok(())
    }
}

/// Build the runner `chalk serve` spawns.
///
/// Every handler this binary can supply is registered here, so
/// `unhandled_kinds()` is an honest answer at startup rather than a discovery
/// made when a queue stops draining.
///
/// `ChangeSetCommit` has no handler yet — write-back does not exist — and the
/// runner logs that at startup rather than pretending otherwise. Nothing
/// enqueues one, so the queue cannot stall on it today.
pub fn build_runner(
    config: ChalkConfig,
    jobs: Arc<dyn JobRepository>,
    repos: DeviceSyncRepos,
) -> JobRunner {
    JobRunner::new(jobs).register(DeviceSyncHandler::new(config, repos))
}
