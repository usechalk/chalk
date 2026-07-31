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
use chalk_core::change_commit::commit_change_set;
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{ChangeSetRepository, JobRepository, TenantConfigRepo};
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
    /// Sealed per-tenant configuration, when the install has a master key.
    ///
    /// Checked **before** the TOML path. A credential saved through the console
    /// is the operator's most recent instruction, and a stale path left in
    /// chalk.toml must not quietly win over the key they just uploaded.
    tenant_config: Option<Arc<dyn TenantConfigRepo>>,
}

impl DeviceSyncHandler {
    pub fn new(
        config: ChalkConfig,
        repos: DeviceSyncRepos,
        tenant_config: Option<Arc<dyn TenantConfigRepo>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            repos,
            tenant_config,
        })
    }

    /// Resolve the effective device-sync settings.
    ///
    /// Returns the config to run with, plus a temporary directory holding the
    /// materialised key when it came from the database. The directory is
    /// returned rather than dropped so the file outlives the call — the token
    /// source reads it lazily, and a key deleted before first use produces a
    /// baffling "no such file" from inside Google's client.
    async fn resolve(&self) -> Result<(ChalkConfig, Option<tempfile::TempDir>)> {
        let Some(repo) = &self.tenant_config else {
            return Ok((self.config.clone(), None));
        };
        let Some(stored) = repo.get_device_config().await? else {
            return Ok((self.config.clone(), None));
        };

        let mut config = self.config.clone();
        if !stored.enabled {
            // The database is the newer source, so a module disabled there is
            // disabled — even if TOML still says otherwise.
            config.device_sync.enabled = false;
            return Ok((config, None));
        }
        config.device_sync.enabled = true;
        if let Some(v) = stored.customer_id {
            config.device_sync.customer_id = v;
        }
        if stored.admin_email.is_some() {
            config.device_sync.admin_email = stored.admin_email;
        }
        if let Some(v) = stored.page_size {
            config.device_sync.page_size = v.clamp(1, 300) as u32;
        }
        if let Some(v) = stored.requests_per_minute {
            config.device_sync.requests_per_minute = v.max(1) as u32;
        }

        let mut held = None;
        if let Some(key) = stored.service_account_key {
            let dir = tempfile::tempdir().map_err(|e| {
                ChalkError::Sync(format!("could not materialise the stored key: {e}"))
            })?;
            let path = dir.path().join("service-account.json");
            std::fs::write(&path, &key).map_err(|e| {
                ChalkError::Sync(format!("could not materialise the stored key: {e}"))
            })?;
            config.device_sync.service_account_key_path = Some(path.to_string_lossy().into_owned());
            held = Some(dir);
        }
        Ok((config, held))
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
        // Resolved per run, not captured at startup: an operator who connects
        // Google through the console expects the next sync to use it, without
        // restarting the server.
        let (config, _key_dir) = self.resolve().await?;

        if !config.device_sync.enabled {
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

        let engine = build_engine(&config, self.repos.clone())
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

/// Applies a planned change set.
///
/// Registering this is what fills the `change_set_commit` kind the runner
/// previously reported as unhandled at startup. It writes to a district's
/// records, so `max_attempts` is 1: a failed commit is re-armed by a person
/// through `chalk jobs retry`, never by the runner.
pub struct ChangeSetCommitHandler {
    sets: Arc<dyn ChangeSetRepository>,
}

impl ChangeSetCommitHandler {
    pub fn new(sets: Arc<dyn ChangeSetRepository>) -> Arc<Self> {
        Arc::new(Self { sets })
    }
}

#[async_trait]
impl JobHandler for ChangeSetCommitHandler {
    fn kind(&self) -> JobKind {
        JobKind::ChangeSetCommit
    }

    async fn run(&self, job: &Job) -> Result<()> {
        // The payload carries the hash and count the operator's preview was
        // built from, not just the id — so a set whose rows drifted between
        // preview and worker is refused rather than applied.
        let id = job
            .payload
            .get("changeSetId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChalkError::Sync("commit job has no changeSetId".into()))?;
        let plan_hash = job
            .payload
            .get("planHash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChalkError::Sync("commit job has no planHash".into()))?;
        let expected = job
            .payload
            .get("expectedItemCount")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| ChalkError::Sync("commit job has no expectedItemCount".into()))?;

        info!(job_id = job.id, change_set = id, "committing change set");

        match commit_change_set(&self.sets, id, plan_hash, expected, COMMIT_ACTOR).await? {
            Ok(outcome) => {
                info!(
                    change_set = id,
                    applied = outcome.applied,
                    skipped = outcome.skipped,
                    deferred = outcome.deferred,
                    failed = outcome.failed,
                    "change set committed"
                );
                // A per-item failure is not a job failure: the outcome is
                // recorded on each row, and re-running the whole job would
                // re-apply everything that already worked.
                Ok(())
            }
            // Refusals are surfaced as job failures so they appear in
            // `chalk jobs list` with a reason, rather than a job that
            // "succeeded" while changing nothing.
            Err(refusal) => Err(ChalkError::Sync(format!(
                "change set {id} was not applied: {refusal:?}"
            ))),
        }
    }
}

/// Matches the actor the console writes elsewhere, so history reads
/// consistently whoever initiated the change.
const COMMIT_ACTOR: &str = "console:admin";

/// Build the runner `chalk serve` spawns.
///
/// Every handler this binary can supply is registered here, so
/// `unhandled_kinds()` is an honest answer at startup rather than a discovery
/// made when a queue stops draining.
///
/// Every `JobKind` now has a handler, so `unhandled_kinds()` is empty at
/// startup — which is the state it should be in, and the reason that method
/// exists.
pub fn build_runner(
    config: ChalkConfig,
    jobs: Arc<dyn JobRepository>,
    repos: DeviceSyncRepos,
    tenant_config: Option<Arc<dyn TenantConfigRepo>>,
    change_sets: Arc<dyn ChangeSetRepository>,
) -> JobRunner {
    JobRunner::new(jobs)
        .register(DeviceSyncHandler::new(config, repos, tenant_config))
        .register(ChangeSetCommitHandler::new(change_sets))
}
