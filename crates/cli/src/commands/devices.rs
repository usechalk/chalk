//! `chalk devices sync` — pull the ChromeOS fleet into the asset inventory.
//!
//! Read-only against Google. The scopes requested are the `.readonly` variants
//! in [`chalk_google_sync::token::DEVICE_SYNC_READ_SCOPES`], and the client
//! this builds has no write method to call.

use std::path::Path;
use std::sync::Arc;

use chalk_core::config::ChalkConfig;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_devices::sync::DeviceSyncEngine;
use chalk_google_sync::chromeos::ChromeOsClient;
use chalk_google_sync::token::{GoogleTokenSource, DEVICE_SYNC_READ_SCOPES};
use tracing::info;

use super::common;

/// Assemble a device-sync engine from config and a repository.
///
/// Shared by `chalk devices sync` and by the background job handler, so the
/// two cannot drift on scopes, page size, rate limit or the `[google_sync]`
/// credential fallback — a CLI sync and a console-triggered sync must be the
/// same operation, not two that resemble each other.
/// The four repositories the engine needs, as trait objects.
///
/// A tuple rather than `Arc<SqliteRepository>` so the same builder serves
/// `chalk serve` on Postgres as well as the SQLite-only CLI. They are always
/// the same concrete object in practice — four traits, one store.
pub type DeviceSyncRepos = (
    Arc<dyn chalk_core::db::repository::AssetRepository>,
    Arc<dyn chalk_core::db::repository::AssetEventRepository>,
    Arc<dyn chalk_core::db::repository::GoogleDeviceSyncRepository>,
    Arc<dyn chalk_core::db::repository::UserRepository>,
);

pub fn build_engine(
    config: &ChalkConfig,
    repos: DeviceSyncRepos,
) -> anyhow::Result<DeviceSyncEngine> {
    let devices = &config.device_sync;
    let key_path = devices
        .resolved_key_path(&config.google_sync)
        .ok_or_else(|| anyhow::anyhow!("device_sync.service_account_key_path not configured"))?;
    let admin_email = devices
        .resolved_admin_email(&config.google_sync)
        .ok_or_else(|| anyhow::anyhow!("device_sync.admin_email not configured"))?;

    let auth = GoogleTokenSource::from_service_account_file(
        key_path,
        admin_email,
        DEVICE_SYNC_READ_SCOPES,
    )?
    .into_shared();

    let client = ChromeOsClient::new(auth, &devices.customer_id)
        .with_max_results(devices.page_size)
        .with_rate_limiter(chalk_google_sync::backoff::RateLimiter::per_minute(
            devices.requests_per_minute,
        ));

    // The engine reads the Workspace domain off its own config, so resolve the
    // `[google_sync]` fallback into the copy it receives.
    let mut engine_config = devices.clone();
    engine_config.workspace_domain = devices
        .resolved_workspace_domain(&config.google_sync)
        .map(str::to_string);

    let (assets, events, state, roster) = repos;
    Ok(DeviceSyncEngine::new(
        assets,
        events,
        state,
        roster,
        client,
        engine_config,
    ))
}

/// Run `chalk devices sync`.
pub async fn sync(config_path: &str, dry_run: bool) -> anyhow::Result<()> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    config.validate()?;

    if !config.device_sync.enabled {
        anyhow::bail!(
            "Device sync is not enabled in configuration. Set device_sync.enabled = true."
        );
    }

    common::assert_sqlite_only(&config.chalk.database.driver)?;

    let path = config
        .chalk
        .database
        .path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SQLite path not configured"))?;
    let pool = DatabasePool::new_sqlite(&format!("sqlite:{path}?mode=rwc")).await?;
    let repo = Arc::new(SqliteRepository::new(common::unwrap_sqlite_pool(pool)?));

    // Credential resolution now lives in `build_engine`, which the job handler
    // shares. Read here only for the log line.
    let devices = &config.device_sync;
    info!(
        admin_email = devices
            .resolved_admin_email(&config.google_sync)
            .unwrap_or("<unset>"),
        customer_id = devices.customer_id,
        page_size = devices.page_size,
        dry_run,
        "Starting ChromeOS device sync"
    );

    let engine = build_engine(&config, (repo.clone(), repo.clone(), repo.clone(), repo))?;

    let summary = engine.run_sync(dry_run).await?;
    let counters = summary.counters;

    println!(
        "ChromeOS device sync {}!",
        if dry_run { "preview" } else { "completed" }
    );
    println!("  Devices seen:      {}", counters.devices_seen);
    println!("  Devices created:   {}", counters.devices_created);
    println!("  Devices updated:   {}", counters.devices_updated);
    println!("  Matched to users:  {}", counters.devices_matched);
    println!("  Needing a person:  {}", counters.devices_unmatched);
    println!("  Google API calls:  {}", counters.api_calls);
    if counters.throttle_events > 0 {
        println!("  Throttled:         {}", counters.throttle_events);
    }
    if dry_run {
        println!();
        println!("This was a dry run. Nothing was written to the inventory.");
        println!("Run `chalk devices sync` without --dry-run to apply it.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn devices_sync_requires_a_config_file() {
        assert!(sync("/nonexistent/chalk.toml", true).await.is_err());
    }

    #[tokio::test]
    async fn devices_sync_refuses_when_the_module_is_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chalk.toml");
        std::fs::write(
            &path,
            "[chalk]\ninstance_name = \"Test\"\ndata_dir = \"/tmp/chalk-test\"\n",
        )
        .unwrap();

        let err = sync(path.to_str().unwrap(), true).await.unwrap_err();
        assert!(err.to_string().contains("device_sync.enabled"));
    }
}
