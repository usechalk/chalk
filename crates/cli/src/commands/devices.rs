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
use chalk_google_sync::token::{device_sync_scopes, GoogleTokenSource};
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

/// A ChromeOS client for the *write* path, or the reason there cannot be one.
///
/// Returns `Ok(None)` rather than an error when write-back is simply not
/// enabled: that is a configuration choice, not a fault, and the caller turns
/// it into a refusal an operator can read on each item.
pub fn build_write_client(config: &ChalkConfig) -> anyhow::Result<Option<ChromeOsClient>> {
    let devices = &config.device_sync;
    if !devices.enabled || !devices.write_back_enabled {
        return Ok(None);
    }
    let key_path = devices
        .resolved_key_path(&config.google_sync)
        .ok_or_else(|| anyhow::anyhow!("device_sync.service_account_key_path not configured"))?;
    let admin_email = devices
        .resolved_admin_email(&config.google_sync)
        .ok_or_else(|| anyhow::anyhow!("device_sync.admin_email not configured"))?;

    let auth = GoogleTokenSource::from_service_account_file(
        key_path,
        admin_email,
        device_sync_scopes(true),
    )?
    .into_shared();

    Ok(Some(
        ChromeOsClient::new(auth, &devices.customer_id).with_rate_limiter(
            chalk_google_sync::backoff::RateLimiter::per_minute(devices.requests_per_minute),
        ),
    ))
}

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

    // One place decides which scopes are requested, because the delegation
    // grant an administrator pastes into their Admin console has to match the
    // literal strings — a client granted read-only that then asks for
    // read/write gets a 403 that looks nothing like a scope problem.
    let auth = GoogleTokenSource::from_service_account_file(
        key_path,
        admin_email,
        device_sync_scopes(devices.write_back_enabled),
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

/// `chalk devices push --to-ou <path> [--status …] [--dry-run]`
///
/// Plans a fleet change and prints it. **Never commits.** Applying stays in
/// the console, where the diff is reviewed row by row and a deprovision is
/// gated behind a typed confirmation — a CLI flag is not a substitute for
/// either, and a one-line command that writes to five hundred devices is
/// exactly the shape this whole design exists to avoid.
///
/// Without `--dry-run` the plan is left `planned`, so `changeset show` and the
/// console can both open it and it can be committed. With `--dry-run` it is
/// marked `discarded` after printing — still a record, because a discard is
/// worth auditing, but one nothing can apply.
pub async fn push(
    config_path: &str,
    to_ou: &str,
    status: Option<String>,
    dry_run: bool,
) -> anyhow::Result<()> {
    use chalk_core::change_plan::{plan_change, PlannedChange};
    use chalk_core::models::asset::{AssetFilter, AssetSort, AssetStatus};
    use chalk_core::models::page::PageRequest;

    if !to_ou.starts_with('/') {
        anyhow::bail!(
            "{to_ou:?} is not an org unit path — it has to start with a slash, \
             like /Students/HS"
        );
    }

    let config = ChalkConfig::load(Path::new(config_path))?;
    common::assert_sqlite_only(&config.chalk.database.driver)?;
    let db_path = config
        .chalk
        .database
        .path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SQLite path not configured"))?;
    let pool = DatabasePool::new_sqlite(&format!("sqlite:{db_path}?mode=rwc")).await?;
    let repo = Arc::new(SqliteRepository::new(common::unwrap_sqlite_pool(pool)?));

    let filter = AssetFilter {
        status: match status.as_deref() {
            None => None,
            Some(raw) => Some(
                AssetStatus::parse(raw)
                    .map_err(|_| anyhow::anyhow!("{raw:?} is not a device status"))?,
            ),
        },
        sort: AssetSort::AssetTag,
        ..Default::default()
    };

    let assets: Arc<dyn chalk_core::db::repository::AssetRepository> = repo.clone();
    let sets: Arc<dyn chalk_core::db::repository::ChangeSetRepository> = repo.clone();
    let plan = plan_change(
        &assets,
        &sets,
        &filter,
        &PlannedChange::MoveOu {
            org_unit_path: to_ou.to_string(),
        },
        &[],
        "cli",
    )
    .await?;

    if plan.is_empty() {
        println!(
            "Nothing to do — {} device{} already in {to_ou}.",
            plan.unchanged_count,
            if plan.unchanged_count == 1 {
                " is"
            } else {
                "s are"
            }
        );
        sets.discard_change_set(&plan.change_set_id).await?;
        return Ok(());
    }

    println!(
        "{} device{} would move to {to_ou}{}.\n",
        plan.item_count,
        if plan.item_count == 1 { "" } else { "s" },
        if plan.unchanged_count > 0 {
            format!(" ({} already there)", plan.unchanged_count)
        } else {
            String::new()
        }
    );
    if plan.truncated {
        println!(
            "This is only part of the selection — a change set covers at most \
             {} devices.\n",
            chalk_core::change_plan::MAX_PLAN_ITEMS
        );
    }

    let page = sets
        .list_items(&plan.change_set_id, None, PageRequest::new(200, 0))
        .await?;
    println!("{:<20} {:<24} AFTER", "DEVICE", "NOW");
    for item in &page.items {
        println!(
            "{:<20} {:<24} {}",
            item.target_ref.as_deref().unwrap_or("—"),
            item.old_value.as_deref().unwrap_or("—"),
            item.new_value.as_deref().unwrap_or("—")
        );
    }
    if page.total > page.items.len() as i64 {
        println!("\n{} of {} shown.", page.items.len(), page.total);
    }

    if dry_run {
        sets.discard_change_set(&plan.change_set_id).await?;
        // "Discarded", not "deleted". The row stays as an auditable record
        // that somebody planned this and chose not to apply it, which is the
        // same treatment a discard from the console gets — saying "nothing was
        // written" without qualifying it would be a small lie that surprises
        // the first person to run `changeset list`.
        println!(
            "\nDry run — no devices were touched. The plan is recorded as \
             discarded and will not apply."
        );
    } else {
        println!(
            "\nNothing has been applied. The plan is saved as {}.\n\n  \
             chalk devices changeset show {}\n\n\
             Review and apply it in the console — that is where the diff is \
             checked row by row.",
            plan.change_set_id, plan.change_set_id
        );
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
