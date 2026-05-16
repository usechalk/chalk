//! `webhook` subcommands. Currently only `retry-pending`, which drives
//! `WebhookDeliveryEngine::process_pending_retries` for operators (and the
//! retry-machinery E2E test under `testing/webhook-receiver/`).

use std::path::Path;
use std::time::Duration;

use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::WebhookDeliveryRepository;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::webhooks::delivery::WebhookDeliveryEngine;
use tracing::info;

use super::common;

/// Drive the webhook retry queue. When `iterations` is `None` we poll
/// forever on `interval`; otherwise we run exactly that many ticks and
/// exit. Returns the total number of deliveries observed across ticks.
pub async fn retry_pending(
    config_path: &str,
    iterations: Option<u32>,
    interval: Duration,
) -> anyhow::Result<()> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    config.validate()?;
    common::assert_sqlite_only(&config.chalk.database.driver)?;

    let path = config
        .chalk
        .database
        .path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SQLite path not configured"))?;
    let connect_str = format!("sqlite:{}?mode=rwc", path);
    let pool = DatabasePool::new_sqlite(&connect_str).await?;
    let repo = match pool {
        DatabasePool::Sqlite(p) => SqliteRepository::new(p),
        DatabasePool::Postgres(_) => {
            anyhow::bail!("webhook retry-pending currently only supports SQLite")
        }
    };

    let engine = WebhookDeliveryEngine::new();
    info!(backoff = ?engine.backoff(), "webhook retry-pending starting");

    let mut tick = 0u32;
    loop {
        let pending_before = repo.list_pending_retries(50).await?.len();
        engine.process_pending_retries(&repo).await?;
        let pending_after = repo.list_pending_retries(50).await?.len();
        println!("tick {tick}: pending before={pending_before} after={pending_after}");

        tick += 1;
        if let Some(n) = iterations {
            if tick >= n {
                return Ok(());
            }
        }
        tokio::time::sleep(interval).await;
    }
}
