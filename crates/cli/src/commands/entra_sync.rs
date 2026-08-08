//! `chalk entra-sync` — provision roster users into Entra ID (Azure AD).
//!
//! The Graph-API sibling of `chalk ad-sync`, with the same contract:
//! `--dry-run` counts the work without contacting anything, `--status` shows
//! the last run, and departures are disabled rather than deleted.

use std::sync::Arc;

use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::EntraSyncRunRepository;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;

use super::common;

pub async fn run(config_path: &str, dry_run: bool, status: bool) -> anyhow::Result<()> {
    let config = ChalkConfig::load(std::path::Path::new(config_path))?;
    config.validate()?;
    common::assert_sqlite_only(&config.chalk.database.driver)?;
    let path = config
        .chalk
        .database
        .path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SQLite path not configured"))?;
    let pool = DatabasePool::new_sqlite(&format!("sqlite:{path}?mode=rwc")).await?;
    let repo = Arc::new(SqliteRepository::new(common::unwrap_sqlite_pool(pool)?));

    if status {
        return show_status(&repo).await;
    }
    if !config.entra.is_configured() {
        anyhow::bail!(
            "[entra] is not configured — set enabled, tenant_id, client_id, \
             client_secret and domain in chalk.toml"
        );
    }

    let client = chalk_ad_sync::entra::GraphClient::new(config.entra.clone());
    let engine = chalk_ad_sync::entra::EntraSyncEngine::new(repo, client, config.entra.clone());
    let summary = engine.run_sync(dry_run).await?;

    println!(
        "Entra sync {}!",
        if dry_run { "preview" } else { "completed" }
    );
    println!("  Users created:  {}", summary.users_created);
    println!("  Users updated:  {}", summary.users_updated);
    println!("  Users disabled: {}", summary.users_disabled);
    println!("  Users skipped:  {}", summary.users_skipped);
    println!("  Errors:         {}", summary.errors);
    if let Some(details) = summary.error_details {
        println!("---\n{details}");
    }
    Ok(())
}

async fn show_status(repo: &Arc<SqliteRepository>) -> anyhow::Result<()> {
    match repo.get_latest_entra_sync_run().await? {
        None => println!("No Entra sync has run yet."),
        Some(run) => {
            println!("Last Entra sync run:");
            println!("  id:        {}", run.id);
            println!("  status:    {}", run.status.as_str());
            println!("  started:   {}", run.started_at.format("%Y-%m-%d %H:%M"));
            println!("  created:   {}", run.users_created);
            println!("  updated:   {}", run.users_updated);
            println!("  disabled:  {}", run.users_disabled);
            println!("  skipped:   {}", run.users_skipped);
            println!("  errors:    {}", run.errors);
            println!("  dry run:   {}", run.dry_run);
            if let Some(details) = run.error_details {
                println!("---\n{details}");
            }
        }
    }
    Ok(())
}
