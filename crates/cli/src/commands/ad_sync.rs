use std::path::Path;
use std::sync::Arc;

use chalk_core::config::{ChalkConfig, DatabaseDriver};
use chalk_core::db::repository::{AdSyncRunRepository, AdSyncStateRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use tracing::info;

/// Run the `ad-sync` command: sync roster data to Active Directory.
pub async fn run(
    config_path: &str,
    dry_run: bool,
    full: bool,
    export_passwords: bool,
    status_only: bool,
    test_connection: bool,
) -> anyhow::Result<()> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    config.validate()?;

    if !config.ad_sync.enabled {
        anyhow::bail!("AD Sync is not enabled in configuration. Set ad_sync.enabled = true.");
    }

    let pool = match config.chalk.database.driver {
        DatabaseDriver::Sqlite => {
            let path = config
                .chalk
                .database
                .path
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("SQLite path not configured"))?;
            let connect_str = format!("sqlite:{}?mode=rwc", path);
            DatabasePool::new_sqlite(&connect_str).await?
        }
        DatabaseDriver::Postgres => {
            anyhow::bail!("PostgreSQL is not yet supported");
        }
    };

    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
    };

    if status_only {
        return show_status(&repo).await;
    }

    if test_connection {
        return test_ldap_connection(&config).await;
    }

    let effective_dry_run = dry_run || config.ad_sync.options.dry_run;

    info!(
        dry_run = effective_dry_run,
        full, export_passwords, "Starting AD sync"
    );

    let client = chalk_ad_sync::client::AdClient::new(&config.ad_sync.connection);
    let engine =
        chalk_ad_sync::sync::AdSyncEngine::new(repo.clone(), client, config.ad_sync.clone());

    let summary = engine.run_sync(effective_dry_run, full).await?;

    println!(
        "AD sync {}!",
        if effective_dry_run {
            "preview"
        } else {
            "completed"
        }
    );
    println!("  Users created:  {}", summary.users_created);
    println!("  Users updated:  {}", summary.users_updated);
    println!("  Users disabled: {}", summary.users_disabled);
    println!("  Users skipped:  {}", summary.users_skipped);
    println!("  Errors:         {}", summary.errors);

    if let Some(ref details) = summary.error_details {
        println!("  Error details:");
        for line in details.lines() {
            println!("    {}", line);
        }
    }

    if effective_dry_run {
        println!();
        println!("This was a dry run. No changes were made to Active Directory.");
        println!("Run `chalk ad-sync` without --dry-run to apply changes.");
    }

    // Export passwords as CSV if requested
    if export_passwords {
        let states = repo.list_ad_sync_states().await?;
        let has_passwords = states.iter().any(|s| s.initial_password.is_some());
        if has_passwords {
            println!();
            println!("sourced_id,sam_account_name,password");
            for state in &states {
                if let Some(ref pw) = state.initial_password {
                    println!(
                        "{},{},{}",
                        state.user_sourced_id, state.ad_sam_account_name, pw
                    );
                }
            }
        } else {
            println!();
            println!("No initial passwords found in sync state.");
        }
    }

    Ok(())
}

async fn show_status(repo: &SqliteRepository) -> anyhow::Result<()> {
    match repo.get_latest_ad_sync_run().await? {
        Some(run) => {
            println!("Last AD Sync Run:");
            println!("  ID:             {}", run.id);
            println!("  Status:         {:?}", run.status);
            println!("  Started:        {}", run.started_at);
            if let Some(completed) = run.completed_at {
                println!("  Completed:      {}", completed);
            }
            println!("  Users created:  {}", run.users_created);
            println!("  Users updated:  {}", run.users_updated);
            println!("  Users disabled: {}", run.users_disabled);
            println!("  Users skipped:  {}", run.users_skipped);
            println!("  Errors:         {}", run.errors);
            println!("  Dry run:        {}", run.dry_run);
            if let Some(ref details) = run.error_details {
                println!("  Error details:  {}", details);
            }
        }
        None => {
            println!("No AD sync runs found.");
        }
    }
    Ok(())
}

async fn test_ldap_connection(config: &ChalkConfig) -> anyhow::Result<()> {
    println!(
        "Testing LDAP connection to {}...",
        config.ad_sync.connection.server
    );

    let client = chalk_ad_sync::client::AdClient::new(&config.ad_sync.connection);
    match client.test_connection().await {
        Ok(()) => {
            println!("LDAP connection successful!");
            Ok(())
        }
        Err(e) => {
            println!("LDAP connection failed: {e}");
            Err(e.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ad_sync_requires_config_file() {
        let result = run("/nonexistent/chalk.toml", true, false, false, false, false).await;
        assert!(result.is_err());
    }
}
