use std::path::Path;
use std::sync::Arc;

use chalk_core::config::{ChalkConfig, DatabaseDriver};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_google_sync::client::GoogleAdminClient;
use chalk_google_sync::sync::GoogleSyncEngine;
use tracing::info;

/// Run the `google-sync` command: sync roster data to Google Workspace.
pub async fn run(config_path: &str, dry_run: bool) -> anyhow::Result<()> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    config.validate()?;

    if !config.google_sync.enabled {
        anyhow::bail!(
            "Google Sync is not enabled in configuration. Set google_sync.enabled = true."
        );
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

    // In production, auth token would come from service account key file.
    // For now we use a placeholder — real OAuth2 flow is a future enhancement.
    let admin_email = config
        .google_sync
        .admin_email
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("google_sync.admin_email not configured"))?;

    info!(admin_email, dry_run, "Starting Google Workspace sync");

    // The customer ID defaults to "my_customer" for domain-wide delegation
    let client = GoogleAdminClient::new("placeholder-token", "my_customer");
    let engine = GoogleSyncEngine::new(repo, client, config.google_sync.clone());

    let summary = engine.run_sync(dry_run).await?;

    println!(
        "Google Workspace sync {}!",
        if dry_run { "preview" } else { "completed" }
    );
    println!("  Users created:   {}", summary.users_created);
    println!("  Users updated:   {}", summary.users_updated);
    println!("  Users suspended: {}", summary.users_suspended);
    println!("  OUs created:     {}", summary.ous_created);
    if dry_run {
        println!();
        println!("This was a dry run. No changes were made to Google Workspace.");
        println!("Run `chalk google-sync` without --dry-run to apply changes.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn google_sync_requires_config_file() {
        let result = run("/nonexistent/chalk.toml", true).await;
        assert!(result.is_err());
    }
}
