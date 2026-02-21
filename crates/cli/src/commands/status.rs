use std::path::Path;

use chalk_core::config::{ChalkConfig, DatabaseDriver};
use chalk_core::db::repository::{SyncRepository, UserRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use tracing::info;

/// Run the `status` command: show sync status and statistics.
pub async fn run(config_path: &str) -> anyhow::Result<()> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    config.validate()?;

    info!("Loaded configuration from {}", config_path);

    let (repo, driver_name, db_size) = match config.chalk.database.driver {
        DatabaseDriver::Sqlite => {
            let path = config
                .chalk
                .database
                .path
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("SQLite path not configured"))?;
            let connect_str = format!("sqlite:{}?mode=rwc", path);
            let pool = DatabasePool::new_sqlite(&connect_str).await?;

            let size = std::fs::metadata(path)
                .map(|m| format_bytes(m.len()))
                .unwrap_or_else(|_| "unknown".to_string());

            let DatabasePool::Sqlite(sqlite_pool) = pool;
            let repo = SqliteRepository::new(sqlite_pool);
            (repo, "SQLite", size)
        }
        DatabaseDriver::Postgres => {
            anyhow::bail!("PostgreSQL is not yet supported in Phase 1a");
        }
    };

    println!("Chalk Status");
    println!("============");
    println!("Instance: {}", config.chalk.instance_name);
    println!("Database: {} ({})", driver_name, db_size);
    println!();

    // Get provider name for querying sync runs
    let provider_name = if config.sis.enabled {
        format!("{:?}", config.sis.provider).to_lowercase()
    } else {
        "powerschool".to_string()
    };

    match repo.get_latest_sync_run(&provider_name).await? {
        Some(run) => {
            println!("Last Sync");
            println!("---------");
            println!("Provider: {}", run.provider);
            println!("Status:   {:?}", run.status);
            println!(
                "Started:  {}",
                run.started_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            if let Some(completed) = run.completed_at {
                println!("Completed: {}", completed.format("%Y-%m-%d %H:%M:%S UTC"));
            }
            if let Some(ref err) = run.error_message {
                println!("Error:    {}", err);
            }
            println!();
        }
        None => {
            println!("No sync runs recorded.");
            println!();
        }
    }

    let counts = repo.get_user_counts().await?;
    println!("User Counts");
    println!("-----------");
    println!("Students:       {}", counts.students);
    println!("Teachers:       {}", counts.teachers);
    println!("Administrators: {}", counts.administrators);
    println!("Other:          {}", counts.other);
    println!("Total:          {}", counts.total);

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_displays_correctly() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
    }
}
