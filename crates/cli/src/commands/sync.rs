use std::path::Path;
use std::time::Instant;

use chalk_core::config::{ChalkConfig, DatabaseDriver, SisProvider};
use chalk_core::connectors::infinite_campus::InfiniteCampusConnector;
use chalk_core::connectors::powerschool::PowerSchoolConnector;
use chalk_core::connectors::skyward::SkywardConnector;
use chalk_core::connectors::SisConnector;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::sync::SyncEngine;
use tracing::{error, info, warn};

/// Run the `sync` command: connect to the configured SIS and sync data.
pub async fn run(config_path: &str, dry_run: bool) -> anyhow::Result<()> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    config.validate()?;

    info!("Loaded configuration from {}", config_path);

    if !config.sis.enabled {
        warn!("SIS integration is not enabled in the configuration");
        println!("SIS integration is disabled. Enable it in your config file first.");
        return Ok(());
    }

    // Connect to the database
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

    info!("Connected to database");

    // Create the connector based on the configured provider
    let connector: Box<dyn SisConnector> = match config.sis.provider {
        SisProvider::PowerSchool => Box::new(PowerSchoolConnector::new(&config.sis)),
        SisProvider::InfiniteCampus => Box::new(InfiniteCampusConnector::new(&config.sis)?),
        SisProvider::Skyward => Box::new(SkywardConnector::new(&config.sis)?),
    };

    if dry_run {
        println!("Dry run mode - testing connection only");
        println!("Provider: {}", connector.provider_name());
        println!("Base URL: {}", config.sis.base_url);

        match connector.test_connection().await {
            Ok(()) => {
                println!("Connection test: SUCCESS");
                info!("Dry run connection test passed");
            }
            Err(e) => {
                println!("Connection test: FAILED - {e}");
                error!("Dry run connection test failed: {e}");
            }
        }
        return Ok(());
    }

    // Full sync
    println!("Starting sync with {}...", connector.provider_name());
    let start = Instant::now();

    let repo = match pool {
        DatabasePool::Sqlite(p) => SqliteRepository::new(p),
    };
    let engine = SyncEngine::new(repo);

    match engine.run(connector.as_ref()).await {
        Ok(sync_run) => {
            let duration = start.elapsed();
            println!(
                "Sync completed successfully in {:.1}s",
                duration.as_secs_f64()
            );
            println!("  Provider:    {}", sync_run.provider);
            println!("  Orgs:        {}", sync_run.orgs_synced);
            println!("  Users:       {}", sync_run.users_synced);
            println!("  Courses:     {}", sync_run.courses_synced);
            println!("  Classes:     {}", sync_run.classes_synced);
            println!("  Enrollments: {}", sync_run.enrollments_synced);
            if let Some(err) = &sync_run.error_message {
                println!("  Warning:     {err}");
            }
        }
        Err(e) => {
            error!("Sync failed: {e}");
            println!("Sync failed: {e}");
            return Err(e.into());
        }
    }

    Ok(())
}
