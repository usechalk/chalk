use std::path::Path;
use std::time::Instant;

use chalk_core::config::{ChalkConfig, DatabaseDriver};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::oneroster_csv::read_oneroster_csv;
use chalk_core::sync::SyncEngine;
use tracing::{error, info};

/// Run the `import` command: read OneRoster CSV files and persist to the database.
pub async fn run(config_path: &str, csv_dir: &str, dry_run: bool) -> anyhow::Result<()> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    config.validate()?;

    info!("Loaded configuration from {}", config_path);

    let csv_path = Path::new(csv_dir);
    println!("Reading OneRoster CSV from: {}", csv_path.display());

    let start = Instant::now();
    let payload = read_oneroster_csv(csv_path)?;

    println!("Parsed CSV in {:.1}s:", start.elapsed().as_secs_f64());
    println!("  Orgs:              {}", payload.orgs.len());
    println!("  Academic Sessions: {}", payload.academic_sessions.len());
    println!("  Users:             {}", payload.users.len());
    println!("  Courses:           {}", payload.courses.len());
    println!("  Classes:           {}", payload.classes.len());
    println!("  Enrollments:       {}", payload.enrollments.len());
    println!("  Demographics:      {}", payload.demographics.len());

    if dry_run {
        println!("\nDry run mode - no data was written to the database.");
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

    let repo = match pool {
        DatabasePool::Sqlite(p) => SqliteRepository::new(p),
    };

    let engine = SyncEngine::new(repo);
    let persist_start = Instant::now();

    match engine.persist_payload("csv-import", &payload).await {
        Ok(sync_run) => {
            let duration = persist_start.elapsed();
            println!("\nImport completed in {:.1}s", duration.as_secs_f64());
            println!("  Provider:    {}", sync_run.provider);
            println!("  Orgs:        {}", sync_run.orgs_synced);
            println!("  Users:       {}", sync_run.users_synced);
            println!("  Courses:     {}", sync_run.courses_synced);
            println!("  Classes:     {}", sync_run.classes_synced);
            println!("  Enrollments: {}", sync_run.enrollments_synced);
        }
        Err(e) => {
            error!("Import failed: {e}");
            println!("Import failed: {e}");
            return Err(e.into());
        }
    }

    Ok(())
}
