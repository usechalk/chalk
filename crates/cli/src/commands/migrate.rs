use std::path::Path;
use std::time::Instant;

use chalk_core::config::{ChalkConfig, DatabaseDriver};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::migration::classlink::parse_classlink_export;
use chalk_core::migration::clever::parse_clever_export;
use chalk_core::sync::SyncEngine;
use tracing::{error, info};

/// Run the `migrate` command: parse a Clever or ClassLink export and persist to the database.
pub async fn run(
    config_path: &str,
    from: &str,
    export_dir: &str,
    dry_run: bool,
) -> anyhow::Result<()> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    config.validate()?;

    info!("Loaded configuration from {}", config_path);

    let export_path = Path::new(export_dir);
    println!("Parsing {from} export from: {}", export_path.display());

    let start = Instant::now();
    let plan = match from {
        "clever" => parse_clever_export(export_path)?,
        "classlink" => parse_classlink_export(export_path)?,
        _ => anyhow::bail!("Unsupported migration source: {from}. Use 'clever' or 'classlink'."),
    };

    let summary = plan.roster_summary();
    println!(
        "Parsed {} export in {:.1}s:",
        plan.source,
        start.elapsed().as_secs_f64()
    );
    println!("  Orgs:              {}", summary.orgs);
    println!("  Academic Sessions: {}", summary.academic_sessions);
    println!("  Users:             {}", summary.users);
    println!("  Courses:           {}", summary.courses);
    println!("  Classes:           {}", summary.classes);
    println!("  Enrollments:       {}", summary.enrollments);
    println!("  Demographics:      {}", summary.demographics);

    if !plan.app_configs.is_empty() {
        println!("\nApplication Configs ({}):", plan.app_configs.len());
        for app in &plan.app_configs {
            println!("  - {} (SSO: {})", app.app_name, app.sso_type);
        }
    }

    println!("\nCutover Steps:");
    for (i, step) in plan.cutover_steps.iter().enumerate() {
        let check = if step.completed { "x" } else { " " };
        println!("  [{}] {}. {}", check, i + 1, step.description);
    }

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
    let provider = format!("{}-migration", from);
    let persist_start = Instant::now();

    match engine.persist_payload(&provider, &plan.roster_data).await {
        Ok(sync_run) => {
            let duration = persist_start.elapsed();
            println!(
                "\nMigration import completed in {:.1}s",
                duration.as_secs_f64()
            );
            println!("  Provider:    {}", sync_run.provider);
            println!("  Orgs:        {}", sync_run.orgs_synced);
            println!("  Users:       {}", sync_run.users_synced);
            println!("  Courses:     {}", sync_run.courses_synced);
            println!("  Classes:     {}", sync_run.classes_synced);
            println!("  Enrollments: {}", sync_run.enrollments_synced);
        }
        Err(e) => {
            error!("Migration import failed: {e}");
            println!("Migration import failed: {e}");
            return Err(e.into());
        }
    }

    Ok(())
}
