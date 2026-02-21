use std::path::Path;
use std::time::Instant;

use chalk_core::config::{ChalkConfig, DatabaseDriver};
use chalk_core::connectors::SyncPayload;
use chalk_core::db::repository::{
    AcademicSessionRepository, ClassRepository, CourseRepository, DemographicsRepository,
    EnrollmentRepository, OrgRepository, UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::sync::UserFilter;
use chalk_core::oneroster_csv::write_oneroster_csv;
use tracing::{error, info};

/// Run the `export` command: read all data from the database and write OneRoster CSV files.
pub async fn run(config_path: &str, output_dir: &str) -> anyhow::Result<()> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    config.validate()?;

    info!("Loaded configuration from {}", config_path);

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

    println!("Reading data from database...");
    let start = Instant::now();

    let no_filter = UserFilter {
        role: None,
        org_sourced_id: None,
        grade: None,
    };

    let payload = SyncPayload {
        orgs: repo.list_orgs().await?,
        academic_sessions: repo.list_academic_sessions().await?,
        users: repo.list_users(&no_filter).await?,
        courses: repo.list_courses().await?,
        classes: repo.list_classes().await?,
        enrollments: repo.list_enrollments().await?,
        demographics: repo.list_demographics().await?,
    };

    let read_duration = start.elapsed();
    println!("Read data in {:.1}s", read_duration.as_secs_f64());

    let output_path = Path::new(output_dir);
    println!("Writing OneRoster CSV to: {}", output_path.display());

    let write_start = Instant::now();
    match write_oneroster_csv(&payload, output_path) {
        Ok(()) => {
            let duration = write_start.elapsed();
            println!("\nExport completed in {:.1}s", duration.as_secs_f64());
            println!("  Orgs:              {}", payload.orgs.len());
            println!("  Academic Sessions: {}", payload.academic_sessions.len());
            println!("  Users:             {}", payload.users.len());
            println!("  Courses:           {}", payload.courses.len());
            println!("  Classes:           {}", payload.classes.len());
            println!("  Enrollments:       {}", payload.enrollments.len());
            println!("  Demographics:      {}", payload.demographics.len());
            println!("\nFiles written to: {}", output_path.display());
        }
        Err(e) => {
            error!("Export failed: {e}");
            println!("Export failed: {e}");
            return Err(e.into());
        }
    }

    Ok(())
}
