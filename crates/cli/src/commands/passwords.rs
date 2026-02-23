use std::path::Path;

use chalk_core::config::{ChalkConfig, DatabaseDriver};
use chalk_core::db::repository::{DemographicsRepository, PasswordRepository, UserRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::sync::UserFilter;
use chalk_core::passwords::PasswordGenerator;
use chalk_idp::auth::hash_password;
use tracing::info;

/// Run the `passwords generate` command.
pub async fn run(config_path: &str, user_id: Option<&str>, force: bool) -> anyhow::Result<()> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    config.validate()?;

    let pattern = config
        .idp
        .default_password_pattern
        .as_deref()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "idp.default_password_pattern is not set in the configuration. \
                 Add it to [idp] in your chalk.toml."
            )
        })?;

    if config.idp.default_password_roles.is_empty() {
        anyhow::bail!(
            "idp.default_password_roles is empty. \
             Add roles (e.g., [\"student\", \"teacher\"]) to [idp] in your chalk.toml."
        );
    }

    info!("Loaded configuration from {}", config_path);
    println!("Password pattern: {pattern}");
    println!(
        "Target roles: {}",
        config.idp.default_password_roles.join(", ")
    );

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
        DatabasePool::Sqlite(p) => SqliteRepository::new(p),
    };

    let generator = PasswordGenerator::new(pattern, &config.idp.default_password_roles);

    let users = if let Some(sid) = user_id {
        let user = repo
            .get_user(sid)
            .await?
            .ok_or_else(|| anyhow::anyhow!("user not found: {sid}"))?;
        vec![user]
    } else {
        repo.list_users(&UserFilter::default()).await?
    };

    let mut generated = 0u64;
    let mut skipped = 0u64;
    let mut errors = 0u64;

    for user in &users {
        if !generator.matches_role(user) {
            continue;
        }

        if !force {
            if let Some(existing) = repo.get_password_hash(&user.sourced_id).await? {
                if !existing.is_empty() {
                    skipped += 1;
                    continue;
                }
            }
        }

        let demographics = repo.get_demographics(&user.sourced_id).await?;
        match generator.generate_for_user(user, demographics.as_ref()) {
            Ok(password) => {
                let hashed = hash_password(&password)?;
                repo.set_password_hash(&user.sourced_id, &hashed).await?;
                generated += 1;
            }
            Err(e) => {
                eprintln!(
                    "Warning: skipping user {} ({}): {e}",
                    user.sourced_id, user.username
                );
                errors += 1;
            }
        }
    }

    println!("\nPassword generation complete:");
    println!("  Generated: {generated}");
    println!("  Skipped (existing): {skipped}");
    if errors > 0 {
        println!("  Errors (missing data): {errors}");
    }

    Ok(())
}
