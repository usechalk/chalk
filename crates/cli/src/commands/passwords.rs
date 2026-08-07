use std::path::Path;

use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{DemographicsRepository, PasswordRepository, UserRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::sync::UserFilter;
use chalk_core::passwords::PasswordGenerator;
use chalk_idp::auth::hash_password;
use tracing::info;

use super::common;

/// Run the `passwords admin-hash` command.
///
/// Reads a password from stdin and prints the `chalk.toml` line that sets it.
///
/// This exists because `chalk init` was the only thing that ever wrote
/// `admin_password_hash`, so an operator whose console had no password — the
/// state `serve` now refuses to start in — had no supported way out of it. A
/// startup error naming a fix that does not exist is not a guard, it is a wall.
///
/// It prints rather than edits. Rewriting `chalk.toml` in place would mean
/// re-serialising it, and that discards the comments and ordering an operator
/// put there; a line to paste costs them two seconds and cannot corrupt
/// anything.
///
/// Stdin rather than a prompt or an argument: an argument lands in shell
/// history and in `ps`, and a no-echo prompt would mean a new dependency for
/// one command. `printf '%s' 'secret' | chalk passwords admin-hash` leaks
/// neither.
pub fn run_admin_hash() -> anyhow::Result<()> {
    use std::io::Read;

    let mut password = String::new();
    std::io::stdin().read_to_string(&mut password)?;
    // A trailing newline is an artifact of how the password was piped in, not
    // part of it. Anything else is left alone — spaces in a password are the
    // user's business.
    let password = password.strip_suffix('\n').unwrap_or(&password);
    let password = password.strip_suffix('\r').unwrap_or(password);

    if password.is_empty() {
        anyhow::bail!(
            "no password on stdin. Try: printf '%s' 'your-password' | chalk passwords admin-hash"
        );
    }

    let hash = hash_password(password).map_err(|e| anyhow::anyhow!("could not hash: {e}"))?;
    println!("# Add this under [chalk] in your chalk.toml:");
    println!("admin_password_hash = \"{hash}\"");
    Ok(())
}

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

    common::assert_sqlite_only(&config.chalk.database.driver)?;

    let path = config
        .chalk
        .database
        .path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SQLite path not configured"))?;
    let connect_str = format!("sqlite:{}?mode=rwc", path);
    let pool = DatabasePool::new_sqlite(&connect_str).await?;

    let repo = SqliteRepository::new(common::unwrap_sqlite_pool(pool)?);

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

#[cfg(test)]
mod admin_hash_tests {
    /// The whole point of `admin-hash` is that the console accepts what it
    /// prints. This crate hashes with `chalk_idp::auth` and the console
    /// verifies with `chalk_console::auth`; both delegate to
    /// `chalk_core::auth` today, so they agree — but that is an implementation
    /// detail of two crates that could drift apart without either one looking
    /// wrong on its own. If they ever do, the symptom is an operator locked out
    /// of their own console by the command that was supposed to let them in.
    #[test]
    fn the_hash_it_prints_is_one_the_console_will_accept() {
        let hash = super::hash_password("correct horse battery staple").unwrap();
        assert!(
            chalk_core::auth::verify_password(&hash, "correct horse battery staple").unwrap(),
            "the console could not verify a hash this command produced"
        );
        assert!(
            !chalk_core::auth::verify_password(&hash, "wrong password").unwrap(),
            "verification accepted the wrong password"
        );
    }
}
