//! `chalk console-users` — manage per-person console accounts (F1).
//!
//! The console can authenticate individual technicians, but somebody has to
//! create the first one, and that cannot be done from the console UI (which the
//! account is needed to reach). This is the bootstrap, matching how
//! `passwords admin-hash` works: the password is read from stdin so it never
//! lands in shell history or `ps`.
//!
//! Self-host / SQLite only, like the other CLI data commands. Hosted tenants
//! are provisioned through the control plane.

use std::io::Read;

use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::ConsoleUserRepository;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::console_user::{ConsoleRole, ConsoleUser, ConsoleUserStatus};

use super::common;

async fn repo(config_path: &str) -> anyhow::Result<SqliteRepository> {
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
    Ok(SqliteRepository::new(common::unwrap_sqlite_pool(pool)?))
}

fn parse_role(role: &str) -> anyhow::Result<ConsoleRole> {
    role.trim().parse::<ConsoleRole>().map_err(|_| {
        anyhow::anyhow!("unknown role {role:?} — expected admin, technician, or read_only")
    })
}

/// `chalk console-users add --email --name --role`.
///
/// Reads the account password from stdin:
///   printf '%s' 'the-password' | chalk console-users add --email t@d.org --name "Tech" --role admin
pub async fn run_add(config_path: &str, email: &str, name: &str, role: &str) -> anyhow::Result<()> {
    let role = parse_role(role)?;

    let email = email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        anyhow::bail!("--email must be a real address");
    }
    if name.trim().is_empty() {
        anyhow::bail!("--name must not be empty");
    }

    let mut password = String::new();
    std::io::stdin().read_to_string(&mut password)?;
    // A trailing newline is an artifact of how it was piped in, not part of the
    // password. Spaces inside are the user's business and left alone.
    let password = password.strip_suffix('\n').unwrap_or(&password);
    let password = password.strip_suffix('\r').unwrap_or(password);
    if password.is_empty() {
        anyhow::bail!(
            "no password on stdin. Try: printf '%s' 'the-password' | chalk console-users add ..."
        );
    }
    let password_hash = chalk_idp::auth::hash_password(password)
        .map_err(|e| anyhow::anyhow!("could not hash password: {e}"))?;

    let repo = repo(config_path).await?;
    if repo.get_console_user_by_email(&email).await?.is_some() {
        anyhow::bail!("a console account already exists for {email}");
    }

    let now = chrono::Utc::now();
    repo.create_console_user(&ConsoleUser {
        id: uuid::Uuid::new_v4().to_string(),
        email: email.clone(),
        display_name: name.trim().to_string(),
        password_hash: Some(password_hash),
        role,
        status: ConsoleUserStatus::Active,
        totp_secret: None,
        totp_confirmed: false,
        totp_recovery: None,
        created_at: now,
        updated_at: now,
    })
    .await?;

    println!("Created console account {email} ({}).", role.as_str());
    println!("They can now sign in at /login with that email and password.");
    Ok(())
}

/// `chalk console-users list` — who can sign in, and as what.
pub async fn run_list(config_path: &str) -> anyhow::Result<()> {
    let repo = repo(config_path).await?;
    let users = repo.list_console_users().await?;
    if users.is_empty() {
        println!("No console accounts yet. The shared admin password is the only way in.");
        return Ok(());
    }
    println!("{:<32} {:<12} {:<10} NAME", "EMAIL", "ROLE", "STATUS");
    for u in users {
        println!(
            "{:<32} {:<12} {:<10} {}",
            u.email,
            u.role.as_str(),
            u.status.as_str(),
            u.display_name
        );
    }
    Ok(())
}
