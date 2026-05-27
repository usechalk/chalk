//! `reset-admin-password` subcommand — issue a fresh password-reset URL
//! for the admin of an existing tenant.
//!
//! Pre-launch ops escape hatch: a customer who forgets their password has
//! no in-app recovery flow yet (self-serve forgot-password is a future
//! feature). Support staff SSH onto the hosted box and run:
//!
//! ```text
//! chalk-hosted reset-admin-password --tenant <slug> [--email <addr>]
//! ```
//!
//! The command prints a one-time `https://<slug>.<apex>/set-password?reset_token=…`
//! URL to stdout. Hand it to the customer over a trusted channel (a phone
//! call, a verified support ticket — NOT chat or email if you can avoid it,
//! since possession of the link is enough to take over the account).
//!
//! Tokens expire after [`RESET_TOKEN_TTL_HOURS`] (24 by default).

use std::time::Duration as StdDuration;

use anyhow::{anyhow, Context, Result};
use chalk_core::config::is_valid_pg_schema;
use chalk_core::db::repository::ChalkRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::common::RoleType;
use chalk_core::models::sync::UserFilter;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::is_valid_slug;
use crate::meta;
use crate::tenant::TenantRegistry;

const RESET_TOKEN_TTL_HOURS: i64 = 24;

#[derive(Debug, Clone)]
pub struct ResetAdminPasswordArgs {
    pub slug: String,
    /// Optional admin email. If `None`, the tenant must have exactly one
    /// administrator user — if multiple admins exist, the command refuses
    /// to guess and asks the operator to disambiguate.
    pub email: Option<String>,
    pub postgres_url: String,
    pub apex: String,
    pub public_scheme: String,
    pub public_port: Option<u16>,
}

pub async fn run(args: ResetAdminPasswordArgs) -> Result<()> {
    if !is_valid_slug(&args.slug) {
        return Err(anyhow!("invalid slug `{}`", args.slug));
    }

    let meta_pool = meta::connect_meta(&args.postgres_url).await?;
    let registry = TenantRegistry::new(meta_pool);
    let record = registry
        .get(&args.slug)
        .await?
        .ok_or_else(|| anyhow!("tenant `{}` not found in _meta.tenants", args.slug))?;

    if !is_valid_pg_schema(&record.db_schema) {
        return Err(anyhow!(
            "tenant schema `{}` is not a valid identifier",
            record.db_schema
        ));
    }

    let pool = DatabasePool::new_postgres(&args.postgres_url, &record.db_schema).await?;
    let pg_pool = match pool {
        DatabasePool::Postgres(p) => p,
        _ => return Err(anyhow!("expected postgres pool")),
    };
    let repo: Arc<dyn ChalkRepository> = Arc::new(
        chalk_core::db::postgres::PostgresRepository::new(pg_pool, record.db_schema.clone()),
    );

    // Find the admin user.
    let admins = repo
        .list_users(&UserFilter {
            role: Some(RoleType::Administrator),
            org_sourced_id: None,
            grade: None,
        })
        .await
        .with_context(|| "listing administrator users")?;

    let target = match args.email.as_deref() {
        Some(email) => admins
            .into_iter()
            .find(|u| {
                u.email.as_deref().map(str::to_ascii_lowercase) == Some(email.to_ascii_lowercase())
            })
            .ok_or_else(|| {
                anyhow!(
                    "no administrator user with email `{email}` in tenant `{}`",
                    args.slug
                )
            })?,
        None => match admins.len() {
            0 => return Err(anyhow!("tenant `{}` has no administrator users", args.slug)),
            1 => admins.into_iter().next().unwrap(),
            n => {
                return Err(anyhow!(
                    "tenant `{}` has {n} administrators — pass --email to disambiguate",
                    args.slug
                ));
            }
        },
    };

    let reset_token = generate_reset_token();
    let token_hash = sha256_hex(&reset_token);
    let expires_at = Utc::now() + Duration::hours(RESET_TOKEN_TTL_HOURS);
    repo.create_reset_token(&target.sourced_id, &token_hash, expires_at)
        .await
        .with_context(|| "storing reset token")?;

    // Audit the action so the act of issuing a recovery link is not silent.
    let meta_json = serde_json::json!({
        "actor": "reset-admin-password (CLI)",
        "target": target.sourced_id,
        "email": target.email,
        "tenant": args.slug,
    })
    .to_string();
    let _ = repo
        .log_admin_action("admin_password_reset_issued", Some(&meta_json), None)
        .await;

    let url = build_reset_url(
        &args.public_scheme,
        &args.slug,
        &args.apex,
        args.public_port,
        &reset_token,
    );
    println!();
    println!(
        "Reset URL for `{}` (valid {RESET_TOKEN_TTL_HOURS}h):",
        args.slug
    );
    println!("  {url}");
    println!();
    println!("Hand this to the customer over a trusted channel.");

    // Drop the pool gracefully so the binary exits cleanly.
    let _ = tokio::time::sleep(StdDuration::from_millis(50)).await;
    Ok(())
}

fn generate_reset_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(64);
    for b in &bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let bytes = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in bytes.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn build_reset_url(scheme: &str, slug: &str, apex: &str, port: Option<u16>, token: &str) -> String {
    match port {
        Some(p) if p != 443 && p != 80 => {
            format!("{scheme}://{slug}.{apex}:{p}/set-password?reset_token={token}")
        }
        _ => format!("{scheme}://{slug}.{apex}/set-password?reset_token={token}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_token_is_64_hex_chars() {
        let t = generate_reset_token();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn build_reset_url_no_port() {
        let url = build_reset_url("https", "acme", "usechalk.xyz", None, "abc");
        assert_eq!(
            url,
            "https://acme.usechalk.xyz/set-password?reset_token=abc"
        );
    }

    #[test]
    fn build_reset_url_with_port() {
        let url = build_reset_url("http", "acme", "localhost", Some(8080), "abc");
        assert_eq!(
            url,
            "http://acme.localhost:8080/set-password?reset_token=abc"
        );
    }

    #[test]
    fn build_reset_url_omits_default_port() {
        let url = build_reset_url("https", "acme", "usechalk.xyz", Some(443), "abc");
        assert_eq!(
            url,
            "https://acme.usechalk.xyz/set-password?reset_token=abc"
        );
    }
}
