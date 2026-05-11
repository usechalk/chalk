//! `tenant` subcommand group — admin lifecycle operations:
//! `tenant suspend` and `tenant unsuspend`.
//!
//! Note: tenants are routed via the resolver's `StateCache`, so a running
//! `serve` process will keep serving a suspended tenant from cache until
//! the LRU evicts the entry (~10 min idle). Operators who need immediate
//! effect should restart `chalk-hosted`.

use anyhow::{anyhow, Result};
use sqlx::Row;

use crate::is_valid_slug;
use crate::meta;
use crate::tenant::TenantStatus;

#[derive(Debug, Clone)]
pub struct SuspendArgs {
    pub slug: String,
    pub postgres_url: String,
}

#[derive(Debug, Clone)]
pub struct UnsuspendArgs {
    pub slug: String,
    pub postgres_url: String,
}

pub async fn run_suspend(args: SuspendArgs) -> Result<()> {
    if !is_valid_slug(&args.slug) {
        return Err(anyhow!("invalid slug `{}`", args.slug));
    }
    let pool = meta::connect_meta(&args.postgres_url).await?;

    suspend_tenant(&pool, &args.slug).await?;

    println!("suspended tenant `{}`", args.slug);
    println!(
        "note: tenants are routed via the resolver's StateCache; the running \
         serve process will continue serving this tenant from cache until LRU \
         eviction (~10 min idle). For immediate effect, restart chalk-hosted."
    );
    Ok(())
}

pub async fn run_unsuspend(args: UnsuspendArgs) -> Result<()> {
    if !is_valid_slug(&args.slug) {
        return Err(anyhow!("invalid slug `{}`", args.slug));
    }
    let pool = meta::connect_meta(&args.postgres_url).await?;

    unsuspend_tenant(&pool, &args.slug).await?;

    println!("unsuspended tenant `{}` (status = active)", args.slug);
    Ok(())
}

/// Flip an active tenant to suspended. Errors if the slug does not match an
/// active tenant (already-suspended or missing rows are both reported as
/// "no active tenant with slug ..."). Exposed for testcontainer integration
/// tests.
pub async fn suspend_tenant(pool: &sqlx::PgPool, slug: &str) -> Result<()> {
    let row = sqlx::query(
        "UPDATE _meta.tenants \
         SET status = $1, updated_at = now() \
         WHERE slug = $2 AND status = $3 \
         RETURNING slug",
    )
    .bind(TenantStatus::Suspended.as_str())
    .bind(slug)
    .bind(TenantStatus::Active.as_str())
    .fetch_optional(pool)
    .await?;
    match row {
        Some(_) => Ok(()),
        None => Err(anyhow!("no active tenant with slug `{slug}`")),
    }
}

/// Flip a suspended tenant back to active. Errors if the slug does not match
/// a suspended tenant. Exposed for testcontainer integration tests.
pub async fn unsuspend_tenant(pool: &sqlx::PgPool, slug: &str) -> Result<()> {
    let row = sqlx::query(
        "UPDATE _meta.tenants \
         SET status = $1, updated_at = now() \
         WHERE slug = $2 AND status = $3 \
         RETURNING slug",
    )
    .bind(TenantStatus::Active.as_str())
    .bind(slug)
    .bind(TenantStatus::Suspended.as_str())
    .fetch_optional(pool)
    .await?;
    match row {
        Some(r) => {
            let _slug: String = r.try_get("slug")?;
            Ok(())
        }
        None => Err(anyhow!("no suspended tenant with slug `{slug}`")),
    }
}
