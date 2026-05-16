//! `deprovision` subcommand — suspend or delete a tenant.

use anyhow::{anyhow, Result};
use chalk_core::config::is_valid_pg_schema;

use crate::meta;
use crate::notify;
use crate::tenant::TenantRegistry;
use crate::{is_valid_slug, schema_for_slug};

#[derive(Debug, Clone)]
pub struct DeprovisionArgs {
    pub slug: String,
    pub postgres_url: String,
    pub purge_data: bool,
}

pub async fn run(args: DeprovisionArgs) -> Result<()> {
    if !is_valid_slug(&args.slug) {
        return Err(anyhow!("invalid slug `{}`", args.slug));
    }

    let meta_pool = meta::connect_meta(&args.postgres_url).await?;

    let registry = TenantRegistry::new(meta_pool.clone());
    let record = registry
        .get(&args.slug)
        .await?
        .ok_or_else(|| anyhow!("tenant `{}` not found", args.slug))?;

    registry.suspend(&args.slug).await?;
    println!("suspended tenant `{}`", args.slug);

    // NOTIFY immediately so the suspend takes effect across running serve
    // processes. A second NOTIFY follows after purge_data — both are safe
    // (extra invalidations are no-ops).
    if let Err(e) = notify::notify_invalidate(&meta_pool, &args.slug).await {
        eprintln!("warning: suspended tenant in DB but NOTIFY failed ({e})");
    }

    if args.purge_data {
        let schema = schema_for_slug(&args.slug);
        if !is_valid_pg_schema(&schema) || schema != record.db_schema {
            return Err(anyhow!(
                "schema mismatch or invalid identifier; refusing to drop"
            ));
        }
        sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(&meta_pool)
            .await?;
        registry.delete(&args.slug).await?;
        // Second NOTIFY after the schema drop. Replicas that came online
        // between the two get a clean signal either way.
        let _ = notify::notify_invalidate(&meta_pool, &args.slug).await;
        println!("purged schema `{schema}` and removed registry row");
    }
    Ok(())
}
