//! `deprovision` subcommand — suspend or delete a tenant.

use anyhow::{anyhow, Result};
use chalk_core::config::is_valid_pg_schema;

use crate::meta;
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

    // NOTE: a separate running `serve` process will keep its cached
    // `TenantContext` until it restarts or its LRU evicts the entry. There
    // is no IPC channel today; restart the server after deprovisioning, or
    // wait for the LRU to evict naturally.

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
        println!("purged schema `{schema}` and removed registry row");
    }
    Ok(())
}
