//! `migrate-all` subcommand — re-run OSS migrations against every active
//! tenant schema, with bounded concurrency.

use anyhow::Result;
use chalk_core::db::DatabasePool;
use futures_util::stream::{self, StreamExt};

use crate::meta;
use crate::tenant::TenantRegistry;

#[derive(Debug, Clone)]
pub struct MigrateAllArgs {
    pub postgres_url: String,
    pub concurrency: usize,
}

pub async fn run(args: MigrateAllArgs) -> Result<()> {
    let meta_pool = meta::connect_meta(&args.postgres_url).await?;
    let registry = TenantRegistry::new(meta_pool);
    let tenants = registry.list_active().await?;
    println!("migrating {} active tenants", tenants.len());

    let url = args.postgres_url.clone();
    let concurrency = args.concurrency.max(1);

    let results: Vec<(String, Result<()>)> = stream::iter(tenants)
        .map(|t| {
            let url = url.clone();
            async move {
                let res = migrate_one(&url, &t.db_schema).await;
                (t.slug, res)
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let mut failed = 0;
    for (slug, res) in &results {
        match res {
            Ok(()) => println!("ok    {slug}"),
            Err(e) => {
                failed += 1;
                println!("FAIL  {slug}: {e}");
            }
        }
    }
    if failed > 0 {
        anyhow::bail!("{failed} tenant(s) failed to migrate");
    }
    Ok(())
}

async fn migrate_one(url: &str, schema: &str) -> Result<()> {
    let pool = DatabasePool::new_postgres(url, schema).await?;
    pool.run_migrations_postgres(schema).await?;
    Ok(())
}
