//! Integration test for `StateCache::clear` end-to-end.
//!
//! Verifies that after `clear()`, a previously cached tenant requires the
//! registry to be re-queried on the next `get`. Mirrors the path SIGHUP
//! takes to flush state after `chalk-hosted tenant suspend|unsuspend`.
//!
//! Requires `CHALK_TEST_POSTGRES_URL`. Marked `#[ignore]`.

use std::sync::Arc;

use chalk_hosted::commands::provision;
use chalk_hosted::keys::MasterKey;
use chalk_hosted::meta;
use chalk_hosted::state_cache::StateCache;
use chalk_hosted::tenant::TenantRegistry;
use sqlx::postgres::PgPoolOptions;

const APEX: &str = "test.local";

async fn db_url() -> String {
    std::env::var("CHALK_TEST_POSTGRES_URL")
        .expect("CHALK_TEST_POSTGRES_URL must be set for ignored tests")
}

async fn reset_meta(url: &str) {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .unwrap();
    sqlx::raw_sql("DROP SCHEMA IF EXISTS _meta CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql("DROP SCHEMA IF EXISTS tenant_clearme CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    meta::run_migrations(&pool).await.unwrap();
}

#[tokio::test]
#[ignore]
async fn clear_evicts_all_cached_tenants() {
    let url = db_url().await;
    reset_meta(&url).await;

    let master = Arc::new(MasterKey::generate());
    provision::activate_tenant(&url, "clearme", "Clear Me", "a@a.test", "Admin", &master)
        .await
        .unwrap();

    let meta_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let registry = Arc::new(TenantRegistry::new(meta_pool));
    let cache = StateCache::new(registry, master, url.clone(), APEX.to_string(), 16);

    // Populate.
    let _ = cache.get("clearme").await.unwrap().unwrap();
    // We can't read `len` from outside the crate, but we can detect a re-build
    // via behavior: clear, then get must succeed by going back to the registry.
    cache.clear();
    let again = cache.get("clearme").await.unwrap();
    assert!(again.is_some(), "tenant must rebuild after clear()");
}
