//! Integration tests for `chalk-hosted tenant suspend|unsuspend`.
//!
//! Requires Postgres reachable via `CHALK_TEST_POSTGRES_URL`. Marked
//! `#[ignore]` so CI without Postgres skips them. Run locally with:
//!
//!     CHALK_TEST_POSTGRES_URL=postgres://user:pass@localhost/chalk_test \
//!         cargo test -p chalk-hosted --tests -- --ignored

use chalk_hosted::commands::tenant as tenant_cmd;
use chalk_hosted::meta;
use chalk_hosted::tenant::{TenantRegistry, TenantStatus};
use sqlx::postgres::PgPoolOptions;

async fn setup() -> (sqlx::PgPool, TenantRegistry) {
    let url = std::env::var("CHALK_TEST_POSTGRES_URL")
        .expect("CHALK_TEST_POSTGRES_URL must be set for ignored tests");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect");
    sqlx::raw_sql("DROP SCHEMA IF EXISTS _meta CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    meta::run_migrations(&pool).await.unwrap();
    let reg = TenantRegistry::new(pool.clone());
    (pool, reg)
}

#[tokio::test]
#[ignore]
async fn suspend_then_unsuspend_cycle() {
    let (pool, reg) = setup().await;
    reg.create("acme", "Acme School", "admin@acme.test")
        .await
        .unwrap();
    reg.activate("acme").await.unwrap();

    tenant_cmd::suspend_tenant(&pool, "acme").await.unwrap();
    let after = reg.get("acme").await.unwrap().unwrap();
    assert_eq!(after.status, TenantStatus::Suspended);

    tenant_cmd::unsuspend_tenant(&pool, "acme").await.unwrap();
    let after = reg.get("acme").await.unwrap().unwrap();
    assert_eq!(after.status, TenantStatus::Active);
}

#[tokio::test]
#[ignore]
async fn suspend_nonexistent_slug_errors() {
    let (pool, _reg) = setup().await;
    let err = tenant_cmd::suspend_tenant(&pool, "ghost").await;
    assert!(err.is_err(), "expected error for missing slug");
}

#[tokio::test]
#[ignore]
async fn suspend_already_suspended_errors() {
    let (pool, reg) = setup().await;
    reg.create("acme", "Acme", "a@a.test").await.unwrap();
    reg.activate("acme").await.unwrap();
    tenant_cmd::suspend_tenant(&pool, "acme").await.unwrap();
    // Second call must fail because the tenant is no longer 'active'.
    let err = tenant_cmd::suspend_tenant(&pool, "acme").await;
    assert!(err.is_err());
}

#[tokio::test]
#[ignore]
async fn unsuspend_active_tenant_errors() {
    let (pool, reg) = setup().await;
    reg.create("acme", "Acme", "a@a.test").await.unwrap();
    reg.activate("acme").await.unwrap();
    let err = tenant_cmd::unsuspend_tenant(&pool, "acme").await;
    assert!(err.is_err());
}
