//! Integration tests for the tenant registry.
//!
//! These tests require a running Postgres instance reachable via the
//! `CHALK_TEST_POSTGRES_URL` environment variable. They are marked
//! `#[ignore]` so CI without Postgres does not break. Run locally with:
//!
//!     CHALK_TEST_POSTGRES_URL=postgres://user:pass@localhost/chalk_test \
//!         cargo test -p chalk-hosted --tests -- --ignored

use chalk_hosted::meta;
use chalk_hosted::tenant::{TenantRegistry, TenantStatus};
use sqlx::postgres::PgPoolOptions;

async fn setup() -> (PgPoolOptions, TenantRegistry, sqlx::PgPool) {
    let url = std::env::var("CHALK_TEST_POSTGRES_URL")
        .expect("CHALK_TEST_POSTGRES_URL must be set for ignored tests");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect");
    // Reset the _meta schema so this test is isolated.
    sqlx::raw_sql("DROP SCHEMA IF EXISTS _meta CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    meta::run_migrations(&pool).await.unwrap();
    let reg = TenantRegistry::new(pool.clone());
    (PgPoolOptions::new(), reg, pool)
}

#[tokio::test]
#[ignore]
async fn create_get_activate_suspend_delete() {
    let (_opts, reg, _pool) = setup().await;

    assert!(reg.get("acme").await.unwrap().is_none());

    let rec = reg
        .create("acme", "Acme School", "admin@acme.test")
        .await
        .unwrap();
    assert_eq!(rec.status, TenantStatus::Provisioning);
    assert_eq!(rec.db_schema, "tenant_acme");

    reg.activate("acme").await.unwrap();
    let after = reg.get("acme").await.unwrap().unwrap();
    assert_eq!(after.status, TenantStatus::Active);

    let active = reg.list_active().await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].slug, "acme");

    reg.suspend("acme").await.unwrap();
    let after = reg.get("acme").await.unwrap().unwrap();
    assert_eq!(after.status, TenantStatus::Suspended);

    reg.delete("acme").await.unwrap();
    assert!(reg.get("acme").await.unwrap().is_none());
}

#[tokio::test]
#[ignore]
async fn duplicate_create_errors() {
    let (_opts, reg, _pool) = setup().await;
    reg.create("acme", "A", "a@a.test").await.unwrap();
    let err = reg.create("acme", "A", "a@a.test").await;
    assert!(err.is_err());
}
