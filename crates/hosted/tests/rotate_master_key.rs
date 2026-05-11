//! Integration tests for `chalk-hosted rotate-master-key`.
//!
//! Requires Postgres reachable via `CHALK_TEST_POSTGRES_URL`. Marked
//! `#[ignore]` so CI without Postgres skips them.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chalk_hosted::commands::rotate_master_key;
use chalk_hosted::keys::{self, MasterKey};
use chalk_hosted::meta;
use chalk_hosted::tenant::TenantRegistry;
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
async fn rotate_rewraps_existing_secrets() {
    let (pool, reg) = setup().await;
    reg.create("acme", "Acme", "a@a.test").await.unwrap();

    let old_key = MasterKey::generate();
    let new_key = MasterKey::generate();

    let saml_blob = keys::generate_saml_blob("acme.test").unwrap();
    let oidc_blob = keys::generate_oidc_signing_key().unwrap();
    let sealed_saml = keys::seal(&old_key, &saml_blob).unwrap();
    let sealed_oidc = keys::seal(&old_key, &oidc_blob).unwrap();

    reg.set_sealed_keys("acme", &sealed_saml, &sealed_oidc)
        .await
        .unwrap();

    let summary = rotate_master_key::rotate_all(&pool, &old_key, &new_key)
        .await
        .unwrap();
    assert_eq!(summary.rotated, 1);
    assert_eq!(summary.already_rotated, 0);

    // After rotation, sealed material must unseal with the NEW key only.
    let row: (Option<Vec<u8>>, Option<serde_json::Value>) = sqlx::query_as(
        "SELECT saml_keypair, oidc_signing_jwk FROM _meta.tenants WHERE slug = 'acme'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let saml_after = row.0.expect("saml_keypair must be set");
    assert!(keys::unseal(&new_key, &saml_after).is_ok());
    assert!(keys::unseal(&old_key, &saml_after).is_err());

    let oidc_envelope = row.1.expect("oidc_signing_jwk must be set");
    let oidc_b64 = oidc_envelope.get("sealed").unwrap().as_str().unwrap();
    let oidc_after = B64.decode(oidc_b64).unwrap();
    assert!(keys::unseal(&new_key, &oidc_after).is_ok());
    assert!(keys::unseal(&old_key, &oidc_after).is_err());
}

#[tokio::test]
#[ignore]
async fn rotate_is_idempotent_on_retry() {
    let (pool, reg) = setup().await;
    reg.create("acme", "Acme", "a@a.test").await.unwrap();

    let old_key = MasterKey::generate();
    let new_key = MasterKey::generate();

    let saml_blob = keys::generate_saml_blob("acme.test").unwrap();
    let oidc_blob = keys::generate_oidc_signing_key().unwrap();
    let sealed_saml = keys::seal(&old_key, &saml_blob).unwrap();
    let sealed_oidc = keys::seal(&old_key, &oidc_blob).unwrap();
    reg.set_sealed_keys("acme", &sealed_saml, &sealed_oidc)
        .await
        .unwrap();

    let first = rotate_master_key::rotate_all(&pool, &old_key, &new_key)
        .await
        .unwrap();
    assert_eq!(first.rotated, 1);

    // Re-running with the same arguments should detect already-rotated rows
    // and report zero rotations.
    let second = rotate_master_key::rotate_all(&pool, &old_key, &new_key)
        .await
        .unwrap();
    assert_eq!(second.rotated, 0);
    assert_eq!(second.already_rotated, 1);
}

#[tokio::test]
#[ignore]
async fn rotate_aborts_when_blob_unsealable_with_either_key() {
    let (pool, reg) = setup().await;
    reg.create("rogue", "Rogue", "r@r.test").await.unwrap();

    let old_key = MasterKey::generate();
    let new_key = MasterKey::generate();
    let stranger = MasterKey::generate();
    let blob = keys::seal(&stranger, b"unknown").unwrap();
    reg.set_sealed_keys("rogue", &blob, &blob).await.unwrap();

    let err = rotate_master_key::rotate_all(&pool, &old_key, &new_key).await;
    let msg = format!("{:#}", err.unwrap_err());
    assert!(msg.contains("rogue"), "error must name the bad slug: {msg}");
}

#[tokio::test]
#[ignore]
async fn rotate_skips_tenant_with_no_sealed_material() {
    let (pool, reg) = setup().await;
    reg.create("empty", "Empty", "e@e.test").await.unwrap();
    let old_key = MasterKey::generate();
    let new_key = MasterKey::generate();
    let summary = rotate_master_key::rotate_all(&pool, &old_key, &new_key)
        .await
        .unwrap();
    assert_eq!(summary.rotated, 0);
    assert_eq!(summary.already_rotated, 0);
}
