//! Integration test for the Phase 3 per-tenant config loader.
//!
//! Drives `apply_tenant_config` against an in-memory sqlite repo so we can
//! exercise the row -> `ChalkConfig` + filesystem materialization path without
//! needing Postgres. The `TenantContext::build` plumbing on top of this is
//! covered by the existing Postgres-gated integration tests in the same
//! directory.

use std::sync::Arc;

use chalk_core::config::{ChalkConfig, SisProvider};
use chalk_core::db::repository::{
    AdSyncConfigRecord, GoogleSyncConfigRecord, IdpConfigRecord, SisConfigRecord, TenantConfigRepo,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_hosted::keys::MasterKey;
use chalk_hosted::tenant_config::SealingTenantConfigRepo;
use chalk_hosted::tenant_config_loader::apply_tenant_config;
use tempfile::tempdir;

async fn make_sealing() -> (Arc<dyn TenantConfigRepo>, SealingTenantConfigRepo) {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let inner: Arc<dyn TenantConfigRepo> = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!(),
    };
    let sealing = SealingTenantConfigRepo::new(inner.clone(), MasterKey::generate());
    (inner, sealing)
}

#[tokio::test]
async fn loads_sis_powerschool_row_onto_config() {
    let (_inner, sealing) = make_sealing().await;
    sealing
        .put_sis_config(
            SisConfigRecord {
                enabled: true,
                provider: Some("powerschool".into()),
                powerschool_base_url: Some("https://ps.example.com".into()),
                powerschool_token_url: Some("https://ps.example.com/oauth/access_token".into()),
                powerschool_client_id: Some("client-abc".into()),
                powerschool_client_secret: Some(b"hunter2".to_vec()),
                sync_schedule: Some("0 4 * * *".into()),
                ..Default::default()
            },
            "test",
        )
        .await
        .unwrap();

    let dir = tempdir().unwrap();
    let mut cfg = ChalkConfig::generate_default();
    apply_tenant_config(&sealing, &mut cfg, dir.path(), "acme")
        .await
        .unwrap();

    assert!(cfg.sis.enabled);
    assert_eq!(cfg.sis.provider, Some(SisProvider::PowerSchool));
    assert_eq!(cfg.sis.base_url, "https://ps.example.com");
    assert_eq!(
        cfg.sis.token_url.as_deref(),
        Some("https://ps.example.com/oauth/access_token")
    );
    assert_eq!(cfg.sis.client_id, "client-abc");
    assert_eq!(cfg.sis.client_secret, "hunter2");
    assert_eq!(cfg.sis.sync_schedule, "0 4 * * *");
}

#[tokio::test]
async fn loads_google_sync_row_and_writes_service_account_file() {
    let (_inner, sealing) = make_sealing().await;
    let key_bytes = br#"{"type":"service_account","project_id":"x"}"#.to_vec();
    sealing
        .put_google_sync_config(
            GoogleSyncConfigRecord {
                enabled: true,
                workspace_domain: Some("school.edu".into()),
                admin_email: Some("admin@school.edu".into()),
                service_account_key: Some(key_bytes.clone()),
                provision_users: true,
                manage_ous: true,
                suspend_inactive: false,
                sync_schedule: Some("0 3 * * *".into()),
                ..Default::default()
            },
            "test",
        )
        .await
        .unwrap();

    let dir = tempdir().unwrap();
    let mut cfg = ChalkConfig::generate_default();
    apply_tenant_config(&sealing, &mut cfg, dir.path(), "acme")
        .await
        .unwrap();

    assert!(cfg.google_sync.enabled);
    assert_eq!(
        cfg.google_sync.workspace_domain.as_deref(),
        Some("school.edu")
    );
    assert_eq!(
        cfg.google_sync.admin_email.as_deref(),
        Some("admin@school.edu")
    );
    assert!(cfg.google_sync.provision_users);
    assert!(cfg.google_sync.manage_ous);
    assert_eq!(cfg.google_sync.sync_schedule, "0 3 * * *");

    let sa_path = cfg
        .google_sync
        .service_account_key_path
        .as_ref()
        .expect("service_account_key_path should be set");
    let written = std::fs::read(sa_path).expect("service-account file should exist");
    assert_eq!(written, key_bytes);

    let expected_tail = "tenants/acme/google-sa.json";
    assert!(
        sa_path.ends_with(expected_tail),
        "path should live under tenants/<slug>/, got {sa_path}"
    );

    // mode 0600 — verify perms on unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(sa_path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}

#[tokio::test]
async fn loads_idp_row_and_writes_saml_files() {
    let (_inner, sealing) = make_sealing().await;
    sealing
        .put_idp_config(
            IdpConfigRecord {
                enabled: true,
                qr_badge_login: true,
                picture_passwords: false,
                session_timeout_minutes: Some(120),
                default_password_pattern: Some("{lastName}{birthYear}".into()),
                default_password_roles: Some(serde_json::json!(["student", "teacher"])),
                saml_cert: Some(
                    b"-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----\n".to_vec(),
                ),
                saml_signing_key: Some(
                    b"-----BEGIN PRIVATE KEY-----\nMIIBkey\n-----END PRIVATE KEY-----\n".to_vec(),
                ),
                ..Default::default()
            },
            "test",
        )
        .await
        .unwrap();

    let dir = tempdir().unwrap();
    let mut cfg = ChalkConfig::generate_default();
    apply_tenant_config(&sealing, &mut cfg, dir.path(), "acme")
        .await
        .unwrap();

    assert!(cfg.idp.enabled);
    assert!(cfg.idp.qr_badge_login);
    assert_eq!(cfg.idp.session_timeout_minutes, 120);
    assert_eq!(
        cfg.idp.default_password_pattern.as_deref(),
        Some("{lastName}{birthYear}")
    );
    assert_eq!(cfg.idp.default_password_roles, vec!["student", "teacher"]);

    let cert_path = cfg.idp.saml_cert_path.as_ref().expect("saml_cert_path");
    let key_path = cfg.idp.saml_key_path.as_ref().expect("saml_key_path");
    assert!(std::path::Path::new(cert_path).exists());
    assert!(std::path::Path::new(key_path).exists());
}

#[tokio::test]
async fn loads_ad_sync_row_with_ldaps_uri_and_ca_file() {
    let (_inner, sealing) = make_sealing().await;
    sealing
        .put_ad_sync_config(
            AdSyncConfigRecord {
                enabled: true,
                host: Some("dc01.example.com".into()),
                port: Some(636),
                bind_dn: Some("CN=svc,OU=Service Accounts,DC=example,DC=com".into()),
                bind_password: Some(b"bindpw".to_vec()),
                base_dn: Some("DC=example,DC=com".into()),
                user_filter: Some("(objectClass=user)".into()),
                use_tls: true,
                tls_ca_cert: Some(
                    b"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n".to_vec(),
                ),
                sync_schedule: Some("0 5 * * *".into()),
                ou_mapping: None,
                groups: None,
                ..Default::default()
            },
            "test",
        )
        .await
        .unwrap();

    let dir = tempdir().unwrap();
    let mut cfg = ChalkConfig::generate_default();
    apply_tenant_config(&sealing, &mut cfg, dir.path(), "acme")
        .await
        .unwrap();

    assert!(cfg.ad_sync.enabled);
    assert_eq!(
        cfg.ad_sync.connection.server,
        "ldaps://dc01.example.com:636"
    );
    assert_eq!(
        cfg.ad_sync.connection.bind_dn,
        "CN=svc,OU=Service Accounts,DC=example,DC=com"
    );
    assert_eq!(cfg.ad_sync.connection.bind_password, "bindpw");
    assert_eq!(cfg.ad_sync.connection.base_dn, "DC=example,DC=com");
    let ca_path = cfg
        .ad_sync
        .connection
        .tls_ca_cert
        .as_ref()
        .expect("tls_ca_cert path should be set");
    assert!(std::path::Path::new(ca_path).exists());
    assert_eq!(cfg.ad_sync.sync_schedule, "0 5 * * *");
}

#[tokio::test]
async fn empty_db_preserves_defaults() {
    let (_inner, sealing) = make_sealing().await;
    let dir = tempdir().unwrap();
    let mut cfg = ChalkConfig::generate_default();
    apply_tenant_config(&sealing, &mut cfg, dir.path(), "acme")
        .await
        .unwrap();
    assert!(!cfg.sis.enabled);
    assert!(cfg.sis.provider.is_none());
    assert!(cfg.google_sync.service_account_key_path.is_none());
    assert!(cfg.idp.saml_cert_path.is_none());
}
