//! Per-tenant `ChalkConfig` materializer.
//!
//! Reads the four `tenant_config_*` sections (via [`SealingTenantConfigRepo`],
//! so secrets arrive in plaintext) and folds them onto a [`ChalkConfig`] that
//! the OSS console / IDP / sync engines consume.
//!
//! Downstream code (Google service-account auth, SAML signing) still reads
//! its credentials from filesystem paths — those paths come from TOML in
//! the self-hosted CLI. In hosted mode the credentials live in the database,
//! so this loader writes them to per-tenant files under
//! `<data_dir>/tenants/<slug>/` and stitches the paths back into the config.
//! `TenantContext`'s `Drop` impl removes the directory when the context is
//! evicted from the LRU.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chalk_core::config::{
    AdConnectionConfig, AdSyncConfig, ChalkConfig, GoogleSyncConfig, IdpConfig, SisConfig,
    SisProvider,
};
use chalk_core::db::repository::{
    AdSyncConfigRecord, GoogleSyncConfigRecord, IdpConfigRecord, SisConfigRecord, TenantConfigRepo,
};

use crate::tenant_config::SealingTenantConfigRepo;

/// Mode bits for materialized secret files (owner read+write only).
const SECRET_FILE_MODE: u32 = 0o600;

/// Parse an LDAP server URI of the form `[ldap[s]://]host[:port]` into
/// `(use_tls, host, port)`. Returns `None` for empty input. Falls back to
/// `use_tls = true` (LDAPS) when the input has no scheme — that's safer than
/// silently downgrading to plaintext.
pub fn parse_ldap_uri(s: &str) -> Option<(bool, String, Option<i32>)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (use_tls, rest) = if let Some(r) = s.strip_prefix("ldaps://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("ldap://") {
        (false, r)
    } else {
        (true, s)
    };
    // Right-split on `:` so IPv6 literals (which contain colons) don't get
    // mistaken for `host:port`. A trailing numeric component is treated as a
    // port; anything else falls back to the whole `rest` being the host.
    if let Some((host, port_str)) = rest.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<i32>() {
            return Some((use_tls, host.to_string(), Some(port)));
        }
    }
    Some((use_tls, rest.to_string(), None))
}

/// Build `[ldap[s]://]host[:port]` from components — inverse of [`parse_ldap_uri`].
pub fn build_ldap_uri(use_tls: bool, host: &str, port: Option<i32>) -> String {
    let scheme = if use_tls { "ldaps" } else { "ldap" };
    match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    }
}

/// Apply all four tenant config sections onto `config`.
///
/// `data_dir` is the hosted runtime's writable state directory (typically
/// `/var/lib/chalk` in production). Per-tenant secret files are written under
/// `<data_dir>/tenants/<slug>/` with mode 0600.
pub async fn apply_tenant_config(
    repo: &SealingTenantConfigRepo,
    config: &mut ChalkConfig,
    data_dir: &Path,
    slug: &str,
) -> Result<()> {
    let tenant_dir = data_dir.join("tenants").join(slug);

    // The four reads are independent — fan out so a tenant cache miss takes
    // one RTT to Postgres instead of four.
    let (sis, google, idp, ad) = tokio::try_join!(
        repo.get_sis_config(),
        repo.get_google_sync_config(),
        repo.get_idp_config(),
        repo.get_ad_sync_config(),
    )?;

    if let Some(record) = sis {
        apply_sis(record, &mut config.sis)?;
    }
    if let Some(record) = google {
        apply_google_sync(record, &mut config.google_sync, &tenant_dir)?;
    }
    if let Some(record) = idp {
        apply_idp(record, &mut config.idp, &tenant_dir)?;
    }
    if let Some(record) = ad {
        apply_ad_sync(record, &mut config.ad_sync, &tenant_dir)?;
    }

    Ok(())
}

fn apply_sis(record: SisConfigRecord, sis: &mut SisConfig) -> Result<()> {
    sis.enabled = record.enabled;
    sis.provider = match record.provider.as_deref() {
        None => None,
        Some(name) => Some(
            SisProvider::from_wire_name(name)
                .ok_or_else(|| anyhow!("unknown SIS provider in DB: {name}"))?,
        ),
    };

    if let Some(schedule) = record.sync_schedule {
        sis.sync_schedule = schedule;
    }

    // SisConfig has a single (base_url, client_id, client_secret, token_url)
    // tuple regardless of provider — pick the row that matches the selected
    // provider so we don't smuggle PowerSchool credentials into a Skyward
    // tenant.
    match sis.provider {
        Some(SisProvider::PowerSchool) => {
            if let Some(v) = record.powerschool_base_url {
                sis.base_url = v;
            }
            sis.token_url = record.powerschool_token_url;
            if let Some(v) = record.powerschool_client_id {
                sis.client_id = v;
            }
            if let Some(bytes) = record.powerschool_client_secret {
                sis.client_secret = String::from_utf8(bytes)
                    .context("powerschool_client_secret is not valid UTF-8")?;
            }
        }
        Some(SisProvider::InfiniteCampus) => {
            if let Some(v) = record.infinite_campus_base_url {
                sis.base_url = v;
            }
            if let Some(v) = record.infinite_campus_client_id {
                sis.client_id = v;
            }
            if let Some(bytes) = record.infinite_campus_client_secret {
                sis.client_secret = String::from_utf8(bytes)
                    .context("infinite_campus_client_secret is not valid UTF-8")?;
            }
        }
        Some(SisProvider::Skyward) => {
            if let Some(v) = record.skyward_base_url {
                sis.base_url = v;
            }
            if let Some(v) = record.skyward_client_id {
                sis.client_id = v;
            }
            if let Some(bytes) = record.skyward_client_secret {
                sis.client_secret =
                    String::from_utf8(bytes).context("skyward_client_secret is not valid UTF-8")?;
            }
        }
        Some(SisProvider::OneRosterCsv) => {
            sis.csv_dir = record.oneroster_csv_dir;
        }
        None => {}
    }

    Ok(())
}

fn apply_google_sync(
    record: GoogleSyncConfigRecord,
    google: &mut GoogleSyncConfig,
    tenant_dir: &Path,
) -> Result<()> {
    google.enabled = record.enabled;
    google.workspace_domain = record.workspace_domain;
    google.admin_email = record.admin_email;
    google.provision_users = record.provision_users;
    google.manage_ous = record.manage_ous;
    google.suspend_inactive = record.suspend_inactive;
    if let Some(schedule) = record.sync_schedule {
        google.sync_schedule = schedule;
    }

    if let Some(key_bytes) = record.service_account_key {
        let path = tenant_dir.join("google-sa.json");
        write_secret_file(&path, &key_bytes)?;
        google.service_account_key_path = Some(path.to_string_lossy().into_owned());
    }

    Ok(())
}

fn apply_idp(record: IdpConfigRecord, idp: &mut IdpConfig, tenant_dir: &Path) -> Result<()> {
    idp.enabled = record.enabled;
    idp.qr_badge_login = record.qr_badge_login;
    idp.picture_passwords = record.picture_passwords;
    if let Some(minutes) = record.session_timeout_minutes {
        // Negative or zero is meaningless; fall back to the existing default.
        if minutes > 0 {
            idp.session_timeout_minutes = minutes as u32;
        }
    }
    idp.default_password_pattern = record.default_password_pattern;
    if let Some(roles_json) = record.default_password_roles {
        let roles: Vec<String> = serde_json::from_value(roles_json)
            .context("idp.default_password_roles is not a JSON array of strings")?;
        idp.default_password_roles = roles;
    }

    if let Some(cert) = record.saml_cert {
        let path = tenant_dir.join("saml-cert.pem");
        write_secret_file(&path, &cert)?;
        idp.saml_cert_path = Some(path.to_string_lossy().into_owned());
    }
    if let Some(key) = record.saml_signing_key {
        let path = tenant_dir.join("saml-key.pem");
        write_secret_file(&path, &key)?;
        idp.saml_key_path = Some(path.to_string_lossy().into_owned());
    }

    Ok(())
}

fn apply_ad_sync(
    record: AdSyncConfigRecord,
    ad: &mut AdSyncConfig,
    tenant_dir: &Path,
) -> Result<()> {
    ad.enabled = record.enabled;
    if let Some(schedule) = record.sync_schedule {
        ad.sync_schedule = schedule;
    }

    let conn: &mut AdConnectionConfig = &mut ad.connection;
    if let Some(host) = record.host.as_deref() {
        conn.server = build_ldap_uri(record.use_tls, host, record.port);
    }
    if let Some(bind_dn) = record.bind_dn {
        conn.bind_dn = bind_dn;
    }
    if let Some(base_dn) = record.base_dn {
        conn.base_dn = base_dn;
    }
    // Plumb the optional LDAP search filter through to the OSS connector. The
    // standalone `use_tls` flag has no direct counterpart on `AdConnectionConfig`
    // (`tls_verify` is a different concept), so it's intentionally not copied.
    conn.user_filter = record.user_filter;

    if let Some(pw) = record.bind_password {
        conn.bind_password =
            String::from_utf8(pw).context("ad bind_password is not valid UTF-8")?;
    }

    if let Some(ca) = record.tls_ca_cert {
        let path = tenant_dir.join("ad-tls-ca.pem");
        write_secret_file(&path, &ca)?;
        conn.tls_ca_cert = Some(path.to_string_lossy().into_owned());
    }

    // ou_mapping + groups: the DB row is `serde_json::Value` because the
    // schema is provider-flexible; OSS expects strongly-typed structs
    // (`AdOuMappingConfig`, `AdGroupConfig`). Decode them best-effort.
    if let Some(json) = record.ou_mapping {
        match serde_json::from_value(json) {
            Ok(mapping) => ad.ou_mapping = Some(mapping),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "ad_sync.ou_mapping JSON did not match AdOuMappingConfig; ignoring"
                );
            }
        }
    }
    if let Some(json) = record.groups {
        match serde_json::from_value(json) {
            Ok(groups) => ad.groups = Some(groups),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "ad_sync.groups JSON did not match AdGroupConfig; ignoring"
                );
            }
        }
    }

    Ok(())
}

/// Write `bytes` to `path` atomically-ish with mode 0600. Creates parents.
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<PathBuf> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create_dir_all {}", parent.display()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true)
        .create(true)
        .truncate(true)
        .mode(SECRET_FILE_MODE);
    let mut f = opts
        .open(path)
        .with_context(|| format!("open {} for write", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    f.sync_all().ok();
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chalk_core::config::ChalkConfig;
    use chalk_core::db::repository::TenantConfigRepo;
    use chalk_core::db::sqlite::SqliteRepository;
    use chalk_core::db::DatabasePool;
    use std::sync::Arc;
    use tempfile::tempdir;

    use crate::keys::MasterKey;

    async fn make_repo() -> (Arc<dyn TenantConfigRepo>, SealingTenantConfigRepo) {
        let pool = DatabasePool::new_sqlite_memory().await.unwrap();
        let inner: Arc<dyn TenantConfigRepo> = match pool {
            DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
            DatabasePool::Postgres(_) => unreachable!(),
        };
        let sealing = SealingTenantConfigRepo::new(inner.clone(), MasterKey::generate());
        (inner, sealing)
    }

    #[test]
    fn parse_ldap_uri_handles_scheme_and_port_variants() {
        assert_eq!(
            parse_ldap_uri("ldaps://dc.example.com:636"),
            Some((true, "dc.example.com".into(), Some(636)))
        );
        assert_eq!(
            parse_ldap_uri("ldap://dc.example.com:389"),
            Some((false, "dc.example.com".into(), Some(389)))
        );
        assert_eq!(
            parse_ldap_uri("ldaps://dc.example.com"),
            Some((true, "dc.example.com".into(), None))
        );
        // No scheme → assume LDAPS so we don't silently downgrade.
        assert_eq!(
            parse_ldap_uri("dc.example.com"),
            Some((true, "dc.example.com".into(), None))
        );
        // IPv6 literal — the right-split would otherwise misparse the host.
        assert!(matches!(
            parse_ldap_uri("ldaps://[2001:db8::1]"),
            Some((true, _, None))
        ));
        assert_eq!(parse_ldap_uri(""), None);
        assert_eq!(parse_ldap_uri("   "), None);
    }

    #[test]
    fn build_then_parse_ldap_uri_round_trips() {
        for (use_tls, host, port) in [
            (true, "dc.example.com", Some(636)),
            (false, "dc.example.com", Some(389)),
            (true, "dc.example.com", None),
        ] {
            let s = build_ldap_uri(use_tls, host, port);
            assert_eq!(parse_ldap_uri(&s), Some((use_tls, host.into(), port)));
        }
    }

    #[tokio::test]
    async fn ad_user_filter_round_trips() {
        let (_inner, sealing) = make_repo().await;
        let dir = tempdir().unwrap();
        let record = AdSyncConfigRecord {
            enabled: true,
            host: Some("dc01.example.com".into()),
            port: Some(636),
            bind_dn: Some("CN=svc,DC=example,DC=com".into()),
            bind_password: None,
            base_dn: Some("DC=example,DC=com".into()),
            user_filter: Some("(objectClass=user)".into()),
            use_tls: true,
            tls_ca_cert: None,
            sync_schedule: None,
            ou_mapping: None,
            groups: None,
            updated_at: None,
            updated_by: None,
        };
        sealing.put_ad_sync_config(record, "test").await.unwrap();

        let mut cfg = ChalkConfig::generate_default();
        apply_tenant_config(&sealing, &mut cfg, dir.path(), "acme")
            .await
            .unwrap();

        assert_eq!(
            cfg.ad_sync.connection.user_filter.as_deref(),
            Some("(objectClass=user)")
        );
    }

    #[tokio::test]
    async fn empty_db_leaves_defaults() {
        let (_inner, sealing) = make_repo().await;
        let dir = tempdir().unwrap();
        let mut cfg = ChalkConfig::generate_default();
        let before_enabled = cfg.sis.enabled;
        apply_tenant_config(&sealing, &mut cfg, dir.path(), "acme")
            .await
            .unwrap();
        assert_eq!(cfg.sis.enabled, before_enabled);
        assert!(cfg.sis.provider.is_none());
        assert!(cfg.google_sync.service_account_key_path.is_none());
    }
}
