//! `import-toml` subcommand — migrate a legacy `ChalkConfig` TOML file into
//! the per-tenant database tables.
//!
//! This is the migration bridge for operators moving an existing self-hosted
//! tenant onto the hosted multi-tenant runtime: the per-section TOML config
//! (SIS, Google Sync, IDP, AD Sync) is parsed, file-reference fields are
//! materialised by reading their contents off disk, and each section is
//! upserted into the matching `tenant_config_*` table via the sealing wrapper
//! so secrets ride encrypted at rest.
//!
//! Idempotent: every `put_*_config` call is an upsert, so re-running with the
//! same inputs yields the same DB state.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use chalk_core::config::{is_valid_pg_schema, ChalkConfig};
use chalk_core::db::postgres::PostgresRepository;
use chalk_core::db::repository::{
    AdSyncConfigRecord, GoogleSyncConfigRecord, IdpConfigRecord, SisConfigRecord, TenantConfigRepo,
};
use chalk_core::db::DatabasePool;

use crate::is_valid_slug;
use crate::keys::MasterKey;
use crate::meta;
use crate::tenant::TenantRegistry;
use crate::tenant_config::SealingTenantConfigRepo;

/// Audit actor recorded for every section row written by this command.
pub const IMPORT_ACTOR: &str = "import-toml";

#[derive(Debug, Clone)]
pub struct ImportTomlArgs {
    pub slug: String,
    pub file: PathBuf,
    pub postgres_url: String,
}

/// Per-section summary used for the human-readable stdout report.
#[derive(Debug, Default, Clone)]
pub struct ImportSummary {
    pub sis: SectionSummary,
    pub google_sync: SectionSummary,
    pub idp: SectionSummary,
    pub ad_sync: SectionSummary,
    pub materialized_files: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct SectionSummary {
    pub enabled: bool,
    /// `true` if the row was written. We always write the row (even when
    /// `enabled = false`) so admins can see the staged-but-disabled config.
    pub written: bool,
}

pub async fn run(args: ImportTomlArgs) -> Result<()> {
    let master_key = master_key_from_env()?;

    if !is_valid_slug(&args.slug) {
        return Err(anyhow!("invalid slug `{}`", args.slug));
    }

    let meta_pool = meta::connect_meta(&args.postgres_url).await?;
    let registry = TenantRegistry::new(meta_pool);
    let record = registry
        .get(&args.slug)
        .await?
        .ok_or_else(|| anyhow!("tenant `{}` not found in _meta.tenants", args.slug))?;

    if !is_valid_pg_schema(&record.db_schema) {
        return Err(anyhow!(
            "tenant schema `{}` is not a valid identifier",
            record.db_schema
        ));
    }

    let pool = DatabasePool::new_postgres(&args.postgres_url, &record.db_schema).await?;
    let pg_pool = match pool {
        DatabasePool::Postgres(p) => p,
        _ => return Err(anyhow!("expected postgres pool")),
    };
    let inner: Arc<dyn TenantConfigRepo> =
        Arc::new(PostgresRepository::new(pg_pool, record.db_schema.clone()));
    let repo = SealingTenantConfigRepo::new(inner, master_key);

    let summary = import_from_path(&repo, &args.file).await?;
    print_summary(&args.slug, &record.db_schema, &summary);
    Ok(())
}

fn master_key_from_env() -> Result<MasterKey> {
    let raw = std::env::var("MASTER_ENCRYPTION_KEY").map_err(|_| {
        anyhow!("MASTER_ENCRYPTION_KEY env var must be set to seal imported secrets")
    })?;
    MasterKey::from_base64(&raw)
}

/// Core import routine, factored out for tests. Loads the TOML, materialises
/// referenced files, builds the four records, and upserts them via the
/// supplied repo. The repo is expected to handle sealing.
pub async fn import_from_path<R>(repo: &R, path: &Path) -> Result<ImportSummary>
where
    R: TenantConfigRepo + ?Sized,
{
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading config TOML at {}", path.display()))?;
    let config: ChalkConfig = toml::from_str(&raw)
        .with_context(|| format!("parsing config TOML at {}", path.display()))?;
    import_from_config(repo, &config).await
}

/// Same as `import_from_path` but starts from an already-parsed config. The
/// referenced file fields (`saml_cert_path`, `saml_key_path`,
/// `service_account_key_path`, AD `tls_ca_cert`) are read from disk by this
/// function — the test suite exercises this path with a temp dir.
pub async fn import_from_config<R>(repo: &R, config: &ChalkConfig) -> Result<ImportSummary>
where
    R: TenantConfigRepo + ?Sized,
{
    let mut summary = ImportSummary::default();

    // ----- SIS -----
    let sis_record = build_sis_record(&config.sis);
    summary.sis = SectionSummary {
        enabled: sis_record.enabled,
        written: true,
    };
    repo.put_sis_config(sis_record, IMPORT_ACTOR).await?;

    // ----- Google Sync -----
    let (gsync_record, gsync_file) = build_google_sync_record(&config.google_sync)?;
    if let Some(p) = gsync_file {
        summary.materialized_files.push(p);
    }
    summary.google_sync = SectionSummary {
        enabled: gsync_record.enabled,
        written: true,
    };
    repo.put_google_sync_config(gsync_record, IMPORT_ACTOR)
        .await?;

    // ----- IDP -----
    let (idp_record, idp_files) = build_idp_record(&config.idp)?;
    summary.materialized_files.extend(idp_files);
    summary.idp = SectionSummary {
        enabled: idp_record.enabled,
        written: true,
    };
    repo.put_idp_config(idp_record, IMPORT_ACTOR).await?;

    // ----- AD Sync -----
    let (ad_record, ad_file) = build_ad_sync_record(&config.ad_sync)?;
    if let Some(p) = ad_file {
        summary.materialized_files.push(p);
    }
    summary.ad_sync = SectionSummary {
        enabled: ad_record.enabled,
        written: true,
    };
    repo.put_ad_sync_config(ad_record, IMPORT_ACTOR).await?;

    Ok(summary)
}

fn build_sis_record(sis: &chalk_core::config::SisConfig) -> SisConfigRecord {
    use chalk_core::config::SisProvider;

    // The legacy SisConfig has a single set of OAuth fields (`base_url`,
    // `client_id`, `client_secret`, `token_url`) keyed off `provider`. The DB
    // schema separates them per-provider. Route the values into the right
    // columns based on the selected provider; leave the others as None.
    let mut rec = SisConfigRecord {
        enabled: sis.enabled,
        provider: sis.provider.as_ref().map(|p| p.wire_name().to_string()),
        sync_schedule: Some(sis.sync_schedule.clone()),
        oneroster_csv_dir: sis.csv_dir.clone(),
        ..Default::default()
    };

    let client_secret_bytes = if sis.client_secret.is_empty() {
        None
    } else {
        Some(sis.client_secret.as_bytes().to_vec())
    };
    let base_url_opt = if sis.base_url.is_empty() {
        None
    } else {
        Some(sis.base_url.clone())
    };
    let client_id_opt = if sis.client_id.is_empty() {
        None
    } else {
        Some(sis.client_id.clone())
    };

    match sis.provider {
        Some(SisProvider::PowerSchool) => {
            rec.powerschool_base_url = base_url_opt;
            rec.powerschool_token_url = sis.token_url.clone();
            rec.powerschool_client_id = client_id_opt;
            rec.powerschool_client_secret = client_secret_bytes;
        }
        Some(SisProvider::InfiniteCampus) => {
            rec.infinite_campus_base_url = base_url_opt;
            rec.infinite_campus_client_id = client_id_opt;
            rec.infinite_campus_client_secret = client_secret_bytes;
        }
        Some(SisProvider::Skyward) => {
            rec.skyward_base_url = base_url_opt;
            rec.skyward_client_id = client_id_opt;
            rec.skyward_client_secret = client_secret_bytes;
        }
        Some(SisProvider::OneRosterCsv) | None => {
            // CSV provider uses `csv_dir` (already mapped above). No OAuth
            // values to materialise. When provider is `None`, the OAuth
            // fields are likewise meaningless until an operator picks a
            // provider via the webui.
        }
    }

    rec
}

fn build_google_sync_record(
    gs: &chalk_core::config::GoogleSyncConfig,
) -> Result<(GoogleSyncConfigRecord, Option<String>)> {
    let (key_bytes, materialized) = match gs.service_account_key_path.as_deref() {
        Some(path) if !path.is_empty() => {
            let bytes = std::fs::read(path).with_context(|| {
                format!("reading google_sync.service_account_key_path at {path}")
            })?;
            (Some(bytes), Some(path.to_string()))
        }
        _ => (None, None),
    };

    let rec = GoogleSyncConfigRecord {
        enabled: gs.enabled,
        workspace_domain: gs.workspace_domain.clone(),
        admin_email: gs.admin_email.clone(),
        service_account_key: key_bytes,
        provision_users: gs.provision_users,
        manage_ous: gs.manage_ous,
        suspend_inactive: gs.suspend_inactive,
        sync_schedule: Some(gs.sync_schedule.clone()),
        updated_at: None,
        updated_by: None,
    };
    Ok((rec, materialized))
}

fn build_idp_record(idp: &chalk_core::config::IdpConfig) -> Result<(IdpConfigRecord, Vec<String>)> {
    let mut files = Vec::new();
    let saml_cert = match idp.saml_cert_path.as_deref() {
        Some(p) if !p.is_empty() => {
            let bytes =
                std::fs::read(p).with_context(|| format!("reading idp.saml_cert_path at {p}"))?;
            files.push(p.to_string());
            Some(bytes)
        }
        _ => None,
    };
    let saml_key = match idp.saml_key_path.as_deref() {
        Some(p) if !p.is_empty() => {
            let bytes =
                std::fs::read(p).with_context(|| format!("reading idp.saml_key_path at {p}"))?;
            files.push(p.to_string());
            Some(bytes)
        }
        _ => None,
    };

    let roles_json = if idp.default_password_roles.is_empty() {
        None
    } else {
        Some(serde_json::Value::Array(
            idp.default_password_roles
                .iter()
                .map(|r| serde_json::Value::String(r.clone()))
                .collect(),
        ))
    };

    let rec = IdpConfigRecord {
        enabled: idp.enabled,
        qr_badge_login: idp.qr_badge_login,
        picture_passwords: idp.picture_passwords,
        session_timeout_minutes: Some(idp.session_timeout_minutes as i32),
        default_password_pattern: idp.default_password_pattern.clone(),
        default_password_roles: roles_json,
        saml_cert,
        saml_signing_key: saml_key,
        updated_at: None,
        updated_by: None,
    };
    Ok((rec, files))
}

fn build_ad_sync_record(
    ad: &chalk_core::config::AdSyncConfig,
) -> Result<(AdSyncConfigRecord, Option<String>)> {
    // `connection.tls_ca_cert` is documented as a filesystem path. Treat it
    // as one and materialise the file bytes — operators who want inline
    // PEM can render their config via Tera before running this command.
    let (tls_ca_cert, materialized) = match ad.connection.tls_ca_cert.as_deref() {
        Some(p) if !p.is_empty() => {
            let bytes = std::fs::read(p)
                .with_context(|| format!("reading ad_sync.connection.tls_ca_cert at {p}"))?;
            (Some(bytes), Some(p.to_string()))
        }
        _ => (None, None),
    };

    let bind_password = if ad.connection.bind_password.is_empty() {
        None
    } else {
        Some(ad.connection.bind_password.as_bytes().to_vec())
    };

    let ou_mapping = ad.ou_mapping.as_ref().map(|m| {
        serde_json::json!({
            "students": m.students,
            "teachers": m.teachers,
            "staff": m.staff,
        })
    });

    let groups = ad.groups.as_ref().map(|g| {
        serde_json::json!({
            "enabled": g.enabled,
            "base_ou": g.base_ou,
        })
    });

    // The OSS `AdConnectionConfig.server` is a full `ldap[s]://host[:port]`
    // URI; the DB row splits scheme/host/port into separate columns so the
    // settings UI can present them as discrete fields. Round-trip safety here
    // is critical — otherwise import → load produces `ldap://ldaps://...`.
    // `tls_verify` controls certificate validation, NOT transport; the
    // scheme drives `use_tls`.
    let (use_tls, host, port) =
        match crate::tenant_config_loader::parse_ldap_uri(&ad.connection.server) {
            Some((tls, h, p)) => (tls, Some(h), p),
            None => (true, None, None),
        };

    let rec = AdSyncConfigRecord {
        enabled: ad.enabled,
        host,
        port,
        bind_dn: opt_str(&ad.connection.bind_dn),
        bind_password,
        base_dn: opt_str(&ad.connection.base_dn),
        user_filter: ad.connection.user_filter.clone(),
        use_tls,
        tls_ca_cert,
        sync_schedule: Some(ad.sync_schedule.clone()),
        ou_mapping,
        groups,
        updated_at: None,
        updated_by: None,
    };
    Ok((rec, materialized))
}

fn opt_str(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn print_summary(slug: &str, schema: &str, summary: &ImportSummary) {
    println!("imported TOML config for tenant `{slug}` (schema `{schema}`):");
    for (name, sec) in [
        ("sis", &summary.sis),
        ("google_sync", &summary.google_sync),
        ("idp", &summary.idp),
        ("ad_sync", &summary.ad_sync),
    ] {
        let state = if sec.enabled { "enabled" } else { "disabled" };
        println!("  - {name}: written ({state})");
    }
    if summary.materialized_files.is_empty() {
        println!("  - no referenced files materialised");
    } else {
        println!("  - materialised files:");
        for f in &summary.materialized_files {
            println!("      * {f}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chalk_core::db::sqlite::SqliteRepository;
    use chalk_core::db::DatabasePool;
    use std::io::Write;
    use tempfile::TempDir;

    async fn make_repo() -> (Arc<dyn TenantConfigRepo>, SealingTenantConfigRepo) {
        let pool = DatabasePool::new_sqlite_memory().await.unwrap();
        let sqlite_pool = match pool {
            DatabasePool::Sqlite(p) => p,
            DatabasePool::Postgres(_) => unreachable!(),
        };
        let inner: Arc<dyn TenantConfigRepo> = Arc::new(SqliteRepository::new(sqlite_pool));
        let key = MasterKey::generate();
        let repo = SealingTenantConfigRepo::new(inner.clone(), key);
        (inner, repo)
    }

    /// Build a fixture TOML on disk with referenced cert/key/GSA files. Returns
    /// the directory (held to keep tempfiles alive) and the path of the TOML.
    fn fixture() -> (
        TempDir,
        PathBuf,
        &'static [u8],
        &'static [u8],
        &'static [u8],
    ) {
        let dir = tempfile::tempdir().unwrap();

        let cert_bytes: &'static [u8] = b"-----BEGIN CERT-----\nfake-cert\n-----END CERT-----\n";
        let key_bytes: &'static [u8] = b"-----BEGIN KEY-----\nfake-key\n-----END KEY-----\n";
        let gsa_bytes: &'static [u8] = b"{\"type\":\"service_account\",\"k\":\"v\"}";

        let cert_path = dir.path().join("saml.crt");
        let key_path = dir.path().join("saml.key");
        let gsa_path = dir.path().join("gsa.json");
        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(cert_bytes)
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(key_bytes)
            .unwrap();
        std::fs::File::create(&gsa_path)
            .unwrap()
            .write_all(gsa_bytes)
            .unwrap();

        let toml = format!(
            r#"
[chalk]
instance_name = "acme"
data_dir = "/var/lib/chalk"

[sis]
enabled = true
provider = "powerschool"
base_url = "https://ps.example.edu"
client_id = "ps-client"
client_secret = "ps-secret"
sync_schedule = "0 3 * * *"

[idp]
enabled = true
qr_badge_login = true
picture_passwords = false
saml_cert_path = "{cert}"
saml_key_path = "{key}"
session_timeout_minutes = 240
default_password_pattern = "{{lastName}}{{birthYear}}"
default_password_roles = ["student", "teacher"]

[google_sync]
enabled = true
workspace_domain = "acme.edu"
admin_email = "admin@acme.edu"
service_account_key_path = "{gsa}"
provision_users = true
manage_ous = true

[ad_sync]
enabled = false

[ad_sync.connection]
server = "ldaps://dc.acme.local:636"
bind_dn = "CN=svc,DC=acme,DC=local"
bind_password = "ldap-secret"
base_dn = "DC=acme,DC=local"
"#,
            cert = cert_path.display(),
            key = key_path.display(),
            gsa = gsa_path.display(),
        );

        let toml_path = dir.path().join("chalk.toml");
        std::fs::File::create(&toml_path)
            .unwrap()
            .write_all(toml.as_bytes())
            .unwrap();

        (dir, toml_path, cert_bytes, key_bytes, gsa_bytes)
    }

    #[tokio::test]
    async fn imports_all_sections_with_materialised_files() {
        let (_inner, repo) = make_repo().await;
        let (_dir, toml_path, cert_bytes, key_bytes, gsa_bytes) = fixture();

        let summary = import_from_path(&repo, &toml_path).await.unwrap();
        assert!(summary.sis.written && summary.sis.enabled);
        assert!(summary.google_sync.written && summary.google_sync.enabled);
        assert!(summary.idp.written && summary.idp.enabled);
        assert!(summary.ad_sync.written && !summary.ad_sync.enabled);
        assert_eq!(summary.materialized_files.len(), 3);

        // SIS round-trip — secret should come back as plaintext via the
        // sealing wrapper.
        let sis = repo.get_sis_config().await.unwrap().unwrap();
        assert_eq!(sis.provider.as_deref(), Some("powerschool"));
        assert_eq!(
            sis.powerschool_base_url.as_deref(),
            Some("https://ps.example.edu")
        );
        assert_eq!(sis.powerschool_client_id.as_deref(), Some("ps-client"));
        assert_eq!(
            sis.powerschool_client_secret.as_deref(),
            Some(&b"ps-secret"[..])
        );

        // Google Sync — GSA file bytes were materialised + sealed.
        let gs = repo.get_google_sync_config().await.unwrap().unwrap();
        assert_eq!(gs.workspace_domain.as_deref(), Some("acme.edu"));
        assert_eq!(gs.service_account_key.as_deref(), Some(gsa_bytes));
        assert!(gs.provision_users && gs.manage_ous);

        // IDP — cert + key materialised, roles encoded as JSON array.
        let idp = repo.get_idp_config().await.unwrap().unwrap();
        assert!(idp.enabled);
        assert!(idp.qr_badge_login);
        assert_eq!(idp.saml_cert.as_deref(), Some(cert_bytes));
        assert_eq!(idp.saml_signing_key.as_deref(), Some(key_bytes));
        let roles = idp.default_password_roles.expect("roles should be present");
        let arr = roles.as_array().expect("array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_str(), Some("student"));
        assert_eq!(arr[1].as_str(), Some("teacher"));

        // AD Sync — disabled but row written; bind_password sealed. The
        // importer splits `connection.server` into (use_tls, host, port) so
        // a later `apply_tenant_config` reconstructs the URI cleanly without
        // double-prefixing the scheme.
        let ad = repo.get_ad_sync_config().await.unwrap().unwrap();
        assert!(!ad.enabled);
        assert_eq!(ad.host.as_deref(), Some("dc.acme.local"));
        assert_eq!(ad.port, Some(636));
        assert!(ad.use_tls);
        assert_eq!(ad.bind_password.as_deref(), Some(&b"ldap-secret"[..]));
    }

    #[tokio::test]
    async fn idempotent_double_import() {
        let (_inner, repo) = make_repo().await;
        let (_dir, toml_path, _cert, _key, _gsa) = fixture();

        let first = import_from_path(&repo, &toml_path).await.unwrap();
        let second = import_from_path(&repo, &toml_path).await.unwrap();

        // Reading after each pass should produce identical SIS records.
        let sis1 = repo.get_sis_config().await.unwrap().unwrap();
        // Second pass should not error.
        assert!(second.sis.written);
        let sis2 = repo.get_sis_config().await.unwrap().unwrap();
        assert_eq!(sis1.powerschool_base_url, sis2.powerschool_base_url);
        assert_eq!(
            sis1.powerschool_client_secret,
            sis2.powerschool_client_secret
        );
        // Sanity on first summary.
        assert!(first.sis.enabled);
    }

    #[tokio::test]
    async fn empty_toml_writes_disabled_rows() {
        let (_inner, repo) = make_repo().await;
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("min.toml");
        std::fs::File::create(&toml_path)
            .unwrap()
            .write_all(
                br#"
[chalk]
instance_name = "x"
data_dir = "/tmp"
"#,
            )
            .unwrap();

        let summary = import_from_path(&repo, &toml_path).await.unwrap();
        assert!(summary.sis.written && !summary.sis.enabled);
        assert!(summary.google_sync.written && !summary.google_sync.enabled);
        assert!(summary.idp.written && !summary.idp.enabled);
        assert!(summary.ad_sync.written && !summary.ad_sync.enabled);
        assert!(summary.materialized_files.is_empty());

        let sis = repo.get_sis_config().await.unwrap().unwrap();
        assert!(!sis.enabled);
        assert!(sis.provider.is_none());
    }

    /// Regression: importer used to write the full `ldaps://...:636` URI into
    /// the `host` column and leave `port = None`; the loader then prepended
    /// the scheme again, producing `ldap://ldaps://host:636`. Force the full
    /// import → load cycle and assert the server URI survives intact.
    #[tokio::test]
    async fn ad_server_uri_round_trips_through_import_and_load() {
        let (_inner, repo) = make_repo().await;
        let mut config = ChalkConfig::generate_default();
        config.ad_sync.enabled = true;
        config.ad_sync.connection.server = "ldaps://dc01.example.com:636".into();
        config.ad_sync.connection.bind_dn = "CN=svc,DC=example,DC=com".into();
        config.ad_sync.connection.bind_password = "bindpw".into();
        config.ad_sync.connection.base_dn = "DC=example,DC=com".into();
        config.ad_sync.connection.user_filter = Some("(objectClass=user)".into());

        import_from_config(&repo, &config).await.unwrap();

        // The DB row holds host/port split out; use_tls is derived from scheme.
        let ad = repo.get_ad_sync_config().await.unwrap().unwrap();
        assert_eq!(ad.host.as_deref(), Some("dc01.example.com"));
        assert_eq!(ad.port, Some(636));
        assert!(ad.use_tls);
        assert_eq!(ad.user_filter.as_deref(), Some("(objectClass=user)"));

        // And the loader reconstructs the original URI verbatim.
        let dir = tempfile::tempdir().unwrap();
        let mut reloaded = ChalkConfig::generate_default();
        crate::tenant_config_loader::apply_tenant_config(&repo, &mut reloaded, dir.path(), "acme")
            .await
            .unwrap();
        assert_eq!(
            reloaded.ad_sync.connection.server,
            "ldaps://dc01.example.com:636"
        );
        assert_eq!(
            reloaded.ad_sync.connection.user_filter.as_deref(),
            Some("(objectClass=user)"),
        );
    }
}
