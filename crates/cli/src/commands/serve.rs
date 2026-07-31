use std::path::Path;
use std::sync::Arc;

use axum::http::HeaderValue;
use chalk_core::config::{ChalkConfig, DatabaseDriver};
use chalk_core::db::postgres::PostgresRepository;
use chalk_core::db::repository::ChalkRepository;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::sso::{SsoPartner, SsoPartnerSource, SsoProtocol};
use chalk_idp::classlink_compat::{classlink_compat_router, ClassLinkCompatState};
use chalk_idp::clever_compat::{clever_compat_router, CleverCompatState};
use chalk_idp::oidc::{oidc_router, OidcState};
use chalk_idp::routes::{router as idp_router, IdpState};
use chrono::Utc;
use tokio::net::TcpListener;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{info, warn};

/// Run the `serve` command: start the admin console web server.
pub async fn run(config_path: &str, port: u16) -> anyhow::Result<()> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    config.validate()?;

    // 1.4 breaking change: `sis.provider` is no longer implicitly PowerSchool.
    // Surface the misconfiguration loudly at startup so operators upgrading
    // from <=1.3 with `enabled = true` but no provider key notice immediately.
    if config.sis.enabled && config.sis.provider.is_none() {
        warn!(
            "sis.enabled = true but sis.provider is not set. SIS sync will refuse to run. \
             Add `provider = \"powerschool\"` (or another supported provider) under [sis] \
             in your config."
        );
    }

    let (pool, pg_schema) = match config.chalk.database.driver {
        DatabaseDriver::Sqlite => {
            let path = config
                .chalk
                .database
                .path
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("SQLite path not configured"))?;
            let connect_str = format!("sqlite:{}?mode=rwc", path);
            (DatabasePool::new_sqlite(&connect_str).await?, None)
        }
        DatabaseDriver::Postgres => {
            let url = config
                .chalk
                .database
                .url
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("PostgreSQL url not configured"))?;
            let schema = config
                .chalk
                .database
                .schema
                .as_deref()
                .expect("config validation guarantees schema is set for postgres");
            let pool = DatabasePool::new_postgres(url, schema).await?;
            pool.run_migrations_postgres(schema).await?;
            (pool, Some(schema.to_string()))
        }
    };

    let repo: Arc<dyn ChalkRepository> = match &pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p.clone())),
        DatabasePool::Postgres(p) => Arc::new(PostgresRepository::new(
            p.clone(),
            pg_schema.clone().expect("postgres schema set above"),
        )),
    };

    // The asset repository is a standalone trait, so it is constructed
    // alongside `repo` rather than reached through it.
    // One concrete repository, handed over as both traits — they are separate
    // traits for mocking reasons, not because they are separate stores.
    #[allow(clippy::type_complexity)]
    let (assets, asset_events, jobs_repo, sync_state, roster, change_sets): (
        Arc<dyn chalk_core::db::repository::AssetRepository>,
        Arc<dyn chalk_core::db::repository::AssetEventRepository>,
        Arc<dyn chalk_core::db::repository::JobRepository>,
        Arc<dyn chalk_core::db::repository::GoogleDeviceSyncRepository>,
        Arc<dyn chalk_core::db::repository::UserRepository>,
        Arc<dyn chalk_core::db::repository::ChangeSetRepository>,
    ) = match &pool {
        DatabasePool::Sqlite(p) => {
            let r = Arc::new(SqliteRepository::new(p.clone()));
            (r.clone(), r.clone(), r.clone(), r.clone(), r.clone(), r)
        }
        DatabasePool::Postgres(p) => {
            let r = Arc::new(PostgresRepository::new(
                p.clone(),
                pg_schema.clone().expect("postgres schema set above"),
            ));
            (r.clone(), r.clone(), r.clone(), r.clone(), r.clone(), r)
        }
    };
    let tenant_config_inner: Arc<dyn chalk_core::db::repository::TenantConfigRepo> = match &pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p.clone())),
        DatabasePool::Postgres(p) => Arc::new(PostgresRepository::new(
            p.clone(),
            pg_schema.clone().expect("postgres schema set above"),
        )),
    };
    let change_sets_for_jobs = change_sets.clone();
    let jobs_for_console = jobs_repo.clone();
    let runs_for_console = sync_state.clone();
    let assets_for_jobs = assets.clone();
    let events_for_jobs = asset_events.clone();
    let state_for_jobs = sync_state;
    let roster_for_jobs = roster;

    // Sealed per-tenant config, if a master key is on disk.
    //
    // `chalk init` writes `chalk.key`, so this is present on any install set up
    // the normal way. An install missing it — an upgrade from before the key
    // existed, or a hand-assembled data directory — keeps the previous
    // behaviour: settings pages say "not configured" and TOML remains the only
    // source. That is a degraded mode, not a failure, so it warns rather than
    // refusing to start a server that otherwise works.
    let key_path = std::path::Path::new(&config.chalk.data_dir).join("chalk.key");
    let sealing: Option<Arc<dyn chalk_core::db::repository::TenantConfigRepo>> =
        match chalk_core::db::sealing::SealingConfigRepo::load_key(&key_path) {
            Ok(master_key) => {
                info!("Per-tenant configuration is stored sealed in the database");
                Some(Arc::new(chalk_core::db::sealing::SealingConfigRepo::new(
                    tenant_config_inner,
                    master_key,
                )))
            }
            Err(e) => {
                warn!(
                    "no usable master key at {} ({e}); settings pages will stay \
                     read-only and configuration comes from chalk.toml alone",
                    key_path.display()
                );
                None
            }
        };

    // The worker gets the same sealed config the console writes to, so a key
    // uploaded through the browser is the one the next sync uses.
    let sealing_for_jobs = sealing.clone();

    let mut state = chalk_console::AppState::new(repo.clone(), config.clone())
        .with_assets(assets, asset_events)
        .with_device_sync(jobs_for_console, runs_for_console)
        .with_change_sets(change_sets);
    if let Some(repo) = sealing {
        state = state.with_tenant_config(repo);
    }
    let state = Arc::new(state);
    // The background worker. Started before the server binds so an operator
    // never sees a queue that accepts work nothing is draining.
    //
    // Spawning it here rather than reaching into the console is the whole
    // point of the job design: the console enqueues rows through
    // `JobRepository` and knows nothing about `chalk-devices`, while this
    // binary — which already depends on it — supplies the handler.
    // Started whenever a credential could exist in either source. Gating on
    // the TOML flag alone would leave the worker down on exactly the install
    // that just configured Google through the console.
    if config.device_sync.enabled || sealing_for_jobs.is_some() {
        let runner = crate::jobs::build_runner(
            config.clone(),
            jobs_repo,
            (
                assets_for_jobs,
                events_for_jobs,
                state_for_jobs,
                roster_for_jobs,
            ),
            sealing_for_jobs,
            change_sets_for_jobs,
        );
        tokio::spawn(runner.run_forever());
        info!("Background job worker started");
    } else {
        info!("Device sync disabled — background job worker not started");
    }

    let mut app = chalk_console::router(state);

    if config.idp.enabled {
        // Resolve SSO partners from all sources
        let partners = resolve_sso_partners(&config, repo.as_ref()).await;
        info!("Loaded {} SSO partners", partners.len());

        // Load signing key from disk
        let signing_key = load_signing_key(&config);
        let signing_cert = load_signing_cert(&config);

        let idp_state = Arc::new(IdpState::new(
            repo.clone(),
            config.clone(),
            partners.clone(),
            signing_key.clone(),
            signing_cert.clone(),
        ));
        app = app.nest("/idp", idp_router(idp_state));
        info!("IDP routes mounted at /idp");

        // Mount OIDC provider if we have a signing key
        if let Some(ref key) = signing_key {
            let public_url = config
                .chalk
                .public_url
                .clone()
                .unwrap_or_else(|| "https://chalk.local".to_string());
            let oidc_state = Arc::new(OidcState::new(
                repo.clone(),
                partners.clone(),
                key.clone(),
                public_url,
            ));
            app = app.nest("/idp/oidc", oidc_router(oidc_state));
            info!("OIDC provider mounted at /idp/oidc");
        }

        // Mount Clever-compatible routes at root level
        let has_clever_partners = partners
            .iter()
            .any(|p| p.protocol == SsoProtocol::CleverCompat && p.enabled);
        if has_clever_partners {
            if let Some(ref key) = signing_key {
                let public_url = config
                    .chalk
                    .public_url
                    .clone()
                    .unwrap_or_else(|| "https://chalk.local".to_string());

                let district_id = config.chalk.instance_name.replace(' ', "-").to_lowercase();
                let clever_state = Arc::new(CleverCompatState::new(
                    repo.clone(),
                    partners
                        .iter()
                        .filter(|p| p.protocol == SsoProtocol::CleverCompat)
                        .cloned()
                        .collect(),
                    key.clone(),
                    public_url.clone(),
                    district_id,
                    config.chalk.instance_name.clone(),
                ));
                app = app.merge(clever_compat_router(clever_state));
                info!("Clever-compatible SSO routes mounted");
            } else {
                warn!("Clever-compatible partners configured but no signing key available");
            }
        }

        // Mount ClassLink-compatible routes at root level
        let has_classlink_partners = partners
            .iter()
            .any(|p| p.protocol == SsoProtocol::ClassLinkCompat && p.enabled);
        if has_classlink_partners {
            if let Some(ref key) = signing_key {
                let public_url = config
                    .chalk
                    .public_url
                    .clone()
                    .unwrap_or_else(|| "https://chalk.local".to_string());
                let classlink_state = Arc::new(ClassLinkCompatState::new(
                    repo.clone(),
                    partners
                        .iter()
                        .filter(|p| p.protocol == SsoProtocol::ClassLinkCompat)
                        .cloned()
                        .collect(),
                    key.clone(),
                    public_url,
                ));
                app = app.merge(classlink_compat_router(classlink_state));
                info!("ClassLink-compatible SSO routes mounted");
            } else {
                warn!("ClassLink-compatible partners configured but no signing key available");
            }
        }

        // Mount portal at /portal (student-friendly URL)
        let portal_state = Arc::new(IdpState::new(
            repo.clone(),
            config.clone(),
            partners,
            signing_key,
            signing_cert,
        ));
        app = app.nest("/portal", chalk_idp::portal::portal_router(portal_state));
        info!("Student portal mounted at /portal");

        // Log deprecation notice for legacy [idp.google] config
        if config.idp.google.is_some() {
            warn!(
                "The [idp.google] config section is deprecated. \
                 Consider migrating to [[sso_partners]] format for Google SSO."
            );
        }
    }

    // Add security headers
    let app = app
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ));

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;

    println!("Chalk admin console listening on http://{}", addr);
    info!("Starting server on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Server shut down gracefully");
    Ok(())
}

/// Resolve SSO partners from TOML config, database, and legacy Google config.
///
/// Priority: TOML entries take precedence over DB entries (matched by entity_id
/// or client_id). Legacy `[idp.google]` config is synthesized as a partner if
/// no matching partner already exists.
async fn resolve_sso_partners(config: &ChalkConfig, repo: &dyn ChalkRepository) -> Vec<SsoPartner> {
    let mut partners: Vec<SsoPartner> = Vec::new();
    let now = Utc::now();

    // 1. Load from TOML config
    for (i, cfg) in config.sso_partners.iter().enumerate() {
        let protocol = match cfg.protocol.as_str() {
            "saml" => SsoProtocol::Saml,
            "oidc" => SsoProtocol::Oidc,
            "clever-compatible" | "clever_compat" => SsoProtocol::CleverCompat,
            "classlink-compatible" | "classlink_compat" => SsoProtocol::ClassLinkCompat,
            other => {
                warn!(
                    "Unknown SSO protocol '{}' for partner '{}', skipping",
                    other, cfg.name
                );
                continue;
            }
        };

        let id = match protocol {
            SsoProtocol::Saml => cfg
                .saml_entity_id
                .clone()
                .unwrap_or_else(|| format!("toml-saml-{i}")),
            SsoProtocol::Oidc | SsoProtocol::CleverCompat | SsoProtocol::ClassLinkCompat => cfg
                .oidc_client_id
                .clone()
                .unwrap_or_else(|| format!("toml-oidc-{i}")),
            SsoProtocol::Link => format!("toml-link-{i}"),
        };

        partners.push(SsoPartner {
            id,
            name: cfg.name.clone(),
            logo_url: cfg.logo_url.clone(),
            protocol,
            enabled: cfg.enabled,
            source: SsoPartnerSource::Toml,
            tenant_id: None,
            roles: cfg.roles.clone(),
            audience: None,
            saml_entity_id: cfg.saml_entity_id.clone(),
            saml_acs_url: cfg.saml_acs_url.clone(),
            oidc_client_id: cfg.oidc_client_id.clone(),
            oidc_client_secret: cfg.oidc_client_secret.clone(),
            oidc_redirect_uris: cfg.oidc_redirect_uris.clone(),
            launch_url: None,
            created_at: now,
            updated_at: now,
        });
    }

    // 2. Load from database (DB-sourced or marketplace-sourced partners)
    match repo.list_sso_partners().await {
        Ok(db_partners) => {
            for db_partner in db_partners {
                // Skip if a TOML partner already covers this entity_id or client_id
                let already_exists = partners.iter().any(|p| {
                    if let (Some(a), Some(b)) = (&p.saml_entity_id, &db_partner.saml_entity_id) {
                        if a == b {
                            return true;
                        }
                    }
                    if let (Some(a), Some(b)) = (&p.oidc_client_id, &db_partner.oidc_client_id) {
                        if a == b {
                            return true;
                        }
                    }
                    false
                });

                if !already_exists {
                    partners.push(db_partner);
                }
            }
        }
        Err(e) => {
            warn!("Failed to load SSO partners from database: {e}");
        }
    }

    // 3. Synthesize Google SSO as a partner if configured and not already present
    if let Some(ref google) = config.idp.google {
        let google_entity_id = &google.google_entity_id;
        let already_exists = partners
            .iter()
            .any(|p| p.saml_entity_id.as_deref() == Some(google_entity_id));

        if !already_exists {
            partners.push(SsoPartner {
                id: format!("google-{}", google.workspace_domain),
                name: format!("Google Workspace ({})", google.workspace_domain),
                logo_url: None,
                protocol: SsoProtocol::Saml,
                enabled: true,
                source: SsoPartnerSource::Toml,
                tenant_id: None,
                roles: vec![],
                audience: None,
                saml_entity_id: Some(google_entity_id.clone()),
                saml_acs_url: Some(google.google_acs_url.clone()),
                oidc_client_id: None,
                oidc_client_secret: None,
                oidc_redirect_uris: vec![],
                launch_url: None,
                created_at: now,
                updated_at: now,
            });
        }
    }

    partners
}

/// Load the SAML signing private key from disk.
fn load_signing_key(config: &ChalkConfig) -> Option<Vec<u8>> {
    let key_path = config.idp.saml_key_path.as_deref()?;
    match std::fs::read(key_path) {
        Ok(bytes) => {
            info!("Loaded SAML signing key from {key_path}");
            Some(bytes)
        }
        Err(e) => {
            warn!("Failed to load SAML signing key from {key_path}: {e}");
            None
        }
    }
}

/// Load the SAML signing certificate from disk.
fn load_signing_cert(config: &ChalkConfig) -> Option<String> {
    let cert_path = config.idp.saml_cert_path.as_deref()?;
    match std::fs::read_to_string(cert_path) {
        Ok(pem) => {
            // Strip PEM headers/footers and whitespace for embedding in XML
            let cert_base64 = pem
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<Vec<_>>()
                .join("");
            info!("Loaded SAML signing certificate from {cert_path}");
            Some(cert_base64)
        }
        Err(e) => {
            warn!("Failed to load SAML signing certificate from {cert_path}: {e}");
            None
        }
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler");
    info!("Received shutdown signal");
}
