use std::path::Path;
use std::sync::Arc;

use axum::http::HeaderValue;
use chalk_core::config::{ChalkConfig, DatabaseDriver};
use chalk_core::db::repository::SsoPartnerRepository;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::sso::{SsoPartner, SsoPartnerSource, SsoProtocol};
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

    let pool = match config.chalk.database.driver {
        DatabaseDriver::Sqlite => {
            let path = config
                .chalk
                .database
                .path
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("SQLite path not configured"))?;
            let connect_str = format!("sqlite:{}?mode=rwc", path);
            DatabasePool::new_sqlite(&connect_str).await?
        }
        DatabaseDriver::Postgres => {
            anyhow::bail!("PostgreSQL is not yet supported");
        }
    };

    let repo = match pool {
        DatabasePool::Sqlite(p) => SqliteRepository::new(p),
    };
    let repo = Arc::new(repo);

    let state = Arc::new(chalk_console::AppState {
        repo: repo.clone(),
        config: config.clone(),
    });
    let mut app = chalk_console::router(state);

    if config.idp.enabled {
        // Resolve SSO partners from all sources
        let partners = resolve_sso_partners(&config, &repo).await;
        info!("Loaded {} SSO partners", partners.len());

        // Load signing key from disk
        let signing_key = load_signing_key(&config);
        let signing_cert = load_signing_cert(&config);

        let idp_state = Arc::new(IdpState {
            repo: repo.clone(),
            config: config.clone(),
            partners: partners.clone(),
            signing_key: signing_key.clone(),
            signing_cert: signing_cert.clone(),
        });
        app = app.nest("/idp", idp_router(idp_state));
        info!("IDP routes mounted at /idp");

        // Mount OIDC provider if we have a signing key
        if let Some(ref key) = signing_key {
            let public_url = config
                .chalk
                .public_url
                .clone()
                .unwrap_or_else(|| "https://chalk.local".to_string());
            let oidc_state = Arc::new(OidcState {
                repo: repo.clone(),
                partners: partners.clone(),
                signing_key: key.clone(),
                public_url,
            });
            app = app.nest("/idp/oidc", oidc_router(oidc_state));
            info!("OIDC provider mounted at /idp/oidc");
        }

        // Mount portal at /portal (student-friendly URL)
        let portal_state = Arc::new(IdpState {
            repo: repo.clone(),
            config: config.clone(),
            partners,
            signing_key,
            signing_cert,
        });
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
async fn resolve_sso_partners(config: &ChalkConfig, repo: &SqliteRepository) -> Vec<SsoPartner> {
    let mut partners: Vec<SsoPartner> = Vec::new();
    let now = Utc::now();

    // 1. Load from TOML config
    for (i, cfg) in config.sso_partners.iter().enumerate() {
        let protocol = match cfg.protocol.as_str() {
            "saml" => SsoProtocol::Saml,
            "oidc" => SsoProtocol::Oidc,
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
            SsoProtocol::Oidc => cfg
                .oidc_client_id
                .clone()
                .unwrap_or_else(|| format!("toml-oidc-{i}")),
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
            saml_entity_id: cfg.saml_entity_id.clone(),
            saml_acs_url: cfg.saml_acs_url.clone(),
            oidc_client_id: cfg.oidc_client_id.clone(),
            oidc_client_secret: cfg.oidc_client_secret.clone(),
            oidc_redirect_uris: cfg.oidc_redirect_uris.clone(),
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
                saml_entity_id: Some(google_entity_id.clone()),
                saml_acs_url: Some(google.google_acs_url.clone()),
                oidc_client_id: None,
                oidc_client_secret: None,
                oidc_redirect_uris: vec![],
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
