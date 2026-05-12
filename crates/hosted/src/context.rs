//! Per-tenant runtime context: pool, repository, and OSS state structs.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use axum::Router;
use chalk_console::AppState;
use chalk_core::config::ChalkConfig;
use chalk_core::db::postgres::PostgresRepository;
use chalk_core::db::repository::ChalkRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::sso::SsoProtocol;
use chalk_idp::classlink_compat::{classlink_compat_router, ClassLinkCompatState};
use chalk_idp::clever_compat::{clever_compat_router, CleverCompatState};
use chalk_idp::oidc::OidcState;
use chalk_idp::portal::portal_router;
use chalk_idp::routes::IdpState;
use tokio::sync::Semaphore;

use crate::keys::{self, MasterKey};
use crate::state_cache::StateCacheConfig;
use crate::tenant::{SealedTenantKeys, TenantId, TenantRecord};
use crate::tenant_assert::TenantScopedRepository;

/// Default per-tenant in-flight request cap (noisy-neighbor protection).
pub const DEFAULT_TENANT_CONCURRENCY: usize = 32;

/// Per-tenant runtime context. Built lazily by the `StateCache` on first
/// request and held behind an `Arc` so cheap clones can flow into Axum
/// handlers via request extensions.
pub struct TenantContext {
    pub tenant: TenantId,
    pub display_name: String,
    pub db_schema: String,
    pub repo: Arc<dyn ChalkRepository>,
    pub public_url: String,
    pub console_state: Arc<AppState>,
    pub idp_state: Arc<IdpState>,
    pub oidc_state: Arc<OidcState>,
    /// Composed Axum router for this tenant — console + idp + oidc + portal,
    /// each branch wired with this tenant's state. The dispatch closure in
    /// `commands::serve::tenant_router` calls `.clone().oneshot(req)` on this
    /// to hand the request to OSS routes.
    pub app_router: Router,
    /// Per-tenant in-flight request limiter. `resolve_tenant` acquires a
    /// permit before invoking the inner handler; if the cap is saturated
    /// the request is rejected with 503.
    pub concurrency: Arc<Semaphore>,
}

impl TenantContext {
    /// Build a `TenantContext` for the given tenant record.
    ///
    /// Opens a fresh Postgres pool with `search_path` pinned to the tenant's
    /// schema, wraps it in a `PostgresRepository`, and constructs the OSS
    /// state structs. Sealed SAML/OIDC material is unsealed using the master
    /// key. If a tenant has no sealed material yet (legacy rows), the IDP
    /// state is built with empty signing keys and IDP routes will fail until
    /// the tenant is re-provisioned.
    #[allow(clippy::too_many_arguments)]
    pub async fn build(
        record: &TenantRecord,
        sealed: SealedTenantKeys,
        master_key: &MasterKey,
        postgres_url: &str,
        apex: &str,
        public_scheme: &str,
        public_port: Option<u16>,
        cache_config: StateCacheConfig,
    ) -> Result<Arc<Self>> {
        let pool = DatabasePool::new_postgres_with_max_connections(
            postgres_url,
            &record.db_schema,
            cache_config.pool_max_connections,
        )
        .await
        .map_err(|e| anyhow!("failed to open tenant pool {}: {e}", record.db_schema))?;

        let pg_pool = match pool {
            DatabasePool::Postgres(p) => p,
            _ => return Err(anyhow!("expected postgres pool")),
        };

        let inner_repo: Arc<dyn ChalkRepository> =
            Arc::new(PostgresRepository::new(pg_pool, record.db_schema.clone()));
        // Wrap in a schema-asserting facade. Every method call validates
        // CURRENT_TENANT_SCHEMA matches the schema this pool was opened with,
        // catching cross-tenant Arc bleed-through.
        let repo: Arc<dyn ChalkRepository> = Arc::new(TenantScopedRepository::new(
            inner_repo,
            record.db_schema.clone(),
        ));

        // Synthesize a per-tenant config. We intentionally do not parse a
        // file-based config in hosted mode — feature flags are off by default
        // and Wave B will load tenant config rows from the DB.
        let mut config = ChalkConfig::generate_default();
        config.chalk.instance_name = record.display_name.clone();
        // The synthesized config drives the OSS console's display labels.
        // Reflect the actual backing store so the dashboard doesn't show the
        // default SQLite path for a Postgres tenant.
        config.chalk.database.driver = chalk_core::config::DatabaseDriver::Postgres;
        config.chalk.database.url = Some(postgres_url.to_string());
        config.chalk.database.schema = Some(record.db_schema.clone());
        config.chalk.database.path = None;
        let public_url = crate::public_url(public_scheme, Some(&record.slug), apex, public_port);
        config.chalk.public_url = Some(public_url.clone());

        let console_state = Arc::new(AppState::new(repo.clone(), config.clone()));

        // Unseal SAML keypair if present.
        let (saml_signing_key, saml_signing_cert) = match sealed.saml_keypair {
            Some(blob) => {
                let opened = keys::unseal(master_key, &blob)?;
                let pair = keys::decode_saml_blob(&opened)?;
                let cert_b64 = pair
                    .cert_pem
                    .lines()
                    .filter(|l| !l.starts_with("-----"))
                    .collect::<Vec<_>>()
                    .join("");
                (Some(pair.key_pem.into_bytes()), Some(cert_b64))
            }
            None => (None, None),
        };

        let idp_state = Arc::new(IdpState::new(
            repo.clone(),
            config.clone(),
            Vec::new(),
            saml_signing_key.clone(),
            saml_signing_cert,
        ));

        // Unseal OIDC signing key if present.
        let oidc_key = match sealed.oidc_signing_jwk {
            Some(blob) => keys::unseal(master_key, &blob)?,
            None => Vec::new(),
        };

        let oidc_state = Arc::new(OidcState::new(
            repo.clone(),
            Vec::new(),
            oidc_key,
            public_url.clone(),
        ));

        // Compose tenant routes the same way the OSS `chalk serve` does:
        // console at root, idp/oidc/portal under their own prefixes. Using
        // `.merge` on all of them collides on `GET /login` (console's admin
        // login vs portal's user login). Clever- and ClassLink-compat routers
        // are merged at root only when at least one enabled partner uses that
        // protocol — that mirrors `crates/cli/src/commands/serve.rs:103..160`.
        let partners = repo.list_sso_partners().await.unwrap_or_default();

        let mut app_router = chalk_console::router(console_state.clone())
            .nest("/idp", chalk_idp::routes::router(idp_state.clone()))
            .nest(
                "/idp/oidc",
                chalk_idp::oidc::oidc_router(oidc_state.clone()),
            )
            .nest("/portal", portal_router(idp_state.clone()));

        if let Some(ref signing_key) = saml_signing_key {
            let clever_partners: Vec<_> = partners
                .iter()
                .filter(|p| p.protocol == SsoProtocol::CleverCompat && p.enabled)
                .cloned()
                .collect();
            if !clever_partners.is_empty() {
                let district_id = record.slug.clone();
                let clever_state = Arc::new(CleverCompatState::new(
                    repo.clone(),
                    clever_partners,
                    signing_key.clone(),
                    public_url.clone(),
                    district_id,
                    record.display_name.clone(),
                ));
                app_router = app_router.merge(clever_compat_router(clever_state));
            }

            let classlink_partners: Vec<_> = partners
                .iter()
                .filter(|p| p.protocol == SsoProtocol::ClassLinkCompat && p.enabled)
                .cloned()
                .collect();
            if !classlink_partners.is_empty() {
                let classlink_state = Arc::new(ClassLinkCompatState::new(
                    repo.clone(),
                    classlink_partners,
                    signing_key.clone(),
                    public_url.clone(),
                ));
                app_router = app_router.merge(classlink_compat_router(classlink_state));
            }
        }

        Ok(Arc::new(TenantContext {
            tenant: TenantId(record.slug.clone()),
            display_name: record.display_name.clone(),
            db_schema: record.db_schema.clone(),
            repo,
            public_url,
            console_state,
            idp_state,
            oidc_state,
            app_router,
            concurrency: Arc::new(Semaphore::new(cache_config.tenant_concurrency.max(1))),
        }))
    }
}
