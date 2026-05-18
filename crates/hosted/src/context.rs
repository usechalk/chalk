//! Per-tenant runtime context: pool, repository, and OSS state structs.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use axum::Router;
use chalk_console::{AppState, SsoInvalidator};
use chalk_core::config::ChalkConfig;
use chalk_core::db::postgres::PostgresRepository;
use chalk_core::db::repository::{ChalkRepository, TenantConfigRepo};
use chalk_core::db::DatabasePool;
use chalk_core::models::sso::SsoProtocol;
use chalk_idp::classlink_compat::{classlink_compat_router, ClassLinkCompatState};
use chalk_idp::clever_compat::{clever_compat_router, CleverCompatState};
use chalk_idp::oidc::OidcState;
use chalk_idp::portal::portal_router;
use chalk_idp::routes::IdpState;
use tokio::sync::Semaphore;

use crate::keys::{self, MasterKey};
use crate::state_cache::{StateCache, StateCacheConfig};
use crate::tenant::{SealedTenantKeys, TenantId, TenantRecord};
use crate::tenant_assert::TenantScopedRepository;
use crate::tenant_config::SealingTenantConfigRepo;
use crate::tenant_config_loader::apply_tenant_config;

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
    /// Per-tenant materialized-secrets directory (`<data_dir>/tenants/<slug>/`).
    /// `Drop` removes this directory recursively so secret files don't linger
    /// past LRU eviction + completion of all in-flight requests.
    materialized_dir: Option<PathBuf>,
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
        cache: Weak<StateCache>,
        data_dir: &Path,
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

        let pg_repo = Arc::new(PostgresRepository::new(pg_pool, record.db_schema.clone()));
        let inner_repo: Arc<dyn ChalkRepository> = pg_repo.clone();
        // Wrap in a schema-asserting facade. Every method call validates
        // CURRENT_TENANT_SCHEMA matches the schema this pool was opened with,
        // catching cross-tenant Arc bleed-through.
        let repo: Arc<dyn ChalkRepository> = Arc::new(TenantScopedRepository::new(
            inner_repo,
            record.db_schema.clone(),
        ));
        // `pg_repo` is also our `TenantConfigRepo` source — the trait is not
        // part of the `ChalkRepository` super-trait, so we keep a typed
        // `Arc<PostgresRepository>` for the sealing wrapper. Build the wrapper
        // once and share it between the Phase 3 loader (`apply_tenant_config`)
        // and the Phase 4 console settings handlers (via `AppState`).
        let tenant_config_inner: Arc<dyn TenantConfigRepo> = pg_repo;
        let sealing_tenant_config = Arc::new(SealingTenantConfigRepo::new(
            tenant_config_inner,
            master_key.clone(),
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

        // Wave B Phase 3: fold per-tenant `tenant_config_*` rows onto the
        // synthesized config. Routes through the sealing wrapper so
        // secret-bearing columns arrive in plaintext. If the tenant has no
        // rows yet (legacy), every section returns `None` and the defaults
        // stay in place.
        apply_tenant_config(
            sealing_tenant_config.as_ref(),
            &mut config,
            data_dir,
            &record.slug,
        )
        .await
        .map_err(|e| anyhow!("failed to load tenant_config rows: {e}"))?;

        // 1.4 breaking change: `sis.provider` is now optional. With Phase 3
        // wired in we now source the provider from `tenant_config_sis`. This
        // branch fires only when the operator has enabled SIS sync without
        // choosing a provider — log loudly so they notice.
        if config.sis.enabled && config.sis.provider.is_none() {
            tracing::warn!(
                tenant = %record.slug,
                "sis.enabled = true but sis.provider is not set — SIS sync will refuse to run for this tenant"
            );
        }

        // Wire an SSO invalidator so admin-console partner CRUD evicts this
        // tenant from the LRU. Next request rebuilds the router with the new
        // partner set, picking up Clever/ClassLink compat routes without a
        // restart. `Weak<StateCache>` avoids an Arc cycle with the cached ctx.
        let invalidator_cache = cache.clone();
        let sso_invalidator: SsoInvalidator = Arc::new(move |slug: &str| {
            if let Some(cache) = invalidator_cache.upgrade() {
                let slug = slug.to_string();
                tokio::spawn(async move { cache.invalidate(&slug).await });
            }
        });
        // Reuse the sealing wrapper built above for the Phase 3 loader. The
        // raw postgres repo (NOT the schema-asserting facade — that does not
        // implement `TenantConfigRepo`) is the inner source; the pool's
        // pinned `search_path` keeps writes inside the tenant schema.
        let tenant_config_repo: Arc<dyn TenantConfigRepo> = sealing_tenant_config.clone();
        let console_state = Arc::new(
            AppState::new(repo.clone(), config.clone())
                .with_sso_invalidator(record.slug.clone(), sso_invalidator)
                .with_tenant_config(tenant_config_repo),
        );

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

        // Unseal OIDC signing key if present. Clever- and ClassLink-compat
        // /jwks endpoints reuse this RSA-2048 key — the SAML keypair is ECDSA
        // P-256 (rcgen's default) and the JWT-style JWKS the compat layer
        // exposes uses RS256 only. Cloning keeps `oidc_state` owning one copy
        // while the compat routers get their own.
        let oidc_key: Vec<u8> = match sealed.oidc_signing_jwk {
            Some(blob) => keys::unseal(master_key, &blob)?,
            None => Vec::new(),
        };
        let oidc_key_for_compat = oidc_key.clone();

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

        // Compat routers need an RSA key for /jwks and the JWT id_token. Gate
        // on the OIDC signing key (RSA) rather than the SAML keypair (ECDSA).
        if !oidc_key_for_compat.is_empty() {
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
                    oidc_key_for_compat.clone(),
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
                    oidc_key_for_compat.clone(),
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
            materialized_dir: Some(data_dir.join("tenants").join(&record.slug)),
        }))
    }
}

/// Remove a tenant's materialized-secrets directory, ignoring `NotFound`.
/// Logs a warning on other failures. Exposed for the Drop impl and for
/// integration tests that exercise the cleanup path without spinning up a
/// full Postgres-backed `TenantContext::build`.
pub fn cleanup_materialized_dir(tenant: &str, dir: &Path) {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(
                tenant = %tenant,
                path = %dir.display(),
                error = %e,
                "failed to remove materialized-secrets dir on TenantContext drop"
            );
        }
    }
}

impl Drop for TenantContext {
    /// Remove the per-tenant materialized-secrets directory when the last
    /// `Arc` clone is dropped. `Arc<TenantContext>` is held by the LRU cache
    /// and by every in-flight request's extensions, so this only fires once
    /// the cache has evicted the entry AND every handler using it has
    /// finished. Failures are logged at warn level — never panic in `Drop`.
    fn drop(&mut self) {
        if let Some(dir) = self.materialized_dir.as_ref() {
            cleanup_materialized_dir(&self.tenant.0, dir);
        }
    }
}
