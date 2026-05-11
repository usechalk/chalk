//! `serve` subcommand — launch the multi-tenant Axum server.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use axum::{
    extract::Request,
    http::{header::HOST, StatusCode},
    middleware,
    response::IntoResponse,
    routing::get,
    Router,
};
use chalk_core::db::DatabasePool;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tower_http::timeout::TimeoutLayer;
use tracing::info;

use crate::context::DEFAULT_TENANT_CONCURRENCY;
use crate::keys::MasterKey;
use crate::meta;
use crate::middleware::{resolve_tenant, ResolverConfig};
use crate::scheduler::{Scheduler, SyncRunner};
use crate::signup::{router as signup_router, SignupState};
use crate::state_cache::{StateCache, StateCacheConfig};
use crate::tenant::TenantRegistry;

/// Default global request timeout for both apex and tenant routes.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
/// Default scheduler tick interval.
const DEFAULT_SCHEDULER_TICK_SECS: u64 = 60;
/// Default per-tick sync concurrency (across tenants).
const DEFAULT_SCHEDULER_CONCURRENCY: usize = 4;

/// On-disk hosted config. Most operational values come from env so secrets
/// do not have to live on disk.
#[derive(Debug, Deserialize, Default)]
pub struct HostedConfig {
    #[serde(default)]
    pub apex: Option<String>,
    #[serde(default)]
    pub bind: Option<String>,
    #[serde(default)]
    pub postgres_url: Option<String>,
    #[serde(default)]
    pub cache_capacity: Option<usize>,
    /// Enable the multi-tenant sync scheduler. Defaults to `true`.
    #[serde(default)]
    pub sync_enabled: Option<bool>,
    /// Global per-request timeout in seconds. Defaults to 30.
    #[serde(default)]
    pub request_timeout_secs: Option<u64>,
    /// How often the multi-tenant sync scheduler fires. Defaults to 60.
    #[serde(default)]
    pub scheduler_tick_secs: Option<u64>,
    /// Maximum tenants whose syncs run concurrently per tick. Defaults to 4.
    #[serde(default)]
    pub scheduler_concurrency: Option<usize>,
    /// Per-tenant in-flight request cap. Defaults to 32.
    #[serde(default)]
    pub tenant_concurrency: Option<usize>,
    /// Per-tenant Postgres pool `max_connections`. Defaults to 3.
    #[serde(default)]
    pub pool_max_connections: Option<u32>,
}

impl HostedConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&raw)?;
        Ok(cfg)
    }
}

/// Resolved runtime values, with env overrides applied.
struct ResolvedConfig {
    apex: String,
    bind: SocketAddr,
    postgres_url: String,
    cache_capacity: usize,
    master_key: Arc<MasterKey>,
    sync_enabled: bool,
    request_timeout: Duration,
    scheduler_tick: Duration,
    scheduler_concurrency: usize,
    cache_config: StateCacheConfig,
}

fn resolve(cfg: HostedConfig) -> Result<ResolvedConfig> {
    let apex = cfg
        .apex
        .or_else(|| std::env::var("CHALK_APEX").ok())
        .ok_or_else(|| anyhow!("apex is required (config `apex` or env CHALK_APEX)"))?;
    let bind_str = cfg
        .bind
        .or_else(|| std::env::var("CHALK_BIND").ok())
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let bind: SocketAddr = bind_str
        .parse()
        .map_err(|e| anyhow!("invalid bind address {bind_str}: {e}"))?;
    let postgres_url = cfg
        .postgres_url
        .or_else(|| std::env::var("POSTGRES_URL").ok())
        .ok_or_else(|| anyhow!("postgres_url is required (config or env POSTGRES_URL)"))?;
    let cache_capacity = cfg.cache_capacity.unwrap_or(256);

    let master_key_b64 = std::env::var("MASTER_ENCRYPTION_KEY").map_err(|_| {
        anyhow!("MASTER_ENCRYPTION_KEY env var is required (32-byte base64-encoded key)")
    })?;
    let master_key = Arc::new(MasterKey::from_base64(&master_key_b64)?);

    let sync_enabled = cfg.sync_enabled.unwrap_or(true);

    let request_timeout = Duration::from_secs(
        cfg.request_timeout_secs
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
    );
    let scheduler_tick = Duration::from_secs(
        cfg.scheduler_tick_secs
            .unwrap_or(DEFAULT_SCHEDULER_TICK_SECS),
    );
    let scheduler_concurrency = cfg
        .scheduler_concurrency
        .unwrap_or(DEFAULT_SCHEDULER_CONCURRENCY)
        .max(1);
    let cache_config = StateCacheConfig {
        tenant_concurrency: cfg
            .tenant_concurrency
            .unwrap_or(DEFAULT_TENANT_CONCURRENCY)
            .max(1),
        pool_max_connections: cfg
            .pool_max_connections
            .unwrap_or(DatabasePool::DEFAULT_POSTGRES_MAX_CONNECTIONS)
            .max(1),
    };

    Ok(ResolvedConfig {
        apex,
        bind,
        postgres_url,
        cache_capacity,
        master_key,
        sync_enabled,
        request_timeout,
        scheduler_tick,
        scheduler_concurrency,
        cache_config,
    })
}

/// Run the hosted server. Resolves config, runs `_meta` migrations, and
/// dispatches host-based to either the apex or tenant routers.
pub async fn run(config_path: &Path) -> Result<()> {
    let cfg = resolve(HostedConfig::load(config_path)?)?;

    let meta_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&cfg.postgres_url)
        .await?;
    meta::run_migrations(&meta_pool).await?;
    info!("_meta schema migrations applied");

    let registry = Arc::new(TenantRegistry::new(meta_pool));
    let cache = Arc::new(StateCache::with_config(
        registry.clone(),
        cfg.master_key.clone(),
        cfg.postgres_url.clone(),
        cfg.apex.clone(),
        cfg.cache_capacity,
        cfg.cache_config,
    ));

    let resolver_cfg = ResolverConfig {
        cache: cache.clone(),
        apex: cfg.apex.clone(),
    };

    let signup_state = SignupState::new(
        registry.clone(),
        cfg.master_key.clone(),
        cfg.apex.clone(),
        cfg.postgres_url.clone(),
    );

    // Spawn the multi-tenant sync scheduler. The runner reads the tenant's
    // effective sync schedules via the OSS `effective_schedule` helper so
    // operators can override schedules per-tenant via `_config_overrides`
    // rows. Actual SIS/Google/AD dispatch is gated behind per-tenant
    // connector configuration loaders that have not landed yet:
    //   - `SyncEngine::run` requires a `&dyn SisConnector`, which means we
    //     need to know the tenant's chosen SIS provider + sealed credentials
    //     and instantiate the right connector. The hosted side has no
    //     loader for that today — `TenantContext::build` synthesizes a
    //     bare-bones `ChalkConfig` and intentionally leaves connector
    //     credentials empty.
    //   - `GoogleSyncEngine::new` and `AdSyncEngine::new` similarly need
    //     `GoogleAdminClient` / `AdClient` (themselves built from per-tenant
    //     OAuth / LDAP credentials) plus their own typed config.
    // Until that loader lands the runner is a documented TODO that still
    // exercises the plumbing: it reads the schedules, runs inside the
    // schema-scoped task-local (the scheduler does the scoping), and
    // returns errors via `Result` so future work is a localized change.
    if cfg.sync_enabled {
        let runner: SyncRunner = Arc::new(|ctx| {
            Box::pin(async move {
                // Read effective schedules. Defaults match the OSS CLI's
                // `[sis]`/`[google_sync]`/`[ad_sync]` defaults so a tenant
                // without overrides behaves like a single-tenant install.
                let sis_schedule = chalk_core::db::sqlite::effective_schedule(
                    &*ctx.repo,
                    "sis.sync_schedule",
                    "0 2 * * *",
                )
                .await;
                let google_schedule = chalk_core::db::sqlite::effective_schedule(
                    &*ctx.repo,
                    "google_sync.sync_schedule",
                    "0 3 * * *",
                )
                .await;
                let ad_schedule = chalk_core::db::sqlite::effective_schedule(
                    &*ctx.repo,
                    "ad_sync.sync_schedule",
                    "0 4 * * *",
                )
                .await;

                tracing::debug!(
                    slug = %ctx.tenant.0,
                    sis_schedule = %sis_schedule,
                    google_schedule = %google_schedule,
                    ad_schedule = %ad_schedule,
                    "scheduler tick: schedules resolved",
                );

                // TODO(hosted-sync): dispatch the OSS sync engines once a
                // per-tenant connector-config loader lands. The shape will
                // be roughly:
                //
                //   if sis_enabled(&ctx).await? && cron_due(&sis_schedule, &ctx).await? {
                //       let connector = build_sis_connector_for_tenant(&ctx).await?;
                //       SyncEngine::new(ctx.repo.clone()).run(&*connector).await?;
                //   }
                //   if google_enabled(&ctx).await? && cron_due(&google_schedule, &ctx).await? {
                //       let client = build_google_client_for_tenant(&ctx).await?;
                //       GoogleSyncEngine::new(ctx.repo.clone(), client, gcfg)
                //           .run_sync(false).await?;
                //   }
                //   // ditto AdSyncEngine
                //
                // Each branch is gated by a config check + cron-due check
                // against the run-history tables already persisted by the
                // engines themselves (`sync_runs`, `google_sync_runs`,
                // `ad_sync_runs`). Per the scheduler contract a `?` here
                // becomes a `tracing::warn!` at the scheduler level — one
                // tenant's failure does not poison the others.

                Ok(())
            })
        });
        let tick = cfg.scheduler_tick;
        let scheduler = Scheduler::new(
            cache.clone(),
            registry.clone(),
            tick,
            cfg.scheduler_concurrency,
            runner,
        );
        scheduler.spawn();
        info!("multi-tenant sync scheduler spawned (tick={tick:?})");
    } else {
        info!("multi-tenant sync scheduler disabled by config");
    }

    // SIGHUP -> StateCache::clear. After `chalk-hosted tenant suspend|unsuspend`
    // an operator runs `systemctl kill -s HUP chalk-hosted` (see runbook 3.2)
    // to flush the LRU instead of waiting up to ~10 min for idle eviction.
    spawn_sighup_listener(cache.clone());

    let tenant_router = tenant_router(resolver_cfg.clone());
    let apex_router = apex_router(signup_state);
    let apex = cfg.apex.clone();

    // Top-level dispatch: branch on Host header into apex vs. tenant routers.
    let app = Router::new()
        .fallback(move |req: Request| {
            let apex = apex.clone();
            let apex_router = apex_router.clone();
            let tenant_router = tenant_router.clone();
            async move {
                let host = req
                    .headers()
                    .get(HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.split(':').next().unwrap_or(s).to_string());
                match host {
                    Some(h) if h == apex => apex_router.oneshot_into_response(req).await,
                    Some(_) => tenant_router.oneshot_into_response(req).await,
                    None => StatusCode::BAD_REQUEST.into_response(),
                }
            }
        })
        // Global request timeout: a single tenant cannot hold a connection
        // open indefinitely, even if its handler is wedged.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            cfg.request_timeout,
        ));

    let listener = TcpListener::bind(cfg.bind).await?;
    info!(
        "chalk-hosted listening on http://{} (apex={})",
        cfg.bind, cfg.apex
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Spawn a task that calls `StateCache::clear` on every `SIGHUP`. On
/// non-unix platforms (Windows, where the hosted binary is unsupported)
/// this is a no-op so the build stays portable.
#[cfg(unix)]
fn spawn_sighup_listener(cache: Arc<StateCache>) {
    use tokio::signal::unix::{signal, SignalKind};
    tokio::spawn(async move {
        let mut stream = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGHUP handler; cache flush via signal disabled");
                return;
            }
        };
        loop {
            if stream.recv().await.is_none() {
                tracing::warn!("SIGHUP stream closed; cache flush via signal disabled");
                return;
            }
            cache.clear();
            info!("SIGHUP received: state cache cleared");
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_listener(_cache: Arc<StateCache>) {
    tracing::info!("SIGHUP cache flush is unix-only; skipping listener");
}

/// Routes for requests whose Host equals the apex.
fn apex_router(signup_state: SignupState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(signup_router(signup_state))
}

/// Routes for tenant subdomain requests. Applies the resolver middleware so
/// downstream handlers can extract `CurrentTenant`.
fn tenant_router(resolver_cfg: ResolverConfig) -> Router {
    Router::new()
        .route(
            "/health",
            get(
                |crate::middleware::CurrentTenant(ctx): crate::middleware::CurrentTenant| async move {
                    format!("ok {}", ctx.tenant.0)
                },
            ),
        )
        .layer(middleware::from_fn_with_state(
            resolver_cfg,
            resolve_tenant,
        ))
}

/// Helper trait so the dispatch closure can call a sub-router with a single
/// request and get an `axum::Response` back.
trait OneshotIntoResponse {
    fn oneshot_into_response(
        self,
        req: Request,
    ) -> futures_util::future::BoxFuture<'static, axum::response::Response>;
}

impl OneshotIntoResponse for Router {
    fn oneshot_into_response(
        self,
        req: Request,
    ) -> futures_util::future::BoxFuture<'static, axum::response::Response> {
        use tower::ServiceExt;
        Box::pin(async move {
            match self.oneshot(req).await {
                Ok(resp) => resp,
                Err(_never) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        })
    }
}
