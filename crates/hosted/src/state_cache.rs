//! LRU pool-per-tenant cache.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use lru::LruCache;
use parking_lot::Mutex;
use tokio::sync::Mutex as AsyncMutex;

use crate::context::{TenantContext, DEFAULT_TENANT_CONCURRENCY};
use crate::keys::MasterKey;
use crate::tenant::{TenantRegistry, TenantStatus};

/// Default per-tenant Postgres pool size for the hosted runtime. Each cached
/// tenant holds one pool; we keep this small so a 256-tenant cache doesn't
/// blow past Postgres' default `max_connections=100`.
pub const DEFAULT_POOL_MAX_CONNECTIONS: u32 = 3;

/// Tunables threaded into per-tenant context construction.
#[derive(Clone, Copy, Debug)]
pub struct StateCacheConfig {
    /// Per-tenant in-flight request cap (Semaphore size in [`TenantContext`]).
    pub tenant_concurrency: usize,
    /// Per-tenant Postgres pool `max_connections`.
    pub pool_max_connections: u32,
}

impl Default for StateCacheConfig {
    fn default() -> Self {
        Self {
            tenant_concurrency: DEFAULT_TENANT_CONCURRENCY,
            pool_max_connections: DEFAULT_POOL_MAX_CONNECTIONS,
        }
    }
}

/// LRU cache that resolves slug -> `Arc<TenantContext>`. Misses query the
/// registry and lazily build a context (which in turn opens a Postgres pool).
pub struct StateCache {
    /// Hot lookup cache. Critical section is non-async (LRU read/write only),
    /// so we use `parking_lot::Mutex` to avoid the overhead of yielding the
    /// task on every cache hit.
    inner: Mutex<LruCache<String, Arc<TenantContext>>>,
    /// Per-slug single-flight gate. On a miss we acquire a slug-keyed async
    /// mutex, recheck the LRU, and only then build a fresh context. This
    /// prevents two concurrent first-time lookups from racing to open two
    /// Postgres pools for the same tenant.
    miss_gates: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    registry: Arc<TenantRegistry>,
    master_key: Arc<MasterKey>,
    postgres_url: String,
    apex: String,
    /// Scheme used to build externally-facing per-tenant URLs.
    public_scheme: String,
    /// Optional port appended to externally-facing per-tenant URLs.
    public_port: Option<u16>,
    config: StateCacheConfig,
    /// Writable per-process state directory. Per-tenant materialized secret
    /// files (Google service-account JSON, SAML cert/key, AD CA cert) are
    /// written under `<data_dir>/tenants/<slug>/`. Defaults to
    /// [`default_data_dir`] when constructed via [`StateCache::new`] /
    /// [`StateCache::with_config`]; the server entrypoint overrides this via
    /// [`StateCache::set_data_dir`].
    data_dir: PathBuf,
}

/// Process-wide default `data_dir`. Picked so tests and ad-hoc uses do not
/// need to thread a path through every constructor call. Production overrides
/// this via `CHALK_DATA_DIR` (see `commands::serve`).
fn default_data_dir() -> PathBuf {
    std::env::temp_dir().join("chalk-hosted-data")
}

impl StateCache {
    pub fn new(
        registry: Arc<TenantRegistry>,
        master_key: Arc<MasterKey>,
        postgres_url: String,
        apex: String,
        capacity: usize,
    ) -> Self {
        Self::with_config(
            registry,
            master_key,
            postgres_url,
            apex,
            "https".to_string(),
            None,
            capacity,
            StateCacheConfig::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_config(
        registry: Arc<TenantRegistry>,
        master_key: Arc<MasterKey>,
        postgres_url: String,
        apex: String,
        public_scheme: String,
        public_port: Option<u16>,
        capacity: usize,
        config: StateCacheConfig,
    ) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            miss_gates: Mutex::new(HashMap::new()),
            registry,
            master_key,
            postgres_url,
            apex,
            public_scheme,
            public_port,
            config,
            data_dir: default_data_dir(),
        }
    }

    /// Override the per-process state directory. Called by the server
    /// entrypoint with the operator-supplied `CHALK_DATA_DIR`. Returns `self`
    /// for chaining at construction sites.
    pub fn with_data_dir(mut self, data_dir: PathBuf) -> Self {
        self.data_dir = data_dir;
        self
    }

    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    pub fn public_scheme(&self) -> &str {
        &self.public_scheme
    }

    pub fn public_port(&self) -> Option<u16> {
        self.public_port
    }

    pub fn registry(&self) -> &Arc<TenantRegistry> {
        &self.registry
    }

    pub fn master_key(&self) -> &Arc<MasterKey> {
        &self.master_key
    }

    pub fn apex(&self) -> &str {
        &self.apex
    }

    pub fn postgres_url(&self) -> &str {
        &self.postgres_url
    }

    pub fn config(&self) -> StateCacheConfig {
        self.config
    }

    /// Resolve a slug. Returns `Ok(None)` if the tenant doesn't exist or is
    /// not active (suspended/provisioning).
    ///
    /// Takes `&Arc<Self>` so we can hand a `Weak<Self>` to the per-tenant
    /// `SsoInvalidator` callback the console uses to flush this cache after
    /// SSO partner CRUD without restarting the server.
    pub async fn get(self: &Arc<Self>, slug: &str) -> Result<Option<Arc<TenantContext>>> {
        // Fast path: LRU hit. We deliberately scope the parking_lot guard
        // tightly so it is dropped before any `.await` below.
        {
            let mut guard = self.inner.lock();
            if let Some(ctx) = guard.get(slug) {
                return Ok(Some(ctx.clone()));
            }
        }

        // Slow path: serialize per-slug so concurrent first-time lookups for
        // the same tenant only build one context (one Postgres pool open).
        let gate = {
            let mut gates = self.miss_gates.lock();
            gates
                .entry(slug.to_string())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let _gate_guard = gate.lock().await;

        // Recheck the LRU under the per-slug gate.
        {
            let mut guard = self.inner.lock();
            if let Some(ctx) = guard.get(slug) {
                return Ok(Some(ctx.clone()));
            }
        }

        let record = match self.registry.get(slug).await? {
            Some(r) => r,
            None => {
                self.drop_gate(slug);
                return Ok(None);
            }
        };
        if record.status != TenantStatus::Active {
            self.drop_gate(slug);
            return Ok(None);
        }

        let sealed = self.registry.get_sealed_keys(slug).await?;
        let ctx = TenantContext::build(
            &record,
            sealed,
            &self.master_key,
            &self.postgres_url,
            &self.apex,
            &self.public_scheme,
            self.public_port,
            self.config,
            Arc::downgrade(self),
            &self.data_dir,
        )
        .await?;
        {
            let mut guard = self.inner.lock();
            guard.put(slug.to_string(), ctx.clone());
        }
        self.drop_gate(slug);
        Ok(Some(ctx))
    }

    /// Drop a slug from the cache. Use after deprovision/suspend so a running
    /// `serve` process stops vending the old context.
    pub async fn invalidate(&self, slug: &str) {
        let mut guard = self.inner.lock();
        guard.pop(slug);
    }

    /// Drop every cached tenant. Subsequent `get` calls re-query the registry
    /// and rebuild contexts. Wired up to `SIGHUP` in the serve command so an
    /// operator can flush state after `tenant suspend` / `tenant unsuspend`
    /// without restarting the running process.
    pub fn clear(&self) {
        let mut guard = self.inner.lock();
        guard.clear();
    }

    /// Test helper: number of currently cached tenants.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Remove the per-slug single-flight gate so the gate map doesn't grow
    /// without bound. Safe even if another waiter still holds the `Arc<AsyncMutex>` —
    /// they keep using their cloned handle while future callers create a new one.
    fn drop_gate(&self, slug: &str) {
        let mut gates = self.miss_gates.lock();
        gates.remove(slug);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    fn make_cache() -> StateCache {
        // `connect_lazy` produces a pool handle without actually opening a
        // connection — perfect for unit tests that exercise only the in-memory
        // LRU side of `StateCache` and never call `get`.
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://chalk-test-noop:noop@127.0.0.1:1/none")
            .expect("connect_lazy");
        let registry = Arc::new(TenantRegistry::new(pool));
        let master_key = Arc::new(MasterKey::generate());
        StateCache::new(
            registry,
            master_key,
            "postgres://unused".to_string(),
            "apex.example".to_string(),
            16,
        )
    }

    #[tokio::test]
    async fn clear_is_noop_on_empty() {
        let cache = make_cache();
        assert_eq!(cache.len(), 0);
        cache.clear();
        assert_eq!(cache.len(), 0);
        // Idempotent.
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn invalidate_does_not_panic_on_missing_slug() {
        let cache = make_cache();
        cache.invalidate("never-cached").await;
        assert_eq!(cache.len(), 0);
    }
}
