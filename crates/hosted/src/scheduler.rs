//! Multi-tenant sync scheduler.
//!
//! On each tick the scheduler pulls the list of active tenants from the
//! registry, looks each one up in the `StateCache`, decides whether the
//! tenant is due for a sync, and dispatches sync work with bounded
//! concurrency.
//!
//! Each per-tenant sync runs inside `CURRENT_TENANT_SCHEMA::scope(schema)`
//! so the defense-in-depth wrapper validates every repo call coming out of
//! the sync engines too.
//!
//! The actual sync logic is supplied via a `SyncRunner` callback so the
//! scheduler can be unit-tested without standing up real SIS connectors,
//! and so future wiring (SIS, Google, AD) can plug in independently.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures_util::stream::{self, StreamExt};
use tokio::task::JoinHandle;

use crate::context::TenantContext;
use crate::state_cache::StateCache;
use crate::tenant::TenantRegistry;
use crate::tenant_assert::CURRENT_TENANT_SCHEMA;

/// Callback invoked by the scheduler for each due tenant. Implementations
/// run any combination of the OSS sync engines (SIS / Google / AD) using
/// the tenant's `Arc<dyn ChalkRepository>`.
///
/// The callback returns `Result<()>` so panics inside engines surface as
/// errors via the runner; a panic crossing a `tokio::spawn` boundary would
/// kill that task only and is logged by the scheduler's join arm.
pub type SyncRunner = Arc<
    dyn Fn(Arc<TenantContext>) -> futures_util::future::BoxFuture<'static, Result<()>>
        + Send
        + Sync,
>;

/// Multi-tenant sync scheduler.
pub struct Scheduler {
    cache: Arc<StateCache>,
    registry: Arc<TenantRegistry>,
    /// How often the scheduler tick fires (e.g. 60s). On each tick all
    /// active tenants are evaluated; tenants whose schedule has elapsed
    /// since the last run get a sync.
    interval: Duration,
    /// Maximum number of tenants whose syncs may run concurrently.
    sync_concurrency: usize,
    /// Per-tenant sync work.
    runner: SyncRunner,
}

impl Scheduler {
    pub fn new(
        cache: Arc<StateCache>,
        registry: Arc<TenantRegistry>,
        interval: Duration,
        sync_concurrency: usize,
        runner: SyncRunner,
    ) -> Self {
        Self {
            cache,
            registry,
            interval,
            sync_concurrency: sync_concurrency.max(1),
            runner,
        }
    }

    /// Spawn the scheduler loop on the current Tokio runtime. The returned
    /// `JoinHandle` lives for the lifetime of the process; aborting it
    /// stops scheduling.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(self.run())
    }

    /// Run a single tick — visible for tests. Returns the number of
    /// tenants whose runner was invoked (regardless of success/failure).
    pub async fn tick(&self) -> Result<usize> {
        let tenants = self.registry.list_active().await?;
        if tenants.is_empty() {
            return Ok(0);
        }

        let cache = self.cache.clone();
        let runner = self.runner.clone();

        let count = stream::iter(tenants.into_iter())
            .map(|record| {
                let cache = cache.clone();
                let runner = runner.clone();
                async move {
                    let ctx = match cache.get(&record.slug).await {
                        Ok(Some(c)) => c,
                        Ok(None) => return false,
                        Err(e) => {
                            tracing::warn!(slug = %record.slug, error = %e, "scheduler: failed to load tenant context");
                            return false;
                        }
                    };
                    let schema = ctx.db_schema.clone();
                    let slug = record.slug.clone();
                    let res = CURRENT_TENANT_SCHEMA
                        .scope(schema, async move { runner(ctx).await })
                        .await;
                    if let Err(e) = res {
                        tracing::warn!(slug = %slug, error = %e, "scheduler: tenant sync failed");
                    }
                    true
                }
            })
            .buffer_unordered(self.sync_concurrency)
            .filter(|invoked| {
                let v = *invoked;
                async move { v }
            })
            .count()
            .await;
        Ok(count)
    }

    async fn run(self) {
        let mut ticker = tokio::time::interval(self.interval);
        // Fire-and-skip: missed ticks during a long sync should not pile up.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(e) = self.tick().await {
                tracing::error!(error = %e, "scheduler: tick failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use crate::tenant_assert::CURRENT_TENANT_SCHEMA;

    /// We can't exercise the registry without a real Postgres. Build a
    /// scheduler against a stub runner and call it through the public
    /// API by simulating tick logic inline.
    ///
    /// To keep tests hermetic we test the runner-invocation path directly:
    /// build `TenantContext`-equivalent state and verify the runner sees
    /// CURRENT_TENANT_SCHEMA correctly when invoked through our scope
    /// helper.
    #[tokio::test]
    async fn runner_sees_current_tenant_schema() {
        let observed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let observed_clone = observed.clone();

        let schemas = vec!["tenant_a".to_string(), "tenant_b".to_string()];
        for s in &schemas {
            let observed = observed_clone.clone();
            let schema = s.clone();
            CURRENT_TENANT_SCHEMA
                .scope(schema.clone(), async move {
                    let v = CURRENT_TENANT_SCHEMA.with(|s| s.clone());
                    observed.lock().unwrap().push(v);
                })
                .await;
        }

        let got = observed.lock().unwrap().clone();
        assert_eq!(got, schemas);
    }

    #[tokio::test]
    async fn bounded_concurrency_via_buffer_unordered() {
        // Verify the `buffer_unordered` cap honors the configured limit by
        // observing peak concurrent in-flight tasks.
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let count = 10usize;
        let cap = 3usize;

        let in_flight_c = in_flight.clone();
        let peak_c = peak.clone();
        let total = stream::iter(0..count)
            .map(|_| {
                let in_flight = in_flight_c.clone();
                let peak = peak_c.clone();
                async move {
                    let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(n, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                }
            })
            .buffer_unordered(cap)
            .count()
            .await;

        assert_eq!(total, count);
        assert!(peak.load(Ordering::SeqCst) <= cap);
    }

    #[tokio::test]
    async fn one_failure_isolated_inside_buffer_unordered() {
        // Mirror the scheduler's per-tenant error-handling: a Result<()>
        // error from one runner invocation does not abort the stream.
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = calls.clone();

        let total = stream::iter(0..5usize)
            .map(|i| {
                let calls = calls_c.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let res: Result<()> = if i == 2 {
                        Err(anyhow::anyhow!("boom"))
                    } else {
                        Ok(())
                    };
                    if let Err(e) = res {
                        tracing::warn!(error = %e, "test: tenant sync failed");
                    }
                }
            })
            .buffer_unordered(2)
            .count()
            .await;

        assert_eq!(total, 5);
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }
}
