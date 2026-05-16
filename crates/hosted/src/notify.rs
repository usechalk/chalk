//! Postgres `LISTEN`/`NOTIFY` channel for surgical per-tenant cache
//! invalidation.
//!
//! Why: the per-process `StateCache` LRU is fast-path for tenant routing,
//! but mutations performed by a separate process (the `chalk-hosted
//! tenant suspend|unsuspend|deprovision` CLI, or a future admin API)
//! can't reach in to evict a cached entry. The previous workaround was
//! `SIGHUP → StateCache::clear`, which evicts **every** tenant and forces
//! a stampede of context rebuilds on next request.
//!
//! `LISTEN`/`NOTIFY` lets us evict exactly one slug. The CLI sends
//! `NOTIFY chalk_tenant_invalidate, '<slug>'` after a successful write;
//! every running `chalk-hosted serve` process holds a `PgListener` on
//! that channel and calls `StateCache::invalidate(slug)` on receipt.
//!
//! Failure modes:
//! - Connection drop: `PgListener` auto-reconnects. While disconnected,
//!   notifications are lost — operators get the old SIGHUP behavior as a
//!   safety net by re-running the CLI command. In practice the channel
//!   reconnects in seconds.
//! - Multi-replica deploys: every replica subscribes to the same channel
//!   and each receives the notification, so the eviction is fan-out by
//!   design.

use std::sync::Arc;

use anyhow::Result;
use sqlx::postgres::{PgListener, PgPool};
use tracing::{debug, error, info, warn};

use crate::state_cache::StateCache;

/// Channel name. Single channel for all tenant invalidations; the payload
/// carries the slug. Picked the `chalk_` prefix to keep the global Postgres
/// channel namespace tidy in shared databases.
pub const CHANNEL: &str = "chalk_tenant_invalidate";

/// Fire a per-slug invalidation. Called by the `tenant` and `deprovision`
/// CLI commands after they commit the underlying status change. Cheap,
/// fire-and-forget — `NOTIFY` is itself non-blocking and a single Postgres
/// round trip.
pub async fn notify_invalidate(pool: &PgPool, slug: &str) -> Result<()> {
    // sqlx doesn't have a typed NOTIFY helper; the command-form is the
    // canonical way to fire one. Use a string-bound parameter for the
    // payload (Postgres NOTIFY accepts only literal strings, so we
    // escape the slug — slugs are validated to `[a-z0-9_-]` so an
    // injection here is structurally impossible, but escaping is cheap
    // insurance).
    let safe = slug.replace('\'', "''");
    sqlx::query(&format!("NOTIFY {CHANNEL}, '{safe}'"))
        .execute(pool)
        .await?;
    debug!(slug = %slug, "sent NOTIFY chalk_tenant_invalidate");
    Ok(())
}

/// Spawn a background task that holds a `PgListener` open, invalidating
/// `cache` entries by slug as notifications arrive. Returns immediately.
/// Logs and re-enters its loop on listener failures so a transient
/// connection blip doesn't take down the eviction channel permanently.
pub fn spawn_listener(pool: PgPool, cache: Arc<StateCache>) {
    tokio::spawn(async move {
        loop {
            match listen_loop(&pool, &cache).await {
                Ok(()) => {
                    warn!("tenant invalidation listener exited cleanly; restarting");
                }
                Err(e) => {
                    error!(error = %e, "tenant invalidation listener errored; restarting in 5s");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    });
    info!(
        "tenant invalidation listener spawned on channel '{}'",
        CHANNEL
    );
}

async fn listen_loop(pool: &PgPool, cache: &Arc<StateCache>) -> Result<()> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(CHANNEL).await?;
    info!("LISTEN {CHANNEL} established");
    loop {
        let notification = listener.recv().await?;
        let slug = notification.payload().trim();
        if slug.is_empty() {
            warn!("received empty tenant invalidation payload; ignoring");
            continue;
        }
        info!(slug = %slug, "invalidating tenant from notify");
        cache.invalidate(slug).await;
    }
}
