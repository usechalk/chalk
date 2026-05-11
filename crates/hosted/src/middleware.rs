//! Tenant resolver middleware and `CurrentTenant` extractor.

use std::sync::Arc;

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::context::TenantContext;
use crate::state_cache::StateCache;
use crate::tenant_assert::CURRENT_TENANT_SCHEMA;

/// Configured apex for the resolver. Stored alongside the cache in the
/// request state so middleware can strip the apex suffix from `Host`.
#[derive(Clone)]
pub struct ResolverConfig {
    pub cache: Arc<StateCache>,
    pub apex: String,
}

/// Extract the tenant slug from a `Host` header value, given the configured
/// apex. Returns `Some(slug)` only when the host is `<slug>.<apex>` (with a
/// non-empty slug prefix). Returns `None` for the apex itself or anything
/// else.
pub fn slug_from_host(host: &str, apex: &str) -> Option<String> {
    // Strip optional `:port`.
    let host = host.split(':').next().unwrap_or(host);
    if host == apex {
        return None;
    }
    let suffix = format!(".{apex}");
    if let Some(prefix) = host.strip_suffix(&suffix) {
        if !prefix.is_empty() && !prefix.contains('.') {
            return Some(prefix.to_string());
        }
    }
    None
}

/// Axum middleware: read `Host`, resolve tenant via `StateCache`, attach an
/// `Arc<TenantContext>` to request extensions for downstream handlers.
///
/// Returns 404 if the host is the apex (apex routes should be handled by a
/// separate router branch) or if the tenant doesn't exist / is not active.
pub async fn resolve_tenant(
    State(cfg): State<ResolverConfig>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_string();

    let slug = match slug_from_host(&host, &cfg.apex) {
        Some(s) => s,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let ctx = cfg
        .cache
        .get(&slug)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Noisy-neighbor: bound per-tenant in-flight requests. The permit is
    // held for the duration of the inner handler via `_permit` drop.
    let _permit = match ctx.concurrency.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };

    let schema = ctx.db_schema.clone();
    req.extensions_mut().insert(ctx);
    // Defense-in-depth: pin CURRENT_TENANT_SCHEMA for the duration of this
    // request so every repo call validates the in-flight tenant.
    Ok(CURRENT_TENANT_SCHEMA
        .scope(schema, async move { next.run(req).await })
        .await)
}

/// Axum extractor that pulls the `Arc<TenantContext>` set by `resolve_tenant`.
pub struct CurrentTenant(pub Arc<TenantContext>);

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for CurrentTenant
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Arc<TenantContext>>()
            .cloned()
            .map(CurrentTenant)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;

    #[test]
    fn host_parsing() {
        assert_eq!(
            slug_from_host("acme.test.local", "test.local"),
            Some("acme".into())
        );
        assert_eq!(
            slug_from_host("acme.test.local:8080", "test.local"),
            Some("acme".into())
        );
        assert_eq!(slug_from_host("test.local", "test.local"), None);
        assert_eq!(slug_from_host("foo.bar.test.local", "test.local"), None);
        assert_eq!(slug_from_host("evil.com", "test.local"), None);
    }

    /// Mirrors the per-tenant concurrency cap behavior of `resolve_tenant`:
    /// once the tenant's semaphore is saturated, additional acquisitions
    /// fail and the middleware returns 503. We can't easily build a real
    /// `TenantContext` in a unit test (requires a Postgres pool) so this
    /// test exercises the cap directly via the same `try_acquire_owned`
    /// API the middleware uses.
    #[tokio::test]
    async fn per_tenant_concurrency_cap_returns_503_when_saturated() {
        use std::sync::Arc;
        let cap = 32usize;
        let sem = Arc::new(Semaphore::new(cap));

        let mut held = Vec::new();
        for _ in 0..cap {
            let p = sem
                .clone()
                .try_acquire_owned()
                .expect("acquire should succeed within cap");
            held.push(p);
        }

        // 33rd acquisition fails -> middleware would emit 503.
        let saturated = sem.clone().try_acquire_owned();
        assert!(
            saturated.is_err(),
            "expected saturation at cap={cap}, got success"
        );

        // Drop one permit, next acquisition succeeds.
        held.pop();
        let after = sem.clone().try_acquire_owned();
        assert!(after.is_ok(), "permit should be available after drop");
    }
}
