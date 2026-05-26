//! Integration test for the resolver middleware end-to-end.
//!
//! Requires `CHALK_TEST_POSTGRES_URL`. Marked `#[ignore]`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware;
use axum::routing::get;
use axum::Router;
use chalk_hosted::commands::provision;
use chalk_hosted::keys::MasterKey;
use chalk_hosted::meta;
use chalk_hosted::middleware::{resolve_tenant, CurrentTenant, ResolverConfig};
use chalk_hosted::state_cache::StateCache;
use chalk_hosted::tenant::TenantRegistry;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

const APEX: &str = "test.local";

async fn db_url() -> String {
    std::env::var("CHALK_TEST_POSTGRES_URL")
        .expect("CHALK_TEST_POSTGRES_URL must be set for ignored tests")
}

async fn reset_meta(url: &str) {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .unwrap();
    sqlx::raw_sql("DROP SCHEMA IF EXISTS _meta CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql("DROP SCHEMA IF EXISTS tenant_resolvr CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    meta::run_migrations(&pool).await.unwrap();
}

fn build_router(cfg: ResolverConfig) -> Router {
    Router::new()
        .route(
            "/health",
            get(|CurrentTenant(ctx): CurrentTenant| async move { ctx.tenant.0.clone() }),
        )
        .layer(middleware::from_fn_with_state(cfg, resolve_tenant))
}

#[tokio::test]
#[ignore]
async fn resolver_dispatches_known_tenant_and_404s_unknown() {
    let url = db_url().await;
    reset_meta(&url).await;

    let master = Arc::new(MasterKey::generate());

    // Activate a tenant via the same code path the signup verify-callback uses.
    provision::activate_tenant(
        &url, "resolvr", "Resolvr", "a@a.test", "Admin", &master, None,
    )
    .await
    .unwrap();

    let meta_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let registry = Arc::new(TenantRegistry::new(meta_pool));
    let cache = Arc::new(StateCache::new(
        registry,
        master.clone(),
        url.clone(),
        APEX.to_string(),
        16,
    ));
    let cfg = ResolverConfig {
        cache: cache.clone(),
        apex: APEX.to_string(),
    };
    let app = build_router(cfg);

    // Known tenant -> 200 with body == slug.
    let req = Request::builder()
        .uri("/health")
        .header("host", "resolvr.test.local")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 64).await.unwrap();
    assert_eq!(&body[..], b"resolvr");

    // Unknown tenant -> 404.
    let req = Request::builder()
        .uri("/health")
        .header("host", "unknown.test.local")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Apex host -> 404 (apex routes are handled by a separate router branch).
    let req = Request::builder()
        .uri("/health")
        .header("host", "test.local")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Suspend + invalidate -> 404 even though row exists.
    let meta_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let registry = TenantRegistry::new(meta_pool);
    registry.suspend("resolvr").await.unwrap();
    cache.invalidate("resolvr").await;

    let req = Request::builder()
        .uri("/health")
        .header("host", "resolvr.test.local")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
