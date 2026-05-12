//! Integration tests for the apex `/api/signup` flow.
//!
//! Requires `CHALK_TEST_POSTGRES_URL`. Marked `#[ignore]` so CI without
//! Postgres does not break.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use chalk_hosted::keys::MasterKey;
use chalk_hosted::meta;
use chalk_hosted::signup::{self, SignupState};
use chalk_hosted::tenant::TenantRegistry;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

const APEX: &str = "test.local";

async fn db_url() -> String {
    std::env::var("CHALK_TEST_POSTGRES_URL")
        .expect("CHALK_TEST_POSTGRES_URL must be set for ignored tests")
}

async fn reset_meta(url: &str, slugs: &[&str]) {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .unwrap();
    sqlx::raw_sql("DROP SCHEMA IF EXISTS _meta CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    for s in slugs {
        let stmt = format!(
            "DROP SCHEMA IF EXISTS tenant_{} CASCADE",
            s.replace('-', "_")
        );
        sqlx::raw_sql(&stmt).execute(&pool).await.unwrap();
    }
    meta::run_migrations(&pool).await.unwrap();
}

async fn build_app(url: &str) -> (axum::Router, Arc<TenantRegistry>) {
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(url)
        .await
        .unwrap();
    let registry = Arc::new(TenantRegistry::new(pool));
    let master = Arc::new(MasterKey::generate());
    let state = SignupState::new(
        registry.clone(),
        master,
        APEX.to_string(),
        url.to_string(),
        "https".to_string(),
        None,
    );
    let router = signup::router(state);
    let mock_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let router = router.layer(MockConnectInfo(mock_addr));
    (router, registry)
}

fn signup_body(slug: &str) -> Body {
    Body::from(
        serde_json::to_vec(&serde_json::json!({
            "slug": slug,
            "admin_email": "admin@example.com",
            "admin_name": "Jane Admin",
            "district_name": "Test District",
            "captcha_token": "dev-skip"
        }))
        .unwrap(),
    )
}

#[tokio::test]
#[ignore]
async fn signup_post_creates_pending_row() {
    let url = db_url().await;
    reset_meta(&url, &["acme"]).await;

    let (app, registry) = build_app(&url).await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/signup")
        .header("content-type", "application/json")
        .body(signup_body("acme"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _meta.signup_pending WHERE slug = 'acme'")
            .fetch_one(registry.pool())
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
#[ignore]
async fn signup_verify_activates_tenant_and_redirects() {
    let url = db_url().await;
    reset_meta(&url, &["acme"]).await;
    let (app, registry) = build_app(&url).await;

    // Submit signup.
    let req = Request::builder()
        .method("POST")
        .uri("/api/signup")
        .header("content-type", "application/json")
        .body(signup_body("acme"))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Read the token out of _meta.signup_pending.
    let token: String =
        sqlx::query_scalar("SELECT token FROM _meta.signup_pending WHERE slug = 'acme'")
            .fetch_one(registry.pool())
            .await
            .unwrap();

    // Hit the verify endpoint.
    let req = Request::builder()
        .uri(format!("/api/signup/verify?token={token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("https://acme.test.local/login?reset_token="));

    // Pending row was consumed.
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _meta.signup_pending")
        .fetch_one(registry.pool())
        .await
        .unwrap();
    assert_eq!(remaining, 0);

    // Tenant is active.
    let rec = registry.get("acme").await.unwrap().expect("tenant exists");
    assert_eq!(rec.status, chalk_hosted::tenant::TenantStatus::Active);

    // Re-using the same token must fail (single-use).
    let req = Request::builder()
        .uri(format!("/api/signup/verify?token={token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore]
async fn signup_verify_stale_token_400() {
    let url = db_url().await;
    reset_meta(&url, &[]).await;
    let (app, _registry) = build_app(&url).await;
    let req = Request::builder()
        .uri("/api/signup/verify?token=does-not-exist")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore]
async fn signup_post_reserved_slug_400() {
    let url = db_url().await;
    reset_meta(&url, &[]).await;
    let (app, _registry) = build_app(&url).await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/signup")
        .header("content-type", "application/json")
        .body(signup_body("www"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore]
async fn signup_post_rate_limit() {
    let url = db_url().await;
    reset_meta(&url, &["a1", "a2", "a3", "a4"]).await;
    let (app, _registry) = build_app(&url).await;
    for slug in ["a1", "a2", "a3"] {
        let req = Request::builder()
            .method("POST")
            .uri("/api/signup")
            .header("content-type", "application/json")
            .body(signup_body(slug))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "slug {slug}");
    }
    let req = Request::builder()
        .method("POST")
        .uri("/api/signup")
        .header("content-type", "application/json")
        .body(signup_body("a4"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}
