//! POs and funding sources through the real router: create, count received
//! devices via the po_number join, refuse deleting while referenced.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::db::repository::{AdminSessionRepository, AssetRepository, ProcurementRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::audit::AdminSession;
use chrono::Duration;
use tower::ServiceExt;

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!(),
    };
    let mut config = crate::tests::default_config();
    config.chalk.admin_password_hash = Some(crate::auth::hash_password("unused").unwrap());
    let state = Arc::new(crate::tests::wire_all(repo.clone(), config));
    repo.create_admin_session(&AdminSession {
        token: "adm".into(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: None,
        actor_id: None,
        actor_label: None,
        actor_role: None,
    })
    .await
    .unwrap();
    Fx { state, repo }
}

async fn post(fx: &Fx, uri: &str, body: &str) -> String {
    let csrf = crate::csrf::generate_csrf_token();
    let res = crate::router(fx.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", format!("chalk_session=adm; chalk_csrf={csrf}"))
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

async fn get_html(fx: &Fx, uri: &str) -> (StatusCode, String) {
    let res = crate::router(fx.state.clone())
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("cookie", "chalk_session=adm")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).to_string())
}

#[tokio::test]
async fn a_po_counts_received_devices_and_guards_deletion() {
    let fx = fixture().await;
    let loc = post(
        &fx,
        "/devices/purchase-orders",
        "po_number=PO-2026-114&vendor=Trafera&funding_source=ESSER+III&po_date=2026-07-01&notes=300+Chromebooks",
    )
    .await;
    assert!(loc.contains("notice=created"), "got {loc}");
    // The same number twice is a duplicate, said plainly.
    let loc = post(&fx, "/devices/purchase-orders", "po_number=PO-2026-114").await;
    assert!(loc.contains("notice=duplicate"), "got {loc}");

    // A device received against it — the count follows the join.
    let mut a = chalk_core::models::asset::Asset::new("dev-po");
    a.asset_tag = Some("CB-PO-1".into());
    a.po_number = Some("PO-2026-114".into());
    fx.repo.create_asset(&a).await.unwrap();

    let (status, html) = get_html(&fx, "/devices/purchase-orders").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("PO-2026-114"));
    assert!(html.contains("1 devices"), "received count from the join");
    assert!(
        html.contains("/devices?q=PO-2026-114"),
        "the count links to the filtered inventory"
    );

    // Referenced: delete refused. Freed: delete works.
    let id = fx.repo.list_purchase_orders().await.unwrap()[0]
        .po
        .id
        .clone();
    let loc = post(&fx, &format!("/devices/purchase-orders/{id}/delete"), "").await;
    assert!(loc.contains("notice=in_use"), "got {loc}");

    // The inventory search finds the device by PO number.
    let (_, html) = get_html(&fx, "/devices?q=PO-2026-114").await;
    assert!(html.contains("CB-PO-1"));
}

#[tokio::test]
async fn funding_sources_feed_the_device_form() {
    let fx = fixture().await;
    let loc = post(&fx, "/settings/funding-sources", "name=ESSER+III").await;
    assert!(loc.contains("notice=created"), "got {loc}");
    let loc = post(&fx, "/settings/funding-sources", "name=ESSER+III").await;
    assert!(loc.contains("notice=duplicate"), "got {loc}");

    // The device form offers the managed name as a datalist choice.
    let (_, html) = get_html(&fx, "/devices/new").await;
    assert!(html.contains(r#"<option value="ESSER III">"#));

    // Unreferenced sources delete cleanly.
    let id = fx.repo.list_funding_sources().await.unwrap()[0].id.clone();
    let loc = post(&fx, &format!("/settings/funding-sources/{id}/delete"), "").await;
    assert!(loc.contains("notice=deleted"), "got {loc}");
}
