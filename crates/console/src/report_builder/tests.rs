//! Report-builder tests: a saved filter counts the same devices the
//! inventory shows, buckets resolve to words, junk is refused, and the CSV
//! is the table.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetEventRepository, AssetReportRepository, AssetRepository, ChalkRepository, OrgRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::asset::{Asset, AssetStatus};
use chalk_core::models::common::{OrgType, Status};
use chalk_core::models::org::Org;
use tower::ServiceExt;

use crate::router;

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    for (sid, name) in [("org-a", "Alpha High"), ("org-b", "Beta Middle")] {
        repo.upsert_org(&Org {
            sourced_id: sid.into(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            name: name.into(),
            org_type: OrgType::School,
            identifier: None,
            parent: None,
            children: vec![],
        })
        .await
        .unwrap();
    }
    // 2 repair at Alpha, 1 repair at Beta, 1 active at Alpha.
    for (id, school, status) in [
        ("d1", "org-a", AssetStatus::Repair),
        ("d2", "org-a", AssetStatus::Repair),
        ("d3", "org-b", AssetStatus::Repair),
        ("d4", "org-a", AssetStatus::Active),
    ] {
        let mut a = Asset::new(id);
        a.asset_tag = Some(format!("CB-{id}"));
        a.school_org_sourced_id = Some(school.into());
        a.status = status;
        repo.create_asset(&a).await.unwrap();
    }
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let assets: Arc<dyn AssetRepository> = repo.clone();
    let events: Arc<dyn AssetEventRepository> = repo.clone();
    let reports: Arc<dyn AssetReportRepository> = repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, ChalkConfig::generate_default())
            .with_assets(assets, events)
            .with_asset_reports(reports),
    );
    Fx { state, repo }
}

async fn post(state: Arc<AppState>, uri: &str, body: &str) -> (StatusCode, String) {
    let token = crate::csrf::generate_csrf_token();
    let res = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", format!("chalk_csrf={token}"))
                .header("x-csrf-token", &token)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let location = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, location)
}

async fn get(state: Arc<AppState>, uri: &str) -> (StatusCode, String) {
    let res = router(state)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// "Repairs by school": save, run, drill-down link carries the same filter,
/// CSV matches the table.
#[tokio::test]
async fn a_repairs_by_school_counts_and_exports() {
    let f = fixture().await;
    let (_, loc) = post(
        f.state.clone(),
        "/devices/reports/custom",
        "name=Repairs+by+school&group_by=school&status=repair",
    )
    .await;
    assert!(loc.contains("notice=created"), "got {loc}");
    let report = &f.repo.list_asset_reports().await.unwrap()[0];

    let (status, html) = get(
        f.state.clone(),
        &format!("/devices/reports/custom/{}", report.id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Alpha High"), "school ids resolve to names");
    assert!(html.contains("Beta Middle"));
    assert!(html.contains("3 devices"), "total counts the filtered set");
    assert!(
        html.contains("/devices?status=repair"),
        "drill-down opens the same filter in the inventory"
    );

    let (_, csv) = get(
        f.state.clone(),
        &format!("/devices/reports/custom/{}/export.csv", report.id),
    )
    .await;
    assert!(csv.contains("\"Alpha High\",2"));
    assert!(csv.contains("\"Beta Middle\",1"));
}

/// Grouping by status with no filter buckets the whole fleet.
#[tokio::test]
async fn a_status_report_over_everything() {
    let f = fixture().await;
    post(
        f.state.clone(),
        "/devices/reports/custom",
        "name=Fleet+by+status&group_by=status",
    )
    .await;
    let report = &f.repo.list_asset_reports().await.unwrap()[0];
    let (_, html) = get(
        f.state.clone(),
        &format!("/devices/reports/custom/{}", report.id),
    )
    .await;
    assert!(html.contains("4 devices"));
    assert!(html.contains("repair"));
    assert!(html.contains("active"));
}

/// Junk group-by and a missing name are refused; deleting removes it.
#[tokio::test]
async fn a_junk_is_refused_and_delete_deletes() {
    let f = fixture().await;
    let (_, loc) = post(
        f.state.clone(),
        "/devices/reports/custom",
        "name=X&group_by=password_hash",
    )
    .await;
    assert!(loc.contains("notice=bad_input"));
    let (_, loc) = post(
        f.state.clone(),
        "/devices/reports/custom",
        "name=&group_by=status",
    )
    .await;
    assert!(loc.contains("notice=bad_input"));

    post(
        f.state.clone(),
        "/devices/reports/custom",
        "name=Temp&group_by=status",
    )
    .await;
    let report_id = f.repo.list_asset_reports().await.unwrap()[0].id.clone();
    let (_, loc) = post(
        f.state.clone(),
        &format!("/devices/reports/custom/{report_id}/delete"),
        "",
    )
    .await;
    assert!(loc.contains("notice=deleted"));
    assert!(f.repo.list_asset_reports().await.unwrap().is_empty());
}
