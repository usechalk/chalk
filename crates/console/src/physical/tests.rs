//! Physical-inventory tests: the scan lookup resolves tag-then-serial, the
//! label sheet prints what the filter matched and says when it was cut, and
//! the audit reconciles a scope into found / missing / stray with nothing
//! held server-side between scans.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetEventRepository, AssetRepository, ChalkRepository, OrgRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::common::Status;
use chalk_core::models::org::Org;
use chrono::{TimeZone, Utc};
use tower::ServiceExt;

use crate::router;

struct Fx {
    state: Arc<AppState>,
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
            date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
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

    // Alpha High holds two devices; Beta Middle holds one; one device has a
    // serial but no tag.
    for (id, tag, serial, school) in [
        ("d-1", Some("CB-0001"), Some("SER-1"), "org-a"),
        ("d-2", None, Some("SER-2"), "org-a"),
        ("d-3", Some("CB-0003"), Some("SER-3"), "org-b"),
    ] {
        let mut a = Asset::new(id);
        a.asset_tag = tag.map(str::to_string);
        a.serial_number = serial.map(str::to_string);
        a.model = Some("Spin 511".into());
        a.school_org_sourced_id = Some(school.into());
        repo.create_asset(&a).await.unwrap();
    }

    let assets: Arc<dyn AssetRepository> = repo.clone();
    let events: Arc<dyn AssetEventRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, ChalkConfig::generate_default()).with_assets(assets, events),
    );
    Fx { state }
}

async fn get(state: Arc<AppState>, uri: &str) -> (StatusCode, String, String) {
    let res = router(state)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let location = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        location,
        String::from_utf8_lossy(&bytes).to_string(),
    )
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
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

// ---------------------------------------------------------------------------
// Scan lookup
// ---------------------------------------------------------------------------

/// A scanned tag goes straight to the device page; a serial works when there
/// is no tag; junk lands on the searched inventory rather than an error.
#[tokio::test]
async fn a_scan_resolves_tag_then_serial_and_degrades_to_search() {
    let f = fixture().await;

    let (status, location, _) = get(f.state.clone(), "/devices/scan?code=CB-0001").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/devices/d-1", "tag hit goes to the device");

    let (_, location, _) = get(f.state.clone(), "/devices/scan?code=SER-2").await;
    assert_eq!(
        location, "/devices/d-2",
        "serial works when there is no tag"
    );

    let (status, location, _) = get(f.state.clone(), "/devices/scan?code=NOPE-99").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location, "/devices?q=NOPE-99",
        "an unknown code lands on the searched inventory"
    );
}

/// A duplicated tag is ambiguity, and ambiguity goes to the list — jumping to
/// one of two devices would silently pick a side.
#[tokio::test]
async fn a_duplicate_tag_scans_to_the_list_not_a_coin_flip() {
    let f = fixture().await;
    let assets = f.state.assets.clone().unwrap();
    let mut dup = Asset::new("d-dup");
    dup.asset_tag = Some("CB-0001".into());
    assets.create_asset(&dup).await.unwrap();

    let (_, location, _) = get(f.state.clone(), "/devices/scan?code=CB-0001").await;
    assert_eq!(location, "/devices?q=CB-0001");
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

/// The sheet renders one QR per device the filter matched, encoding the same
/// string the scan lookup resolves (tag first, serial when tagless).
#[tokio::test]
async fn a_label_sheet_prints_the_filtered_view() {
    let f = fixture().await;

    let (status, _, html) = get(f.state.clone(), "/devices/labels?school=org-a").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(html.matches("<svg").count(), 2, "one QR per device");
    assert!(html.contains("CB-0001"));
    assert!(
        html.contains("SER-2"),
        "the tagless device is labeled by serial"
    );
    assert!(
        !html.contains("CB-0003"),
        "the other school is not on the sheet"
    );

    // One-device sheet, for the replacement sticker.
    let (status, _, html) = get(f.state.clone(), "/devices/labels/d-3").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(html.matches("<svg").count(), 1);
    assert!(html.contains("CB-0003"));
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// The whole walk: pick a school, scan one of its devices, then a device from
/// another school, then junk. Found / missing / stray all land where they
/// should, and every previously scanned code survives the round trip in the
/// re-rendered form.
#[tokio::test]
async fn a_an_audit_reconciles_found_missing_and_strays() {
    let f = fixture().await;

    // First scan: one of Alpha High's two devices.
    let (status, html) = post(
        f.state.clone(),
        "/devices/audit",
        "school=org-a&code=CB-0001&csrf_token=t",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("<h2>2</h2>"), "two expected in scope");
    assert!(html.contains("<h2>1</h2>"), "one accounted for");
    assert!(
        html.contains("SER-2"),
        "the unscanned device is listed missing"
    );

    // Second scan: Beta Middle's device — in the inventory, not in scope.
    let (_, html) = post(
        f.state.clone(),
        "/devices/audit",
        "school=org-a&scanned=CB-0001&code=CB-0003&csrf_token=t",
    )
    .await;
    assert!(
        html.contains("not in this scope"),
        "misplaced device is a stray"
    );
    assert!(
        html.contains("/devices/d-3"),
        "and it links to what it actually is"
    );

    // Third scan: a code the inventory has never seen.
    let (_, html) = post(
        f.state.clone(),
        "/devices/audit",
        "school=org-a&scanned=CB-0001%0ACB-0003&code=GHOST-1&csrf_token=t",
    )
    .await;
    assert!(html.contains("Not in the inventory at all"));
    // The hidden field carries the full walk for the next round trip.
    assert!(html.contains("CB-0001"));
    assert!(html.contains("GHOST-1"));
}

/// Scanning the same device twice means nothing — the walk's state
/// deduplicates, so the counts do not drift.
#[tokio::test]
async fn a_rescanning_a_device_changes_nothing() {
    let form = AuditForm {
        school: "org-a".into(),
        scanned: "CB-0001\nCB-0001".into(),
        code: "CB-0001".into(),
        ..AuditForm::default()
    };
    assert_eq!(form.all_codes(), vec!["CB-0001".to_string()]);
}

/// GET renders the scope picker with no reconciliation — an audit that has
/// not started must not display "0 missing" as though a walk found everything.
#[tokio::test]
async fn a_the_audit_page_starts_blank() {
    let f = fixture().await;
    let (status, _, html) = get(f.state.clone(), "/devices/audit").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Choose a scope"));
    assert!(!html.contains("Accounted for"), "no counts before a scope");
}
