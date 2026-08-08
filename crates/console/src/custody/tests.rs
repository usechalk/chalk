//! Circulation-desk tests: check-out assigns the device through the audited
//! path, check-in reverses it, and the boundaries hold (double checkout, no
//! such person, bad date).

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetEventRepository, AssetRepository, ChalkRepository, CustodyRepository, OrgRepository,
    UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::asset::{Asset, AssetEventFilter};
use chalk_core::models::common::{OrgType, RoleType, Status};
use chalk_core::models::org::Org;
use chalk_core::models::page::PageRequest;
use chalk_core::models::user::User;
use chrono::TimeZone;
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
    repo.upsert_org(&Org {
        sourced_id: "org-a".into(),
        status: Status::Active,
        date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        metadata: None,
        name: "Alpha High".into(),
        org_type: OrgType::School,
        identifier: None,
        parent: None,
        children: vec![],
    })
    .await
    .unwrap();
    repo.upsert_user(&User {
        sourced_id: "u-lisa".into(),
        status: Status::Active,
        date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        metadata: None,
        username: "lisa.nowak".into(),
        user_ids: vec![],
        enabled_user: true,
        given_name: "Lisa".into(),
        family_name: "Nowak".into(),
        middle_name: None,
        role: RoleType::Student,
        identifier: None,
        email: Some("lisa.nowak@example.edu".into()),
        sms: None,
        phone: None,
        agents: vec![],
        orgs: vec![],
        grades: vec![],
    })
    .await
    .unwrap();
    let mut a = Asset::new("dev-1");
    a.asset_tag = Some("CB-0001".into());
    repo.create_asset(&a).await.unwrap();

    let assets: Arc<dyn AssetRepository> = repo.clone();
    let events: Arc<dyn AssetEventRepository> = repo.clone();
    let custody: Arc<dyn CustodyRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, ChalkConfig::generate_default())
            .with_assets(assets, events)
            .with_custody(custody),
    );
    Fx { state, repo }
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

/// The full loop: check out by email → custody open, device assigned via the
/// audited path → circulation lists it → check in → custody closed with the
/// return condition, device unassigned, history has both events.
#[tokio::test]
async fn the_desk_checks_a_device_out_and_back_in() {
    let f = fixture().await;

    let (status, location) = post(
        f.state.clone(),
        "/devices/dev-1/checkout",
        "user=lisa.nowak@example.edu&due=2027-06-05&condition=good&agreement=1",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("checked_out"), "got {location}");

    // Custody is open, with the agreement recorded and the due date set.
    let open = f
        .repo
        .open_custody_for_asset("dev-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(open.user_sourced_id, "u-lisa", "resolved by exact email");
    assert!(open.agreement_acknowledged);
    assert!(open.due_at.is_some());

    // The device itself is assigned, manually — a sync must not undo the desk.
    let asset = f.repo.get_asset("dev-1").await.unwrap().unwrap();
    assert_eq!(asset.assigned_user_sourced_id.as_deref(), Some("u-lisa"));
    assert_eq!(
        asset.match_state,
        chalk_core::models::asset::MatchState::Manual
    );

    // The device page shows the loan; circulation lists it.
    let (_, page) = get(f.state.clone(), "/devices/dev-1").await;
    assert!(page.contains("Checked out to"));
    assert!(page.contains("Nowak, Lisa"));
    let (_, circ) = get(f.state.clone(), "/devices/circulation").await;
    assert!(circ.contains("CB-0001"));
    assert!(circ.contains("Nowak, Lisa"));

    // Check it back in with a condition note.
    let (status, location) = post(
        f.state.clone(),
        "/devices/dev-1/checkin",
        "condition=one+new+scratch",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("checked_in"), "got {location}");

    assert!(f
        .repo
        .open_custody_for_asset("dev-1")
        .await
        .unwrap()
        .is_none());
    let asset = f.repo.get_asset("dev-1").await.unwrap().unwrap();
    assert_eq!(asset.assigned_user_sourced_id, None, "unassigned at return");
    let history = f.repo.custody_history_for_asset("dev-1").await.unwrap();
    assert_eq!(history[0].condition_in.as_deref(), Some("one new scratch"));

    // Both movements are in the device's audit history.
    let events = f
        .repo
        .list_events(
            &AssetEventFilter::for_asset("dev-1"),
            PageRequest::new(10, 0),
        )
        .await
        .unwrap();
    let kinds: Vec<_> = events
        .items
        .iter()
        .map(|e| e.event_type.as_str().to_string())
        .collect();
    assert!(kinds.contains(&"assigned".to_string()), "checkout audited");
    assert!(kinds.contains(&"unassigned".to_string()), "checkin audited");
}

/// The boundaries: a second checkout is refused in words, an unknown person is
/// refused, a bad date is refused, and checking in an idle device says so.
#[tokio::test]
async fn the_desk_refuses_what_it_must() {
    let f = fixture().await;

    // Unknown person.
    let (_, location) = post(
        f.state.clone(),
        "/devices/dev-1/checkout",
        "user=nobody@example.edu",
    )
    .await;
    assert!(location.contains("custody_no_user"));

    // Bad date.
    let (_, location) = post(
        f.state.clone(),
        "/devices/dev-1/checkout",
        "user=u-lisa&due=tomorrow",
    )
    .await;
    assert!(location.contains("custody_bad_date"));

    // Check in with nothing out.
    let (_, location) = post(f.state.clone(), "/devices/dev-1/checkin", "").await;
    assert!(location.contains("custody_none"));

    // Real checkout by roster id, then a second is refused.
    let (_, location) = post(f.state.clone(), "/devices/dev-1/checkout", "user=u-lisa").await;
    assert!(location.contains("checked_out"));
    let (_, location) = post(f.state.clone(), "/devices/dev-1/checkout", "user=u-lisa").await;
    assert!(
        location.contains("custody_open"),
        "one open loan per device"
    );
}
