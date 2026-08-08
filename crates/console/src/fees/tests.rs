//! Repair + fee tests. The invariants that matter: money parses exactly or
//! not at all, a repair drives the device status through the audited path, a
//! fee lands on the person holding the device, and the balance a family is
//! quoted counts only what is still assessed.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetEventRepository, AssetRepository, ChalkRepository, ChargeRepository, CustodyRepository,
    RepairRepository, UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::asset::Asset;
use chalk_core::models::common::{RoleType, Status};
use chalk_core::models::user::User;
use chrono::TimeZone;
use tower::ServiceExt;

use crate::router;

#[test]
fn dollars_parse_exactly_or_not_at_all() {
    assert_eq!(parse_dollars_to_cents("129.99"), Some(12999));
    assert_eq!(parse_dollars_to_cents("$129.99"), Some(12999));
    assert_eq!(parse_dollars_to_cents("1,299.00"), Some(129900));
    assert_eq!(parse_dollars_to_cents("25"), Some(2500));
    assert_eq!(parse_dollars_to_cents(" 0.50 "), Some(50));
    assert_eq!(parse_dollars_to_cents("129.9"), None, "one cent digit");
    assert_eq!(parse_dollars_to_cents("129.999"), None, "three cent digits");
    assert_eq!(parse_dollars_to_cents("abc"), None);
    assert_eq!(parse_dollars_to_cents(""), None);
    assert_eq!(format_cents(12999), "$129.99");
    assert_eq!(format_cents(50), "$0.50");
}

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
    repo.upsert_user(&User {
        sourced_id: "u-maya".into(),
        status: Status::Active,
        date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        metadata: None,
        username: "maya.chen".into(),
        user_ids: vec![],
        enabled_user: true,
        given_name: "Maya".into(),
        family_name: "Chen".into(),
        middle_name: None,
        role: RoleType::Student,
        identifier: None,
        email: Some("maya.chen@district.test".into()),
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
    a.assigned_user_sourced_id = Some("u-maya".into());
    repo.create_asset(&a).await.unwrap();

    let assets: Arc<dyn AssetRepository> = repo.clone();
    let events: Arc<dyn AssetEventRepository> = repo.clone();
    let custody: Arc<dyn CustodyRepository> = repo.clone();
    let repairs: Arc<dyn RepairRepository> = repo.clone();
    let charges: Arc<dyn ChargeRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, ChalkConfig::generate_default())
            .with_assets(assets, events)
            .with_custody(custody)
            .with_repairs(repairs)
            .with_charges(charges),
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

/// The repair loop: open puts the device in Repair (audited), close with a
/// cost and "assess" puts it back Active and lands the cost as a fee on the
/// holder, linked reason and all.
#[tokio::test]
async fn a_repair_opens_closes_and_assesses_its_cost() {
    let f = fixture().await;

    let (_, location) = post(
        f.state.clone(),
        "/devices/dev-1/repairs",
        "description=Cracked+screen&vendor=Acme+Repair",
    )
    .await;
    assert!(location.contains("repair_opened"), "got {location}");
    let asset = f.repo.get_asset("dev-1").await.unwrap().unwrap();
    assert_eq!(
        asset.status,
        chalk_core::models::asset::AssetStatus::Repair,
        "status follows the record"
    );

    // A second open is refused in words.
    let (_, location) = post(
        f.state.clone(),
        "/devices/dev-1/repairs",
        "description=Another",
    )
    .await;
    assert!(location.contains("repair_open"));

    // Close with a cost and assess it.
    let (_, location) = post(
        f.state.clone(),
        "/devices/dev-1/repairs/close",
        "cost=129.99&assess=1",
    )
    .await;
    assert!(location.contains("repair_closed_fee"), "got {location}");

    let asset = f.repo.get_asset("dev-1").await.unwrap().unwrap();
    assert_eq!(asset.status, chalk_core::models::asset::AssetStatus::Active);
    let history = f.repo.repair_history_for_asset("dev-1").await.unwrap();
    assert_eq!(history[0].cost_cents, Some(12999));
    assert!(!history[0].is_open());

    let charges = f.repo.list_charges_for_user("u-maya").await.unwrap();
    assert_eq!(charges.len(), 1);
    assert_eq!(charges[0].amount_cents, 12999);
    assert_eq!(
        charges[0].kind,
        chalk_core::models::charge::ChargeKind::RepairFee
    );
    assert_eq!(
        charges[0].reason.as_deref(),
        Some("Cracked screen"),
        "the repair description travels to the fee"
    );
}

/// Money that does not parse is refused, and a fee with no holder and no named
/// person has nowhere to land.
#[tokio::test]
async fn bad_money_and_missing_people_are_refused() {
    let f = fixture().await;

    let (_, location) = post(
        f.state.clone(),
        "/devices/dev-1/charges",
        "kind=damage_fine&amount=1.9",
    )
    .await;
    assert!(location.contains("bad_amount"));

    // Unassign the device; a holder-targeted fee now has nobody.
    use chalk_core::models::asset::{AssetPatch, Patch};
    f.repo
        .update_asset(
            "dev-1",
            &AssetPatch {
                assigned_user_sourced_id: Patch::Clear,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_, location) = post(
        f.state.clone(),
        "/devices/dev-1/charges",
        "kind=damage_fine&amount=25.00",
    )
    .await;
    assert!(location.contains("fee_no_holder"));
    assert!(f
        .repo
        .list_charges_for_user("u-maya")
        .await
        .unwrap()
        .is_empty());
}

/// The user page shows the ledger with the outstanding balance, and waiving or
/// settling from it drops the charge from the balance while keeping the row.
#[tokio::test]
async fn the_user_page_shows_and_settles_the_balance() {
    let f = fixture().await;
    for (amount, reason) in [("25.00", "case"), ("100.00", "screen")] {
        post(
            f.state.clone(),
            "/devices/dev-1/charges",
            &format!("kind=damage_fine&amount={amount}&reason={reason}"),
        )
        .await;
    }

    let (_, page) = get(f.state.clone(), "/users/u-maya").await;
    assert!(
        page.contains("$125.00"),
        "balance sums the assessed charges"
    );
    assert!(page.contains("Waive"));

    // Waive one; the balance is what remains.
    let id = f.repo.list_charges_for_user("u-maya").await.unwrap()[0]
        .id
        .clone();
    let (_, location) = post(
        f.state.clone(),
        &format!("/charges/{id}/waive"),
        "user=u-maya",
    )
    .await;
    assert!(
        location.contains("/users/u-maya"),
        "lands back on the person"
    );
    let (_, page) = get(f.state.clone(), "/users/u-maya").await;
    assert!(
        page.contains("$25.00") || page.contains("$100.00"),
        "one remains outstanding"
    );
    assert!(page.contains("Waived"), "the waived row is still shown");
    assert!(!page.contains("$125.00"), "the balance dropped");

    // Settle the other; no balance is quoted at all.
    let remaining = f
        .repo
        .list_charges_for_user("u-maya")
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.status.is_outstanding())
        .unwrap();
    post(
        f.state.clone(),
        &format!("/charges/{}/settle", remaining.id),
        "user=u-maya",
    )
    .await;
    let (_, page) = get(f.state.clone(), "/users/u-maya").await;
    assert!(!page.contains("outstanding"), "nothing left to quote");
    assert!(page.contains("Settled externally"));
}
