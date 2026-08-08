//! Item-class tests. The invariant that carries the module: available =
//! total − open holdings, enforced at issue, at adjust, and at delete — and
//! the accessory/consumable split (returnable vs consumed) never blurs.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{ChalkRepository, ItemRepository, UserRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::common::{RoleType, Status};
use chalk_core::models::user::User;
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
    repo.upsert_user(&User {
        sourced_id: "u-maya".into(),
        status: Status::Active,
        date_last_modified: Utc::now(),
        metadata: None,
        username: "maya.chen".into(),
        user_ids: vec![],
        enabled_user: true,
        given_name: "Maya".into(),
        family_name: "Chen".into(),
        middle_name: None,
        role: RoleType::Student,
        identifier: None,
        email: Some("maya.chen@example.edu".into()),
        sms: None,
        phone: None,
        agents: vec![],
        orgs: vec![],
        grades: vec![],
    })
    .await
    .unwrap();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let items: Arc<dyn ItemRepository> = repo.clone();
    let state =
        Arc::new(AppState::new(chalk_repo, ChalkConfig::generate_default()).with_items(items));
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

/// The accessory loop: create 5 → issue 3 → availability says 2 → issuing 3
/// more is refused in words → return brings the stock home.
#[tokio::test]
async fn a_the_accessory_loop_keeps_the_count_honest() {
    let f = fixture().await;
    post(
        f.state.clone(),
        "/items",
        "name=45W+charger&item_type=accessory&quantity=5",
    )
    .await;
    let item = &f.repo.list_all_items().await.unwrap()[0];

    let (_, loc) = post(
        f.state.clone(),
        &format!("/items/{}/issue", item.id),
        "user=maya.chen@example.edu&quantity=3",
    )
    .await;
    assert!(loc.contains("notice=issued"), "got {loc}");
    assert_eq!(f.repo.issued_quantity(&item.id).await.unwrap(), 3);

    let (_, page) = get(f.state.clone(), &format!("/items/{}", item.id)).await;
    assert!(page.contains("2 of 5 available"));

    // Over-issue: refused, count unchanged.
    let (_, loc) = post(
        f.state.clone(),
        &format!("/items/{}/issue", item.id),
        "user=maya.chen@example.edu&quantity=3",
    )
    .await;
    assert!(loc.contains("notice=not_enough"), "got {loc}");
    assert_eq!(f.repo.issued_quantity(&item.id).await.unwrap(), 3);

    // Return: stock comes home.
    let holding = &f.repo.list_holdings_for_item(&item.id).await.unwrap()[0];
    let (_, loc) = post(
        f.state.clone(),
        &format!("/items/{}/holdings/{}/return", item.id, holding.id),
        "",
    )
    .await;
    assert!(loc.contains("notice=returned"), "got {loc}");
    assert_eq!(f.repo.issued_quantity(&item.id).await.unwrap(), 0);
}

/// A consumable is consumed: its holding cannot be returned, and the issued
/// count only grows.
#[tokio::test]
async fn a_consumable_never_comes_back() {
    let f = fixture().await;
    post(
        f.state.clone(),
        "/items",
        "name=Stylus&item_type=consumable&quantity=10",
    )
    .await;
    let item = &f.repo.list_all_items().await.unwrap()[0];
    post(
        f.state.clone(),
        &format!("/items/{}/issue", item.id),
        "user=u-maya&quantity=4",
    )
    .await;
    let holding = &f.repo.list_holdings_for_item(&item.id).await.unwrap()[0];
    let (_, loc) = post(
        f.state.clone(),
        &format!("/items/{}/holdings/{}/return", item.id, holding.id),
        "",
    )
    .await;
    assert!(loc.contains("notice=failed"), "consumables do not return");
    assert_eq!(f.repo.issued_quantity(&item.id).await.unwrap(), 4);
}

/// Stock in hands cannot be adjusted away on paper, and an item with stock
/// out cannot be deleted.
#[tokio::test]
async fn a_issued_stock_is_protected_from_paperwork() {
    let f = fixture().await;
    post(
        f.state.clone(),
        "/items",
        "name=Hotspot&item_type=accessory&quantity=5",
    )
    .await;
    let item = &f.repo.list_all_items().await.unwrap()[0];
    post(
        f.state.clone(),
        &format!("/items/{}/issue", item.id),
        "user=u-maya&quantity=4",
    )
    .await;

    let (_, loc) = post(
        f.state.clone(),
        &format!("/items/{}/adjust", item.id),
        "quantity=2",
    )
    .await;
    assert!(loc.contains("notice=not_enough"), "got {loc}");
    assert_eq!(
        f.repo
            .get_item(&item.id)
            .await
            .unwrap()
            .unwrap()
            .quantity_total,
        5
    );

    let (_, loc) = post(f.state.clone(), &format!("/items/{}/delete", item.id), "").await;
    assert!(loc.contains("notice=not_enough"), "not deletable while out");
    assert!(f.repo.get_item(&item.id).await.unwrap().is_some());
}

/// Junk inputs refuse in words: unknown user, zero quantity, unknown kind.
#[tokio::test]
async fn a_junk_inputs_refuse_in_words() {
    let f = fixture().await;
    let (_, loc) = post(
        f.state.clone(),
        "/items",
        "name=X&item_type=weapon&quantity=1",
    )
    .await;
    assert!(loc.contains("notice=bad_input"));
    post(
        f.state.clone(),
        "/items",
        "name=Charger&item_type=accessory&quantity=5",
    )
    .await;
    let item = &f.repo.list_all_items().await.unwrap()[0];
    let (_, loc) = post(
        f.state.clone(),
        &format!("/items/{}/issue", item.id),
        "user=ghost@nowhere.test&quantity=1",
    )
    .await;
    assert!(loc.contains("notice=no_user"));
    let (_, loc) = post(
        f.state.clone(),
        &format!("/items/{}/issue", item.id),
        "user=u-maya&quantity=0",
    )
    .await;
    assert!(loc.contains("notice=bad_input"));
}
