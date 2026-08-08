//! Routing-rule tests: the settings page manages rules, and a ticket raised
//! through the console form is auto-assigned by them — proof the service seam
//! is actually wired.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    ChalkRepository, ConsoleUserRepository, RoutingRuleRepository, TicketRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::console_user::{ConsoleRole, ConsoleUser, ConsoleUserStatus};
use chrono::Utc;
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
    for (id, name, active) in [
        ("tech-ana", "Ana Cruz", true),
        ("tech-old", "Gone Tech", false),
    ] {
        repo.create_console_user(&ConsoleUser {
            id: id.into(),
            email: format!("{id}@district.test"),
            display_name: name.into(),
            password_hash: None,
            role: ConsoleRole::Technician,
            status: if active {
                ConsoleUserStatus::Active
            } else {
                ConsoleUserStatus::Disabled
            },
            totp_secret: None,
            totp_confirmed: false,
            totp_recovery: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .await
        .unwrap();
    }
    let tickets: Arc<dyn TicketRepository> = repo.clone();
    let users: Arc<dyn ConsoleUserRepository> = repo.clone();
    let rules: Arc<dyn RoutingRuleRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, ChalkConfig::generate_default())
            .with_tickets(tickets)
            .with_console_users(users)
            .with_routing_rules(rules),
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

/// A rule is added, listed with names rather than ids, and deleted.
#[tokio::test]
async fn a_rule_is_added_listed_and_deleted() {
    let f = fixture().await;

    let (status, location) = post(
        f.state.clone(),
        ROUTING_PATH,
        "category=Hardware&school=&technician=tech-ana",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("ok="), "confirmed, got {location}");

    let (_, page) = get(f.state.clone(), ROUTING_PATH).await;
    assert!(page.contains("hardware"), "category listed, lowercased");
    assert!(page.contains("Ana Cruz"), "the technician is named");
    assert!(page.contains("Any school"), "wildcard said in words");

    let id = f.repo.list_routing_rules().await.unwrap()[0].id.clone();
    let (status, _) = post(f.state.clone(), &format!("{ROUTING_PATH}/{id}/delete"), "").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(f.repo.list_routing_rules().await.unwrap().is_empty());
}

/// A suspended technician cannot be routed to, and a rule with no conditions
/// needs the explicit "any" — a catch-all must be said deliberately.
#[tokio::test]
async fn bad_rules_are_refused() {
    let f = fixture().await;

    let (_, location) = post(
        f.state.clone(),
        ROUTING_PATH,
        "category=hardware&school=&technician=tech-old",
    )
    .await;
    assert!(location.contains("err="), "suspended tech refused");

    let (_, location) = post(
        f.state.clone(),
        ROUTING_PATH,
        "category=&school=&technician=tech-ana",
    )
    .await;
    assert!(location.contains("err="), "conditionless rule refused");

    // The explicit word makes a catch-all.
    let (_, location) = post(
        f.state.clone(),
        ROUTING_PATH,
        "category=any&school=&technician=tech-ana",
    )
    .await;
    assert!(location.contains("ok="), "explicit catch-all accepted");
    let rules = f.repo.list_routing_rules().await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].category, None, "stored as a wildcard");
}

/// The proof the seam is wired: a ticket raised through the console form, with
/// a matching category, arrives already assigned to the routed technician.
#[tokio::test]
async fn a_console_ticket_is_auto_assigned_by_a_matching_rule() {
    let f = fixture().await;
    post(
        f.state.clone(),
        ROUTING_PATH,
        "category=hardware&school=&technician=tech-ana",
    )
    .await;

    let (status, _) = post(
        f.state.clone(),
        "/tickets/new",
        "subject=Cracked+screen&body=It+cracked.&priority=normal\
         &requester_email=coach@district.test&category=Hardware",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let page = f
        .repo
        .list_tickets(
            &chalk_core::models::ticket::TicketFilter::default(),
            &chalk_core::models::ticket::TicketScope::Unrestricted,
            chalk_core::models::page::PageRequest::new(10, 0),
        )
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(
        page.items[0].assignee_console_user_id.as_deref(),
        Some("tech-ana"),
        "routed at creation"
    );
}
