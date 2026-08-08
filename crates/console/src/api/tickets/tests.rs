//! Ticket API tests.
//!
//! Like the device API, almost all of these are about the scope boundary — the
//! part that can be wrong while looking right. A scoped token is how a district
//! shares part of its help desk with a reporting integration; a leak here is a
//! ticket's contents going somewhere the district did not agree to.

use super::*;

use axum::body::Body;
use axum::http::Request;
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{ChalkRepository, OrgRepository, TicketRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::common::{OrgType, Status};
use chalk_core::models::org::Org;
use chalk_core::models::ticket::{NewTicketComment, Ticket};
use chrono::{TimeZone, Utc};
use serde_json::Value;
use tower::ServiceExt;

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
    for (id, name) in [("org-a", "Alpha High"), ("org-b", "Beta Middle")] {
        repo.upsert_org(&Org {
            sourced_id: id.into(),
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

    let tickets: Arc<dyn TicketRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state =
        Arc::new(AppState::new(chalk_repo, ChalkConfig::generate_default()).with_tickets(tickets));
    Fx { state, repo }
}

/// A ticket at a school, with its subject as the identifier. Returns the id the
/// repository assigned so a single-ticket route can address it.
async fn ticket(f: &Fx, id: &str, school: Option<&str>) -> Ticket {
    let mut t = Ticket::new(id, format!("Subject {id}"));
    t.school_org_sourced_id = school.map(str::to_string);
    f.repo.create_ticket(&t).await.unwrap()
}

/// Call the API directly with a scope, bypassing the bearer middleware — the
/// middleware's job (token → `ScopeContext`) is tested where it lives. What
/// matters here is what the handlers do with one.
async fn call(state: Arc<AppState>, uri: &str, scope: Option<TokenScope>) -> (StatusCode, Value) {
    let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    req.extensions_mut().insert(ScopeContext(scope));
    let response = tickets_router()
        .with_state(state)
        .oneshot(req)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn scoped_to(orgs: &[&str]) -> TokenScope {
    TokenScope {
        orgs: orgs.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

/// Subjects of the tickets in a list body, sorted for a stable comparison.
fn subjects(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v["tickets"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|t| t["subject"].as_str().map(str::to_string))
        .collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// The unscoped case
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unscoped_token_sees_the_whole_help_desk() {
    let f = fixture().await;
    ticket(&f, "a", Some("org-a")).await;
    ticket(&f, "b", Some("org-b")).await;
    ticket(&f, "c", None).await;

    let (status, body) = call(f.state.clone(), "/tickets", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(subjects(&body), vec!["Subject a", "Subject b", "Subject c"]);
}

// ---------------------------------------------------------------------------
// The scope boundary
// ---------------------------------------------------------------------------

/// A scoped token sees only its schools — and the boundary is in the query, so
/// the reported total matches what was returned rather than leaking the size of
/// the part the caller was denied.
#[tokio::test]
async fn a_scoped_token_sees_only_its_schools_and_a_matching_total() {
    let f = fixture().await;
    ticket(&f, "a", Some("org-a")).await;
    ticket(&f, "b", Some("org-b")).await;
    ticket(&f, "c", None).await;

    let mut req = Request::builder()
        .uri("/tickets")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ScopeContext(Some(scoped_to(&["org-a"]))));
    let response = tickets_router()
        .with_state(f.state.clone())
        .oneshot(req)
        .await
        .unwrap();
    let total = response
        .headers()
        .get("x-total-count")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(subjects(&body), vec!["Subject a"]);
    assert_eq!(
        total.as_deref(),
        Some("1"),
        "the total must count what the caller may see, not the whole desk"
    );
}

/// A ticket with no school is invisible to a scoped token: the token was
/// granted *specific* schools, and "belongs to none of them" is not one.
#[tokio::test]
async fn a_ticket_with_no_school_is_invisible_to_a_scoped_token() {
    let f = fixture().await;
    let t = ticket(&f, "c", None).await;

    let (_, list) = call(f.state.clone(), "/tickets", Some(scoped_to(&["org-a"]))).await;
    assert!(subjects(&list).is_empty());

    let (status, _) = call(
        f.state.clone(),
        &format!("/tickets/{}", t.id),
        Some(scoped_to(&["org-a"])),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A caller's filter narrows within the boundary; it never widens it.
#[tokio::test]
async fn filtering_to_a_school_outside_the_scope_returns_nothing() {
    let f = fixture().await;
    ticket(&f, "a", Some("org-a")).await;
    ticket(&f, "b", Some("org-b")).await;

    let (status, body) = call(
        f.state.clone(),
        "/tickets?school=org-b",
        Some(scoped_to(&["org-a"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        subjects(&body).is_empty(),
        "the filter must intersect with the scope, not replace it"
    );
}

/// Fetching one ticket outside the scope is **404, not 403** — a 403 would
/// confirm the ticket exists, which is exactly what the scope withholds.
#[tokio::test]
async fn a_ticket_outside_the_scope_is_indistinguishable_from_one_that_is_absent() {
    let f = fixture().await;
    let t = ticket(&f, "b", Some("org-b")).await;

    let (denied, _) = call(
        f.state.clone(),
        &format!("/tickets/{}", t.id),
        Some(scoped_to(&["org-a"])),
    )
    .await;
    let (absent, _) = call(
        f.state.clone(),
        "/tickets/nonexistent",
        Some(scoped_to(&["org-a"])),
    )
    .await;
    assert_eq!(denied, StatusCode::NOT_FOUND);
    assert_eq!(absent, denied, "the two must be the same answer");
}

/// The comments route checks the *ticket's* school before listing anything.
/// Without that, a route that never mentions a school would leak both a
/// ticket's existence and its whole thread.
#[tokio::test]
async fn comments_for_a_ticket_outside_the_scope_are_refused() {
    let f = fixture().await;
    let a = ticket(&f, "a", Some("org-a")).await;
    let b = ticket(&f, "b", Some("org-b")).await;
    for t in [&a, &b] {
        f.repo
            .append_comment(&NewTicketComment::from_console(&t.id, None, "looking").internal())
            .await
            .unwrap();
    }

    let (allowed, body) = call(
        f.state.clone(),
        &format!("/tickets/{}/comments", a.id),
        Some(scoped_to(&["org-a"])),
    )
    .await;
    assert_eq!(allowed, StatusCode::OK);
    assert_eq!(body["comments"].as_array().map(Vec::len), Some(1));

    let (refused, refused_body) = call(
        f.state.clone(),
        &format!("/tickets/{}/comments", b.id),
        Some(scoped_to(&["org-a"])),
    )
    .await;
    assert_eq!(refused, StatusCode::NOT_FOUND);
    assert!(refused_body["comments"].is_null(), "no thread leaks");
}

/// The thread includes internal notes: an API token is the district's own, so
/// withholding its own notes from its own integration would be theatre.
#[tokio::test]
async fn the_thread_includes_internal_notes() {
    let f = fixture().await;
    let t = ticket(&f, "a", Some("org-a")).await;
    f.repo
        .append_comment(
            &NewTicketComment::from_console(&t.id, None, "escalate to vendor").internal(),
        )
        .await
        .unwrap();

    let (status, body) = call(
        f.state.clone(),
        &format!("/tickets/{}/comments", t.id),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let first = &body["comments"][0];
    assert_eq!(first["isInternal"], Value::Bool(true), "flag is intact");
    assert_eq!(first["body"], "escalate to vendor");
}

/// A token denied the tickets resource outright gets 403 on every route,
/// including the ones that would otherwise 404.
#[tokio::test]
async fn a_token_denied_tickets_is_refused_everywhere() {
    let f = fixture().await;
    let t = ticket(&f, "a", Some("org-a")).await;

    let mut scope = TokenScope::default();
    scope.resources.insert(OneRosterResource::Tickets, false);

    for path in [
        "/tickets".to_string(),
        format!("/tickets/{}", t.id),
        format!("/tickets/{}/comments", t.id),
    ] {
        let (status, _) = call(f.state.clone(), &path, Some(scope.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path} was not refused");
    }
}

// ---------------------------------------------------------------------------
// Ordinary behaviour
// ---------------------------------------------------------------------------

/// The limit is clamped rather than trusted, and a zero limit degrades instead
/// of 500ing.
#[tokio::test]
async fn the_page_limit_is_clamped_at_both_ends() {
    let f = fixture().await;
    for i in 0..5 {
        ticket(&f, &format!("d{i}"), Some("org-a")).await;
    }

    let (_, body) = call(f.state.clone(), "/tickets?limit=2", None).await;
    assert_eq!(subjects(&body).len(), 2);

    let (_, huge) = call(f.state.clone(), "/tickets?limit=999999", None).await;
    assert_eq!(subjects(&huge).len(), 5, "clamped, not rejected");

    let (status, _) = call(f.state.clone(), "/tickets?limit=0", None).await;
    assert_eq!(status, StatusCode::OK, "a zero limit degrades, never 500s");
}

/// An unparseable filter value widens rather than 400s, matching the console.
#[tokio::test]
async fn an_unparseable_filter_is_ignored_rather_than_rejected() {
    let f = fixture().await;
    ticket(&f, "a", Some("org-a")).await;

    let (status, body) = call(f.state.clone(), "/tickets?status=nonsense", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(subjects(&body), vec!["Subject a"]);
}

/// There are no write routes, deliberately: a ticket's lifecycle is a console
/// flow with attribution and a disclosure boundary, and an API POST would step
/// around it.
#[tokio::test]
async fn the_api_offers_no_way_to_change_a_ticket() {
    let f = fixture().await;
    let t = ticket(&f, "a", Some("org-a")).await;

    for (method, path) in [
        ("POST", "/tickets".to_string()),
        ("PATCH", format!("/tickets/{}", t.id)),
        ("PUT", format!("/tickets/{}", t.id)),
        ("DELETE", format!("/tickets/{}", t.id)),
        ("POST", format!("/tickets/{}/comments", t.id)),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(&path)
            .body(Body::empty())
            .unwrap();
        let response = tickets_router()
            .with_state(f.state.clone())
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} must not be routable"
        );
    }
}
