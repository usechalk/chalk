//! Canned-response settings tests: create, list, delete through the router, and
//! that a saved reply reaches a ticket's reply picker.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    CannedResponseRepository, ChalkRepository, OrgRepository, TicketRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::common::{OrgType, Status};
use chalk_core::models::org::Org;
use chalk_core::models::ticket::Ticket;
use chrono::{TimeZone, Utc};
use tower::ServiceExt;

use crate::router;

async fn state() -> Arc<AppState> {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    // A school + a ticket, so the reply-picker test has a thread to open.
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
    let mut t = Ticket::new("t-1", "Cracked screen");
    t.school_org_sourced_id = Some("org-a".into());
    repo.create_ticket(&t).await.unwrap();

    let canned: Arc<dyn CannedResponseRepository> = repo.clone();
    let tickets: Arc<dyn TicketRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    Arc::new(
        AppState::new(chalk_repo, ChalkConfig::generate_default())
            .with_tickets(tickets)
            .with_canned_responses(canned),
    )
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

#[tokio::test]
async fn a_saved_reply_is_created_listed_and_deleted() {
    let s = state().await;

    let (status, _) = post(
        s.clone(),
        CANNED_PATH,
        "title=Ready+for+pickup&body=Your+device+is+ready+at+the+front+office.",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, body) = get(s.clone(), CANNED_PATH).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Ready for pickup"), "the title is listed");

    // Find its id to delete it.
    let opts = canned_options(&s).await;
    assert_eq!(opts.len(), 1);
    let id = opts[0].id.clone();

    let (status, _) = post(s.clone(), &format!("{CANNED_PATH}/{id}/delete"), "").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(canned_options(&s).await.is_empty(), "deleted");
}

#[tokio::test]
async fn a_blank_title_or_body_is_refused() {
    let s = state().await;
    let (status, location) = post(s.clone(), CANNED_PATH, "title=&body=something").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("err="), "flags the error");
    assert!(canned_options(&s).await.is_empty(), "nothing saved");
}

#[tokio::test]
async fn a_saved_reply_appears_in_the_ticket_reply_picker() {
    let s = state().await;
    s.canned_responses
        .as_ref()
        .unwrap()
        .create_canned_response(&CannedResponse::new(
            "cr-1",
            "Hard reset",
            "Hold power for ten seconds.",
        ))
        .await
        .unwrap();

    let (status, body) = get(s.clone(), "/tickets/t-1").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("canned-picker"), "the picker is rendered");
    assert!(body.contains("Hard reset"), "and offers the saved reply");
    // The body rides in a data attribute for client-side insertion.
    assert!(body.contains("Hold power for ten seconds."));
}
