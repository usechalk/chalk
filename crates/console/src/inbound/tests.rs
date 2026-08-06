//! The inbound mail endpoint.
//!
//! This is the one route on the console that anybody on the internet can
//! reach, so most of what follows is about the door rather than the mail: it
//! must be shut unless configured, it must not open for a wrong secret, and it
//! must answer 200 to things it declines so a provider stops retrying.

use super::*;

use axum::body::Body;
use axum::http::Request;
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{ChalkRepository, TicketRepository, UserRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::common::{RoleType, Status};
use chalk_core::models::ticket::{TicketFilter, TicketScope};
use chalk_core::models::user::User;
use chrono::{TimeZone, Utc};
use tower::ServiceExt;

use crate::router;

const SECRET: &str = "s3cret-value";

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fx {
    let mut config = ChalkConfig::generate_default();
    config.helpdesk.inbound.provider = Some("postmark".into());
    config.helpdesk.inbound.secret = Some(SECRET.into());
    fixture_with(config).await
}

async fn fixture_with(config: ChalkConfig) -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!(),
    };
    repo.upsert_user(&User {
        sourced_id: "u-lisa".into(),
        status: Status::Active,
        date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        metadata: None,
        username: "lisa".into(),
        user_ids: vec![],
        enabled_user: true,
        given_name: "Lisa".into(),
        family_name: "Nowak".into(),
        middle_name: None,
        role: RoleType::Teacher,
        identifier: None,
        email: Some("lisa@example.edu".into()),
        sms: None,
        phone: None,
        agents: vec![],
        orgs: vec![],
        grades: vec![],
    })
    .await
    .unwrap();

    let tickets: Arc<dyn TicketRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(AppState::new(chalk_repo, config).with_tickets(tickets));
    Fx { state, repo }
}

async fn post(f: &Fx, uri: &str, body: &str) -> StatusCode {
    router(f.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

fn postmark(id: &str, subject: &str, body: &str) -> String {
    format!(
        r#"{{"MessageID":"{id}","From":"lisa@example.edu","Subject":"{subject}",
            "TextBody":"{body}",
            "Headers":[{{"Name":"Received-SPF","Value":"pass"}}]}}"#
    )
}

async fn ticket_count(f: &Fx) -> i64 {
    f.repo
        .count_tickets(&TicketFilter::default(), &TicketScope::Unrestricted)
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// The door
// ---------------------------------------------------------------------------

/// Unconfigured means absent. An operator who has not set this up has not
/// accidentally opened a way to write into their queue.
#[tokio::test]
async fn the_endpoint_does_not_exist_until_it_is_configured() {
    let f = fixture_with(ChalkConfig::generate_default()).await;
    let status = post(&f, INBOUND_PATH, &postmark("m1", "s", "b")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(ticket_count(&f).await, 0);
}

/// Half-configured is still closed. A provider with no secret, or a secret
/// with no provider, must not be treated as "good enough".
#[tokio::test]
async fn a_half_configured_endpoint_stays_shut() {
    for (provider, secret) in [
        (Some("postmark"), None),
        (None, Some(SECRET)),
        (Some("postmark"), Some("  ")),
        (Some("  "), Some(SECRET)),
    ] {
        let mut config = ChalkConfig::generate_default();
        config.helpdesk.inbound.provider = provider.map(str::to_string);
        config.helpdesk.inbound.secret = secret.map(str::to_string);
        assert!(
            !config.helpdesk.inbound.enabled(),
            "provider={provider:?} secret={secret:?} should not count as configured"
        );
    }
}

#[tokio::test]
async fn a_wrong_secret_is_refused() {
    let f = fixture().await;
    for uri in [
        INBOUND_PATH.to_string(),
        format!("{INBOUND_PATH}?secret=wrong"),
        format!("{INBOUND_PATH}?secret="),
        // A prefix of the real secret must not pass.
        format!("{INBOUND_PATH}?secret={}", &SECRET[..4]),
    ] {
        let status = post(&f, &uri, &postmark("m1", "s", "b")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
    }
    assert_eq!(ticket_count(&f).await, 0);
}

#[tokio::test]
async fn the_secret_may_come_from_a_header_instead_of_the_url() {
    let f = fixture().await;
    let status = router(f.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(INBOUND_PATH)
                .header("content-type", "application/json")
                .header(SECRET_HEADER, SECRET)
                .body(Body::from(postmark("m1", "Broken", "cracked")))
                .unwrap(),
        )
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ticket_count(&f).await, 1);
}

/// The comparison must not leak the secret's length through an early return
/// on the first differing byte.
#[test]
fn secrets_are_compared_without_short_circuiting_on_content() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"ab"));
    assert!(!constant_time_eq(b"", b"a"));
    assert!(constant_time_eq(b"", b""));
}

/// CSRF is meaningless here — there is no cookie and no page a token could
/// have come from, so there is no ambient authority for a forged request to
/// ride on. If the middleware were not exempting this path, every provider
/// POST would be a 403 and mail would silently stop.
#[tokio::test]
async fn the_webhook_is_not_blocked_by_csrf() {
    let f = fixture().await;
    let status = post(
        &f,
        &format!("{INBOUND_PATH}?secret={SECRET}"),
        &postmark("m1", "Broken", "cracked"),
    )
    .await;
    assert_ne!(status, StatusCode::FORBIDDEN);
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// What it does with the mail
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_message_becomes_a_ticket() {
    let f = fixture().await;
    let status = post(
        &f,
        &format!("{INBOUND_PATH}?secret={SECRET}"),
        &postmark("m1", "Projector is dead", "Room 214, no power light."),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let page = f
        .repo
        .list_tickets(
            &TicketFilter::default(),
            &TicketScope::Unrestricted,
            chalk_core::models::page::PageRequest::from_page_number(1, 10),
        )
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].subject, "Projector is dead");
    assert_eq!(
        page.items[0].requester_user_sourced_id.as_deref(),
        Some("u-lisa"),
        "SPF passed, so it is attributed to the person"
    );
}

/// **The retry test, at the HTTP layer.** A provider that gets anything other
/// than 2xx tries again — Postmark for hours. A duplicate must be a 200.
#[tokio::test]
async fn a_redelivery_is_a_success_not_a_second_ticket() {
    let f = fixture().await;
    let uri = format!("{INBOUND_PATH}?secret={SECRET}");
    let body = postmark("m1", "Broken", "cracked");

    assert_eq!(post(&f, &uri, &body).await, StatusCode::OK);
    assert_eq!(post(&f, &uri, &body).await, StatusCode::OK);
    assert_eq!(ticket_count(&f).await, 1);
}

/// **The loop test, at the HTTP layer.** An auto-reply is handled by being
/// dropped, and handled means 200 — a non-2xx would have the provider deliver
/// the vacation responder again and again.
#[tokio::test]
async fn an_auto_reply_is_accepted_and_discarded() {
    let f = fixture().await;
    let body = r#"{"MessageID":"auto-1","From":"lisa@example.edu","Subject":"Out of office",
        "TextBody":"I am away until Monday.",
        "Headers":[{"Name":"Auto-Submitted","Value":"auto-replied"}]}"#;

    let status = post(&f, &format!("{INBOUND_PATH}?secret={SECRET}"), body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "dropping it *is* handling it; anything else and it comes back"
    );
    assert_eq!(ticket_count(&f).await, 0);
}

/// An unreadable body will not become readable on retry, so it is a 400 —
/// telling the provider to stop rather than hammer.
#[tokio::test]
async fn an_unreadable_payload_is_a_400() {
    let f = fixture().await;
    let status = post(&f, &format!("{INBOUND_PATH}?secret={SECRET}"), "not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_unverified_sender_still_files_a_ticket_but_not_as_them() {
    let f = fixture().await;
    let body = r#"{"MessageID":"spoof-1","From":"lisa@example.edu","Subject":"Broken",
        "TextBody":"cracked","Headers":[{"Name":"Received-SPF","Value":"fail"}]}"#;

    assert_eq!(
        post(&f, &format!("{INBOUND_PATH}?secret={SECRET}"), body).await,
        StatusCode::OK
    );
    let page = f
        .repo
        .list_tickets(
            &TicketFilter::default(),
            &TicketScope::Unrestricted,
            chalk_core::models::page::PageRequest::from_page_number(1, 10),
        )
        .await
        .unwrap();
    assert_eq!(page.items[0].requester_user_sourced_id, None);
    assert_eq!(
        page.items[0].requester_email.as_deref(),
        Some("lisa@example.edu")
    );
}

/// A provider name nothing implements is an operator error, and one they will
/// only find in the log — so it must say what they could have written.
#[tokio::test]
async fn an_unknown_provider_fails_loudly_rather_than_silently_dropping_mail() {
    let mut config = ChalkConfig::generate_default();
    config.helpdesk.inbound.provider = Some("mailgun".into());
    config.helpdesk.inbound.secret = Some(SECRET.into());
    let f = fixture_with(config).await;

    let status = post(
        &f,
        &format!("{INBOUND_PATH}?secret={SECRET}"),
        &postmark("m1", "s", "b"),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
