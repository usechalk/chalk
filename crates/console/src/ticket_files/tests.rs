//! Ticket attachments over HTTP.
//!
//! Two things are being defended here. **A file must not be downloadable by
//! someone who cannot see its ticket** — the same boundary as the thread, and
//! the one that matters because attachment ids are guessable in exactly the
//! way ticket ids are. And **a file a stranger uploaded must not execute in a
//! colleague's browser** on our origin.

use super::*;

use axum::body::Body;
use axum::http::Request;
use chalk_core::attachments::{AttachmentStore, FsAttachmentStore};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AdminSessionRepository, ChalkRepository, PortalSessionRepository, TicketRepository,
    UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::common::{RoleType, Status};
use chalk_core::models::sso::PortalSession;
use chalk_core::models::ticket::Ticket;
use chrono::{Duration, TimeZone};
use tower::ServiceExt;

use crate::router;

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!(),
    };
    for (id, given) in [("u-lisa", "Lisa"), ("u-omar", "Omar")] {
        repo.upsert_user(&User {
            sourced_id: id.into(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            username: id.into(),
            user_ids: vec![],
            enabled_user: true,
            given_name: given.into(),
            family_name: "Teacher".into(),
            middle_name: None,
            role: RoleType::Teacher,
            identifier: None,
            email: Some(format!("{id}@example.edu")),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec![],
            grades: vec![],
        })
        .await
        .unwrap();
    }

    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn AttachmentStore> = Arc::new(FsAttachmentStore::new(dir.path()));
    let tickets: Arc<dyn TicketRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();

    // A password is set, so `has_admin_session` does not take the
    // local-development shortcut and the tests exercise the real check.
    let mut config = ChalkConfig::generate_default();
    config.chalk.admin_password_hash = Some("$argon2id$fake".into());

    let state = Arc::new(
        AppState::new(chalk_repo, config)
            .with_tickets(tickets)
            .with_attachments(store),
    );
    Fx {
        state,
        repo,
        _dir: dir,
    }
}

async fn ticket_of(f: &Fx, id: &str, requester: &str) {
    let mut t = Ticket::new(id, "Broken thing");
    t.requester_user_sourced_id = Some(requester.into());
    f.repo.create_ticket(&t).await.unwrap();
}

/// Attach `bytes` to a ticket the way an upload would, returning its id.
async fn attach(f: &Fx, ticket: &str, filename: &str, bytes: &[u8]) -> String {
    let stored = store_all(
        &f.state,
        ticket,
        None,
        vec![Incoming {
            filename: filename.into(),
            bytes: bytes.to_vec(),
        }],
    )
    .await;
    assert_eq!(stored, 1, "the fixture failed to store its file");
    f.repo.list_attachments(ticket).await.unwrap()[0].id.clone()
}

async fn portal_session(f: &Fx, user: &str) -> String {
    let s = PortalSession {
        id: format!("sess-{user}"),
        user_sourced_id: user.into(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
    };
    f.repo.create_portal_session(&s).await.unwrap();
    s.id
}

async fn fetch(f: &Fx, cookie: Option<&str>, uri: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut req = Request::builder().uri(uri);
    if let Some(c) = cookie {
        req = req.header("cookie", c);
    }
    let res = router(f.state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, headers, body.to_vec())
}

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n fake pixels";

// ---------------------------------------------------------------------------
// Who may download
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_requester_can_download_their_own_attachment() {
    let f = fixture().await;
    ticket_of(&f, "t-lisa", "u-lisa").await;
    let id = attach(&f, "t-lisa", "screen.png", PNG).await;
    let lisa = portal_session(&f, "u-lisa").await;

    let (status, _, body) = fetch(
        &f,
        Some(&format!("chalk_portal={lisa}")),
        &format!("/attachments/{id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, PNG);
}

/// **The boundary.** Attachment ids are as guessable as ticket ids, so this is
/// the check that stops a colleague's photograph being readable by anybody who
/// tries a few.
#[tokio::test]
async fn another_requester_cannot_download_it() {
    let f = fixture().await;
    ticket_of(&f, "t-lisa", "u-lisa").await;
    let id = attach(&f, "t-lisa", "screen.png", PNG).await;
    let omar = portal_session(&f, "u-omar").await;

    let (status, _, body) = fetch(
        &f,
        Some(&format!("chalk_portal={omar}")),
        &format!("/attachments/{id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_ne!(body, PNG);
}

#[tokio::test]
async fn a_stranger_with_no_session_cannot_download_it() {
    let f = fixture().await;
    ticket_of(&f, "t-lisa", "u-lisa").await;
    let id = attach(&f, "t-lisa", "screen.png", PNG).await;

    let (status, _, _) = fetch(&f, None, &format!("/attachments/{id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Not found, never forbidden — a distinguishable refusal confirms the id is
/// real, which is all an enumeration attack needs.
#[tokio::test]
async fn a_forbidden_file_is_indistinguishable_from_a_missing_one() {
    let f = fixture().await;
    ticket_of(&f, "t-lisa", "u-lisa").await;
    let id = attach(&f, "t-lisa", "screen.png", PNG).await;
    let omar = portal_session(&f, "u-omar").await;
    let cookie = format!("chalk_portal={omar}");

    let (real, _, real_body) = fetch(&f, Some(&cookie), &format!("/attachments/{id}")).await;
    let (fake, _, fake_body) = fetch(&f, Some(&cookie), "/attachments/does-not-exist").await;
    assert_eq!(real, fake);
    assert_eq!(real_body, fake_body);
}

#[tokio::test]
async fn an_administrator_can_download_anybodys_attachment() {
    let f = fixture().await;
    ticket_of(&f, "t-lisa", "u-lisa").await;
    let id = attach(&f, "t-lisa", "screen.png", PNG).await;

    let session = chalk_core::models::audit::AdminSession {
        token: "admin-token".into(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: None,
        actor_id: None,
        actor_label: None,
        actor_role: None,
    };
    f.repo.create_admin_session(&session).await.unwrap();

    let (status, _, body) = fetch(
        &f,
        Some("chalk_session=admin-token"),
        &format!("/attachments/{id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, PNG);
}

/// An expired admin session is not a session, and must not open the door that
/// a live one does.
#[tokio::test]
async fn an_expired_admin_session_cannot_download() {
    let f = fixture().await;
    ticket_of(&f, "t-lisa", "u-lisa").await;
    let id = attach(&f, "t-lisa", "screen.png", PNG).await;

    f.repo
        .create_admin_session(&chalk_core::models::audit::AdminSession {
            token: "stale".into(),
            created_at: Utc::now() - Duration::hours(48),
            expires_at: Utc::now() - Duration::hours(1),
            ip_address: None,
            actor_id: None,
            actor_label: None,
            actor_role: None,
        })
        .await
        .unwrap();

    let (status, _, _) = fetch(
        &f,
        Some("chalk_session=stale"),
        &format!("/attachments/{id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// How it is served
// ---------------------------------------------------------------------------

/// **The stored-XSS test.** A file whose bytes are HTML must be served as an
/// opaque download, whatever it was named — otherwise a link to it runs script
/// on our origin against whoever opens it.
#[tokio::test]
async fn an_html_file_named_png_is_served_as_a_download_not_a_page() {
    let f = fixture().await;
    ticket_of(&f, "t-lisa", "u-lisa").await;
    let hostile = b"<html><script>alert(document.cookie)</script></html>";
    let id = attach(&f, "t-lisa", "innocent.png", hostile).await;
    let lisa = portal_session(&f, "u-lisa").await;

    let (status, headers, _) = fetch(
        &f,
        Some(&format!("chalk_portal={lisa}")),
        &format!("/attachments/{id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "application/octet-stream",
        "the name said png; the bytes did not"
    );
    assert!(headers[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .starts_with("attachment;"));
}

#[tokio::test]
async fn every_download_carries_the_hardening_headers() {
    let f = fixture().await;
    ticket_of(&f, "t-lisa", "u-lisa").await;
    let id = attach(&f, "t-lisa", "screen.png", PNG).await;
    let lisa = portal_session(&f, "u-lisa").await;

    let (_, headers, _) = fetch(
        &f,
        Some(&format!("chalk_portal={lisa}")),
        &format!("/attachments/{id}"),
    )
    .await;
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(
        headers[header::CONTENT_SECURITY_POLICY],
        "default-src 'none'; sandbox"
    );
    // Private, so a shared proxy does not keep somebody's photograph.
    assert!(headers[header::CACHE_CONTROL]
        .to_str()
        .unwrap()
        .contains("private"));
}

#[tokio::test]
async fn an_image_renders_in_place_because_that_is_the_point() {
    let f = fixture().await;
    ticket_of(&f, "t-lisa", "u-lisa").await;
    let id = attach(&f, "t-lisa", "screen.png", PNG).await;
    let lisa = portal_session(&f, "u-lisa").await;

    let (_, headers, _) = fetch(
        &f,
        Some(&format!("chalk_portal={lisa}")),
        &format!("/attachments/{id}"),
    )
    .await;
    assert_eq!(headers[header::CONTENT_TYPE], "image/png");
    assert!(headers[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .starts_with("inline;"));
}

// ---------------------------------------------------------------------------
// Storing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn what_is_stored_records_the_real_type_and_a_digest() {
    let f = fixture().await;
    ticket_of(&f, "t-lisa", "u-lisa").await;
    attach(&f, "t-lisa", "../../etc/passwd", PNG).await;

    let rows = f.repo.list_attachments("t-lisa").await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].content_type, "image/png");
    assert_eq!(rows[0].filename, "passwd", "the path was stripped");
    assert_eq!(rows[0].sha256, chalk_core::attachments::digest(PNG));
    assert_eq!(rows[0].size_bytes, PNG.len() as i64);
}

/// With no store configured, files are dropped and said so in the log rather
/// than producing rows that point at nothing.
#[tokio::test]
async fn uploads_are_discarded_when_no_store_is_configured() {
    let f = fixture().await;
    ticket_of(&f, "t-lisa", "u-lisa").await;

    let chalk_repo: Arc<dyn ChalkRepository> = f.repo.clone();
    let tickets: Arc<dyn TicketRepository> = f.repo.clone();
    let state =
        Arc::new(AppState::new(chalk_repo, ChalkConfig::generate_default()).with_tickets(tickets));

    let stored = store_all(
        &state,
        "t-lisa",
        None,
        vec![Incoming {
            filename: "a.png".into(),
            bytes: PNG.to_vec(),
        }],
    )
    .await;
    assert_eq!(stored, 0);
    assert!(f.repo.list_attachments("t-lisa").await.unwrap().is_empty());
}
