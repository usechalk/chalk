//! Staff help portal.
//!
//! Most of this file is about one question: **can a requester see something
//! that is not theirs?** Every other behaviour here is a convenience; that one
//! is a disclosure bug, and the people on the other side of it are children and
//! the staff who teach them.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetEventRepository, AssetRepository, ChalkRepository, MagicLoginRepository,
    PortalSessionRepository, TicketRepository, UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::asset::Asset;
use chalk_core::models::common::{RoleType, Status};
use chalk_core::models::ticket::TicketStatus;
use chrono::TimeZone;
use tower::ServiceExt;

use crate::router;

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fx {
    fixture_with(ChalkConfig::generate_default()).await
}

async fn fixture_with(config: ChalkConfig) -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    for (id, given, family, email) in [
        ("u-lisa", "Lisa", "Nowak", "lisa@example.edu"),
        ("u-omar", "Omar", "Haddad", "omar@example.edu"),
    ] {
        repo.upsert_user(&User {
            sourced_id: id.into(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            username: id.into(),
            user_ids: vec![],
            enabled_user: true,
            given_name: given.into(),
            family_name: family.into(),
            middle_name: None,
            role: RoleType::Teacher,
            identifier: None,
            email: Some(email.into()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec![],
            grades: vec![],
        })
        .await
        .unwrap();
    }

    let tickets: Arc<dyn TicketRepository> = repo.clone();
    let assets: Arc<dyn AssetRepository> = repo.clone();
    let events: Arc<dyn AssetEventRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, config)
            .with_tickets(tickets)
            .with_assets(assets, events),
    );
    Fx { state, repo }
}

/// Sign somebody in the way the portal does, and return the cookie value.
async fn session_for(f: &Fx, user: &str) -> String {
    let session = PortalSession {
        id: format!("sess-{user}"),
        user_sourced_id: user.into(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
    };
    f.repo.create_portal_session(&session).await.unwrap();
    session.id
}

async fn get_as(f: &Fx, session: Option<&str>, uri: &str) -> (StatusCode, String, String) {
    let mut req = Request::builder().uri(uri);
    if let Some(s) = session {
        req = req.header("cookie", format!("chalk_portal={s}"));
    }
    let res = router(f.state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let location = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).to_string(), location)
}

async fn post_as(
    f: &Fx,
    session: Option<&str>,
    uri: &str,
    form: &str,
) -> (StatusCode, String, String) {
    let token = crate::csrf::generate_csrf_token();
    let mut cookie = format!("chalk_csrf={token}");
    if let Some(s) = session {
        cookie.push_str(&format!("; chalk_portal={s}"));
    }
    let res = router(f.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", cookie)
                .header("x-csrf-token", &token)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.to_string()))
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
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).to_string(), location)
}

/// A ticket belonging to `requester`, returning its id.
async fn ticket_for(f: &Fx, id: &str, requester: &str, subject: &str) -> String {
    let mut t = Ticket::new(id, subject);
    t.requester_user_sourced_id = Some(requester.into());
    t.body = "It stopped working.".into();
    f.repo.create_ticket(&t).await.unwrap();
    id.to_string()
}

// ---------------------------------------------------------------------------
// The boundary
// ---------------------------------------------------------------------------

/// **The disclosure test.** Someone else's request must not be readable by
/// guessing its id.
///
/// The fixtures here avoid apostrophes deliberately: Askama escapes `'` to
/// `&#x27;`, so `!body.contains("Omar's ticket")` can never match the rendered
/// page and would pass even if the ticket *were* shown. A negative assertion
/// that cannot fail is worse than none, because it looks like coverage.
#[tokio::test]
async fn a_requester_cannot_open_somebody_elses_request() {
    let f = fixture().await;
    ticket_for(&f, "t-omar", "u-omar", "Broken projector in 214").await;
    let lisa = session_for(&f, "u-lisa").await;

    let (status, body, _) = get_as(&f, Some(&lisa), "/help/t-omar").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body.contains("Broken projector in 214"));
}

/// Not found, never forbidden. "You may not see this" confirms the id exists,
/// which turns the portal into a way to enumerate other people's requests.
#[tokio::test]
async fn a_foreign_request_is_indistinguishable_from_a_missing_one() {
    let f = fixture().await;
    ticket_for(&f, "t-omar", "u-omar", "Omar request about wifi").await;
    let lisa = session_for(&f, "u-lisa").await;

    let (real, _, _) = get_as(&f, Some(&lisa), "/help/t-omar").await;
    let (fake, _, _) = get_as(&f, Some(&lisa), "/help/t-does-not-exist").await;
    assert_eq!(real, fake, "the two must be the same response");
}

#[tokio::test]
async fn the_list_shows_only_your_own_requests() {
    let f = fixture().await;
    ticket_for(&f, "t-lisa", "u-lisa", "Charger for the cart").await;
    ticket_for(&f, "t-omar", "u-omar", "Projector in 214").await;
    let lisa = session_for(&f, "u-lisa").await;

    let (_, body, _) = get_as(&f, Some(&lisa), "/help").await;
    assert!(body.contains("Charger for the cart"));
    assert!(!body.contains("Projector in 214"));
}

/// **The other disclosure test.** An internal note is IT talking among
/// themselves; it must never render here.
#[tokio::test]
async fn internal_notes_never_reach_the_requester() {
    let f = fixture().await;
    ticket_for(&f, "t-lisa", "u-lisa", "Charger").await;
    f.repo
        .append_comment(&NewTicketComment::reply(
            "t-lisa",
            "u-omar",
            "We have ordered you a replacement.",
        ))
        .await
        .unwrap();
    f.repo
        .append_comment(&NewTicketComment::internal_note(
            "t-lisa",
            "u-omar",
            "Third one this term — check whether she is standing on the cable.",
        ))
        .await
        .unwrap();

    let lisa = session_for(&f, "u-lisa").await;
    let (_, body, _) = get_as(&f, Some(&lisa), "/help/t-lisa").await;
    assert!(body.contains("We have ordered you a replacement."));
    assert!(
        !body.contains("standing on the cable"),
        "an internal note reached the requester's page"
    );
}

#[tokio::test]
async fn a_requester_cannot_reply_to_somebody_elses_request() {
    let f = fixture().await;
    ticket_for(&f, "t-omar", "u-omar", "Omar request about wifi").await;
    let lisa = session_for(&f, "u-lisa").await;

    let (status, _, _) = post_as(&f, Some(&lisa), "/help/t-omar/reply", "body=hello").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(f
        .repo
        .list_comments("t-omar", true)
        .await
        .unwrap()
        .is_empty());
}

// ---------------------------------------------------------------------------
// Sign in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_page_needs_a_session() {
    let f = fixture().await;
    ticket_for(&f, "t-lisa", "u-lisa", "Charger").await;
    for uri in ["/help", "/help/new", "/help/t-lisa"] {
        let (status, _, location) = get_as(&f, None, uri).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{uri}");
        assert_eq!(location, "/help/signin", "{uri}");
    }
}

#[tokio::test]
async fn an_expired_session_is_not_a_session() {
    let f = fixture().await;
    f.repo
        .create_portal_session(&PortalSession {
            id: "stale".into(),
            user_sourced_id: "u-lisa".into(),
            created_at: Utc::now() - Duration::hours(48),
            expires_at: Utc::now() - Duration::hours(1),
        })
        .await
        .unwrap();

    let (status, _, location) = get_as(&f, Some("stale"), "/help").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/help/signin");
}

/// The sign-in form must not become a way to test who works at the district.
#[tokio::test]
async fn the_signin_response_is_the_same_whether_or_not_the_address_exists() {
    let f = fixture().await;
    let (known, real, _) = post_as(&f, None, "/help/signin", "email=lisa%40example.edu").await;
    let (unknown, fake, _) = post_as(&f, None, "/help/signin", "email=nobody%40example.edu").await;

    assert_eq!(known, unknown);
    assert_eq!(
        real, fake,
        "the page must not differ by whether the person exists"
    );
    assert!(real.contains("If that address belongs to someone"));
}

#[tokio::test]
async fn a_bad_address_is_refused_before_anything_is_minted() {
    let f = fixture().await;
    let (_, body, _) = post_as(&f, None, "/help/signin", "email=notanemail").await;
    assert!(body.contains("Enter your school email address."));
}

/// A link works once. Redeeming it twice must not produce a second session.
#[tokio::test]
async fn a_signin_link_cannot_be_reused() {
    let f = fixture().await;
    let raw = crate::auth::generate_session_token();
    let hash = crate::auth::hash_token(&raw);
    f.repo
        .create_magic_login_token("u-lisa", &hash, Utc::now() + Duration::minutes(10))
        .await
        .unwrap();

    let (first, _, location) = get_as(&f, None, &format!("/help/verify?token={raw}")).await;
    assert_eq!(first, StatusCode::SEE_OTHER);
    assert_eq!(location, "/help");

    let (second, body, _) = get_as(&f, None, &format!("/help/verify?token={raw}")).await;
    assert_ne!(second, StatusCode::SEE_OTHER);
    assert!(body.contains("expired"));
}

#[tokio::test]
async fn an_unknown_token_does_not_sign_anybody_in() {
    let f = fixture().await;
    let (status, body, _) = get_as(&f, None, "/help/verify?token=made-up").await;
    assert_ne!(status, StatusCode::SEE_OTHER);
    assert!(body.contains("expired"));
}

// ---------------------------------------------------------------------------
// Raising and replying
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_teacher_can_raise_a_request_and_it_is_theirs() {
    let f = fixture().await;
    let lisa = session_for(&f, "u-lisa").await;

    let (status, _, location) = post_as(
        &f,
        Some(&lisa),
        "/help/new",
        "subject=My+Chromebook+will+not+charge&body=No+light+at+all.",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.ends_with("notice=raised"));

    let (_, body, _) = get_as(&f, Some(&lisa), &location).await;
    assert!(body.contains("My Chromebook will not charge"));
    assert!(body.contains("Your request has been sent to IT."));

    // And it is filed under them, not under whoever the form said.
    let page = f
        .repo
        .list_tickets(
            &TicketFilter::default(),
            &TicketScope::Unrestricted,
            PageRequest::from_page_number(1, 10),
        )
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(
        page.items[0].requester_user_sourced_id.as_deref(),
        Some("u-lisa")
    );
}

/// The form has no requester field, so this is really a check that no future
/// one silently starts working: a posted `requester` must be ignored.
#[tokio::test]
async fn the_requester_is_the_signed_in_user_whatever_the_form_says() {
    let f = fixture().await;
    let lisa = session_for(&f, "u-lisa").await;

    post_as(
        &f,
        Some(&lisa),
        "/help/new",
        "subject=Mine&body=x&requester=u-omar&requester_user_sourced_id=u-omar",
    )
    .await;

    let page = f
        .repo
        .list_tickets(
            &TicketFilter::default(),
            &TicketScope::Unrestricted,
            PageRequest::from_page_number(1, 10),
        )
        .await
        .unwrap();
    assert_eq!(
        page.items[0].requester_user_sourced_id.as_deref(),
        Some("u-lisa"),
        "a form field must not be able to raise a ticket as somebody else"
    );
}

#[tokio::test]
async fn the_requesters_device_is_attached_without_them_naming_it() {
    let f = fixture().await;
    let mut a = Asset::new("a-1");
    a.asset_tag = Some("CB-0108".into());
    a.assigned_user_sourced_id = Some("u-lisa".into());
    f.repo.create_asset(&a).await.unwrap();

    let lisa = session_for(&f, "u-lisa").await;
    let (_, form, _) = get_as(&f, Some(&lisa), "/help/new").await;
    assert!(
        form.contains("CB-0108"),
        "the form says which device it will attach"
    );

    let (_, _, location) = post_as(&f, Some(&lisa), "/help/new", "subject=Charge&body=x").await;
    let (_, page, _) = get_as(&f, Some(&lisa), &location).await;
    assert!(page.contains("CB-0108"));
}

#[tokio::test]
async fn an_empty_request_is_refused_with_what_was_typed_kept() {
    let f = fixture().await;
    let lisa = session_for(&f, "u-lisa").await;

    let (status, body, _) = post_as(
        &f,
        Some(&lisa),
        "/help/new",
        "subject=&body=The+screen+flickers+constantly",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Give the ticket a short subject."));
    assert!(body.contains("The screen flickers constantly"));
}

#[tokio::test]
async fn a_reply_lands_on_the_thread_and_is_never_internal() {
    let f = fixture().await;
    ticket_for(&f, "t-lisa", "u-lisa", "Charger").await;
    let lisa = session_for(&f, "u-lisa").await;

    let (status, _, location) = post_as(
        &f,
        Some(&lisa),
        "/help/t-lisa/reply",
        "body=It+started+again+this+morning.",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.ends_with("notice=replied"));

    let all = f.repo.list_comments("t-lisa", true).await.unwrap();
    assert_eq!(all.len(), 1);
    assert!(
        !all[0].is_internal,
        "a requester cannot post an internal note"
    );
    // And it is visible to them, which is the point of replying.
    assert_eq!(
        f.repo.list_comments("t-lisa", false).await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn an_empty_reply_is_refused() {
    let f = fixture().await;
    ticket_for(&f, "t-lisa", "u-lisa", "Charger").await;
    let lisa = session_for(&f, "u-lisa").await;

    let (_, _, location) = post_as(&f, Some(&lisa), "/help/t-lisa/reply", "body=+++").await;
    assert!(location.ends_with("notice=empty"));
    assert!(f
        .repo
        .list_comments("t-lisa", true)
        .await
        .unwrap()
        .is_empty());
}

// ---------------------------------------------------------------------------
// What the requester is told
// ---------------------------------------------------------------------------

/// "Waiting" is the one status whose technician-facing label actively misleads
/// the person it describes: they would read it as IT working on it, when it
/// means IT is waiting on them.
#[tokio::test]
async fn statuses_are_worded_for_the_person_waiting() {
    let f = fixture().await;
    let lisa = session_for(&f, "u-lisa").await;

    for (status, expected) in [
        (TicketStatus::Open, "Received"),
        (TicketStatus::InProgress, "Being worked on"),
        (TicketStatus::Waiting, "Waiting for your reply"),
        (TicketStatus::Resolved, "Fixed"),
    ] {
        let id = format!("t-{}", status.as_str());
        let mut t = Ticket::new(&id, "Subject");
        t.requester_user_sourced_id = Some("u-lisa".into());
        t.status = status;
        f.repo.create_ticket(&t).await.unwrap();

        let (_, body, _) = get_as(&f, Some(&lisa), &format!("/help/{id}")).await;
        assert!(body.contains(expected), "{status} should read {expected:?}");
    }
}

/// The portal never shows the internal vocabulary — a requester reading
/// "in_progress" or "sla" is reading our database, not an answer.
#[tokio::test]
async fn the_portal_does_not_leak_internal_vocabulary() {
    let f = fixture().await;
    ticket_for(&f, "t-lisa", "u-lisa", "Charger").await;
    let lisa = session_for(&f, "u-lisa").await;

    let (_, body, _) = get_as(&f, Some(&lisa), "/help/t-lisa").await;
    for jargon in ["in_progress", "sourced_id", "SLA", "sla_due"] {
        assert!(!body.contains(jargon), "{jargon:?} showed on the portal");
    }
}

// ---------------------------------------------------------------------------
// Module gating
// ---------------------------------------------------------------------------

/// The portal belongs to the helpdesk module.
#[tokio::test]
async fn the_portal_is_absent_when_the_helpdesk_is_off() {
    let mut config = ChalkConfig::generate_default();
    config.modules.helpdesk = false;
    let f = fixture_with(config).await;

    for uri in ["/help", "/help/signin", "/help/new"] {
        let (status, _, _) = get_as(&f, None, uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
    }
}

/// **The whole reason this portal exists.** The Devices + Helpdesk tier has no
/// identity layer; if the portal went with it, that tier would be sold a help
/// desk with nowhere for staff to use it.
#[tokio::test]
async fn the_portal_survives_the_roster_sso_module_being_off() {
    let mut config = ChalkConfig::generate_default();
    config.modules.roster_sso = false;
    let f = fixture_with(config).await;
    ticket_for(&f, "t-lisa", "u-lisa", "Charger").await;
    let lisa = session_for(&f, "u-lisa").await;

    let (signin, _, _) = get_as(&f, None, "/help/signin").await;
    assert_eq!(signin, StatusCode::OK);

    let (mine, body, _) = get_as(&f, Some(&lisa), "/help").await;
    assert_eq!(mine, StatusCode::OK);
    assert!(body.contains("Charger"));
}

/// The portal must not require an admin session — its audience is precisely
/// the people who do not have one.
#[tokio::test]
async fn the_portal_does_not_demand_an_admin_session() {
    let f = fixture().await;
    let lisa = session_for(&f, "u-lisa").await;
    let (status, body, _) = get_as(&f, Some(&lisa), "/help").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Hello, Lisa"));
    assert!(
        !body.contains("sidebar-link"),
        "a teacher must not be shown the admin console's navigation"
    );
}
