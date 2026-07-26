//! Unmatched-queue tests.
//!
//! Two properties dominate what is worth testing here.
//!
//! **A device that has been decided about must never come back.** `manual` and
//! `ignored` are the two states an operator creates, and a queue that resurfaces
//! them turns a finished job into a treadmill. Several tests below exist only
//! to pin that down.
//!
//! **The queue must never claim a fleet is clean when it is not.** The empty
//! state here says "every device is attached to a person", which is a much
//! stronger claim than the inventory's "no results" — so every path that can
//! reach it is tested, including the out-of-range page that produced exactly
//! that false claim on the inventory.

use super::*;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetEventRepository, AssetRepository, ChalkRepository, OrgRepository, UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::asset::{Asset, AssetEventFilter, AssetStatus};
use chalk_core::models::common::{OrgType, RoleType, Status};
use chalk_core::models::org::Org;
use chalk_core::models::page::PageRequest;
use chalk_core::models::user::User;
use chrono::{TimeZone, Utc};
use tower::ServiceExt;

use crate::{router, AppState};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fixture {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => SqliteRepository::new(p),
        DatabasePool::Postgres(_) => unreachable!("test setup uses sqlite memory"),
    };
    let repo = Arc::new(repo);

    let assets: Arc<dyn AssetRepository> = repo.clone();
    let events: Arc<dyn AssetEventRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();

    let state = Arc::new(
        AppState::new(chalk_repo, ChalkConfig::generate_default()).with_assets(assets, events),
    );
    Fixture { state, repo }
}

fn org(sourced_id: &str, name: &str) -> Org {
    Org {
        sourced_id: sourced_id.to_string(),
        status: Status::Active,
        date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        metadata: None,
        name: name.to_string(),
        org_type: OrgType::School,
        identifier: None,
        parent: None,
        children: vec![],
    }
}

fn user(sourced_id: &str, given: &str, family: &str) -> User {
    User {
        sourced_id: sourced_id.to_string(),
        status: Status::Active,
        date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        metadata: None,
        username: format!("{given}.{family}").to_lowercase(),
        user_ids: vec![],
        enabled_user: true,
        given_name: given.to_string(),
        family_name: family.to_string(),
        middle_name: None,
        role: RoleType::Student,
        identifier: None,
        email: Some(format!("{given}.{family}@example.edu").to_lowercase()),
        sms: None,
        phone: None,
        agents: vec![],
        orgs: vec![],
        grades: vec![],
    }
}

/// One device in a given match state, with a given `annotatedUser`.
fn device(id: &str, match_state: MatchState, annotated_user: Option<&str>) -> Asset {
    let mut a = Asset::new(id);
    a.asset_tag = Some(format!("CB-{id}"));
    a.serial_number = Some(format!("SN-{id}"));
    a.model = Some("Chromebook Spin 511".into());
    a.status = AssetStatus::Active;
    a.school_org_sourced_id = Some("org-hs".into());
    a.org_unit_path = Some("/Students/HS".into());
    a.match_state = match_state;
    a.annotated_user = annotated_user.map(str::to_string);
    a
}

async fn seed_base(f: &Fixture) {
    f.repo
        .upsert_org(&org("org-hs", "Springfield High"))
        .await
        .unwrap();
    f.repo
        .upsert_user(&user("u-1", "Jane", "Doe"))
        .await
        .unwrap();
}

async fn get(state: Arc<AppState>, uri: &str) -> (StatusCode, String) {
    let response = router(state)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// A form POST, carrying the CSRF pair a browser would.
///
/// Going through `router` rather than calling the handler directly is the
/// point: it exercises the real middleware stack, so a route that is
/// registered with the wrong path-parameter syntax fails here rather than in
/// production. That is not hypothetical — these routes were first written with
/// axum 0.8's `{id}` syntax on axum 0.7, and every one of them 404'd.
async fn post(state: Arc<AppState>, uri: &str, body: &str) -> StatusCode {
    let token = crate::csrf::generate_csrf_token();
    let response = router(state)
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
    response.status()
}

// ---------------------------------------------------------------------------
// Why a device is unmatched
// ---------------------------------------------------------------------------

/// The three reasons have three different remedies, so telling them apart is
/// the queue's main job.
#[test]
fn reason_distinguishes_a_cart_from_a_leaver_from_a_note() {
    assert_eq!(UnmatchedReason::of(None), UnmatchedReason::NoGoogleUser);
    assert_eq!(UnmatchedReason::of(Some("")), UnmatchedReason::NoGoogleUser);
    assert_eq!(
        UnmatchedReason::of(Some("   ")),
        UnmatchedReason::NoGoogleUser,
        "whitespace is not a Google user"
    );
    assert_eq!(
        UnmatchedReason::of(Some("Cart 3")),
        UnmatchedReason::NotAnEmail
    );
    assert_eq!(
        UnmatchedReason::of(Some("Ms. Rivera's cart")),
        UnmatchedReason::NotAnEmail
    );
    assert_eq!(
        UnmatchedReason::of(Some("j.alvarez@old-district.org")),
        UnmatchedReason::UnknownAddress
    );
}

/// The reason is computed with the *same* `looks_like_email` the matching
/// ladder calls, imported from `chalk-core` rather than reimplemented. This
/// pins the cases where a hand-rolled near-copy would drift: an earlier version
/// of this module accepted internal whitespace and multiple `@`, so it would
/// have told a technician "not in the roster" about values the ladder had
/// rejected as free text.
#[test]
fn reason_agrees_with_the_ladders_own_address_test() {
    for free_text in ["room 5 @school.edu", "a@b@school.edu", "jdoe@school"] {
        assert_eq!(
            UnmatchedReason::of(Some(free_text)),
            UnmatchedReason::NotAnEmail,
            "{free_text} is not an address the ladder would have looked up"
        );
    }
    assert_eq!(
        UnmatchedReason::of(Some("jdoe@school.edu")),
        UnmatchedReason::UnknownAddress
    );
}

/// Every reason carries an action. A reason a technician cannot act on is
/// decoration, and this is a queue.
#[test]
fn every_reason_states_a_remedy() {
    for r in [
        UnmatchedReason::NoGoogleUser,
        UnmatchedReason::NotAnEmail,
        UnmatchedReason::UnknownAddress,
    ] {
        assert!(!r.summary().is_empty());
        assert!(!r.hint().is_empty());
        assert!(!r.as_str().is_empty());
        // The framing rule for this whole screen.
        let text = format!("{} {}", r.summary(), r.hint()).to_lowercase();
        assert!(
            !text.contains("fail") && !text.contains("error"),
            "{r:?} reads as an error: {text}"
        );
    }
}

// ---------------------------------------------------------------------------
// The queue only holds undecided devices
// ---------------------------------------------------------------------------

/// The property the queue exists on. `manual` and `ignored` are decisions; a
/// queue that shows them again makes resolving devices pointless.
#[tokio::test]
async fn only_unmatched_devices_are_queued() {
    let f = fixture().await;
    seed_base(&f).await;
    for (id, state) in [
        ("a", MatchState::Unmatched),
        ("b", MatchState::Matched),
        ("c", MatchState::Manual),
        ("d", MatchState::Ignored),
    ] {
        f.repo.create_asset(&device(id, state, None)).await.unwrap();
    }

    let (status, body) = get(f.state.clone(), "/devices/unmatched").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("CB-a"), "the unmatched device is queued");
    for decided in ["CB-b", "CB-c", "CB-d"] {
        assert!(
            !body.contains(decided),
            "{decided} has been decided about and must not reappear"
        );
    }
}

/// Resolving writes `manual`, which is what makes the decision survive the next
/// sync — the engine refuses to touch `manual` and `ignored` rows.
#[tokio::test]
async fn resolving_attaches_the_user_and_marks_the_row_manual() {
    let f = fixture().await;
    seed_base(&f).await;
    f.repo
        .create_asset(&device("a", MatchState::Unmatched, Some("jane@old.org")))
        .await
        .unwrap();

    let status = post(
        f.state.clone(),
        "/devices/a/resolve",
        "user=u-1&back=/devices/unmatched",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let asset = f.repo.get_asset("a").await.unwrap().unwrap();
    assert_eq!(asset.assigned_user_sourced_id.as_deref(), Some("u-1"));
    assert_eq!(
        asset.match_state,
        MatchState::Manual,
        "a resolved device must not be re-matched by the next sync"
    );

    // And it left the queue.
    let (_, body) = get(f.state.clone(), "/devices/unmatched").await;
    assert!(!body.contains("CB-a"));
}

/// The audit row is the point of the compound op. An assignment nobody can
/// explain is worse than no assignment.
#[tokio::test]
async fn resolving_records_who_did_it_and_how() {
    let f = fixture().await;
    seed_base(&f).await;
    f.repo
        .create_asset(&device("a", MatchState::Unmatched, None))
        .await
        .unwrap();

    post(
        f.state.clone(),
        "/devices/a/resolve",
        "user=u-1&back=/devices/unmatched",
    )
    .await;

    let events = f
        .repo
        .list_events(&AssetEventFilter::for_asset("a"), PageRequest::new(10, 0))
        .await
        .unwrap();
    assert_eq!(events.total, 1);
    let e = &events.items[0];
    assert_eq!(e.event_type, AssetEventType::Assigned);
    let payload = e.payload.as_ref().expect("payload records the decision");
    assert_eq!(payload["user"], "u-1");
    assert_eq!(
        payload["rule"], "manual",
        "the history must distinguish a human decision from an automatic match"
    );
    assert_eq!(payload["via"], "unmatched_queue");
}

/// Ignoring is the other half of the decision, and by far the commoner one.
#[tokio::test]
async fn ignoring_takes_a_shared_device_out_of_the_queue_without_an_owner() {
    let f = fixture().await;
    seed_base(&f).await;
    f.repo
        .create_asset(&device("a", MatchState::Unmatched, None))
        .await
        .unwrap();

    let status = post(
        f.state.clone(),
        "/devices/a/ignore",
        "back=/devices/unmatched",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let asset = f.repo.get_asset("a").await.unwrap().unwrap();
    assert_eq!(asset.match_state, MatchState::Ignored);
    assert_eq!(
        asset.assigned_user_sourced_id, None,
        "ignoring assigns nobody — a cart has no owner"
    );

    let (_, body) = get(f.state.clone(), "/devices/unmatched").await;
    assert!(!body.contains("CB-a"));
}

/// Resolving to a user who is not in the roster must be a sentence, not a 500
/// from a foreign-key violation.
#[tokio::test]
async fn resolving_to_a_missing_user_changes_nothing() {
    let f = fixture().await;
    seed_base(&f).await;
    f.repo
        .create_asset(&device("a", MatchState::Unmatched, None))
        .await
        .unwrap();

    let status = post(
        f.state.clone(),
        "/devices/a/resolve",
        "user=nobody&back=/devices/unmatched",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "a message, not a crash");

    let asset = f.repo.get_asset("a").await.unwrap().unwrap();
    assert_eq!(asset.assigned_user_sourced_id, None);
    assert_eq!(asset.match_state, MatchState::Unmatched);
    let events = f
        .repo
        .list_events(&AssetEventFilter::for_asset("a"), PageRequest::new(10, 0))
        .await
        .unwrap();
    assert_eq!(events.total, 0, "nothing happened, so nothing was logged");
}

// ---------------------------------------------------------------------------
// Bulk ignore
// ---------------------------------------------------------------------------

/// Bulk ignore acts on ticked ids only. It is page-scoped by construction —
/// there is no "all matching" variant, and there must not be one until a diff
/// preview exists.
#[tokio::test]
async fn bulk_ignore_acts_only_on_the_ticked_rows() {
    let f = fixture().await;
    seed_base(&f).await;
    for id in ["a", "b", "c"] {
        f.repo
            .create_asset(&device(id, MatchState::Unmatched, None))
            .await
            .unwrap();
    }

    let status = post(
        f.state.clone(),
        "/devices/unmatched/bulk-ignore",
        "ids=a&ids=b&back=/devices/unmatched",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    assert_eq!(
        f.repo.get_asset("a").await.unwrap().unwrap().match_state,
        MatchState::Ignored
    );
    assert_eq!(
        f.repo.get_asset("b").await.unwrap().unwrap().match_state,
        MatchState::Ignored
    );
    assert_eq!(
        f.repo.get_asset("c").await.unwrap().unwrap().match_state,
        MatchState::Unmatched,
        "an unticked row must be untouched"
    );
}

/// The body parser is hand-rolled because axum's `Form` cannot decode repeated
/// keys into a `Vec` — it answers 422 for exactly the shape a checkbox column
/// produces. These are the cases that broke when it was `Form<BulkForm>`.
#[test]
fn the_bulk_body_parser_handles_repeated_keys_and_encoding() {
    let form = BulkForm::parse("ids=a&ids=b&ids=c&back=%2Fdevices%2Funmatched%3Fpage%3D2");
    assert_eq!(form.ids, vec!["a", "b", "c"]);
    assert_eq!(form.back, "/devices/unmatched?page=2");

    // `+` is a space in form encoding. Decoding percent-escapes without
    // handling it first turns "Cart 3" into "Cart+3" — silent corruption.
    let spaced = BulkForm::parse("ids=cart+3&back=");
    assert_eq!(spaced.ids, vec!["cart 3"]);

    // Nothing ticked, and junk that must not become an id.
    assert_eq!(BulkForm::parse("back=/devices/unmatched").ids.len(), 0);
    assert_eq!(
        BulkForm::parse("ids=&back=x").ids.len(),
        0,
        "empty is not an id"
    );
    assert_eq!(BulkForm::parse("").ids.len(), 0);
    assert_eq!(BulkForm::parse("garbage").ids.len(), 0);
    assert_eq!(
        BulkForm::parse("other=x&ids=a").ids,
        vec!["a"],
        "unknown fields are ignored, not misfiled"
    );
}

/// A bulk action that reports only its successes is how an operator comes to
/// believe a fleet is tidier than it is.
#[test]
fn bulk_summary_states_the_parts_that_did_not_work() {
    let clean = bulk_summary(3, 0, 0);
    assert!(clean.contains('3'));
    assert!(!clean.contains("could not"));

    let messy = bulk_summary(2, 1, 4);
    assert!(messy.contains('2'));
    assert!(
        messy.contains('1') && messy.contains('4'),
        "missing and failed counts must both be stated: {messy}"
    );

    assert!(
        bulk_summary(1, 0, 0).contains("1 device"),
        "singular, not '1 devices'"
    );
}

// ---------------------------------------------------------------------------
// Empty states — the queue makes a strong claim, so every path is pinned
// ---------------------------------------------------------------------------

/// The win state, and the strongest claim on the screen.
#[tokio::test]
async fn an_all_decided_fleet_says_every_device_is_attached() {
    let f = fixture().await;
    seed_base(&f).await;
    f.repo
        .create_asset(&device("a", MatchState::Matched, None))
        .await
        .unwrap();

    let (status, body) = get(f.state.clone(), "/devices/unmatched").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Every device is attached to a person"));
    assert!(
        !body.contains("No devices yet"),
        "a matched fleet is not a fresh install"
    );
}

/// A fresh install must not be told its fleet is fully attached — that is a
/// claim about zero devices, and it is the opposite of true.
#[tokio::test]
async fn a_fresh_install_offers_google_rather_than_claiming_success() {
    let f = fixture().await;
    seed_base(&f).await;

    let (status, body) = get(f.state.clone(), "/devices/unmatched").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No devices yet"));
    assert!(
        !body.contains("Every device is attached to a person"),
        "nothing has been imported, so nothing is attached"
    );
}

/// A filter that matches nothing is not an empty fleet. Shown separately
/// because a technician who sees "no devices yet" after filtering concludes
/// data was lost.
#[tokio::test]
async fn a_filter_matching_nothing_is_not_the_first_run_state() {
    let f = fixture().await;
    seed_base(&f).await;
    f.repo
        .create_asset(&device("a", MatchState::Unmatched, None))
        .await
        .unwrap();

    let (status, body) = get(f.state.clone(), "/devices/unmatched?q=nothingmatchesthis").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No devices match these filters"));
    assert!(!body.contains("No devices yet"));
    assert!(!body.contains("Every device is attached to a person"));
}

/// The bug found on the inventory during manual testing, in the one place
/// where it would tell a worse lie: an out-of-range page here would render
/// "every device is attached" over a queue that is not empty.
#[tokio::test]
async fn a_page_past_the_end_clamps_instead_of_claiming_the_queue_is_clear() {
    let f = fixture().await;
    seed_base(&f).await;
    for i in 0..5 {
        f.repo
            .create_asset(&device(&format!("d{i}"), MatchState::Unmatched, None))
            .await
            .unwrap();
    }

    let (status, body) = get(f.state.clone(), "/devices/unmatched?page=99").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("Every device is attached to a person"),
        "five devices are waiting; the page number was just too high"
    );
    assert!(!body.contains("No devices yet"));
    assert!(body.contains("CB-d0"), "clamped back to the last real page");
}

// ---------------------------------------------------------------------------
// The resolve picker
// ---------------------------------------------------------------------------

/// An HTMX request gets the bare `<tr>` to swap in; anything else gets a
/// document. The Resolve control is an ordinary `<a href>`, so a browser with
/// scripting off — or a link pasted into a ticket — lands on this route
/// directly, and a bare table row is not a page.
#[tokio::test]
async fn the_picker_is_a_fragment_for_htmx_and_a_document_otherwise() {
    let f = fixture().await;
    seed_base(&f).await;
    f.repo
        .create_asset(&device("a", MatchState::Unmatched, None))
        .await
        .unwrap();

    let (status, page) = get(f.state.clone(), "/devices/a/resolve").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("<html"), "a plain navigation gets a document");
    assert!(page.contains("Back to the queue"), "and a way out of it");

    let token = crate::csrf::generate_csrf_token();
    let response = router(f.state.clone())
        .oneshot(
            Request::builder()
                .uri("/devices/a/resolve")
                .header("HX-Request", "true")
                .header("cookie", format!("chalk_csrf={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let fragment = String::from_utf8_lossy(&bytes).to_string();
    assert!(
        !fragment.contains("<html"),
        "HTMX swaps this into a table; a document would nest one inside a row"
    );
    assert!(fragment.trim_start().starts_with("<tr"));
}

/// An empty search offers no candidates rather than the whole roster: the
/// picker is a type-ahead, and listing 20,000 students is not a choice.
#[tokio::test]
async fn the_picker_does_not_list_the_roster_until_asked() {
    let f = fixture().await;
    seed_base(&f).await;
    f.repo
        .create_asset(&device("a", MatchState::Unmatched, None))
        .await
        .unwrap();

    let (status, body) = get(f.state.clone(), "/devices/a/resolve").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Type a name, email or username"));
    assert!(!body.contains("Doe, Jane"));
}

#[tokio::test]
async fn the_picker_finds_a_roster_user_by_surname() {
    let f = fixture().await;
    seed_base(&f).await;
    f.repo
        .create_asset(&device("a", MatchState::Unmatched, None))
        .await
        .unwrap();

    let (status, body) = get(f.state.clone(), "/devices/a/resolve?q=doe").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Doe, Jane"));
    assert!(
        body.contains("u-1"),
        "the Attach form carries the sourced id"
    );
}

/// A search that finds nobody points at the other remedy rather than dead-ending.
#[tokio::test]
async fn a_search_with_no_matches_offers_the_shared_route_out() {
    let f = fixture().await;
    seed_base(&f).await;
    f.repo
        .create_asset(&device("a", MatchState::Unmatched, None))
        .await
        .unwrap();

    let (_, body) = get(f.state.clone(), "/devices/a/resolve?q=nobodyhere").await;
    assert!(body.contains("Nobody in the roster matches"));
    assert!(body.contains("shared"));
}

/// The picker is seeded from the address Google gave us, which is what turns
/// "j.alvarez@old-district.org" into a search that finds the person who changed
/// domains — the commonest resolvable case in the queue.
#[tokio::test]
async fn the_queue_seeds_the_picker_with_the_local_part_of_a_stale_address() {
    let row = UnmatchedRowView::from_row(&AssetRow::bare(device(
        "a",
        MatchState::Unmatched,
        Some("j.alvarez@old-district.org"),
    )));
    assert_eq!(row.search_seed, "j.alvarez");

    // A cart has nothing to seed with, and guessing would send the operator
    // searching for a phrase that cannot match a person.
    let cart = UnmatchedRowView::from_row(&AssetRow::bare(device(
        "b",
        MatchState::Unmatched,
        Some("Cart 3"),
    )));
    assert_eq!(cart.search_seed, "");
}

/// Google's value is shown exactly as stored. Tidying it would hide the typo
/// that is often the whole reason the device is here.
#[tokio::test]
async fn the_queue_shows_googles_value_verbatim() {
    let row = UnmatchedRowView::from_row(&AssetRow::bare(device(
        "a",
        MatchState::Unmatched,
        Some("  J.Alvarez@Old-District.ORG  "),
    )));
    assert_eq!(
        row.google_user, "J.Alvarez@Old-District.ORG",
        "trimmed for display, but never case-folded or rewritten"
    );
}

// ---------------------------------------------------------------------------
// Redirect safety
// ---------------------------------------------------------------------------

/// `back` arrives in a form field, so an unchecked redirect would let a crafted
/// page bounce a signed-in admin off-site.
#[test]
fn back_targets_outside_the_queue_are_refused() {
    assert_eq!(
        safe_back("/devices/unmatched?page=3"),
        "/devices/unmatched?page=3"
    );
    assert_eq!(safe_back("/devices/unmatched"), "/devices/unmatched");

    for hostile in [
        "https://evil.example/steal",
        "//evil.example",
        "/settings",
        "javascript:alert(1)",
        "",
    ] {
        assert_eq!(
            safe_back(hostile),
            "/devices/unmatched",
            "{hostile} must not survive as a redirect target"
        );
    }
}

/// A protocol-relative URL passes a naive "starts with /" check and is a real
/// open-redirect. Pinned separately because it is the one an author adding a
/// second `safe_back` would most likely miss.
#[test]
fn a_protocol_relative_url_is_not_a_local_path() {
    assert_eq!(
        safe_back("//evil.example/devices/unmatched"),
        "/devices/unmatched"
    );
}

// ---------------------------------------------------------------------------
// The flash message
// ---------------------------------------------------------------------------

/// The message travels in a cookie rather than the URL. A query parameter would
/// let any crafted link render arbitrary text inside a success banner shown to
/// a signed-in administrator — escaped, so not script injection, but a
/// ready-made phishing surface.
#[tokio::test]
async fn a_notice_in_the_url_is_not_rendered() {
    let f = fixture().await;
    seed_base(&f).await;
    f.repo
        .create_asset(&device("a", MatchState::Unmatched, None))
        .await
        .unwrap();

    let (status, body) = get(
        f.state.clone(),
        "/devices/unmatched?notice=Your+session+expired,+call+555-0100",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("555-0100"),
        "text from the URL must never reach the flash banner"
    );
}

/// Control characters are stripped and the length is bounded before a cookie
/// value reaches a template. A cookie is far harder to plant than a URL, but it
/// is still client-side storage.
#[test]
fn flash_values_are_bounded_and_stripped() {
    let mut headers = HeaderMap::new();
    let long = "x".repeat(FLASH_MAX_LEN + 50);
    headers.insert(
        axum::http::header::COOKIE,
        format!("{FLASH_COOKIE}={long}").parse().unwrap(),
    );
    assert_eq!(take_flash(&headers).len(), FLASH_MAX_LEN);

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        format!("{FLASH_COOKIE}=one%0Atwo").parse().unwrap(),
    );
    assert_eq!(
        take_flash(&headers),
        "onetwo",
        "a newline would let a message forge a second line of UI"
    );

    assert_eq!(take_flash(&HeaderMap::new()), "");
}
