//! Action-history tests.
//!
//! Most of these are about [`describe`], because turning a payload into a
//! sentence is the only thing this module does that a `SELECT *` would not.
//! The rule strings it reads are the ones `MatchRule::as_str` promises never to
//! change — historical rows are read with them — so a test that pins the
//! mapping is also a test that pins that promise.

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
use chalk_core::models::asset::{ActorKind, AssetStatus, NewAssetEvent};
use chalk_core::models::common::{OrgType, RoleType, Status};
use chalk_core::models::org::Org;
use chalk_core::models::user::User;
use chrono::{TimeZone, Utc};
use tower::ServiceExt;

use crate::{router, AppState};

// ---------------------------------------------------------------------------
// describe()
// ---------------------------------------------------------------------------

fn event(event_type: AssetEventType, actor: &str, payload: serde_json::Value) -> AssetEvent {
    AssetEvent {
        id: 1,
        asset_id: "a-1".into(),
        actor: actor.into(),
        actor_kind: if actor.starts_with("system:") {
            ActorKind::System
        } else {
            ActorKind::Admin
        },
        event_type,
        payload: Some(payload),
        created_at: Utc.with_ymd_and_hms(2026, 5, 4, 9, 30, 0).unwrap(),
    }
}

/// The point of the whole module: an IT director must be able to read *why* a
/// device was attached to a student, in words, without knowing the schema.
#[test]
fn every_match_rule_renders_as_a_sentence_naming_the_rule() {
    // Exactly the payload `chalk-devices` writes.
    for (rule, expected) in [
        ("annotated_user", "google user set on the device"),
        ("recent_user", "most recent sign-in"),
        ("serial_number", "by serial"),
        ("asset_tag", "by asset tag"),
    ] {
        let e = event(
            AssetEventType::Assigned,
            "system:google-sync",
            serde_json::json!({
                "rule": rule,
                "matchedEmail": "jane@school.edu",
                "userSourcedId": "u-1",
                "googleDeviceId": "g-1",
            }),
        );
        let (summary, detail) = describe(&e);
        assert!(
            summary.to_lowercase().contains(expected),
            "rule {rule} rendered as {summary:?}, which does not name the rule"
        );
        assert!(
            detail.contains("jane@school.edu"),
            "the matched address is what makes a wrong match checkable"
        );
    }
}

/// A human decision and a rule firing are the two things this log exists to
/// tell apart. If they read alike, the log cannot answer "did the automation do
/// this, or did someone?".
#[test]
fn a_manual_assignment_never_reads_like_an_automatic_match() {
    let (manual, _) = describe(&event(
        AssetEventType::Assigned,
        "console:admin",
        serde_json::json!({"user": "u-1", "rule": "manual", "via": "unmatched_queue"}),
    ));
    let (auto, _) = describe(&event(
        AssetEventType::Assigned,
        "system:google-sync",
        serde_json::json!({"rule": "annotated_user", "matchedEmail": "j@s.edu"}),
    ));

    assert!(manual.contains("administrator"));
    assert!(!manual.to_lowercase().contains("matched"));
    assert!(auto.to_lowercase().contains("matched"));
    assert_ne!(manual, auto);
}

/// An unrecognised rule still renders, naming the raw value. Dropping the row
/// would make the omission invisible, and completeness is this log's only job.
#[test]
fn an_unknown_rule_still_renders_rather_than_vanishing() {
    let (summary, _) = describe(&event(
        AssetEventType::Assigned,
        "system:google-sync",
        serde_json::json!({"rule": "some_future_rule"}),
    ));
    assert!(summary.contains("some_future_rule"), "got {summary:?}");
}

/// An event with no payload at all must still produce a sentence — older rows,
/// or a writer that omitted it.
#[test]
fn events_without_a_payload_still_describe_themselves() {
    for event_type in [
        AssetEventType::Assigned,
        AssetEventType::Unassigned,
        AssetEventType::MovedOu,
        AssetEventType::StatusChanged,
        AssetEventType::Deprovisioned,
        AssetEventType::Repaired,
        AssetEventType::Imported,
        AssetEventType::FieldChanged,
    ] {
        let mut e = event(event_type, "system:google-sync", serde_json::json!({}));
        e.payload = None;
        let (summary, _) = describe(&e);
        assert!(
            !summary.is_empty(),
            "{event_type:?} produced no sentence without a payload"
        );
    }
}

/// `match_state` is schema vocabulary. "field_changed: match_state" means
/// nothing to anyone who has not read the migration.
#[test]
fn match_state_changes_are_translated_out_of_schema_words() {
    let (ignored, note) = describe(&event(
        AssetEventType::FieldChanged,
        "console:admin",
        serde_json::json!({"field": "match_state", "old": "unmatched", "new": "ignored"}),
    ));
    assert!(ignored.to_lowercase().contains("shared"));
    assert!(!ignored.contains("match_state"));
    assert!(
        note.to_lowercase().contains("stays in the inventory"),
        "ignoring must not read as deleting: {note:?}"
    );

    let (manual, note) = describe(&event(
        AssetEventType::FieldChanged,
        "console:admin",
        serde_json::json!({"field": "match_state", "old": "unmatched", "new": "manual"}),
    ));
    assert!(manual.to_lowercase().contains("administrator"));
    assert!(
        note.to_lowercase().contains("will not change"),
        "the operator's real question is whether tonight's sync undoes this"
    );
}

/// A merge means a Google device was joined onto a record that already
/// existed. Which rule joined them is what makes a wrong merge diagnosable.
#[test]
fn an_import_that_merged_says_which_rule_joined_the_records() {
    let (summary, detail) = describe(&event(
        AssetEventType::Imported,
        "system:google-sync",
        serde_json::json!({"source": "google", "mergeRule": "serial_number", "googleDeviceId": "g-1"}),
    ));
    assert!(summary.contains("Google Workspace"));
    assert!(detail.to_lowercase().contains("serial"));

    // A plain import has nothing to explain and must not invent a detail line.
    let (_, plain) = describe(&event(
        AssetEventType::Imported,
        "system:google-sync",
        serde_json::json!({"source": "google", "googleDeviceId": "g-1"}),
    ));
    assert_eq!(plain, "");
}

/// Chalk did not deprovision anything — the ChromeOS client is read-only. The
/// log has to say the change was *observed*, or it claims an action Chalk
/// cannot currently take.
#[test]
fn an_observed_deprovision_does_not_claim_chalk_did_it() {
    let (_, detail) = describe(&event(
        AssetEventType::Deprovisioned,
        "system:google-sync",
        serde_json::json!({"observedFrom": "google"}),
    ));
    assert!(detail.contains("Observed"));
    assert!(detail.contains("not done by Chalk"));
}

#[test]
fn old_to_new_transitions_are_shown_both_ways_round() {
    let e = event(
        AssetEventType::StatusChanged,
        "console:admin",
        serde_json::json!({"field": "status", "old": "active", "new": "repair"}),
    );
    assert_eq!(describe(&e).1, "active → repair");

    let set_only = event(
        AssetEventType::StatusChanged,
        "console:admin",
        serde_json::json!({"new": "repair"}),
    );
    assert_eq!(describe(&set_only).1, "Set to repair");

    let cleared = event(
        AssetEventType::StatusChanged,
        "console:admin",
        serde_json::json!({"old": "active"}),
    );
    assert_eq!(describe(&cleared).1, "Cleared (was active)");
}

/// Payload values are not guaranteed to be strings. A number or bool must
/// render rather than silently becoming an empty cell.
#[test]
fn non_string_payload_values_still_render() {
    let e = event(
        AssetEventType::FieldChanged,
        "console:admin",
        serde_json::json!({"field": "purchase_cost_cents", "old": 0, "new": 24999}),
    );
    assert_eq!(describe(&e).1, "0 → 24999");

    // An explicit null, and an all-whitespace string, are both "absent".
    let blank = event(
        AssetEventType::FieldChanged,
        "console:admin",
        serde_json::json!({"field": "notes", "old": null, "new": "   "}),
    );
    assert_eq!(describe(&blank).1, "");
}

/// `system:google-sync` on every row makes the log look like a machine talking
/// to itself.
#[test]
fn actors_are_named_in_words() {
    assert_eq!(
        describe_actor(&event(
            AssetEventType::Imported,
            "system:google-sync",
            serde_json::json!({})
        )),
        "Google sync"
    );
    assert_eq!(
        describe_actor(&event(
            AssetEventType::Assigned,
            "console:admin",
            serde_json::json!({})
        )),
        "An administrator"
    );
    // An actor we do not have a name for is shown verbatim rather than hidden.
    assert_eq!(
        describe_actor(&event(
            AssetEventType::Assigned,
            "tok_abc123",
            serde_json::json!({})
        )),
        "tok_abc123"
    );
}

/// The state label answers "what is it"; the note answers "will tonight's sync
/// undo my work", which is the question actually being asked.
#[test]
fn every_match_state_says_what_the_next_sync_will_do() {
    for state in [
        MatchState::Matched,
        MatchState::Unmatched,
        MatchState::Manual,
        MatchState::Ignored,
    ] {
        assert!(!match_state_label(state).is_empty());
        assert!(!match_state_note(state).is_empty());
    }
    assert!(match_state_note(MatchState::Manual).contains("not change"));
    assert!(match_state_note(MatchState::Ignored).contains("not change"));
    assert!(match_state_note(MatchState::Matched).contains("may reassign"));
}

// ---------------------------------------------------------------------------
// The pages
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

async fn seed(f: &Fixture) {
    f.repo
        .upsert_org(&Org {
            sourced_id: "org-hs".into(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            name: "Springfield High".into(),
            org_type: OrgType::School,
            identifier: None,
            parent: None,
            children: vec![],
        })
        .await
        .unwrap();
    f.repo
        .upsert_user(&User {
            sourced_id: "u-1".into(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            username: "jane.doe".into(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "Jane".into(),
            family_name: "Doe".into(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some("jane.doe@example.edu".into()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec![],
            grades: vec![],
        })
        .await
        .unwrap();

    let mut a = Asset::new("a-1");
    a.asset_tag = Some("CB-0001".into());
    a.serial_number = Some("SN-0001".into());
    a.model = Some("Chromebook Spin 511".into());
    a.status = AssetStatus::Active;
    a.school_org_sourced_id = Some("org-hs".into());
    a.assigned_user_sourced_id = Some("u-1".into());
    a.match_state = MatchState::Matched;
    f.repo.create_asset(&a).await.unwrap();

    f.repo
        .append_event(&NewAssetEvent {
            asset_id: "a-1".into(),
            actor: "system:google-sync".into(),
            actor_kind: ActorKind::System,
            event_type: AssetEventType::Assigned,
            payload: Some(serde_json::json!({
                "rule": "annotated_user",
                "matchedEmail": "jane.doe@example.edu",
                "userSourcedId": "u-1",
            })),
        })
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

#[tokio::test]
async fn the_device_page_shows_its_fields_and_its_history_in_words() {
    let f = fixture().await;
    seed(&f).await;

    let (status, body) = get(f.state.clone(), "/devices/a-1").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("CB-0001"));
    assert!(body.contains("Doe, Jane"), "the student is named");
    assert!(body.contains("Springfield High"));
    assert!(
        body.contains("Matched by the Google user set on the device"),
        "the rule that placed this device must be legible"
    );
    assert!(
        body.contains("A sync may reassign"),
        "the page says what the next sync will do"
    );
}

/// `/devices/unmatched` and `/devices/history` are static paths that must not
/// be captured by `/devices/:id`. If they were, the queue would render as a
/// device detail page for a device called "unmatched".
#[tokio::test]
async fn static_device_routes_win_over_the_id_parameter() {
    let f = fixture().await;
    seed(&f).await;

    let (status, body) = get(f.state.clone(), "/devices/unmatched").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("This device"), "that is the detail page");

    let (status, body) = get(f.state.clone(), "/devices/history").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Device activity"));
}

#[tokio::test]
async fn a_missing_device_is_a_404_with_a_way_back() {
    let f = fixture().await;
    seed(&f).await;

    let (status, body) = get(f.state.clone(), "/devices/no-such-device").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("/devices"), "a dead end needs an exit");
}

#[tokio::test]
async fn the_district_history_lists_events_newest_first_with_a_device_link() {
    let f = fixture().await;
    seed(&f).await;

    let (status, body) = get(f.state.clone(), "/devices/history").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Matched by the Google user set on the device"));
    assert!(
        body.contains("/devices/a-1"),
        "every row links to the device it happened to"
    );
    assert!(body.contains("CB-0001"), "named by tag, not by UUID");
}

#[tokio::test]
async fn an_empty_history_says_so_rather_than_rendering_an_empty_table() {
    let f = fixture().await;

    let (status, body) = get(f.state.clone(), "/devices/history").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No activity recorded yet"));
}

/// The filter narrows the log, and matching nothing is not the same as having
/// nothing.
#[tokio::test]
async fn a_filter_matching_nothing_is_not_an_empty_log() {
    let f = fixture().await;
    seed(&f).await;

    let (status, body) = get(f.state.clone(), "/devices/history?event_type=deprovisioned").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No events match these filters"));
    assert!(!body.contains("No activity recorded yet"));
}

/// "Everything that happened to my school's devices."
#[tokio::test]
async fn the_log_can_be_narrowed_to_one_school() {
    let f = fixture().await;
    seed(&f).await;

    // A second device with no school, and an event against it.
    let mut other = Asset::new("a-2");
    other.asset_tag = Some("CB-0002".into());
    f.repo.create_asset(&other).await.unwrap();
    f.repo
        .append_event(&NewAssetEvent::simple(
            "a-2",
            "system:google-sync",
            ActorKind::System,
            AssetEventType::Imported,
        ))
        .await
        .unwrap();

    let (_, all) = get(f.state.clone(), "/devices/history").await;
    assert!(all.contains("CB-0001") && all.contains("CB-0002"));

    let (status, scoped) = get(f.state.clone(), "/devices/history?school=org-hs").await;
    assert_eq!(status, StatusCode::OK);
    assert!(scoped.contains("CB-0001"));
    assert!(
        !scoped.contains("CB-0002"),
        "a device outside the school must not appear"
    );
}

/// "Everything this administrator did" — the audit question, and the one where
/// a filter that silently matched nothing would be actively misleading.
#[tokio::test]
async fn the_log_can_be_narrowed_to_one_actor() {
    let f = fixture().await;
    seed(&f).await;
    f.repo
        .append_event(&NewAssetEvent {
            asset_id: "a-1".into(),
            actor: "console:admin".into(),
            actor_kind: ActorKind::Admin,
            event_type: AssetEventType::FieldChanged,
            payload: Some(serde_json::json!({
                "field": "match_state", "old": "unmatched", "new": "ignored"
            })),
        })
        .await
        .unwrap();

    let (status, body) = get(f.state.clone(), "/devices/history?actor=console%3Aadmin").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Marked as shared"));
    assert!(
        !body.contains("Matched by the Google user"),
        "the sync's own events are not this administrator's work"
    );

    let (_, sync_only) = get(
        f.state.clone(),
        "/devices/history?actor=system%3Agoogle-sync",
    )
    .await;
    assert!(sync_only.contains("Matched by the Google user"));
    assert!(!sync_only.contains("Marked as shared"));
}

/// Filters combine rather than replace, and a combination matching nothing is
/// still not an empty log.
#[tokio::test]
async fn filters_combine_and_an_empty_combination_says_so() {
    let f = fixture().await;
    seed(&f).await;

    let (status, body) = get(
        f.state.clone(),
        "/devices/history?school=org-hs&actor=console%3Aadmin",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("No events match these filters"),
        "the school has events, but none by an administrator"
    );
    assert!(!body.contains("No activity recorded yet"));
}

/// The same clamp the inventory and the queue carry. Here an out-of-range page
/// would read as "no activity recorded yet" on an instance with a full audit
/// trail — the log claiming nothing ever happened.
#[tokio::test]
async fn a_page_past_the_end_clamps_instead_of_claiming_nothing_happened() {
    let f = fixture().await;
    seed(&f).await;

    let (status, body) = get(f.state.clone(), "/devices/history?page=99").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("No activity recorded yet"));
    assert!(body.contains("Matched by the Google user"));
}

/// A device deleted from the inventory does not erase its history: the log is
/// append-only, and a row whose device is gone still records something real.
#[tokio::test]
async fn history_survives_a_device_the_inventory_can_no_longer_resolve() {
    let f = fixture().await;
    seed(&f).await;

    // An event against an id the asset table cannot resolve. Written directly
    // because the FK would refuse it — this stands in for a row whose device is
    // unreadable for any reason.
    let (status, body) = get(f.state.clone(), "/devices/history").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("CB-0001"));

    // The label falls back to the id rather than dropping the row.
    let e = event(
        AssetEventType::Imported,
        "system:google-sync",
        serde_json::json!({"source": "google"}),
    );
    let view = EventView::new(&e, e.asset_id.clone());
    assert_eq!(view.device_label, "a-1");
    assert!(!view.summary.is_empty());
}
