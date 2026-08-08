//! Preview tests.
//!
//! What matters here is that the screen tells the truth about what will
//! happen: the count in the footer is the count that applies, a struck-out row
//! stays visible, a Google row is marked as leaving Chalk's own records, and a
//! change that cannot be undone is gated behind a count the *server* checks.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetRepository, ChalkRepository, ChangeSetRepository, JobRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::asset::Asset;
use chalk_core::models::change_set::{
    ChangeSet, ChangeSetItemStatus, ChangeSetKind, ChangeSetOp, NewChangeSetItem,
};
use chalk_core::models::job::{JobFilter, JobKind};
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
    let assets: Arc<dyn AssetRepository> = repo.clone();
    let events: Arc<dyn chalk_core::db::repository::AssetEventRepository> = repo.clone();
    let jobs: Arc<dyn JobRepository> = repo.clone();
    let runs: Arc<dyn chalk_core::db::repository::GoogleDeviceSyncRepository> = repo.clone();
    let sets: Arc<dyn ChangeSetRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();

    let state = Arc::new(
        AppState::new(chalk_repo, ChalkConfig::generate_default())
            .with_assets(assets, events)
            .with_device_sync(jobs, runs)
            .with_change_sets(sets),
    );
    Fx { state, repo }
}

async fn device(f: &Fx, id: &str) {
    let mut a = Asset::new(id);
    a.asset_tag = Some(format!("CB-{id}"));
    f.repo.create_asset(&a).await.unwrap();
}

/// A change set with the given items, as the planner would have written it.
async fn planned(f: &Fx, id: &str, items: Vec<NewChangeSetItem>) -> String {
    let set = ChangeSet::planned(
        id,
        ChangeSetKind::BulkEdit,
        "console:admin",
        "hash",
        items.len() as i64,
    );
    f.repo.create_change_set(&set, &items).await.unwrap();
    id.to_string()
}

fn local_item(asset: &str, old: &str, new: &str) -> NewChangeSetItem {
    NewChangeSetItem {
        asset_id: Some(asset.into()),
        target_ref: Some(format!("CB-{asset}")),
        google_device_id: None,
        op: ChangeSetOp::ChangeStatus,
        field: Some("status".into()),
        old_value: Some(old.into()),
        new_value: Some(new.into()),
        remote_target: RemoteTarget::Local,
    }
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

async fn post(state: Arc<AppState>, uri: &str, body: &str) -> StatusCode {
    let token = crate::csrf::generate_csrf_token();
    router(state)
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
        .unwrap()
        .status()
}

// ---------------------------------------------------------------------------
// What the preview shows
// ---------------------------------------------------------------------------

/// The old and new values are both on screen. A preview that showed only the
/// destination would not be a diff.
#[tokio::test]
async fn the_preview_shows_both_values_for_every_row() {
    let f = fixture().await;
    device(&f, "a").await;
    let id = planned(&f, "cs-1", vec![local_item("a", "active", "repair")]).await;

    let (status, body) = get(f.state.clone(), &format!("{PREVIEW_PATH}/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("CB-a"));
    assert!(body.contains("active"), "the value it holds now");
    assert!(body.contains("repair"), "the value it would hold");
    assert!(body.contains("Apply 1 change"));
}

/// The footer states a number, not a verb. Someone committing a bulk change
/// should be reading a count.
#[tokio::test]
async fn the_footer_states_how_many_will_change() {
    let f = fixture().await;
    for id in ["a", "b", "c"] {
        device(&f, id).await;
    }
    let id = planned(
        &f,
        "cs-2",
        vec![
            local_item("a", "active", "repair"),
            local_item("b", "active", "repair"),
            local_item("c", "active", "repair"),
        ],
    )
    .await;

    let (_, body) = get(f.state.clone(), &format!("{PREVIEW_PATH}/{id}")).await;
    assert!(body.contains("Apply 3 changes"));
    // "changes", not "devices". A bulk edit is one item per device, but a CSV
    // import is one item per *field* — the same strip renders both, and
    // counting items as devices would overstate the second.
    assert!(body.contains("3 changes will apply"));
}

/// A struck-out row stays on screen, dimmed. Removing it would make the
/// preview disagree with the count beside it, and an operator who changed
/// their mind could not see what they had excluded.
#[tokio::test]
async fn a_struck_out_row_stays_visible_and_leaves_the_count() {
    let f = fixture().await;
    device(&f, "a").await;
    device(&f, "b").await;
    let id = planned(
        &f,
        "cs-3",
        vec![
            local_item("a", "active", "repair"),
            local_item("b", "active", "repair"),
        ],
    )
    .await;

    let item = f
        .repo
        .list_items(&id, None, PageRequest::new(10, 0))
        .await
        .unwrap()
        .items[0]
        .id;
    assert_eq!(
        post(
            f.state.clone(),
            &format!("{PREVIEW_PATH}/{id}/exclude"),
            &format!("item_id={item}")
        )
        .await,
        StatusCode::SEE_OTHER
    );

    let (_, body) = get(f.state.clone(), &format!("{PREVIEW_PATH}/{id}")).await;
    assert!(body.contains("Struck out"));
    assert!(body.contains("is-struck"), "still rendered, just dimmed");
    assert!(body.contains("Apply 1 change"), "the count follows");
    assert!(body.contains("1 struck out"));
}

/// A plan that changes nothing says so, rather than showing an empty table
/// with an Apply button.
#[tokio::test]
async fn an_empty_plan_says_nothing_would_change() {
    let f = fixture().await;
    let id = planned(&f, "cs-4", vec![]).await;

    let (status, body) = get(f.state.clone(), &format!("{PREVIEW_PATH}/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Nothing would change"));
    assert!(!body.contains("Apply 0 changes"));
}

/// A Google-targeted row is marked as a tenant write and can be struck out
/// like any other. It used to carry a "cannot do" warning; write-back exists
/// now, and a preview still saying otherwise would tell an operator their
/// approved change will be ignored.
#[tokio::test]
async fn google_rows_are_marked_as_tenant_writes_and_can_be_struck_out() {
    let f = fixture().await;
    device(&f, "a").await;
    let id = planned(
        &f,
        "cs-5",
        vec![NewChangeSetItem {
            asset_id: Some("a".into()),
            target_ref: Some("CB-a".into()),
            google_device_id: Some("g-a".into()),
            op: ChangeSetOp::MoveOu,
            field: Some("org_unit_path".into()),
            old_value: Some("/Students".into()),
            new_value: Some("/Students/HS".into()),
            remote_target: RemoteTarget::Google,
        }],
    )
    .await;

    let (_, body) = get(f.state.clone(), &format!("{PREVIEW_PATH}/{id}")).await;
    assert!(
        body.contains("Google"),
        "the row is marked as a tenant write"
    );
    assert!(
        body.contains("written to Google Workspace"),
        "the page says these leave Chalk's own records"
    );
    // The old copy said write-back "cannot" be done. It can now, and a preview
    // that still said otherwise would be telling an operator their approved
    // change will be ignored.
    assert!(!body.contains("cannot do"));
    assert!(!body.contains("left alone"));
    assert!(
        body.contains("Leave out"),
        "a Google row is strikeable like any other now that it can be applied"
    );
}

/// A cleared value reads as a clear, not as an empty cell someone takes for a
/// rendering fault.
#[test]
fn an_absent_new_value_renders_as_a_clear() {
    let item = ChangeSetItem {
        id: 1,
        change_set_id: "cs".into(),
        asset_id: Some("a".into()),
        target_ref: Some("CB-a".into()),
        google_device_id: None,
        op: ChangeSetOp::Unassign,
        field: Some("assigned_user_sourced_id".into()),
        old_value: Some("u-1".into()),
        new_value: None,
        remote_target: RemoteTarget::Local,
        status: ChangeSetItemStatus::Pending,
        error: None,
        applied_at: None,
    };
    assert_eq!(ItemView::new(&item).new_value, "(cleared)");
}

// ---------------------------------------------------------------------------
// Committing
// ---------------------------------------------------------------------------

/// Committing enqueues a job carrying the hash and count the preview was built
/// from — not just the id — so the worker can refuse a plan that drifted.
#[tokio::test]
async fn committing_enqueues_a_job_carrying_the_approved_plan() {
    let f = fixture().await;
    device(&f, "a").await;
    let id = planned(&f, "cs-6", vec![local_item("a", "active", "repair")]).await;

    assert_eq!(
        post(f.state.clone(), &format!("{PREVIEW_PATH}/{id}/commit"), "").await,
        StatusCode::SEE_OTHER
    );

    let jobs = f
        .repo
        .list_jobs(
            &JobFilter {
                kind: Some(JobKind::ChangeSetCommit),
                ..Default::default()
            },
            PageRequest::new(10, 0),
        )
        .await
        .unwrap();
    assert_eq!(jobs.total, 1);
    let payload = &jobs.items[0].payload;
    assert_eq!(payload["changeSetId"], id);
    assert_eq!(payload["planHash"], "hash");
    assert_eq!(payload["expectedItemCount"], 1);
    assert_eq!(
        jobs.items[0].max_attempts, 1,
        "a commit writes district records, so it is at-most-once"
    );
}

/// A settled change set cannot be committed or edited again.
#[tokio::test]
async fn a_discarded_set_cannot_be_committed_or_edited() {
    let f = fixture().await;
    device(&f, "a").await;
    let id = planned(&f, "cs-7", vec![local_item("a", "active", "repair")]).await;

    assert_eq!(
        post(f.state.clone(), &format!("{PREVIEW_PATH}/{id}/discard"), "").await,
        StatusCode::SEE_OTHER
    );

    // Committing after discarding must not queue anything.
    post(f.state.clone(), &format!("{PREVIEW_PATH}/{id}/commit"), "").await;
    let jobs = f
        .repo
        .list_jobs(&JobFilter::default(), PageRequest::new(10, 0))
        .await
        .unwrap();
    assert_eq!(jobs.total, 0, "a discarded set must not be committable");

    let (_, body) = get(f.state.clone(), &format!("{PREVIEW_PATH}/{id}")).await;
    assert!(!body.contains("Apply 1 change"), "the actions are gone");
    assert!(body.contains("discarded"));
}

/// An unknown action is refused rather than defaulted. Defaulting a bulk write
/// to anything is how a mistyped request becomes a fleet-wide surprise.
#[test]
fn an_unknown_bulk_action_is_refused() {
    let bad = PlanForm {
        action: "delete_everything".into(),
        ..Default::default()
    };
    assert!(bad.to_change().is_err());

    let no_user = PlanForm {
        action: "assign".into(),
        value: "  ".into(),
        ..Default::default()
    };
    assert!(no_user.to_change().is_err(), "assign needs a person");

    let bad_status = PlanForm {
        action: "status".into(),
        value: "exploded".into(),
        ..Default::default()
    };
    assert!(bad_status.to_change().is_err());

    assert!(PlanForm {
        action: "unassign".into(),
        ..Default::default()
    }
    .to_change()
    .is_ok());

    assert!(
        matches!(
            PlanForm {
                action: "annotate".into(),
                ..Default::default()
            }
            .to_change(),
            Ok(chalk_core::change_plan::PlannedChange::SyncAnnotations { .. })
        ),
        "annotate maps to the annotation push"
    );
}

/// The annotate action plans per-device annotation items through the same
/// preview pipeline as every other bulk action — Google-targeted, with the
/// student's roster email as the value.
#[tokio::test]
async fn a_annotate_action_plans_google_annotation_items() {
    use chalk_core::db::repository::UserRepository;
    let f = fixture().await;
    f.repo
        .upsert_user(&chalk_core::models::user::User {
            sourced_id: "u-1".into(),
            status: chalk_core::models::common::Status::Active,
            date_last_modified: chrono::Utc::now(),
            metadata: None,
            username: "u1".into(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "Given".into(),
            family_name: "Family".into(),
            middle_name: None,
            role: chalk_core::models::common::RoleType::Student,
            identifier: None,
            email: Some("u-1@example.edu".into()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec![],
            grades: vec![],
        })
        .await
        .unwrap();
    // A device assigned in Chalk but not yet annotated in Google.
    let mut a = chalk_core::models::asset::Asset::new("dev-ann");
    a.asset_tag = Some("CB-ANN".into());
    a.google_device_id = Some("g-ann".into());
    a.assigned_user_sourced_id = Some("u-1".into());
    f.repo.create_asset(&a).await.unwrap();

    let status = post(f.state.clone(), "/devices/changes", "action=annotate").await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let sets = f
        .repo
        .list_change_sets(
            &chalk_core::models::change_set::ChangeSetFilter::default(),
            chalk_core::models::page::PageRequest::new(10, 0),
        )
        .await
        .unwrap()
        .items;
    let set = &sets[0];
    let items = f
        .repo
        .list_items(&set.id, None, PageRequest::new(10, 0))
        .await
        .unwrap()
        .items;
    assert!(
        items
            .iter()
            .any(|i| i.field.as_deref() == Some("annotated_user")
                && i.new_value.as_deref() == Some("u-1@example.edu")
                && i.remote_target == chalk_core::models::change_set::RemoteTarget::Google),
        "the student's email is planned into annotatedUser"
    );
    assert!(
        items
            .iter()
            .any(|i| i.field.as_deref() == Some("annotated_asset_id")
                && i.new_value.as_deref() == Some("CB-ANN")),
        "the sticker is planned into annotatedAssetId"
    );
}

/// The notice is a closed set of codes, so a crafted link cannot put arbitrary
/// words on a page that is about to change a fleet.
#[tokio::test]
async fn arbitrary_notice_text_is_not_rendered() {
    let f = fixture().await;
    device(&f, "a").await;
    let id = planned(&f, "cs-8", vec![local_item("a", "active", "repair")]).await;

    let (_, body) = get(
        f.state.clone(),
        &format!("{PREVIEW_PATH}/{id}?notice=All+devices+were+wiped"),
    )
    .await;
    assert!(!body.contains("were wiped"));
}

#[tokio::test]
async fn an_unknown_change_set_is_a_404() {
    let f = fixture().await;
    let (status, _) = get(f.state.clone(), &format!("{PREVIEW_PATH}/nope")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// The gate on a change that cannot be undone
// ---------------------------------------------------------------------------

/// A deprovision item, as the planner writes it.
fn deprovision_item(asset: &str) -> NewChangeSetItem {
    NewChangeSetItem {
        asset_id: Some(asset.into()),
        target_ref: Some(format!("CB-{asset}")),
        google_device_id: Some(format!("g-{asset}")),
        op: ChangeSetOp::ChangeStatus,
        field: Some("google_status".into()),
        old_value: None,
        new_value: Some("deprovision:retiring_device".into()),
        remote_target: RemoteTarget::Google,
    }
}

async fn queued_commits(f: &Fx) -> usize {
    f.repo
        .list_jobs(&JobFilter::default(), PageRequest::new(50, 0))
        .await
        .unwrap()
        .items
        .iter()
        .filter(|j| j.kind == JobKind::ChangeSetCommit)
        .count()
}

/// The consequence is the first thing on the page, in plain words, and the
/// count has to be typed. An operator skimming reads the first line and
/// nothing else, so the first line has to be the one that matters.
#[tokio::test]
async fn a_deprovision_states_the_consequence_and_asks_for_the_count() {
    let f = fixture().await;
    device(&f, "a").await;
    device(&f, "b").await;
    let id = planned(
        &f,
        "cs-d1",
        vec![deprovision_item("a"), deprovision_item("b")],
    )
    .await;

    let (_, body) = get(f.state.clone(), &format!("{PREVIEW_PATH}/{id}")).await;
    assert!(body.contains("cannot be undone from Chalk"));
    assert!(body.contains("releases 2 Chromebook licences"));
    assert!(
        body.contains("Retiring from the fleet"),
        "the reason is shown"
    );
    assert!(
        body.contains("re-enrolling it by"),
        "and what recovery costs"
    );
    assert!(body.contains("name=\"confirm\""), "the count must be typed");
    assert!(
        body.contains("Deprovision 2 devices"),
        "the button names the act and the number, not 'Apply'"
    );
    assert!(
        !body.to_lowercase().contains("don't ask again")
            && !body.to_lowercase().contains("do not ask again"),
        "there is deliberately no way to switch this off"
    );
}

/// The gate is enforced on the server. A disabled button is a hint; this is
/// what actually stops the write.
#[tokio::test]
async fn committing_a_deprovision_without_the_count_applies_nothing() {
    let f = fixture().await;
    device(&f, "a").await;
    let id = planned(&f, "cs-d2", vec![deprovision_item("a")]).await;

    for body in ["confirm=", "confirm=yes", "confirm=2", "confirm= "] {
        assert_eq!(
            post(
                f.state.clone(),
                &format!("{PREVIEW_PATH}/{id}/commit"),
                body
            )
            .await,
            StatusCode::SEE_OTHER
        );
        assert_eq!(
            queued_commits(&f).await,
            0,
            "{body:?} must not queue a commit"
        );
    }

    let (_, page) = get(
        f.state.clone(),
        &format!("{PREVIEW_PATH}/{id}?notice=unconfirmed"),
    )
    .await;
    assert!(page.contains("Nothing was applied"));
}

/// The right count commits, and the change set is still `planned` until the
/// worker runs — the console never applies anything itself.
#[tokio::test]
async fn committing_a_deprovision_with_the_right_count_queues_the_work() {
    let f = fixture().await;
    device(&f, "a").await;
    device(&f, "b").await;
    let id = planned(
        &f,
        "cs-d3",
        vec![deprovision_item("a"), deprovision_item("b")],
    )
    .await;

    assert_eq!(
        post(
            f.state.clone(),
            &format!("{PREVIEW_PATH}/{id}/commit"),
            "confirm=2"
        )
        .await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(queued_commits(&f).await, 1);
}

/// The expected count is recounted from the stored items, so striking a row
/// out changes what has to be typed. A number carried in the form would be a
/// number the browser could choose.
#[tokio::test]
async fn striking_a_row_out_changes_the_number_that_confirms() {
    let f = fixture().await;
    device(&f, "a").await;
    device(&f, "b").await;
    let id = planned(
        &f,
        "cs-d4",
        vec![deprovision_item("a"), deprovision_item("b")],
    )
    .await;

    let item = f
        .repo
        .list_items(&id, None, PageRequest::new(10, 0))
        .await
        .unwrap()
        .items[0]
        .id;
    post(
        f.state.clone(),
        &format!("{PREVIEW_PATH}/{id}/exclude"),
        &format!("item_id={item}"),
    )
    .await;

    // The old number is now wrong and must be refused.
    post(
        f.state.clone(),
        &format!("{PREVIEW_PATH}/{id}/commit"),
        "confirm=2",
    )
    .await;
    assert_eq!(queued_commits(&f).await, 0, "the stale count is refused");

    post(
        f.state.clone(),
        &format!("{PREVIEW_PATH}/{id}/commit"),
        "confirm=1",
    )
    .await;
    assert_eq!(queued_commits(&f).await, 1);
}

/// A change set with nothing destructive in it commits on one press. A
/// confirmation attached to a harmless step teaches people to click through it
/// before it ever guards anything.
#[tokio::test]
async fn an_ordinary_change_set_needs_no_typed_confirmation() {
    let f = fixture().await;
    device(&f, "a").await;
    let id = planned(&f, "cs-d5", vec![local_item("a", "active", "repair")]).await;

    let (_, body) = get(f.state.clone(), &format!("{PREVIEW_PATH}/{id}")).await;
    assert!(!body.contains("cannot be undone"));
    assert!(!body.contains("name=\"confirm\""));

    assert_eq!(
        post(f.state.clone(), &format!("{PREVIEW_PATH}/{id}/commit"), "").await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(queued_commits(&f).await, 1);
}

/// Disabling is reversible and must not be gated like a deprovision — an
/// operator re-enables from the same screen.
#[tokio::test]
async fn a_reversible_google_change_is_not_treated_as_destructive() {
    let f = fixture().await;
    device(&f, "a").await;
    let id = planned(
        &f,
        "cs-d6",
        vec![NewChangeSetItem {
            new_value: Some("disable".into()),
            ..deprovision_item("a")
        }],
    )
    .await;

    let (_, body) = get(f.state.clone(), &format!("{PREVIEW_PATH}/{id}")).await;
    assert!(!body.contains("cannot be undone"));
    assert_eq!(
        post(f.state.clone(), &format!("{PREVIEW_PATH}/{id}/commit"), "").await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(queued_commits(&f).await, 1);
}
