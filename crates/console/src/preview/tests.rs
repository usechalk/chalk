//! Preview tests.
//!
//! What matters here is that the screen tells the truth about what will
//! happen: the count in the footer is the count that applies, a struck-out row
//! stays visible, and nothing about a Google-targeted row implies it will be
//! written.

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
    assert!(body.contains("3 devices will change"));
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

/// A Google-targeted row is marked and the page warns, rather than implying it
/// will apply. Write-back does not exist yet.
#[tokio::test]
async fn google_rows_are_marked_and_the_page_says_they_will_not_apply() {
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
    assert!(body.contains("Needs Google"));
    assert!(body.contains("cannot do"), "the page is explicit about it");
    assert!(body.contains("left alone"));
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
