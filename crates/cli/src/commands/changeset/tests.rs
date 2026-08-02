//! Changeset-CLI tests.
//!
//! The command exists for the moment something went wrong, so these are mostly
//! about `retry-failed`: what it re-arms, what it deliberately leaves alone,
//! and that it queues work rather than applying any itself.
//!
//! They exercise the repository operations the commands are built from rather
//! than capturing stdout. Printing is not the behaviour worth protecting — what
//! rows move, and which do not, is.

use super::*;

use chalk_core::db::repository::AssetRepository;

use chalk_core::models::change_set::{
    ChangeSet, ChangeSetDisplayStatus, ChangeSetItemStatus, ChangeSetKind, ChangeSetOp,
    NewChangeSetItem, RemoteTarget,
};

async fn repo() -> Arc<SqliteRepository> {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    }
}

fn item(tag: &str) -> NewChangeSetItem {
    NewChangeSetItem {
        asset_id: None,
        target_ref: Some(tag.into()),
        google_device_id: Some(format!("g-{tag}")),
        op: ChangeSetOp::MoveOu,
        field: Some("org_unit_path".into()),
        old_value: Some("/Students".into()),
        new_value: Some("/Students/HS".into()),
        remote_target: RemoteTarget::Google,
    }
}

/// A committed set whose items ended in mixed states — the situation the
/// command exists for.
async fn mixed_set(repo: &Arc<SqliteRepository>, id: &str) -> Vec<i64> {
    let set = ChangeSet::planned(id, ChangeSetKind::GoogleWriteback, "console:admin", "h", 4);
    repo.create_change_set(
        &set,
        &[item("CB-1"), item("CB-2"), item("CB-3"), item("CB-4")],
    )
    .await
    .unwrap();
    let ids: Vec<i64> = repo
        .list_items(id, None, PageRequest::new(10, 0))
        .await
        .unwrap()
        .items
        .iter()
        .map(|i| i.id)
        .collect();

    repo.claim_for_commit(id, "h", 4).await.unwrap();
    repo.mark_item_outcome(ids[1], ChangeSetItemStatus::Failed, Some("forbidden"))
        .await
        .unwrap();
    repo.mark_item_outcome(
        ids[2],
        ChangeSetItemStatus::Indeterminate,
        Some("chunk timed out"),
    )
    .await
    .unwrap();
    repo.mark_item_outcome(ids[3], ChangeSetItemStatus::Skipped, None)
        .await
        .unwrap();
    repo.finish_commit(id).await.unwrap();
    ids
}

/// A committed set with unresolved items reads as `partial`, not `committed`.
/// That distinction is the whole reason the display status is derived — the
/// column cannot hold it, and "committed" over a set where three devices did
/// not move would be a lie.
#[tokio::test]
async fn a_set_with_unresolved_items_reads_as_partial() {
    let repo = repo().await;
    mixed_set(&repo, "cs-1").await;

    let set = repo.get_change_set("cs-1").await.unwrap().unwrap();
    let progress = repo.item_status_counts("cs-1").await.unwrap();
    assert_eq!(
        progress.display_status(&set, chrono::Utc::now()),
        ChangeSetDisplayStatus::Partial
    );
    assert_eq!(
        progress.display_status(&set, chrono::Utc::now()).as_str(),
        "partial"
    );
}

/// `retry-failed` re-arms the failed and the unknown, and leaves the operator's
/// own decision alone. A struck-out row was a human saying no; re-arming it
/// would overrule them silently.
#[tokio::test]
async fn retrying_re_arms_failures_and_unknowns_but_never_a_struck_out_row() {
    let repo = repo().await;
    let ids = mixed_set(&repo, "cs-2").await;

    let before = repo.item_status_counts("cs-2").await.unwrap();
    assert_eq!(before.failed, 1);
    assert_eq!(before.indeterminate, 1);
    assert_eq!(before.skipped, 1);

    let rearmed = repo.rearm_failed_items("cs-2").await.unwrap();
    assert_eq!(rearmed, 3, "the failed, the unknown, and the still-pending");

    let after = repo.item_status_counts("cs-2").await.unwrap();
    assert_eq!(after.failed, 0);
    assert_eq!(after.indeterminate, 0);
    assert_eq!(after.pending, 3);
    assert_eq!(after.skipped, 1, "the human's decision survives");

    let items = repo
        .list_items("cs-2", None, PageRequest::new(10, 0))
        .await
        .unwrap()
        .items;
    let struck = items.iter().find(|i| i.id == ids[3]).unwrap();
    assert_eq!(struck.status, ChangeSetItemStatus::Skipped);
}

/// Re-arming puts the set back to `planned`, which is what lets a commit claim
/// it again. A set left `committed` would be refused by the staleness guard and
/// the re-arm would be inert.
#[tokio::test]
async fn re_arming_returns_the_set_to_planned_so_a_commit_can_claim_it() {
    let repo = repo().await;
    mixed_set(&repo, "cs-3").await;
    repo.rearm_failed_items("cs-3").await.unwrap();

    let set = repo.get_change_set("cs-3").await.unwrap().unwrap();
    assert_eq!(set.status, ChangeSetStatus::Planned);

    // And a commit can now claim it, with the count the re-arm left behind.
    let total = repo.item_status_counts("cs-3").await.unwrap().total();
    assert!(matches!(
        repo.claim_for_commit("cs-3", &set.plan_hash, total)
            .await
            .unwrap(),
        chalk_core::models::change_set::CommitClaim::Claimed
    ));
}

/// An already-applied item is never re-armed. Re-applying a confirmed write is
/// the double-write this design exists to prevent.
#[tokio::test]
async fn an_applied_item_is_never_re_armed() {
    let repo = repo().await;
    // The audit event references a real device: `asset_events.asset_id` is
    // RESTRICT, which is what stops an applied item pointing at nothing.
    repo.create_asset(&chalk_core::models::asset::Asset::new("a"))
        .await
        .unwrap();
    let set = ChangeSet::planned("cs-4", ChangeSetKind::GoogleWriteback, "admin", "h", 1);
    repo.create_change_set(&set, &[item("CB-1")]).await.unwrap();
    let id = repo
        .list_items("cs-4", None, PageRequest::new(10, 0))
        .await
        .unwrap()
        .items[0]
        .id;

    repo.claim_for_commit("cs-4", "h", 1).await.unwrap();
    repo.mark_item_applied(
        id,
        None,
        &chalk_core::models::asset::NewAssetEvent::simple(
            "a",
            "admin",
            chalk_core::models::asset::ActorKind::Admin,
            chalk_core::models::asset::AssetEventType::MovedOu,
        ),
    )
    .await
    .unwrap();
    repo.finish_commit("cs-4").await.unwrap();

    assert_eq!(
        repo.rearm_failed_items("cs-4").await.unwrap(),
        0,
        "nothing to re-arm — the write already landed"
    );
    assert_eq!(repo.item_status_counts("cs-4").await.unwrap().applied, 1);
}

/// Long values are cut on character boundaries. An asset tag with an accent
/// sliced mid-codepoint panics, and a panic while *listing* a failed change set
/// is the worst possible moment for one.
#[test]
fn truncation_never_splits_a_character() {
    assert_eq!(truncate("short", 20), "short");
    assert_eq!(truncate("exactlyten", 10), "exactlyten");
    assert_eq!(truncate("abcdefghijk", 10), "abcdefghi…");
    // Multi-byte throughout, cut in the middle.
    assert_eq!(truncate("ééééééééééé", 4), "ééé…");
    // A device tag as a district might actually write it.
    assert_eq!(truncate("CB—LIBRARY—MOBILE—CART—07", 12), "CB—LIBRARY—…");
}
