//! Commit-phase tests.
//!
//! The guarantee being tested is that nothing is applied which the operator did
//! not approve, and that what *is* applied leaves the device, its history and
//! the item's status agreeing with each other.

use super::*;

use crate::change_plan::{plan_change, PlannedChange};
use crate::db::repository::{AssetEventRepository, AssetRepository, OrgRepository, UserRepository};
use crate::db::sqlite::SqliteRepository;
use crate::db::DatabasePool;
use crate::models::asset::{Asset, AssetEventFilter, AssetEventType, AssetFilter, AssetSort};
use crate::models::change_set::ChangeSetStatus;
use crate::models::common::{OrgType, RoleType, Status};
use crate::models::org::Org;
use crate::models::user::User;
use chrono::{TimeZone, Utc};

struct Fx {
    assets: Arc<dyn AssetRepository>,
    sets: Arc<dyn ChangeSetRepository>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    repo.upsert_org(&Org {
        sourced_id: "org-1".into(),
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
    for sid in ["u-1", "u-2"] {
        repo.upsert_user(&User {
            sourced_id: sid.into(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            username: sid.into(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "Given".into(),
            family_name: "Family".into(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some(format!("{sid}@example.edu")),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec![],
            grades: vec![],
        })
        .await
        .unwrap();
    }
    Fx {
        assets: repo.clone(),
        sets: repo.clone(),
        repo,
    }
}

async fn device(f: &Fx, id: &str, status: AssetStatus, assigned: Option<&str>) {
    let mut a = Asset::new(id);
    a.asset_tag = Some(format!("CB-{id}"));
    a.status = status;
    a.assigned_user_sourced_id = assigned.map(str::to_string);
    f.repo.create_asset(&a).await.unwrap();
}

fn all() -> AssetFilter {
    AssetFilter {
        sort: AssetSort::AssetTag,
        ..Default::default()
    }
}

async fn plan_status(f: &Fx, status: AssetStatus) -> (String, String, i64) {
    let plan = plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::SetStatus { status },
        &[],
        "admin",
    )
    .await
    .unwrap();
    let set = f
        .sets
        .get_change_set(&plan.change_set_id)
        .await
        .unwrap()
        .unwrap();
    (set.id, set.plan_hash, set.expected_item_count)
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

/// The device changes, its history records the change, and the item is marked
/// applied — all three, or the commit is not doing its job.
#[tokio::test]
async fn committing_changes_the_device_and_records_why() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    let (id, hash, count) = plan_status(&f, AssetStatus::Repair).await;

    let outcome = commit_change_set(&f.sets, &id, &hash, count, "admin")
        .await
        .unwrap()
        .expect("the plan is fresh, so the commit is allowed");
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.failed, 0);

    assert_eq!(
        f.assets.get_asset("a").await.unwrap().unwrap().status,
        AssetStatus::Repair
    );

    let events = f
        .repo
        .list_events(&AssetEventFilter::for_asset("a"), PageRequest::new(10, 0))
        .await
        .unwrap();
    assert_eq!(events.total, 1);
    let e = &events.items[0];
    assert_eq!(e.event_type, AssetEventType::StatusChanged);
    let payload = e.payload.as_ref().unwrap();
    assert_eq!(payload["old"], "active");
    assert_eq!(payload["new"], "repair");
    assert_eq!(payload["via"], "bulk_edit");
    assert_eq!(
        payload["changeSetId"], id,
        "the history points back at the change set that did it"
    );

    let set = f.sets.get_change_set(&id).await.unwrap().unwrap();
    assert_eq!(set.status, ChangeSetStatus::Committed);
    assert!(set.committed_at.is_some());
}

/// An assignment made by hand outranks the matcher and must survive the next
/// sync, which refuses to touch `manual` rows.
#[tokio::test]
async fn a_bulk_assignment_marks_the_device_manual() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;

    let plan = plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::Assign {
            user_sourced_id: "u-1".into(),
        },
        &[],
        "admin",
    )
    .await
    .unwrap();
    let set = f
        .sets
        .get_change_set(&plan.change_set_id)
        .await
        .unwrap()
        .unwrap();
    commit_change_set(
        &f.sets,
        &set.id,
        &set.plan_hash,
        set.expected_item_count,
        "admin",
    )
    .await
    .unwrap()
    .unwrap();

    let asset = f.assets.get_asset("a").await.unwrap().unwrap();
    assert_eq!(asset.assigned_user_sourced_id.as_deref(), Some("u-1"));
    assert_eq!(
        asset.match_state,
        MatchState::Manual,
        "a human decision must not be undone by tonight's sync"
    );
}

// ---------------------------------------------------------------------------
// The staleness guard — the reason this phase exists
// ---------------------------------------------------------------------------

/// A device edited between preview and commit invalidates the plan. Applying
/// anyway would write a diff nobody looked at.
#[tokio::test]
async fn a_plan_whose_devices_moved_is_refused() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    device(&f, "b", AssetStatus::Active, None).await;
    let (id, hash, count) = plan_status(&f, AssetStatus::Repair).await;
    assert_eq!(count, 2);

    // Someone commits with a stale expectation — the preview said two rows,
    // and the caller claims one.
    let refusal = commit_change_set(&f.sets, &id, &hash, 1, "admin")
        .await
        .unwrap()
        .expect_err("an item count that disagrees with the plan must be refused");
    assert!(matches!(refusal, CommitRefusal::Stale { .. }));

    // Nothing was applied.
    for dev in ["a", "b"] {
        assert_eq!(
            f.assets.get_asset(dev).await.unwrap().unwrap().status,
            AssetStatus::Active,
            "{dev} was written despite a refused commit"
        );
    }
    assert_eq!(
        f.sets.get_change_set(&id).await.unwrap().unwrap().status,
        ChangeSetStatus::Planned,
        "a refused commit must leave the set re-committable"
    );
}

/// A hash that does not match is refused for the same reason.
#[tokio::test]
async fn a_plan_with_a_different_hash_is_refused() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    let (id, _hash, count) = plan_status(&f, AssetStatus::Repair).await;

    let refusal = commit_change_set(&f.sets, &id, "not-the-hash", count, "admin")
        .await
        .unwrap()
        .expect_err("a mismatched plan hash must be refused");
    assert!(matches!(refusal, CommitRefusal::Stale { .. }));
    assert_eq!(
        f.assets.get_asset("a").await.unwrap().unwrap().status,
        AssetStatus::Active
    );
}

/// The claim is conditional, so committing twice applies once. Otherwise a
/// double-clicked button would write everything twice.
#[tokio::test]
async fn committing_twice_applies_once() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    let (id, hash, count) = plan_status(&f, AssetStatus::Repair).await;

    let first = commit_change_set(&f.sets, &id, &hash, count, "admin")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.applied, 1);

    let second = commit_change_set(&f.sets, &id, &hash, count, "admin")
        .await
        .unwrap()
        .expect_err("a committed set cannot be committed again");
    assert!(matches!(second, CommitRefusal::AlreadySettled { .. }));

    let events = f
        .repo
        .list_events(&AssetEventFilter::for_asset("a"), PageRequest::new(10, 0))
        .await
        .unwrap();
    assert_eq!(events.total, 1, "the change was recorded exactly once");
}

#[tokio::test]
async fn committing_a_missing_change_set_is_refused() {
    let f = fixture().await;
    let refusal = commit_change_set(&f.sets, "no-such-set", "h", 0, "admin")
        .await
        .unwrap()
        .expect_err("there is nothing to commit");
    assert_eq!(refusal, CommitRefusal::NotFound);
}

// ---------------------------------------------------------------------------
// Struck-out and deferred items
// ---------------------------------------------------------------------------

/// A row the operator struck out is not applied.
#[tokio::test]
async fn items_struck_out_at_preview_are_not_applied() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    device(&f, "b", AssetStatus::Active, None).await;
    let (id, hash, count) = plan_status(&f, AssetStatus::Repair).await;

    // Strike one out, exactly as the preview does.
    let items = f
        .sets
        .list_items(&id, None, PageRequest::new(50, 0))
        .await
        .unwrap();
    let struck = items
        .items
        .iter()
        .find(|i| i.asset_id.as_deref() == Some("b"))
        .unwrap();
    f.sets
        .mark_item_outcome(struck.id, ChangeSetItemStatus::Skipped, None)
        .await
        .unwrap();

    let outcome = commit_change_set(&f.sets, &id, &hash, count, "admin")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.skipped, 1);

    assert_eq!(
        f.assets.get_asset("a").await.unwrap().unwrap().status,
        AssetStatus::Repair
    );
    assert_eq!(
        f.assets.get_asset("b").await.unwrap().unwrap().status,
        AssetStatus::Active,
        "a struck-out device must be untouched"
    );
}

/// An item needing a Google write is left alone, and stays `pending` rather
/// than being marked failed. Nothing was attempted, so "failed" would be a lie
/// — and the operator can see exactly what is waiting on write-back.
#[tokio::test]
async fn google_items_are_deferred_not_failed() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;

    let set = ChangeSet::planned("cs-1", ChangeSetKind::GoogleWriteback, "admin", "h", 1);
    f.sets
        .create_change_set(
            &set,
            &[NewChangeSetItem {
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
        .await
        .unwrap();

    let outcome = commit_change_set(&f.sets, "cs-1", "h", 1, "admin")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.deferred, 1);
    assert_eq!(outcome.applied, 0);
    assert_eq!(
        outcome.failed, 0,
        "nothing was attempted, so nothing failed"
    );

    let item = &f
        .sets
        .list_items("cs-1", None, PageRequest::new(10, 0))
        .await
        .unwrap()
        .items[0];
    assert_eq!(
        item.status,
        ChangeSetItemStatus::Pending,
        "it is still waiting on a capability, not resolved"
    );
}

/// One unwritable device must not abandon the rest. The failure is recorded
/// against its own item.
#[tokio::test]
async fn one_bad_item_does_not_abandon_the_others() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;

    let set = ChangeSet::planned("cs-2", ChangeSetKind::BulkEdit, "admin", "h", 2);
    f.sets
        .create_change_set(
            &set,
            &[
                // A status the enum does not have — stands in for a row
                // hand-edited in the database.
                NewChangeSetItem {
                    asset_id: Some("a".into()),
                    target_ref: Some("CB-a".into()),
                    google_device_id: None,
                    op: ChangeSetOp::ChangeStatus,
                    field: Some("status".into()),
                    old_value: Some("active".into()),
                    new_value: Some("exploded".into()),
                    remote_target: RemoteTarget::Local,
                },
                NewChangeSetItem {
                    asset_id: Some("a".into()),
                    target_ref: Some("CB-a".into()),
                    google_device_id: None,
                    op: ChangeSetOp::ChangeStatus,
                    field: Some("status".into()),
                    old_value: Some("active".into()),
                    new_value: Some("repair".into()),
                    remote_target: RemoteTarget::Local,
                },
            ],
        )
        .await
        .unwrap();

    let outcome = commit_change_set(&f.sets, "cs-2", "h", 2, "admin")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.failed, 1);
    assert_eq!(outcome.applied, 1, "the good item still applied");

    assert_eq!(
        f.assets.get_asset("a").await.unwrap().unwrap().status,
        AssetStatus::Repair
    );

    let items = f
        .sets
        .list_items("cs-2", None, PageRequest::new(10, 0))
        .await
        .unwrap();
    let failed = items
        .items
        .iter()
        .find(|i| i.status == ChangeSetItemStatus::Failed)
        .expect("the bad item is marked failed");
    assert!(
        failed.error.is_some(),
        "a failed item must say why, or nobody can fix it"
    );
}

use crate::models::change_set::{ChangeSet, ChangeSetKind, NewChangeSetItem};
