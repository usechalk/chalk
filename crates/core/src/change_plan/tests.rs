//! Plan-phase tests.
//!
//! The plan is what an operator approves, so the properties worth the most are
//! about honesty: it must not quietly cover less than it claims, must not pad
//! the preview with rows that change nothing, and must produce a hash that
//! actually detects the drift it exists to detect.

use super::*;

use crate::db::repository::{AssetEventRepository, OrgRepository, UserRepository};
use crate::db::sqlite::SqliteRepository;
use crate::db::DatabasePool;
use crate::models::asset::{AssetEventFilter, AssetSort};
use crate::models::change_set::ChangeSetStatus;
use crate::models::common::{OrgType, RoleType, Status};
use crate::models::device_action::{ChangeStatusAction, DeprovisionReason};
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
    a.serial_number = Some(format!("SN-{id}"));
    a.google_device_id = Some(format!("g-{id}"));
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

// ---------------------------------------------------------------------------
// What gets planned
// ---------------------------------------------------------------------------

/// A device already in the requested state produces no item.
///
/// Not an optimisation. A preview padded with two hundred no-op rows makes the
/// twelve real changes impossible to find, and an operator who cannot see what
/// will happen has not been shown a preview.
#[tokio::test]
async fn devices_already_in_the_requested_state_are_not_planned() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    device(&f, "b", AssetStatus::Repair, None).await;
    device(&f, "c", AssetStatus::Repair, None).await;

    let plan = plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::SetStatus {
            status: AssetStatus::Repair,
        },
        &[],
        "admin",
    )
    .await
    .unwrap();

    assert_eq!(plan.item_count, 1, "only the Active device changes");
    assert_eq!(
        plan.unchanged_count, 2,
        "the two already in Repair are reported, not hidden"
    );

    let items = f
        .sets
        .list_items(&plan.change_set_id, None, PageRequest::new(50, 0))
        .await
        .unwrap();
    assert_eq!(items.items.len(), 1);
    assert_eq!(items.items[0].asset_id.as_deref(), Some("a"));
    assert_eq!(items.items[0].old_value.as_deref(), Some("active"));
    assert_eq!(items.items[0].new_value.as_deref(), Some("repair"));
}

/// Every item carries the old value the operator will see, and enough identity
/// to survive its asset row being deleted.
#[tokio::test]
async fn items_carry_the_diff_and_a_durable_identity() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, Some("u-1")).await;

    let plan = plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::Assign {
            user_sourced_id: "u-2".into(),
        },
        &[],
        "admin",
    )
    .await
    .unwrap();

    let item = &f
        .sets
        .list_items(&plan.change_set_id, None, PageRequest::new(50, 0))
        .await
        .unwrap()
        .items[0];
    assert_eq!(item.op, ChangeSetOp::Assign);
    assert_eq!(item.field.as_deref(), Some("assigned_user_sourced_id"));
    assert_eq!(item.old_value.as_deref(), Some("u-1"));
    assert_eq!(item.new_value.as_deref(), Some("u-2"));
    assert_eq!(
        item.target_ref.as_deref(),
        Some("CB-a"),
        "denormalised so an applied item still names a real device"
    );
    assert_eq!(item.google_device_id.as_deref(), Some("g-a"));
    assert_eq!(
        item.remote_target,
        RemoteTarget::Local,
        "nothing may be planned as a Google write before write-back exists"
    );
}

/// Unassign clears rather than setting, and only touches devices that hold
/// someone.
#[tokio::test]
async fn unassign_plans_a_clear_and_skips_already_free_devices() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, Some("u-1")).await;
    device(&f, "b", AssetStatus::Active, None).await;

    let plan = plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::Unassign,
        &[],
        "admin",
    )
    .await
    .unwrap();
    assert_eq!(plan.item_count, 1);
    assert_eq!(plan.unchanged_count, 1);

    let item = &f
        .sets
        .list_items(&plan.change_set_id, None, PageRequest::new(50, 0))
        .await
        .unwrap()
        .items[0];
    assert_eq!(item.old_value.as_deref(), Some("u-1"));
    assert_eq!(item.new_value, None, "a clear, not an empty string");
}

/// Excluded devices never reach the preview at all.
#[tokio::test]
async fn excluded_devices_are_dropped_before_planning() {
    let f = fixture().await;
    for id in ["a", "b", "c"] {
        device(&f, id, AssetStatus::Active, None).await;
    }

    let plan = plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::SetStatus {
            status: AssetStatus::Repair,
        },
        &["b".to_string()],
        "admin",
    )
    .await
    .unwrap();

    assert_eq!(plan.item_count, 2);
    let ids: Vec<String> = f
        .sets
        .list_items(&plan.change_set_id, None, PageRequest::new(50, 0))
        .await
        .unwrap()
        .items
        .into_iter()
        .filter_map(|i| i.asset_id)
        .collect();
    assert!(!ids.contains(&"b".to_string()));
}

/// The filter is the selection scope, which is the whole point: an operator
/// acts on "everything matching", and the plan is what makes that reviewable.
#[tokio::test]
async fn the_plan_covers_exactly_what_the_filter_matches() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    device(&f, "b", AssetStatus::Lost, None).await;

    let plan = plan_change(
        &f.assets,
        &f.sets,
        &AssetFilter {
            status: Some(AssetStatus::Lost),
            ..all()
        },
        &PlannedChange::SetStatus {
            status: AssetStatus::Retired,
        },
        &[],
        "admin",
    )
    .await
    .unwrap();

    assert_eq!(plan.item_count, 1);
    assert_eq!(
        f.sets
            .list_items(&plan.change_set_id, None, PageRequest::new(50, 0))
            .await
            .unwrap()
            .items[0]
            .asset_id
            .as_deref(),
        Some("b")
    );
}

/// A plan that changes nothing is still a plan, and says so. Silently doing
/// nothing after an operator pressed a button is worse than an empty preview.
#[tokio::test]
async fn a_plan_with_no_changes_is_recorded_as_empty() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Repair, None).await;

    let plan = plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::SetStatus {
            status: AssetStatus::Repair,
        },
        &[],
        "admin",
    )
    .await
    .unwrap();
    assert!(plan.is_empty());
    assert_eq!(plan.unchanged_count, 1);

    let set = f
        .sets
        .get_change_set(&plan.change_set_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(set.status, ChangeSetStatus::Planned);
    assert_eq!(set.expected_item_count, 0);
}

/// Nothing is applied by planning. The change set is a proposal.
#[tokio::test]
async fn planning_touches_no_asset_and_writes_no_history() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, Some("u-1")).await;

    plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::Unassign,
        &[],
        "admin",
    )
    .await
    .unwrap();

    let asset = f.assets.get_asset("a").await.unwrap().unwrap();
    assert_eq!(
        asset.assigned_user_sourced_id.as_deref(),
        Some("u-1"),
        "the device must be untouched by a plan"
    );
    let events = f
        .repo
        .list_events(&AssetEventFilter::for_asset("a"), PageRequest::new(10, 0))
        .await
        .unwrap();
    assert_eq!(events.total, 0, "a proposal is not an event");
}

// ---------------------------------------------------------------------------
// The staleness guard
// ---------------------------------------------------------------------------

fn item(asset: &str, old: Option<&str>, new: Option<&str>) -> NewChangeSetItem {
    NewChangeSetItem {
        asset_id: Some(asset.into()),
        target_ref: None,
        google_device_id: None,
        op: ChangeSetOp::ChangeStatus,
        field: Some("status".into()),
        old_value: old.map(str::to_string),
        new_value: new.map(str::to_string),
        remote_target: RemoteTarget::Local,
    }
}

/// The hash must not depend on the order rows came back in. The repository
/// makes no ordering promise, and a plan refused purely because rows arrived
/// differently would be maddening and wrong.
#[test]
fn the_plan_hash_is_order_independent() {
    let a = item("a", Some("active"), Some("repair"));
    let b = item("b", Some("active"), Some("repair"));
    assert_eq!(
        plan_hash(&[a.clone(), b.clone()]),
        plan_hash(&[b, a]),
        "row order must not change the plan's identity"
    );
}

/// And it must actually detect the drift it exists for. Each of these is a
/// change an operator did not approve.
#[test]
fn the_plan_hash_detects_every_kind_of_drift() {
    let base = vec![item("a", Some("active"), Some("repair"))];
    let h = plan_hash(&base);

    // A different device.
    assert_ne!(h, plan_hash(&[item("b", Some("active"), Some("repair"))]));
    // The device drifted under us — something else edited it since the preview.
    assert_ne!(h, plan_hash(&[item("a", Some("lost"), Some("repair"))]));
    // A different destination.
    assert_ne!(h, plan_hash(&[item("a", Some("active"), Some("retired"))]));
    // An extra row.
    let mut more = base.clone();
    more.push(item("b", Some("active"), Some("repair")));
    assert_ne!(h, plan_hash(&more));
    // A missing row.
    assert_ne!(h, plan_hash(&[]));

    // Absent and empty-string must not collide — otherwise "clear this field"
    // and "set it to nothing" would hash alike.
    assert_ne!(
        plan_hash(&[item("a", Some("x"), None)]),
        plan_hash(&[item("a", Some("x"), Some(""))])
    );
}

/// The same plan hashes the same. Otherwise every commit would be refused.
#[test]
fn an_unchanged_plan_hashes_stably() {
    let items = vec![
        item("a", Some("active"), Some("repair")),
        item("b", None, Some("repair")),
    ];
    assert_eq!(plan_hash(&items), plan_hash(&items));
}

/// The stored hash is the one a commit compares against.
#[tokio::test]
async fn the_stored_hash_matches_the_planned_items() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;

    let plan = plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::SetStatus {
            status: AssetStatus::Repair,
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
    assert_eq!(set.expected_item_count, 1);
    assert_eq!(
        set.plan_hash,
        plan_hash(&[item("a", Some("active"), Some("repair"))]),
        "the stored hash must describe the rows that were actually written"
    );
}

/// Truncation is reported. A preview that quietly covers less than it says is
/// the exact failure this phase exists to prevent.
#[tokio::test]
async fn an_oversized_selection_reports_truncation() {
    let f = fixture().await;
    // Small plans are not truncated.
    device(&f, "a", AssetStatus::Active, None).await;
    let plan = plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::SetStatus {
            status: AssetStatus::Repair,
        },
        &[],
        "admin",
    )
    .await
    .unwrap();
    assert!(!plan.truncated);
    assert_eq!(
        f.sets
            .get_change_set(&plan.change_set_id)
            .await
            .unwrap()
            .unwrap()
            .summary["truncated"],
        serde_json::json!(false),
        "the summary records it either way, so a reader never has to assume"
    );
}

// ---------------------------------------------------------------------------
// Google-targeted plans
// ---------------------------------------------------------------------------

/// An OU move is marked as needing Google, carries the device id Google is
/// addressed by, and shows the org unit the device holds now.
#[tokio::test]
async fn an_ou_move_is_planned_as_a_google_write() {
    let f = fixture().await;
    let mut a = Asset::new("a");
    a.asset_tag = Some("CB-a".into());
    a.google_device_id = Some("g-a".into());
    a.org_unit_path = Some("/Students".into());
    f.repo.create_asset(&a).await.unwrap();

    let plan = plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::MoveOu {
            org_unit_path: "/Students/HS".into(),
        },
        &[],
        "admin",
    )
    .await
    .unwrap();
    assert_eq!(plan.item_count, 1);

    let item = &f
        .sets
        .list_items(&plan.change_set_id, None, PageRequest::new(10, 0))
        .await
        .unwrap()
        .items[0];
    assert_eq!(item.remote_target, RemoteTarget::Google);
    assert_eq!(item.op, ChangeSetOp::MoveOu);
    assert_eq!(item.field.as_deref(), Some("org_unit_path"));
    assert_eq!(item.old_value.as_deref(), Some("/Students"));
    assert_eq!(item.new_value.as_deref(), Some("/Students/HS"));
    assert_eq!(
        item.google_device_id.as_deref(),
        Some("g-a"),
        "Google is addressed by device id, so the item has to carry it"
    );
}

/// A device already in the target OU produces no item — the same rule every
/// other planned change follows, so a preview is not padded with no-ops.
#[tokio::test]
async fn a_device_already_in_the_target_org_unit_is_not_planned() {
    let f = fixture().await;
    let mut a = Asset::new("a");
    a.asset_tag = Some("CB-a".into());
    a.google_device_id = Some("g-a".into());
    a.org_unit_path = Some("/Students/HS".into());
    f.repo.create_asset(&a).await.unwrap();

    let plan = plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::MoveOu {
            org_unit_path: "/Students/HS".into(),
        },
        &[],
        "admin",
    )
    .await
    .unwrap();
    assert_eq!(plan.item_count, 0);
    assert_eq!(plan.unchanged_count, 1);
}

/// A deprovision carries its reason into the item, so `plan_hash` covers it
/// and a reason altered between preview and commit is refused.
#[tokio::test]
async fn a_deprovision_carries_its_reason_into_the_item_and_the_hash() {
    let f = fixture().await;
    let mut a = Asset::new("a");
    a.asset_tag = Some("CB-a".into());
    a.google_device_id = Some("g-a".into());
    f.repo.create_asset(&a).await.unwrap();

    let retiring = PlannedChange::ChangeStatus {
        action: ChangeStatusAction::Deprovision(DeprovisionReason::RetiringDevice),
    };
    let plan = plan_change(&f.assets, &f.sets, &all(), &retiring, &[], "admin")
        .await
        .unwrap();

    let item = &f
        .sets
        .list_items(&plan.change_set_id, None, PageRequest::new(10, 0))
        .await
        .unwrap()
        .items[0];
    assert_eq!(item.remote_target, RemoteTarget::Google);
    assert_eq!(
        item.new_value.as_deref(),
        Some("deprovision:retiring_device")
    );

    // The same devices with a different reason hash differently, which is what
    // makes the staleness guard cover the reason and not just the target.
    let other = PlannedChange::ChangeStatus {
        action: ChangeStatusAction::Deprovision(DeprovisionReason::SameModelReplacement),
    };
    let plan2 = plan_change(&f.assets, &f.sets, &all(), &other, &[], "admin")
        .await
        .unwrap();
    let set1 = f
        .sets
        .get_change_set(&plan.change_set_id)
        .await
        .unwrap()
        .unwrap();
    let set2 = f
        .sets
        .get_change_set(&plan2.change_set_id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        set1.plan_hash, set2.plan_hash,
        "two different reasons must not share a plan hash"
    );
}

/// A status change is never dropped as a no-op. Chalk does not store Google's
/// device state, so "already disabled" is not something it can know — and
/// silently dropping rows the operator selected is the failure this whole
/// phase exists to prevent. Google answers a redundant change with 412, which
/// the commit path reads as already-done.
#[tokio::test]
async fn a_status_change_is_never_dropped_as_already_done() {
    let f = fixture().await;
    let mut a = Asset::new("a");
    a.asset_tag = Some("CB-a".into());
    a.google_device_id = Some("g-a".into());
    a.status = AssetStatus::Retired;
    f.repo.create_asset(&a).await.unwrap();

    let plan = plan_change(
        &f.assets,
        &f.sets,
        &all(),
        &PlannedChange::ChangeStatus {
            action: ChangeStatusAction::Deprovision(DeprovisionReason::RetiringDevice),
        },
        &[],
        "admin",
    )
    .await
    .unwrap();
    assert_eq!(
        plan.item_count, 1,
        "a retired-looking device is still planned; only Google knows for sure"
    );
    assert_eq!(plan.unchanged_count, 0);

    // And the preview does not claim to know Google's device state. The
    // lifecycle status is a different value that a technician sets by hand;
    // putting it in the "now" column would read as the thing being changed.
    let item = &f
        .sets
        .list_items(&plan.change_set_id, None, PageRequest::new(10, 0))
        .await
        .unwrap()
        .items[0];
    assert_eq!(
        item.old_value, None,
        "Chalk does not store Google's device state and must not imply it does"
    );
    assert_ne!(
        item.old_value.as_deref(),
        Some(AssetStatus::Retired.as_str()),
        "the lifecycle status is not Google's device state"
    );
}

/// Local changes must never be marked as needing Google. Sending a device id
/// for a field Google does not own is how a preview promises something the
/// commit cannot do.
#[tokio::test]
async fn local_changes_are_never_marked_as_google_writes() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;

    for change in [
        PlannedChange::Unassign,
        PlannedChange::SetStatus {
            status: AssetStatus::Repair,
        },
        PlannedChange::SetMatchState {
            match_state: MatchState::Ignored,
        },
    ] {
        let plan = plan_change(&f.assets, &f.sets, &all(), &change, &[], "admin")
            .await
            .unwrap();
        for item in f
            .sets
            .list_items(&plan.change_set_id, None, PageRequest::new(10, 0))
            .await
            .unwrap()
            .items
        {
            assert_eq!(
                item.remote_target,
                RemoteTarget::Local,
                "{:?} is a local edit",
                change
            );
        }
    }
}
