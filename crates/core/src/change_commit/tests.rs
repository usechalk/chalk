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
use crate::models::device_action::{ChangeStatusAction, DeprovisionReason};
use crate::models::org::Org;
use crate::models::user::User;
use crate::remote_write::{RemoteOutcome, RemoteResult, RemoteWriter};
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

/// Without a configured writer, a Google item comes back **failed with a
/// reason**, not left pending forever.
///
/// This changed when write-back landed, and deliberately. "Still waiting on a
/// capability" was honest while there was no capability at all; now the
/// capability exists and the honest answer is "this deployment has not set it
/// up". A pending item nobody can explain is the worse of the two.
#[tokio::test]
async fn without_a_writer_google_items_fail_with_a_reason_rather_than_hanging() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    google_move_set(&f, "cs-1", &[("a", "g-a")]).await;

    let outcome = commit_change_set(&f.sets, "cs-1", "h", 1, "admin")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.failed, 1);
    assert_eq!(outcome.applied, 0);

    let item = &items(&f, "cs-1").await[0];
    assert_eq!(item.status, ChangeSetItemStatus::Failed);
    assert!(
        item.error
            .as_deref()
            .unwrap_or_default()
            .contains("not configured"),
        "the operator has to be told why: {:?}",
        item.error
    );
}

// ---------------------------------------------------------------------------
// The remote pass
// ---------------------------------------------------------------------------

/// A writer that answers however a test needs, and records what it was asked.
struct FakeWriter {
    /// device id -> the answer for it. Absent means Google said nothing.
    answers: std::collections::HashMap<String, RemoteResult>,
    calls: std::sync::Mutex<Vec<(String, Vec<String>)>>,
}

impl FakeWriter {
    fn new() -> Self {
        Self {
            answers: std::collections::HashMap::new(),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn answering(mut self, device: &str, result: RemoteResult) -> Self {
        self.answers.insert(device.to_string(), result);
        self
    }

    fn record(&self, target: &str, ids: &[String]) -> Vec<RemoteOutcome> {
        self.calls
            .lock()
            .unwrap()
            .push((target.to_string(), ids.to_vec()));
        ids.iter()
            .filter_map(|id| {
                self.answers.get(id).map(|r| RemoteOutcome {
                    device_id: id.clone(),
                    result: r.clone(),
                })
            })
            .collect()
    }

    fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl RemoteWriter for FakeWriter {
    async fn move_to_ou(&self, org_unit_path: &str, device_ids: &[String]) -> Vec<RemoteOutcome> {
        self.record(org_unit_path, device_ids)
    }

    async fn change_status(
        &self,
        action: ChangeStatusAction,
        device_ids: &[String],
    ) -> Vec<RemoteOutcome> {
        self.record(&action.as_item_value(), device_ids)
    }
}

/// A change set of OU moves, one item per (asset, google device id).
async fn google_move_set(f: &Fx, id: &str, devices: &[(&str, &str)]) {
    let items: Vec<NewChangeSetItem> = devices
        .iter()
        .map(|(asset, gid)| NewChangeSetItem {
            asset_id: Some((*asset).into()),
            target_ref: Some(format!("CB-{asset}")),
            google_device_id: (!gid.is_empty()).then(|| (*gid).to_string()),
            op: ChangeSetOp::MoveOu,
            field: Some("org_unit_path".into()),
            old_value: Some("/Students".into()),
            new_value: Some("/Students/HS".into()),
            remote_target: RemoteTarget::Google,
        })
        .collect();
    let set = ChangeSet::planned(
        id,
        ChangeSetKind::GoogleWriteback,
        "admin",
        "h",
        items.len() as i64,
    );
    f.sets.create_change_set(&set, &items).await.unwrap();
}

async fn items(f: &Fx, id: &str) -> Vec<crate::models::change_set::ChangeSetItem> {
    f.sets
        .list_items(id, None, PageRequest::new(50, 0))
        .await
        .unwrap()
        .items
}

async fn commit_with(
    f: &Fx,
    writer: Arc<dyn RemoteWriter>,
    id: &str,
    expected: i64,
) -> CommitOutcome {
    commit_change_set_with(&f.sets, &writer, id, "h", expected, "admin")
        .await
        .unwrap()
        .unwrap()
}

/// An applied remote write also updates Chalk's own copy and writes history,
/// so the inventory does not disagree with the tenant until the next sync.
#[tokio::test]
async fn an_applied_remote_write_mirrors_locally_and_is_audited() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    google_move_set(&f, "cs-1", &[("a", "g-a")]).await;

    let writer = Arc::new(FakeWriter::new().answering("g-a", RemoteResult::Applied));
    let outcome = commit_with(&f, writer, "cs-1", 1).await;
    assert_eq!(outcome.applied, 1);

    let asset = f.assets.get_asset("a").await.unwrap().unwrap();
    assert_eq!(
        asset.org_unit_path.as_deref(),
        Some("/Students/HS"),
        "Chalk mirrors what Google now holds"
    );

    let events = f
        .repo
        .list_events(
            &AssetEventFilter {
                asset_id: Some("a".into()),
                ..Default::default()
            },
            PageRequest::new(10, 0),
        )
        .await
        .unwrap();
    let payload = events.items[0].payload.as_ref().unwrap();
    assert_eq!(events.items[0].event_type, AssetEventType::MovedOu);
    assert_eq!(payload["target"], "google");
}

/// Five hundred devices going to the same OU are one call, not five hundred.
/// Grouping is the whole reason the remote pass is separate from the local one.
#[tokio::test]
async fn devices_bound_for_the_same_place_go_out_in_one_call() {
    let f = fixture().await;
    let mut devices = Vec::new();
    for i in 0..5 {
        let id = format!("d{i}");
        device(&f, &id, AssetStatus::Active, None).await;
        devices.push((id, format!("g-{i}")));
    }
    let refs: Vec<(&str, &str)> = devices
        .iter()
        .map(|(a, g)| (a.as_str(), g.as_str()))
        .collect();
    google_move_set(&f, "cs-1", &refs).await;

    let mut writer = FakeWriter::new();
    for (_, g) in &devices {
        writer = writer.answering(g, RemoteResult::Applied);
    }
    let writer = Arc::new(writer);
    let outcome = commit_with(&f, writer.clone(), "cs-1", 5).await;

    assert_eq!(outcome.applied, 5);
    let calls = writer.calls();
    assert_eq!(calls.len(), 1, "one grouped call, not one per device");
    assert_eq!(calls[0].0, "/Students/HS");
    assert_eq!(calls[0].1.len(), 5);
}

/// A refusal and an unknown outcome land as different item states. This is the
/// distinction the whole third state exists for: the UI can say "may have
/// applied — verify" instead of telling an operator it definitely did not.
#[tokio::test]
async fn a_refusal_and_a_timeout_are_recorded_differently() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    device(&f, "b", AssetStatus::Active, None).await;
    google_move_set(&f, "cs-1", &[("a", "g-a"), ("b", "g-b")]).await;

    let writer = Arc::new(
        FakeWriter::new()
            .answering(
                "g-a",
                RemoteResult::Failed {
                    message: "forbidden".into(),
                },
            )
            .answering(
                "g-b",
                RemoteResult::Indeterminate {
                    detail: "chunk timed out".into(),
                },
            ),
    );
    let outcome = commit_with(&f, writer, "cs-1", 2).await;
    assert_eq!(outcome.failed, 1);
    assert_eq!(outcome.indeterminate, 1);
    assert_eq!(outcome.applied, 0);

    let by_device: std::collections::HashMap<_, _> = items(&f, "cs-1")
        .await
        .into_iter()
        .map(|i| (i.google_device_id.clone().unwrap(), i))
        .collect();
    assert_eq!(by_device["g-a"].status, ChangeSetItemStatus::Failed);
    assert_eq!(by_device["g-b"].status, ChangeSetItemStatus::Indeterminate);
    assert!(by_device["g-b"]
        .error
        .as_deref()
        .unwrap()
        .contains("timed out"));

    // Neither device was mirrored locally — only a confirmed write is.
    for id in ["a", "b"] {
        assert_eq!(
            f.assets.get_asset(id).await.unwrap().unwrap().org_unit_path,
            None
        );
    }
}

/// Silence is never consent for a write. A device Google did not mention is
/// indeterminate, not applied.
#[tokio::test]
async fn a_device_google_said_nothing_about_is_not_assumed_applied() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    google_move_set(&f, "cs-1", &[("a", "g-a")]).await;

    // The fake answers for nobody.
    let outcome = commit_with(&f, Arc::new(FakeWriter::new()), "cs-1", 1).await;
    assert_eq!(outcome.indeterminate, 1);
    assert_eq!(outcome.applied, 0);
    assert_eq!(
        f.assets
            .get_asset("a")
            .await
            .unwrap()
            .unwrap()
            .org_unit_path,
        None
    );
}

/// A device Chalk created itself has no Google device id, so Google has no way
/// to address it. Reported rather than silently dropped, and never sent.
#[tokio::test]
async fn an_item_with_no_google_device_id_is_failed_and_never_sent() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    google_move_set(&f, "cs-1", &[("a", "")]).await;

    let writer = Arc::new(FakeWriter::new());
    let outcome = commit_with(&f, writer.clone(), "cs-1", 1).await;

    assert_eq!(outcome.failed, 1);
    assert!(writer.calls().is_empty(), "nothing may be sent for it");
    assert!(items(&f, "cs-1").await[0]
        .error
        .as_deref()
        .unwrap()
        .contains("never synced"));
}

/// Two different target OUs are two calls. Grouping must key on what will be
/// sent, or devices bound for one OU end up in another's request.
#[tokio::test]
async fn devices_bound_for_different_org_units_are_not_merged() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    device(&f, "b", AssetStatus::Active, None).await;

    let set = ChangeSet::planned("cs-1", ChangeSetKind::GoogleWriteback, "admin", "h", 2);
    f.sets
        .create_change_set(
            &set,
            &[
                NewChangeSetItem {
                    asset_id: Some("a".into()),
                    target_ref: Some("CB-a".into()),
                    google_device_id: Some("g-a".into()),
                    op: ChangeSetOp::MoveOu,
                    field: Some("org_unit_path".into()),
                    old_value: None,
                    new_value: Some("/Students/HS".into()),
                    remote_target: RemoteTarget::Google,
                },
                NewChangeSetItem {
                    asset_id: Some("b".into()),
                    target_ref: Some("CB-b".into()),
                    google_device_id: Some("g-b".into()),
                    op: ChangeSetOp::MoveOu,
                    field: Some("org_unit_path".into()),
                    old_value: None,
                    new_value: Some("/Staff".into()),
                    remote_target: RemoteTarget::Google,
                },
            ],
        )
        .await
        .unwrap();

    let writer = Arc::new(
        FakeWriter::new()
            .answering("g-a", RemoteResult::Applied)
            .answering("g-b", RemoteResult::Applied),
    );
    commit_with(&f, writer.clone(), "cs-1", 2).await;

    let mut calls = writer.calls();
    calls.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(calls.len(), 2, "one call per destination");
    assert_eq!(calls[0].0, "/Staff");
    assert_eq!(calls[0].1, vec!["g-b"]);
    assert_eq!(calls[1].0, "/Students/HS");
    assert_eq!(calls[1].1, vec!["g-a"]);
}

/// A deprovision carries its reason all the way to the writer, and mirrors
/// locally as retired.
#[tokio::test]
async fn a_deprovision_reaches_the_writer_with_its_reason() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;

    let action = ChangeStatusAction::Deprovision(DeprovisionReason::RetiringDevice);
    let set = ChangeSet::planned("cs-1", ChangeSetKind::GoogleWriteback, "admin", "h", 1);
    f.sets
        .create_change_set(
            &set,
            &[NewChangeSetItem {
                asset_id: Some("a".into()),
                target_ref: Some("CB-a".into()),
                google_device_id: Some("g-a".into()),
                op: ChangeSetOp::ChangeStatus,
                field: Some("google_status".into()),
                old_value: Some("active".into()),
                new_value: Some(action.as_item_value()),
                remote_target: RemoteTarget::Google,
            }],
        )
        .await
        .unwrap();

    let writer = Arc::new(FakeWriter::new().answering("g-a", RemoteResult::Applied));
    let outcome = commit_with(&f, writer.clone(), "cs-1", 1).await;
    assert_eq!(outcome.applied, 1);
    assert_eq!(
        writer.calls()[0].0,
        "deprovision:retiring_device",
        "the reason Google requires must survive the round trip"
    );
    assert_eq!(
        f.assets.get_asset("a").await.unwrap().unwrap().status,
        AssetStatus::Retired
    );
}

/// A hand-edited action that is not a real action fails the items rather than
/// sending something Google will reject — and nothing is sent at all.
#[tokio::test]
async fn an_unreadable_action_fails_without_calling_google() {
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
                op: ChangeSetOp::ChangeStatus,
                field: Some("google_status".into()),
                old_value: None,
                new_value: Some("deprovision:whenever_i_feel_like_it".into()),
                remote_target: RemoteTarget::Google,
            }],
        )
        .await
        .unwrap();

    let writer = Arc::new(FakeWriter::new());
    let outcome = commit_with(&f, writer.clone(), "cs-1", 1).await;
    assert_eq!(outcome.failed, 1);
    assert!(writer.calls().is_empty(), "nothing may be sent");
    assert_eq!(
        f.assets.get_asset("a").await.unwrap().unwrap().status,
        AssetStatus::Active
    );
}

/// Local items still apply even when the remote pass has work to do, and they
/// apply first — a failure talking to Google must not strand edits that were
/// already safe to make.
#[tokio::test]
async fn local_items_apply_alongside_remote_ones() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active, None).await;
    device(&f, "b", AssetStatus::Active, None).await;

    let set = ChangeSet::planned("cs-1", ChangeSetKind::GoogleWriteback, "admin", "h", 2);
    f.sets
        .create_change_set(
            &set,
            &[
                NewChangeSetItem {
                    asset_id: Some("a".into()),
                    target_ref: Some("CB-a".into()),
                    google_device_id: Some("g-a".into()),
                    op: ChangeSetOp::MoveOu,
                    field: Some("org_unit_path".into()),
                    old_value: None,
                    new_value: Some("/Students/HS".into()),
                    remote_target: RemoteTarget::Google,
                },
                NewChangeSetItem {
                    asset_id: Some("b".into()),
                    target_ref: Some("CB-b".into()),
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

    // Google refuses; the local edit must still have landed.
    let writer = Arc::new(FakeWriter::new().answering(
        "g-a",
        RemoteResult::Failed {
            message: "forbidden".into(),
        },
    ));
    let outcome = commit_with(&f, writer, "cs-1", 2).await;
    assert_eq!(outcome.applied, 1, "the local one");
    assert_eq!(outcome.failed, 1, "the remote one");
    assert_eq!(
        f.assets.get_asset("b").await.unwrap().unwrap().status,
        AssetStatus::Repair
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
