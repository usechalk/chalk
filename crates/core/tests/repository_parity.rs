//! Repository parity tests: same operations against SQLite (in-memory) and
//! Postgres (testcontainer) producing matching results. `#[ignore]` because
//! the Postgres half needs Docker — run with `cargo test -- --ignored`.

use chalk_core::db::postgres::PostgresRepository;
use chalk_core::db::repository::ChalkRepository;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::common::{OrgType, RoleType, Status};
use chalk_core::models::org::Org;
use chalk_core::models::sync::UserFilter;
use chalk_core::models::user::User;
use chrono::Utc;
use std::sync::Arc;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

fn sample_org() -> Org {
    Org {
        sourced_id: "org-1".into(),
        status: Status::Active,
        date_last_modified: Utc::now(),
        metadata: None,
        name: "Parity School".into(),
        org_type: OrgType::School,
        identifier: Some("PS-1".into()),
        parent: None,
        children: vec![],
    }
}

fn sample_user() -> User {
    User {
        sourced_id: "u-1".into(),
        status: Status::Active,
        date_last_modified: Utc::now(),
        metadata: None,
        username: "alice".into(),
        enabled_user: true,
        given_name: "Alice".into(),
        family_name: "Anderson".into(),
        middle_name: None,
        role: RoleType::Student,
        identifier: None,
        email: Some("alice@example.com".into()),
        sms: None,
        phone: None,
        agents: vec![],
        orgs: vec!["org-1".into()],
        user_ids: vec![],
        grades: vec!["09".into()],
    }
}

async fn exercise(repo: Arc<dyn ChalkRepository>) -> (Org, User, usize, i64) {
    repo.upsert_org(&sample_org()).await.unwrap();
    repo.upsert_user(&sample_user()).await.unwrap();

    let org = repo.get_org("org-1").await.unwrap().unwrap();
    let user = repo.get_user("u-1").await.unwrap().unwrap();
    let users = repo.list_users(&UserFilter::default()).await.unwrap();
    let audit_id = repo
        .log_admin_action("test.action", Some("parity"), Some("127.0.0.1"))
        .await
        .unwrap();

    (org, user, users.len(), audit_id)
}

#[tokio::test]
#[ignore = "requires Docker; run with `cargo test -- --ignored`"]
async fn parity_sqlite_vs_postgres() {
    // SQLite (in-memory)
    let sqlite_pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let sqlite_repo: Arc<dyn ChalkRepository> = match sqlite_pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        _ => unreachable!(),
    };

    // Postgres (testcontainer)
    let container = Postgres::default().start().await.expect("pg container");
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pg_pool = DatabasePool::new_postgres(&url, "parity")
        .await
        .expect("pg pool");
    pg_pool
        .run_migrations_postgres("parity")
        .await
        .expect("pg migrations");
    let pg_repo: Arc<dyn ChalkRepository> = match pg_pool {
        DatabasePool::Postgres(p) => Arc::new(PostgresRepository::new(p, "parity".into())),
        _ => unreachable!(),
    };

    let (s_org, s_user, s_count, _s_audit) = exercise(sqlite_repo).await;
    let (p_org, p_user, p_count, _p_audit) = exercise(pg_repo).await;

    assert_eq!(s_org.sourced_id, p_org.sourced_id);
    assert_eq!(s_org.name, p_org.name);
    assert_eq!(s_org.org_type, p_org.org_type);
    assert_eq!(s_org.identifier, p_org.identifier);

    assert_eq!(s_user.sourced_id, p_user.sourced_id);
    assert_eq!(s_user.username, p_user.username);
    assert_eq!(s_user.given_name, p_user.given_name);
    assert_eq!(s_user.family_name, p_user.family_name);
    assert_eq!(s_user.role, p_user.role);
    assert_eq!(s_user.email, p_user.email);
    assert_eq!(s_user.orgs, p_user.orgs);
    assert_eq!(s_user.grades, p_user.grades);

    assert_eq!(s_count, 1);
    assert_eq!(p_count, 1);
}

// ===========================================================================
// Device / asset parity (migrations 019, 021, 022)
//
// `AssetRepository` and friends are deliberately not part of `ChalkRepository`
// (see `db/repository.rs`), so this block is generic over the concrete repo
// types via the four trait bounds rather than taking an `Arc<dyn …>`.
//
// The same sequence runs against both drivers and every observable output is
// compared. The traps this is built to catch:
//   - Postgres `LIKE` is case-sensitive and SQLite's is not, so a lowercase
//     `search` must still match an uppercase stored value in both.
//   - `as i32` counter binds truncate silently, so a counter above `i32::MAX`
//     must round-trip.
//   - `mark_item_applied` is one transaction, so a failing event insert must
//     leave the asset and the item untouched.
// ===========================================================================

use chalk_core::db::repository::{
    AssetEventRepository, AssetRepository, ChangeSetRepository, GoogleDeviceSyncRepository,
};
use chalk_core::models::asset::{
    ActorKind, Asset, AssetEventFilter, AssetEventType, AssetFilter, AssetPatch, AssetSort,
    AssetStatus, NewAssetEvent, Patch,
};
use chalk_core::models::change_set::{
    ChangeSet, ChangeSetItemStatus, ChangeSetKind, ChangeSetProgress, CommitClaim, NewChangeSetItem,
};
use chalk_core::models::device_sync::{
    DeviceSyncCounters, DeviceSyncMode, DeviceSyncRun, DeviceSyncRunStatus,
};
use chalk_core::models::page::{Page, PageRequest, SortDirection};
use chrono::{DateTime, TimeZone};

/// A counter value that a 32-bit bind would silently truncate.
const HUGE_COUNTER: i64 = i32::MAX as i64 + 1_000;

fn fixed_ts() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap()
}

/// `updated_at` is stamped by the driver's own `now()`, so it can never match
/// across two processes. Everything else must.
fn normalize(mut asset: Asset) -> Asset {
    asset.updated_at = asset.created_at;
    asset
}

fn parity_asset(id: &str, tag: &str, serial: &str, annotated_user: Option<&str>) -> Asset {
    let mut a = Asset::new(id);
    a.asset_tag = Some(tag.to_string());
    a.serial_number = Some(serial.to_string());
    a.annotated_user = annotated_user.map(|s| s.to_string());
    a.org_unit_path = Some("/Students".to_string());
    a.notes = Some("original note".to_string());
    a.created_at = fixed_ts();
    a.updated_at = fixed_ts();
    a
}

/// Everything the two drivers must agree on.
#[derive(Debug, PartialEq)]
struct DeviceParity {
    created: Asset,
    updated: Asset,
    updated_at_advanced: bool,
    listed_ids: Vec<String>,
    listed_total: i64,
    listed_limit: i64,
    listed_offset: i64,
    search_ids: Vec<String>,
    search_total: i64,
    // (asset_id, actor, event_type, payload) — ids are excluded because a
    // rolled-back insert consumes a Postgres sequence value but not a SQLite
    // AUTOINCREMENT one.
    events: Vec<(String, String, AssetEventType, Option<serde_json::Value>)>,
    events_total: i64,
    run_after_counters: DeviceSyncRun,
    runs_page_total: i64,
    progress_before: ChangeSetProgress,
    stale_claim: CommitClaim,
    happy_claim: CommitClaim,
    item_after_apply: (Option<String>, ChangeSetItemStatus, bool),
    asset_after_apply: Asset,
    progress_after: ChangeSetProgress,
    events_after_apply: i64,
    rollback_errored: bool,
    item_after_rollback: (ChangeSetItemStatus, bool),
    asset_after_rollback: Asset,
    events_after_rollback: i64,
    outcome_applied_rejected: bool,
}

async fn exercise_devices<R>(repo: &R) -> DeviceParity
where
    R: AssetRepository + AssetEventRepository + GoogleDeviceSyncRepository + ChangeSetRepository,
{
    // ---- create / get -----------------------------------------------------
    repo.create_asset(&parity_asset(
        "a-1",
        "TAG-001",
        "SN-UPPER-1",
        Some("Alice@Example.COM"),
    ))
    .await
    .unwrap();
    repo.create_asset(&parity_asset("a-2", "TAG-002", "SN-LOWER-2", None))
        .await
        .unwrap();
    repo.create_asset(&parity_asset("a-3", "TAG-003", "SN-OTHER-3", None))
        .await
        .unwrap();

    let created = repo.get_asset("a-1").await.unwrap().unwrap();

    // ---- update: one Clear and one Set ------------------------------------
    let patch = AssetPatch {
        status: Some(AssetStatus::Repair),
        notes: Patch::Clear,
        purchase_cost_cents: Patch::Set(24_999),
        ..Default::default()
    };
    assert!(repo.update_asset("a-1", &patch).await.unwrap());
    assert!(
        !repo.update_asset("nope", &patch).await.unwrap(),
        "updating a missing asset must report false"
    );
    assert!(
        repo.update_asset("a-1", &AssetPatch::default())
            .await
            .unwrap(),
        "an empty patch is a no-op that still reports existence"
    );

    let updated = repo.get_asset("a-1").await.unwrap().unwrap();
    let updated_at_advanced = updated.updated_at > updated.created_at;

    // ---- list: filter + window --------------------------------------------
    let filter = AssetFilter {
        status: Some(AssetStatus::Active),
        sort: AssetSort::AssetTag,
        direction: SortDirection::Asc,
        ..Default::default()
    };
    let listed: Page<Asset> = repo
        .list_assets(&filter, PageRequest::new(1, 1))
        .await
        .unwrap();
    assert_eq!(
        repo.count_assets(&filter).await.unwrap(),
        listed.total,
        "count_assets and list_assets must share a WHERE clause"
    );

    // ---- list: the roster join --------------------------------------------
    // Same window, same order, same total as the bare listing — the join is a
    // decoration, and a driver that lets it change the result set would hide
    // devices from the inventory page on one backend only.
    let joined = repo
        .list_assets_with_roster(&filter, PageRequest::new(1, 1))
        .await
        .unwrap();
    assert_eq!(
        joined.total, listed.total,
        "join changed the matching total"
    );
    assert_eq!(
        joined
            .items
            .iter()
            .map(|r| r.asset.clone())
            .collect::<Vec<_>>(),
        listed.items,
        "join changed the page window or its order"
    );

    // ---- case-insensitive search ------------------------------------------
    // Lowercase query, uppercase stored value: `LIKE` alone fails on Postgres.
    let search_filter = AssetFilter {
        search: Some("sn-upper".to_string()),
        sort: AssetSort::AssetTag,
        ..Default::default()
    };
    let searched = repo
        .list_assets(&search_filter, PageRequest::new(50, 0))
        .await
        .unwrap();

    // ---- events -----------------------------------------------------------
    repo.append_event(&NewAssetEvent::simple(
        "a-1",
        "admin-1",
        ActorKind::Admin,
        AssetEventType::Imported,
    ))
    .await
    .unwrap();
    repo.append_event(&NewAssetEvent::field_changed(
        "a-1",
        "admin-1",
        ActorKind::Admin,
        "status",
        Some("active"),
        Some("repair"),
    ))
    .await
    .unwrap();

    let events_page = repo
        .list_events(&AssetEventFilter::for_asset("a-1"), PageRequest::new(50, 0))
        .await
        .unwrap();

    // ---- device sync run: counters above i32::MAX -------------------------
    let run = repo.start_run(DeviceSyncMode::Full, false).await.unwrap();
    let counters = DeviceSyncCounters {
        devices_seen: HUGE_COUNTER,
        devices_created: HUGE_COUNTER + 1,
        devices_updated: 2,
        devices_matched: 3,
        devices_unmatched: 4,
        api_calls: HUGE_COUNTER + 2,
        throttle_events: 5,
    };
    repo.update_run_counters(run.id, &counters).await.unwrap();
    let mid = repo.get_run(run.id).await.unwrap().unwrap();
    assert_eq!(
        mid.counters, counters,
        "BIGINT counters must not be truncated by a 32-bit bind"
    );
    repo.finish_run(run.id, DeviceSyncRunStatus::Succeeded, &counters, None)
        .await
        .unwrap();
    let mut run_after = repo.get_run(run.id).await.unwrap().unwrap();
    assert_eq!(repo.latest_run().await.unwrap().unwrap().id, run.id);
    // Ids and wall-clock stamps are per-process; the payload is what must match.
    run_after.id = 0;
    run_after.started_at = fixed_ts();
    run_after.completed_at = run_after.completed_at.map(|_| fixed_ts());
    let runs_page = repo.list_runs(PageRequest::new(10, 0)).await.unwrap();

    // ---- change set: create, count, stale claim, real claim ---------------
    let mut set = ChangeSet::planned("cs-1", ChangeSetKind::BulkEdit, "admin-1", "hash-1", 2);
    set.created_at = fixed_ts();
    let items = vec![
        NewChangeSetItem::update_field("a-1", "notes", None, Some("committed".into())),
        NewChangeSetItem::update_field("a-2", "notes", None, Some("committed".into())),
    ];
    repo.create_change_set(&set, &items).await.unwrap();

    let progress_before = repo.item_status_counts("cs-1").await.unwrap();
    let stale_claim = repo
        .claim_for_commit("cs-1", "wrong-hash", 2)
        .await
        .unwrap();
    let happy_claim = repo.claim_for_commit("cs-1", "hash-1", 2).await.unwrap();

    let item_ids: Vec<i64> = repo
        .list_items("cs-1", None, PageRequest::new(50, 0))
        .await
        .unwrap()
        .items
        .iter()
        .map(|i| i.id)
        .collect();

    // ---- the atom: asset write + event + item status ----------------------
    repo.mark_item_applied(
        item_ids[0],
        Some(&AssetPatch {
            notes: Patch::Set("committed".to_string()),
            ..Default::default()
        }),
        &NewAssetEvent::field_changed(
            "a-1",
            "admin-1",
            ActorKind::Admin,
            "notes",
            None,
            Some("committed"),
        ),
    )
    .await
    .unwrap();

    let applied_item = repo
        .list_items(
            "cs-1",
            Some(ChangeSetItemStatus::Applied),
            PageRequest::new(50, 0),
        )
        .await
        .unwrap();
    let item_after_apply = {
        let i = &applied_item.items[0];
        (i.asset_id.clone(), i.status, i.applied_at.is_some())
    };
    let asset_after_apply = repo.get_asset("a-1").await.unwrap().unwrap();
    let progress_after = repo.item_status_counts("cs-1").await.unwrap();
    let events_after_apply = repo
        .list_events(&AssetEventFilter::for_asset("a-1"), PageRequest::new(50, 0))
        .await
        .unwrap()
        .total;

    // ---- rollback: the event's asset_id violates the FK -------------------
    let rollback_errored = repo
        .mark_item_applied(
            item_ids[1],
            Some(&AssetPatch {
                notes: Patch::Set("must not persist".to_string()),
                ..Default::default()
            }),
            &NewAssetEvent::simple(
                "ghost-asset",
                "admin-1",
                ActorKind::Admin,
                AssetEventType::FieldChanged,
            ),
        )
        .await
        .is_err();

    let rolled_back_item = repo
        .list_items(
            "cs-1",
            Some(ChangeSetItemStatus::Pending),
            PageRequest::new(50, 0),
        )
        .await
        .unwrap();
    let item_after_rollback = {
        let i = &rolled_back_item.items[0];
        (i.status, i.applied_at.is_some())
    };
    let asset_after_rollback = repo.get_asset("a-2").await.unwrap().unwrap();
    let events_after_rollback = repo
        .list_events(&AssetEventFilter::default(), PageRequest::new(50, 0))
        .await
        .unwrap()
        .total;

    // `applied` must never come through mark_item_outcome.
    let outcome_applied_rejected = repo
        .mark_item_outcome(item_ids[1], ChangeSetItemStatus::Applied, None)
        .await
        .is_err();

    DeviceParity {
        created: normalize(created),
        updated: normalize(updated),
        updated_at_advanced,
        listed_ids: listed.items.iter().map(|a| a.id.clone()).collect(),
        listed_total: listed.total,
        listed_limit: listed.limit,
        listed_offset: listed.offset,
        search_ids: searched.items.iter().map(|a| a.id.clone()).collect(),
        search_total: searched.total,
        events: events_page
            .items
            .iter()
            .map(|e| {
                (
                    e.asset_id.clone(),
                    e.actor.clone(),
                    e.event_type,
                    e.payload.clone(),
                )
            })
            .collect(),
        events_total: events_page.total,
        run_after_counters: run_after,
        runs_page_total: runs_page.total,
        progress_before,
        stale_claim,
        happy_claim,
        item_after_apply,
        asset_after_apply: normalize(asset_after_apply),
        progress_after,
        events_after_apply,
        rollback_errored,
        item_after_rollback,
        asset_after_rollback: normalize(asset_after_rollback),
        events_after_rollback,
        outcome_applied_rejected,
    }
}

#[tokio::test]
#[ignore = "requires Docker; run with `cargo test -- --ignored`"]
async fn parity_devices_sqlite_vs_postgres() {
    let sqlite_pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let sqlite_repo = match sqlite_pool {
        DatabasePool::Sqlite(p) => SqliteRepository::new(p),
        _ => unreachable!(),
    };

    let container = Postgres::default().start().await.expect("pg container");
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pg_pool = DatabasePool::new_postgres(&url, "parity_devices")
        .await
        .expect("pg pool");
    pg_pool
        .run_migrations_postgres("parity_devices")
        .await
        .expect("pg migrations");
    let pg_repo = match pg_pool {
        DatabasePool::Postgres(p) => PostgresRepository::new(p, "parity_devices".into()),
        _ => unreachable!(),
    };

    let sqlite_result = exercise_devices(&sqlite_repo).await;
    let pg_result = exercise_devices(&pg_repo).await;

    // Spot-check the invariants individually first so a failure names itself,
    // then assert wholesale equality.
    assert!(sqlite_result.updated_at_advanced && pg_result.updated_at_advanced);
    assert_eq!(
        sqlite_result.search_ids,
        vec!["a-1".to_string()],
        "lowercase search must match the uppercase stored serial (SQLite)"
    );
    assert_eq!(
        pg_result.search_ids,
        vec!["a-1".to_string()],
        "lowercase search must match the uppercase stored serial (Postgres: ILIKE, not LIKE)"
    );
    assert_eq!(
        pg_result.run_after_counters.counters.devices_seen,
        HUGE_COUNTER
    );
    assert_eq!(
        sqlite_result.run_after_counters.counters.devices_seen,
        HUGE_COUNTER
    );
    assert!(matches!(pg_result.stale_claim, CommitClaim::Stale { .. }));
    assert_eq!(pg_result.happy_claim, CommitClaim::Claimed);
    assert!(pg_result.rollback_errored && sqlite_result.rollback_errored);
    assert_eq!(
        pg_result.asset_after_rollback.notes.as_deref(),
        Some("original note"),
        "a failed event insert must roll the asset write back"
    );
    assert!(pg_result.outcome_applied_rejected && sqlite_result.outcome_applied_rejected);

    assert_eq!(sqlite_result, pg_result);
}
