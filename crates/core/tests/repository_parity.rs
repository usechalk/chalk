//! Repository parity tests: same operations against SQLite (in-memory) and
//! Postgres (testcontainer) producing matching results. `#[ignore]` because
//! the Postgres half needs Docker — run with `cargo test -- --ignored`.

use chalk_core::db::postgres::PostgresRepository;
use chalk_core::db::repository::{ChalkRepository, TicketRepository, UserRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::common::{OrgType, RoleType, Status};
use chalk_core::models::org::Org;
use chalk_core::models::sync::UserFilter;
use chalk_core::models::ticket::{
    NewTicketComment, Ticket, TicketFilter, TicketScope, TicketStatus,
};
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

async fn exercise(repo: Arc<dyn ChalkRepository>) -> (Org, User, usize, i64, Vec<String>) {
    repo.upsert_org(&sample_org()).await.unwrap();
    repo.upsert_user(&sample_user()).await.unwrap();

    let org = repo.get_org("org-1").await.unwrap().unwrap();
    let user = repo.get_user("u-1").await.unwrap().unwrap();
    let users = repo.list_users(&UserFilter::default()).await.unwrap();
    let audit_id = repo
        .log_admin_action("test.action", Some("parity"), Some("127.0.0.1"))
        .await
        .unwrap();

    // The resolve picker's roster lookup. Postgres `LIKE` is case-sensitive and
    // SQLite's is not, so this is the exact shape that drifts silently: a
    // technician typing a lowercase surname would find the student on a
    // self-hosted SQLite install and find nothing on hosted Postgres. The
    // wildcard case is here for the same reason — an unescaped `%` matches the
    // whole roster on both, but only if both escape it identically.
    let mut searched: Vec<String> = repo
        .list_users(&UserFilter::search("ANDERSON", 10))
        .await
        .unwrap()
        .into_iter()
        .map(|u| u.sourced_id)
        .collect();
    searched.sort();
    let wildcard_hits = repo
        .list_users(&UserFilter::search("%", 10))
        .await
        .unwrap()
        .len();
    searched.push(format!("wildcard:{wildcard_hits}"));

    (org, user, users.len(), audit_id, searched)
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

    let (s_org, s_user, s_count, _s_audit, s_search) = exercise(sqlite_repo).await;
    let (p_org, p_user, p_count, _p_audit, p_search) = exercise(pg_repo).await;

    assert_eq!(
        s_search, p_search,
        "roster search drifted between backends (LIKE vs ILIKE, or wildcard escaping)"
    );

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
    AssetEventRepository, AssetRepository, ChangeSetRepository, DeviceConfigRecord,
    GoogleDeviceSyncRepository, JobRepository, OrgRepository, TenantConfigRepo,
};
use chalk_core::models::asset::{
    ActorKind, Asset, AssetEventFilter, AssetEventType, AssetFilter, AssetPatch, AssetSort,
    AssetSource, AssetStatus, MatchState, NewAssetEvent, Patch,
};
use chalk_core::models::change_set::{
    ChangeSet, ChangeSetItemStatus, ChangeSetKind, ChangeSetOp, ChangeSetProgress, CommitClaim,
    NewChangeSetItem, RemoteTarget,
};
use chalk_core::models::device_sync::{
    DeviceSyncCounters, DeviceSyncMode, DeviceSyncRun, DeviceSyncRunStatus,
};
use chalk_core::models::job::{JobKind, JobStatus, NewJob};
use chalk_core::models::page::{Page, PageRequest, SortDirection};
use chrono::{DateTime, Duration, TimeZone};

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
    compound_applied: bool,
    compound_asset: Asset,
    compound_missing_reported_false: bool,
    compound_events_for_a3: i64,
    events_for_school: Vec<String>,
    events_for_actor: Vec<String>,
    job_after_enqueue: (String, i64, i64),
    job_claim_outcomes: (bool, bool),
    job_after_claim: (String, i64),
    job_delayed_is_hidden: bool,
    job_abandoned_swept: u64,
    job_after_recovery: (String, Option<String>),
    job_finish_on_queued_refused: bool,
    device_config_key: Option<Vec<u8>>,
    device_config_fields: (bool, bool, Option<String>, Option<i64>),
    /// Write-back is a *separate* opt-in from `enabled`, and both drivers have
    /// to store it that way. A backend that conflated the two would let a
    /// district that agreed only to be read start being written to.
    device_config_write_back_off: (bool, bool),
    /// The multi-school filter that carries an API token's authorization
    /// boundary. A backend that dropped it would serve rows the token may not
    /// read — the one filter where a difference is a data leak rather than a
    /// wrong count.
    assets_by_school_set: Vec<String>,
    assets_by_school_set_intersecting: Vec<String>,
    /// The grouped report query, including its ORDER BY. Postgres defaults
    /// NULLs *last* on ASC and SQLite sorts them *first*, so a report built on
    /// this would list its rows differently per backend without an explicit
    /// NULLS FIRST — same numbers, different page.
    asset_group_counts: Vec<(Option<String>, String, i64)>,
    /// Tickets. The scope results matter most: a backend that dropped the
    /// boundary would serve a scoped token rows it may not read, and the two
    /// drivers express "no schools granted" differently enough to get wrong.
    ticket_numbers: Vec<i64>,
    ticket_first_response_set: (bool, bool, bool),
    /// A staff reply on an email-sourced ticket with no roster requester.
    /// Postgres needs `IS DISTINCT FROM` here — `NULL <> 'u-2'` is NULL, which
    /// makes the whole clause false and silently skips the stamp.
    ticket_first_response_on_anonymous: bool,
    ticket_visible_comments: usize,
    ticket_all_comments: usize,
    /// Email idempotency looks at the comment table as well as the ticket
    /// table, so both drivers must answer the same way — a driver that
    /// returned `None` here would retry-loop a provider on that backend only.
    ticket_id_for_known_email_comment: Option<String>,
    ticket_id_for_unknown_email_comment: Option<String>,
    ticket_scoped_ids: Vec<String>,
    ticket_empty_scope_total: i64,
    ticket_breached_ids: Vec<String>,
    device_config_cleared_key: Option<Vec<u8>>,
    tag_lookup_unique: Vec<String>,
    tag_lookup_duplicated: Vec<String>,
    tag_lookup_missing: Vec<String>,
    created_item_status: (ChangeSetItemStatus, bool, Option<String>),
    created_asset: Option<Asset>,
    created_events: Vec<(String, AssetEventType)>,
    create_on_missing_item_errored: bool,
    create_after_missing_item_left_no_asset: bool,
}

async fn exercise_devices<R>(repo: &R) -> DeviceParity
where
    // `OrgRepository` is in the bound only so the school an asset points at can
    // exist: `assets.school_org_sourced_id` is a foreign key, so the school
    // filter cannot be exercised without a real org row.
    R: AssetRepository
        + AssetEventRepository
        + GoogleDeviceSyncRepository
        + ChangeSetRepository
        + TicketRepository
        // Tickets reference a requester and an author, and the FKs are real.
        + UserRepository
        + OrgRepository
        + JobRepository
        + TenantConfigRepo,
{
    // ---- create / get -----------------------------------------------------
    repo.upsert_org(&sample_org()).await.unwrap();

    // a-1 is at the school and a-2/a-3 are not, so the school filter has both
    // something to match and something to exclude. Without that, comparing two
    // empty result sets would pass while proving nothing.
    let mut at_school = parity_asset("a-1", "TAG-001", "SN-UPPER-1", Some("Alice@Example.COM"));
    at_school.school_org_sourced_id = Some("org-1".to_string());
    repo.create_asset(&at_school).await.unwrap();
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

    // ---- the transactional compound op ------------------------------------
    // The patch and its audit event commit together or not at all. Both halves
    // have to agree across backends: a driver that committed the patch but
    // dropped the event would leave a device assigned to a student with no
    // record of who did it, on one backend only.
    //
    // The patch marks a device ignored — a cart or loaner the queue should stop
    // asking about — rather than assigning it to a student. Same atomicity
    // property, and it needs no roster: `exercise_devices` is bounded by the
    // four device traits, so it cannot seed a user to satisfy the
    // `assigned_user_sourced_id` foreign key.
    let compound_applied = repo
        .apply_patch_with_event(
            "a-3",
            &AssetPatch {
                match_state: Some(MatchState::Ignored),
                ..Default::default()
            },
            &NewAssetEvent::simple(
                "a-3",
                "admin-1",
                ActorKind::Admin,
                AssetEventType::FieldChanged,
            ),
        )
        .await
        .unwrap();
    let compound_asset = normalize(repo.get_asset("a-3").await.unwrap().unwrap());

    // A missing asset must roll back rather than orphan an event against an id
    // that does not exist — `asset_events.asset_id` is RESTRICT, so without the
    // rollback this errors instead of answering false.
    let compound_missing_reported_false = !repo
        .apply_patch_with_event(
            "no-such-asset",
            &AssetPatch {
                status: Some(AssetStatus::Repair),
                ..Default::default()
            },
            &NewAssetEvent::simple(
                "no-such-asset",
                "admin-1",
                ActorKind::Admin,
                AssetEventType::StatusChanged,
            ),
        )
        .await
        .unwrap();
    let compound_events_for_a3 = repo
        .list_events(&AssetEventFilter::for_asset("a-3"), PageRequest::new(50, 0))
        .await
        .unwrap()
        .total;

    // An event against the school's device, and one against a device that is
    // not at that school. Without both, the filter has nothing to return and
    // nothing to exclude, and comparing two empty sets would pass while
    // proving nothing — which is exactly what the first version of this guard
    // did.
    repo.append_event(&NewAssetEvent::simple(
        "a-1",
        "admin-1",
        ActorKind::Admin,
        AssetEventType::Repaired,
    ))
    .await
    .unwrap();
    repo.append_event(&NewAssetEvent::simple(
        "a-2",
        "admin-1",
        ActorKind::Admin,
        AssetEventType::Repaired,
    ))
    .await
    .unwrap();
    // A second actor, for the same reason: with only `admin-1` in the table,
    // filtering by actor and not filtering at all return the same rows, and the
    // comparison below would pass with the filter deleted entirely.
    repo.append_event(&NewAssetEvent::simple(
        "a-1",
        "system:google-sync",
        ActorKind::System,
        AssetEventType::Repaired,
    ))
    .await
    .unwrap();

    // ---- jobs -------------------------------------------------------------
    // The claim protocol is the one piece of this schema where a driver
    // difference is not a cosmetic bug: if `claim` ever returned true twice,
    // two workers would run the same fleet-wide mutation. Both drivers
    // implement it as a conditional UPDATE checked by rows_affected, and this
    // compares the observable behaviour rather than the SQL.
    let enqueued = repo
        .enqueue(&NewJob::now(JobKind::ChangeSetCommit).with_payload(serde_json::json!({"cs": 1})))
        .await
        .unwrap();
    let job_after_enqueue = (
        enqueued.status.as_str().to_string(),
        enqueued.attempt,
        enqueued.max_attempts,
    );

    let claim_at = fixed_ts();
    let first = repo.claim(&enqueued.id, claim_at).await.unwrap();
    let second = repo.claim(&enqueued.id, claim_at).await.unwrap();
    let job_claim_outcomes = (first, second);
    let claimed = repo.get_job(&enqueued.id).await.unwrap().unwrap();
    let job_after_claim = (claimed.status.as_str().to_string(), claimed.attempt);

    // A delayed job must be invisible until its time on both drivers, or a
    // backoff means nothing on one of them.
    let delayed = repo
        .enqueue(
            &NewJob::now(JobKind::GoogleDeviceSync).run_after(fixed_ts() + Duration::days(365)),
        )
        .await
        .unwrap();
    let job_delayed_is_hidden = repo
        .next_claimable(fixed_ts())
        .await
        .unwrap()
        .map(|j| j.id != delayed.id)
        .unwrap_or(true);

    // Recovery: the claimed job is old enough to sweep, the delayed one is not
    // running at all and must be untouched.
    let job_abandoned_swept = repo
        .fail_abandoned(fixed_ts() + Duration::hours(1))
        .await
        .unwrap();
    let recovered = repo.get_job(&enqueued.id).await.unwrap().unwrap();
    let job_after_recovery = (recovered.status.as_str().to_string(), recovered.last_error);

    // A queued job was never claimed, so it cannot be finished.
    let job_finish_on_queued_refused = !repo
        .finish(&delayed.id, JobStatus::Succeeded, None)
        .await
        .unwrap();

    // ---- tenant_config_devices ----------------------------------------------
    // Sealed key material is BLOB on SQLite and BYTEA on Postgres. AES-256-GCM
    // output is not valid UTF-8, so a driver that coerced it to text would
    // corrupt it — and the corruption surfaces much later as a decryption
    // failure that looks like a wrong master key rather than a storage bug.
    let sealed: Vec<u8> = vec![0x00, 0xff, 0xfe, 0x01, 0x80, 0x00, 0x7f, 0xc3, 0x28];
    repo.put_device_config(
        DeviceConfigRecord {
            enabled: true,
            write_back_enabled: true,
            customer_id: Some("my_customer".into()),
            admin_email: Some("admin@example.edu".into()),
            service_account_key: Some(sealed.clone()),
            page_size: Some(200),
            requests_per_minute: Some(500),
            sync_schedule: Some("0 4 * * *".into()),
            ..Default::default()
        },
        "admin-1",
    )
    .await
    .unwrap();
    let device_cfg = repo.get_device_config().await.unwrap().unwrap();
    let device_config_key = device_cfg.service_account_key.clone();
    let device_config_fields = (
        device_cfg.enabled,
        device_cfg.write_back_enabled,
        device_cfg.admin_email.clone(),
        device_cfg.page_size,
    );

    // Enabled, but write-back explicitly off: the two flags must move
    // independently, so a district can be read without being writable.
    repo.put_device_config(
        DeviceConfigRecord {
            enabled: true,
            write_back_enabled: false,
            customer_id: Some("my_customer".into()),
            ..Default::default()
        },
        "admin-1",
    )
    .await
    .unwrap();
    let off = repo.get_device_config().await.unwrap().unwrap();
    let device_config_write_back_off = (off.enabled, off.write_back_enabled);

    // Clearing must write a real NULL on both, not an empty blob — the console
    // reads `is_some()` to decide whether a key is on file.
    repo.put_device_config(
        DeviceConfigRecord {
            service_account_key: None,
            ..Default::default()
        },
        "admin-1",
    )
    .await
    .unwrap();
    let device_config_cleared_key = repo
        .get_device_config()
        .await
        .unwrap()
        .unwrap()
        .service_account_key;

    // The school filter is a subquery against `assets` written separately in
    // each dialect, so it is exactly the kind of thing that drifts: a
    // technician asking "what happened to my school's devices" would get an
    // answer on one backend and a different one on the other.
    let mut events_for_school: Vec<String> = repo
        .list_events(
            &AssetEventFilter {
                school_org_sourced_id: Some("org-1".into()),
                ..Default::default()
            },
            PageRequest::new(50, 0),
        )
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|e| format!("{}:{}", e.asset_id, e.event_type.as_str()))
        .collect();
    events_for_school.sort();

    let mut events_for_actor: Vec<String> = repo
        .list_events(
            &AssetEventFilter {
                actor: Some("admin-1".into()),
                ..Default::default()
            },
            PageRequest::new(50, 0),
        )
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|e| format!("{}:{}", e.asset_id, e.event_type.as_str()))
        .collect();
    events_for_actor.sort();

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

    // ---- multi-school filter (API token scope) --------------------------
    let mut school_set = AssetFilter {
        school_org_sourced_ids: vec!["org-1".into(), "org-nope".into()],
        sort: AssetSort::AssetTag,
        ..Default::default()
    };
    let mut assets_by_school_set: Vec<String> = repo
        .list_assets(&school_set, PageRequest::new(50, 0))
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|a| a.id)
        .collect();
    assets_by_school_set.sort();

    // ANDed with the single-school filter, never ORed: an operator's choice has
    // to narrow within the boundary rather than widen past it.
    school_set.school_org_sourced_id = Some("org-nope".into());
    let mut assets_by_school_set_intersecting: Vec<String> = repo
        .list_assets(&school_set, PageRequest::new(50, 0))
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|a| a.id)
        .collect();
    assets_by_school_set_intersecting.sort();

    // ---- tickets (WS-4) --------------------------------------------------
    // `tickets.requester_user_sourced_id` is a foreign key, so the roster rows
    // have to exist before a ticket can name one.
    for sid in ["u-1", "u-2"] {
        let mut u = sample_user();
        u.sourced_id = sid.to_string();
        u.username = sid.to_string();
        repo.upsert_user(&u).await.unwrap();
    }

    let mut ticket_numbers = Vec::new();
    for (i, school) in [Some("org-1"), None, Some("org-1")].iter().enumerate() {
        let mut t = Ticket::new(format!("tk-{i}"), format!("Ticket {i}"));
        t.requester_user_sourced_id = Some("u-1".into());
        t.school_org_sourced_id = school.map(|s| s.to_string());
        if i == 2 {
            t.sla_due_at = Some(Utc::now() - chrono::Duration::days(1));
        }
        ticket_numbers.push(repo.create_ticket(&t).await.unwrap().number);
    }

    // Two more overdue tickets whose statuses must EXCLUDE them from the
    // breach filter, for opposite reasons: `waiting` pauses the SLA clock, and
    // `resolved` is settled. Without these every ticket in the fixture is
    // `open`, so the breach predicate is satisfied by the date alone and both
    // drivers would agree on a wrong answer — the filter's whole status clause
    // could be deleted and parity would still pass.
    for (id, status) in [
        ("tk-waiting", TicketStatus::Waiting),
        ("tk-resolved", TicketStatus::Resolved),
    ] {
        let mut t = Ticket::new(id, format!("Overdue but {status}"));
        t.requester_user_sourced_id = Some("u-1".into());
        t.school_org_sourced_id = Some("org-1".into());
        t.status = status;
        t.sla_due_at = Some(Utc::now() - chrono::Duration::days(3));
        repo.create_ticket(&t).await.unwrap();
    }

    // An internal note is not a first response, the requester answering
    // themselves is not either, and a staff reply is.
    repo.append_comment(&NewTicketComment::internal_note("tk-0", "u-2", "note"))
        .await
        .unwrap();
    let after_note = repo
        .get_ticket("tk-0")
        .await
        .unwrap()
        .unwrap()
        .first_response_at
        .is_some();
    repo.append_comment(&NewTicketComment::reply("tk-0", "u-1", "any update?"))
        .await
        .unwrap();
    let after_requester = repo
        .get_ticket("tk-0")
        .await
        .unwrap()
        .unwrap()
        .first_response_at
        .is_some();
    repo.append_comment(&NewTicketComment::reply("tk-0", "u-2", "on our way"))
        .await
        .unwrap();
    let after_staff = repo
        .get_ticket("tk-0")
        .await
        .unwrap()
        .unwrap()
        .first_response_at
        .is_some();
    let ticket_first_response_set = (after_note, after_requester, after_staff);

    // An email-sourced ticket has no roster requester. A staff reply to it is
    // still the first response — the NULL must not swallow the comparison.
    let mut anon = Ticket::new("tk-anon", "Mailed in");
    anon.requester_user_sourced_id = None;
    anon.requester_email = Some("parent@example.com".into());
    repo.create_ticket(&anon).await.unwrap();
    repo.append_comment(&NewTicketComment::reply("tk-anon", "u-2", "we can help"))
        .await
        .unwrap();
    let ticket_first_response_on_anonymous = repo
        .get_ticket("tk-anon")
        .await
        .unwrap()
        .unwrap()
        .first_response_at
        .is_some();

    let ticket_visible_comments = repo.list_comments("tk-0", false).await.unwrap().len();
    let ticket_all_comments = repo.list_comments("tk-0", true).await.unwrap().len();

    // A comment that arrived by email, so the idempotency lookup has something
    // to find. Without one this pair would be (None, None) on both drivers and
    // agree while testing nothing.
    repo.append_comment(&NewTicketComment {
        ticket_id: "tk-0".into(),
        author_user_sourced_id: None,
        author_email: Some("parent@example.org".into()),
        body: "sent by email".into(),
        is_internal: false,
        source: chalk_core::models::ticket::TicketSource::Email,
        email_message_id: Some("mail-abc@example.org".into()),
    })
    .await
    .unwrap();
    let ticket_id_for_known_email_comment = repo
        .ticket_id_for_comment_message_id("mail-abc@example.org")
        .await
        .unwrap();
    assert_eq!(
        ticket_id_for_known_email_comment.as_deref(),
        Some("tk-0"),
        "the fixture must actually find something, or the parity pair is vacuous"
    );
    let ticket_id_for_unknown_email_comment = repo
        .ticket_id_for_comment_message_id("never-seen@example.org")
        .await
        .unwrap();

    let ticket_scoped_ids: Vec<String> = repo
        .list_tickets(
            &TicketFilter::default(),
            &TicketScope::Schools(vec!["org-1".into()]),
            PageRequest::new(50, 0),
        )
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|t| t.id)
        .collect();

    // An empty grant grants nothing. The two drivers build this clause
    // differently, and getting it wrong turns the narrowest scope into the
    // widest.
    let ticket_empty_scope_total = repo
        .list_tickets(
            &TicketFilter::default(),
            &TicketScope::Schools(Vec::new()),
            PageRequest::new(50, 0),
        )
        .await
        .unwrap()
        .total;

    let ticket_breached_ids: Vec<String> = repo
        .list_tickets(
            &TicketFilter {
                breached_only: true,
                ..Default::default()
            },
            &TicketScope::Unrestricted,
            PageRequest::new(50, 0),
        )
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|t| t.id)
        .collect();

    // ---- grouped counts (reports) ----------------------------------------
    let asset_group_counts: Vec<(Option<String>, String, i64)> = repo
        .count_assets_by_school_and_status(&AssetFilter::default())
        .await
        .unwrap()
        .into_iter()
        .map(|g| {
            (
                g.school_org_sourced_id,
                g.status.as_str().to_string(),
                g.count,
            )
        })
        .collect();

    // ---- lookup by asset tag ----------------------------------------------
    // Asset tags carry no unique index, so this returns a list. Both a unique
    // tag and a duplicated one are exercised: comparing two empty vectors would
    // pass while proving nothing about ordering or duplicate handling.
    let mut dup = parity_asset("a-dup", "TAG-001", "SN-DUP-9", None);
    dup.status = AssetStatus::Storage;
    repo.create_asset(&dup).await.unwrap();

    let mut tag_lookup_duplicated: Vec<String> = repo
        .find_assets_by_asset_tag("TAG-001")
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.id)
        .collect();
    // Neither driver promises an order, and a parity test must not assert one.
    tag_lookup_duplicated.sort();

    let tag_lookup_unique: Vec<String> = repo
        .find_assets_by_asset_tag("TAG-002")
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.id)
        .collect();
    let tag_lookup_missing: Vec<String> = repo
        .find_assets_by_asset_tag("TAG-NOPE")
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.id)
        .collect();

    // ---- mark_item_created: the CSV import's commit atom ------------------
    // One transaction over the asset insert, its audit event, and the item's
    // status — plus pointing the item at the row it just made, which is the
    // part that cannot be done before the asset exists (the FK forbids it).
    let create_set = ChangeSet::planned(
        "cs-create",
        ChangeSetKind::CsvImport,
        "admin-1",
        "create-hash",
        1,
    );
    repo.create_change_set(
        &create_set,
        &[NewChangeSetItem {
            asset_id: None,
            target_ref: Some("TAG-NEW".into()),
            google_device_id: None,
            op: ChangeSetOp::Create,
            field: None,
            old_value: None,
            new_value: Some("{}".into()),
            remote_target: RemoteTarget::Local,
        }],
    )
    .await
    .unwrap();
    let create_item_id = repo
        .list_items("cs-create", None, PageRequest::new(10, 0))
        .await
        .unwrap()
        .items[0]
        .id;

    let mut fresh = parity_asset("a-new", "TAG-NEW", "SN-NEW-1", None);
    fresh.source = AssetSource::Csv;
    repo.mark_item_created(
        create_item_id,
        &fresh,
        &NewAssetEvent::simple(
            "a-new",
            "admin-1",
            ActorKind::Admin,
            AssetEventType::Imported,
        ),
    )
    .await
    .unwrap();

    let created_item = repo
        .list_items("cs-create", None, PageRequest::new(10, 0))
        .await
        .unwrap()
        .items[0]
        .clone();
    let created_item_status = (
        created_item.status,
        created_item.applied_at.is_some(),
        created_item.asset_id.clone(),
    );
    let created_asset = repo.get_asset("a-new").await.unwrap().map(normalize);
    let created_events: Vec<(String, AssetEventType)> = repo
        .list_events(
            &AssetEventFilter {
                asset_id: Some("a-new".into()),
                ..Default::default()
            },
            PageRequest::new(10, 0),
        )
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|e| (e.actor, e.event_type))
        .collect();

    // An item id that does not exist must error *and* roll the asset insert
    // back. Without the rollback both drivers would leave an orphan device
    // that no change set ever accounted for.
    let create_on_missing_item_errored = repo
        .mark_item_created(
            i64::MAX,
            &parity_asset("a-orphan", "TAG-ORPHAN", "SN-ORPHAN-1", None),
            &NewAssetEvent::simple(
                "a-orphan",
                "admin-1",
                ActorKind::Admin,
                AssetEventType::Imported,
            ),
        )
        .await
        .is_err();
    let create_after_missing_item_left_no_asset =
        repo.get_asset("a-orphan").await.unwrap().is_none();

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
        compound_applied,
        compound_asset,
        compound_missing_reported_false,
        compound_events_for_a3,
        events_for_school,
        events_for_actor,
        job_after_enqueue,
        job_claim_outcomes,
        job_after_claim,
        job_delayed_is_hidden,
        job_abandoned_swept,
        job_after_recovery,
        job_finish_on_queued_refused,
        device_config_key,
        device_config_fields,
        device_config_write_back_off,
        assets_by_school_set,
        assets_by_school_set_intersecting,
        asset_group_counts,
        ticket_numbers,
        ticket_first_response_set,
        ticket_first_response_on_anonymous,
        ticket_visible_comments,
        ticket_all_comments,
        ticket_id_for_known_email_comment,
        ticket_id_for_unknown_email_comment,
        ticket_scoped_ids,
        ticket_empty_scope_total,
        ticket_breached_ids,
        device_config_cleared_key,
        tag_lookup_unique,
        tag_lookup_duplicated,
        tag_lookup_missing,
        created_item_status,
        created_asset,
        created_events,
        create_on_missing_item_errored,
        create_after_missing_item_left_no_asset,
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
