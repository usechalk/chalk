//! MDM engine tests. The discipline under test is inherited from the ChromeOS
//! sync and must hold identically here: the console owns hardware facts, Chalk
//! owns assignment and status, a human's decision is untouchable, and a merge
//! into an existing row is recorded as the moment two identities became one.

use super::*;

use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::asset::AssetEventFilter;
use chalk_core::models::common::{RoleType, Status};
use chalk_core::models::user::User;
use chrono::TimeZone;
use std::sync::Mutex;

struct FakeConnector {
    source: MdmSource,
    devices: Mutex<Vec<MdmDevice>>,
}

#[async_trait]
impl MdmConnector for FakeConnector {
    fn source(&self) -> MdmSource {
        self.source
    }
    async fn fetch_devices(&self) -> Result<Vec<MdmDevice>> {
        Ok(self.devices.lock().unwrap().clone())
    }
}

async fn repo() -> Arc<SqliteRepository> {
    let repo = match DatabasePool::new_sqlite_memory().await.unwrap() {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    for (sid, email) in [
        ("u-maya", "maya.chen@district.test"),
        ("u-devon", "devon.price@district.test"),
    ] {
        repo.upsert_user(&User {
            sourced_id: sid.into(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            username: email.split('@').next().unwrap().into(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "Given".into(),
            family_name: "Family".into(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some(email.into()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec![],
            grades: vec![],
        })
        .await
        .unwrap();
    }
    repo
}

fn engine(repo: &Arc<SqliteRepository>, connector: Arc<FakeConnector>) -> MdmSyncEngine {
    MdmSyncEngine::new(repo.clone(), repo.clone(), repo.clone(), connector)
}

fn windows(external_id: &str, serial: &str, email: Option<&str>) -> MdmDevice {
    MdmDevice {
        external_id: external_id.into(),
        serial_number: Some(serial.into()),
        make: Some("Dell".into()),
        model: Some("Latitude 3310".into()),
        os_version: Some("10.0.26100".into()),
        user_email: email.map(str::to_string),
        asset_type: AssetType::Laptop,
        ..Default::default()
    }
}

/// First contact: devices become assets carrying the connector's source and
/// external id, matched by exact roster email or queued unmatched, with
/// Imported and Assigned events naming the rule.
#[tokio::test]
async fn a_first_sync_creates_matches_and_queues() {
    let repo = repo().await;
    let connector = Arc::new(FakeConnector {
        source: MdmSource::Intune,
        devices: Mutex::new(vec![
            windows("int-1", "SER-100", Some("maya.chen@district.test")),
            windows("int-2", "SER-200", None),
        ]),
    });
    let summary = engine(&repo, connector).run_sync(false).await.unwrap();
    assert_eq!(
        summary,
        MdmSyncSummary {
            fetched: 2,
            created: 2,
            updated: 0,
            matched: 1,
            unmatched: 1
        }
    );

    let a = repo
        .get_asset_by_serial("SER-100")
        .await
        .unwrap()
        .expect("created");
    assert_eq!(a.source, AssetSource::Intune);
    assert_eq!(a.external_id.as_deref(), Some("int-1"));
    assert_eq!(a.asset_type, AssetType::Laptop);
    assert_eq!(a.assigned_user_sourced_id.as_deref(), Some("u-maya"));
    assert_eq!(a.match_state, MatchState::Matched);
    assert_eq!(a.make.as_deref(), Some("Dell"));

    let b = repo.get_asset_by_serial("SER-200").await.unwrap().unwrap();
    assert_eq!(b.match_state, MatchState::Unmatched);

    let events = repo
        .list_events(&AssetEventFilter::for_asset(&a.id), PageRequest::new(10, 0))
        .await
        .unwrap();
    let kinds: Vec<_> = events
        .items
        .iter()
        .map(|e| e.event_type.as_str().to_string())
        .collect();
    assert!(kinds.contains(&"imported".to_string()));
    assert!(kinds.contains(&"assigned".to_string()));
}

/// Re-running converges: no duplicates, and a changed hardware fact lands
/// while an unchanged fleet writes nothing.
#[tokio::test]
async fn a_second_sync_is_idempotent_and_merges_changes() {
    let repo = repo().await;
    let connector = Arc::new(FakeConnector {
        source: MdmSource::Intune,
        devices: Mutex::new(vec![windows(
            "int-1",
            "SER-100",
            Some("maya.chen@district.test"),
        )]),
    });
    let engine = engine(&repo, connector.clone());
    engine.run_sync(false).await.unwrap();

    // Same fleet again: nothing new, nothing duplicated. (last_sync_at always
    // refreshes, so the row counts as updated — the point is no second row.)
    let summary = engine.run_sync(false).await.unwrap();
    assert_eq!(summary.created, 0, "no duplicate rows");
    assert_eq!(repo.count_assets(&AssetFilter::default()).await.unwrap(), 1);

    // The console reports a new OS build; the merge adopts it.
    connector.devices.lock().unwrap()[0].os_version = Some("10.0.26200".into());
    engine.run_sync(false).await.unwrap();
    let a = repo.get_asset_by_serial("SER-100").await.unwrap().unwrap();
    assert_eq!(a.os_version.as_deref(), Some("10.0.26200"));
}

/// A CSV-imported row with the same serial is the same machine: the connector
/// merges into it, adopts the external id, records the merge — and never
/// rewrites the district's own sticker.
#[tokio::test]
async fn a_connector_device_merges_into_an_existing_row_by_serial() {
    let repo = repo().await;
    let mut existing = Asset::new("csv-1");
    existing.serial_number = Some("SER-100".into());
    existing.asset_tag = Some("00123".into());
    existing.source = AssetSource::Csv;
    repo.create_asset(&existing).await.unwrap();

    let mut dev = windows("int-9", "SER-100", None);
    dev.asset_tag = Some("123".into()); // the console's opinion of the sticker

    let connector = Arc::new(FakeConnector {
        source: MdmSource::Intune,
        devices: Mutex::new(vec![dev]),
    });
    let summary = engine(&repo, connector).run_sync(false).await.unwrap();
    assert_eq!(summary.created, 0, "merged, not duplicated");

    let a = repo.get_asset("csv-1").await.unwrap().unwrap();
    assert_eq!(a.external_id.as_deref(), Some("int-9"), "identity adopted");
    assert_eq!(a.asset_tag.as_deref(), Some("00123"), "sticker untouched");

    let events = repo
        .list_events(
            &AssetEventFilter::for_asset("csv-1"),
            PageRequest::new(10, 0),
        )
        .await
        .unwrap();
    assert!(
        events.items.iter().any(|e| {
            e.event_type == AssetEventType::Imported
                && e.payload
                    .as_ref()
                    .is_some_and(|p| p["mergeRule"] == "serial_number")
        }),
        "the merge is recorded with the rule that joined them"
    );
}

/// A human's decision is untouchable: a manually assigned device keeps its
/// person whatever the console says, forever.
#[tokio::test]
async fn a_manual_assignment_survives_the_console() {
    let repo = repo().await;
    let mut existing = Asset::new("m-1");
    existing.serial_number = Some("SER-100".into());
    existing.assigned_user_sourced_id = Some("u-devon".into());
    existing.match_state = MatchState::Manual;
    repo.create_asset(&existing).await.unwrap();

    let connector = Arc::new(FakeConnector {
        source: MdmSource::Jamf,
        devices: Mutex::new(vec![windows(
            "jamf-1",
            "SER-100",
            Some("maya.chen@district.test"),
        )]),
    });
    engine(&repo, connector).run_sync(false).await.unwrap();

    let a = repo.get_asset("m-1").await.unwrap().unwrap();
    assert_eq!(
        a.assigned_user_sourced_id.as_deref(),
        Some("u-devon"),
        "the console does not outrank the human"
    );
    assert_eq!(a.match_state, MatchState::Manual);
}

/// A dry run counts everything and writes nothing.
#[tokio::test]
async fn a_dry_run_writes_nothing() {
    let repo = repo().await;
    let connector = Arc::new(FakeConnector {
        source: MdmSource::Intune,
        devices: Mutex::new(vec![windows("int-1", "SER-100", None)]),
    });
    let summary = engine(&repo, connector).run_sync(true).await.unwrap();
    assert_eq!(summary.created, 1, "counted");
    assert_eq!(
        repo.count_assets(&AssetFilter::default()).await.unwrap(),
        0,
        "not written"
    );
}
