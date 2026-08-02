//! Sync tests.
//!
//! Google is a wiremock server; the four repositories are small in-memory
//! fakes. The fakes exist because the engine takes standalone repository
//! traits — that is the whole reason it does, and these ~200 lines are what
//! the 800-line `MockRepo` would otherwise have cost.

use super::*;

use std::sync::Mutex;

use async_trait::async_trait;
use chalk_core::error::ChalkError;
use chalk_core::models::asset::{
    Asset, AssetEvent, AssetEventFilter, AssetFilter, AssetPatch, AssetRow, NewAssetEvent,
};
use chalk_core::models::common::{RoleType, Status};
use chalk_core::models::device_sync::{DeviceSyncRun, DeviceSyncRunStatus};
use chalk_core::models::page::Page;
use chalk_core::models::sync::UserCounts;
use chalk_core::models::user::User;
use chalk_google_sync::backoff::{RateLimiter, RetryPolicy};
use chalk_google_sync::token::StaticTokenProvider;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DEVICES_PATH: &str = "/admin/directory/v1/customer/my_customer/devices/chromeos";
const OUS_PATH: &str = "/admin/directory/v1/customer/my_customer/orgunits";

// ---------------------------------------------------------------- fakes ---

#[derive(Default)]
struct FakeAssets {
    rows: Mutex<Vec<Asset>>,
    /// Events written through the transactional compound op, kept apart from
    /// `FakeEvents` so a test can tell which path wrote a given event.
    compound_events: Mutex<Vec<NewAssetEvent>>,
}

impl FakeAssets {
    fn with(assets: Vec<Asset>) -> Arc<Self> {
        Arc::new(Self {
            rows: Mutex::new(assets),
            compound_events: Mutex::new(Vec::new()),
        })
    }

    fn all(&self) -> Vec<Asset> {
        self.rows.lock().unwrap().clone()
    }

    fn by_device_id(&self, device_id: &str) -> Option<Asset> {
        self.all()
            .into_iter()
            .find(|a| a.google_device_id.as_deref() == Some(device_id))
    }
}

/// Apply a patch to a row exactly as a backend would, so assertions are about
/// the engine's intent and not about the fake's shortcuts.
fn apply_patch(asset: &mut Asset, patch: &AssetPatch) {
    macro_rules! text_field {
        ($($field:ident),+ $(,)?) => {
            $(match &patch.$field {
                Patch::Set(v) => asset.$field = Some(v.clone()),
                Patch::Clear => asset.$field = None,
                Patch::Unchanged => {}
            })+
        };
    }
    text_field!(
        asset_tag,
        serial_number,
        make,
        model,
        school_org_sourced_id,
        assigned_user_sourced_id,
        org_unit_path,
        google_device_id,
        annotated_user,
        annotated_asset_id,
        os_version,
        last_known_ip,
        funding_source,
        location,
        notes,
    );
    if let Some(v) = patch.asset_type {
        asset.asset_type = v;
    }
    if let Some(v) = patch.status {
        asset.status = v;
    }
    if let Some(v) = patch.source {
        asset.source = v;
    }
    if let Some(v) = patch.match_state {
        asset.match_state = v;
    }
    match &patch.aue_date {
        Patch::Set(v) => asset.aue_date = Some(*v),
        Patch::Clear => asset.aue_date = None,
        Patch::Unchanged => {}
    }
    match &patch.last_sync_at {
        Patch::Set(v) => asset.last_sync_at = Some(*v),
        Patch::Clear => asset.last_sync_at = None,
        Patch::Unchanged => {}
    }
    asset.updated_at = Utc::now();
}

#[async_trait]
impl AssetRepository for FakeAssets {
    async fn create_asset(&self, asset: &Asset) -> Result<()> {
        self.rows.lock().unwrap().push(asset.clone());
        Ok(())
    }

    async fn upsert_asset(&self, asset: &Asset) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        match rows.iter_mut().find(|a| a.id == asset.id) {
            Some(existing) => *existing = asset.clone(),
            None => rows.push(asset.clone()),
        }
        Ok(())
    }

    async fn get_asset(&self, id: &str) -> Result<Option<Asset>> {
        Ok(self.all().into_iter().find(|a| a.id == id))
    }

    async fn get_asset_by_google_device_id(&self, google_device_id: &str) -> Result<Option<Asset>> {
        Ok(self.by_device_id(google_device_id))
    }

    async fn get_asset_by_serial(&self, serial_number: &str) -> Result<Option<Asset>> {
        Ok(self
            .all()
            .into_iter()
            .find(|a| a.serial_number.as_deref() == Some(serial_number)))
    }

    /// The sync engine never reports; a real answer here would be dead code.
    async fn count_assets_by_school_and_status(
        &self,
        _filter: &AssetFilter,
    ) -> Result<Vec<chalk_core::models::asset::AssetGroupCount>> {
        Ok(Vec::new())
    }

    async fn find_assets_by_asset_tag(&self, asset_tag: &str) -> Result<Vec<Asset>> {
        Ok(self
            .all()
            .into_iter()
            .filter(|a| a.asset_tag.as_deref() == Some(asset_tag))
            .collect())
    }

    /// Filters are irrelevant here: the engine only ever asks for everything.
    async fn list_assets(&self, _filter: &AssetFilter, page: PageRequest) -> Result<Page<Asset>> {
        let mut rows = self.all();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        let total = rows.len() as i64;
        let items = rows
            .into_iter()
            .skip(page.offset() as usize)
            .take(page.limit() as usize)
            .collect();
        Ok(Page::new(items, total, page))
    }

    async fn count_assets(&self, _filter: &AssetFilter) -> Result<i64> {
        Ok(self.all().len() as i64)
    }

    /// The roster join is a console concern. The sync engine never renders a
    /// student name, so this fake returns the same window with no context
    /// rather than reimplementing a LEFT JOIN over two more fakes.
    async fn list_assets_with_roster(
        &self,
        filter: &AssetFilter,
        page: PageRequest,
    ) -> Result<Page<AssetRow>> {
        let bare = self.list_assets(filter, page).await?;
        Ok(Page::new(
            bare.items.into_iter().map(AssetRow::bare).collect(),
            bare.total,
            page,
        ))
    }

    async fn update_asset(&self, id: &str, patch: &AssetPatch) -> Result<bool> {
        let mut rows = self.rows.lock().unwrap();
        match rows.iter_mut().find(|a| a.id == id) {
            Some(asset) => {
                apply_patch(asset, patch);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// The sync engine reconciles machine state and never takes this path —
    /// the compound op exists for operator-initiated changes in the console.
    /// Recording the event alongside the patch keeps the fake honest if the
    /// engine ever does start using it.
    async fn apply_patch_with_event(
        &self,
        id: &str,
        patch: &AssetPatch,
        event: &NewAssetEvent,
    ) -> Result<bool> {
        let mut rows = self.rows.lock().unwrap();
        match rows.iter_mut().find(|a| a.id == id) {
            Some(asset) => {
                apply_patch(asset, patch);
                drop(rows);
                self.compound_events.lock().unwrap().push(event.clone());
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

#[derive(Default)]
struct FakeEvents {
    rows: Mutex<Vec<NewAssetEvent>>,
}

impl FakeEvents {
    fn all(&self) -> Vec<NewAssetEvent> {
        self.rows.lock().unwrap().clone()
    }

    fn of_type(&self, event_type: AssetEventType) -> Vec<NewAssetEvent> {
        self.all()
            .into_iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }
}

#[async_trait]
impl AssetEventRepository for FakeEvents {
    async fn append_event(&self, event: &NewAssetEvent) -> Result<i64> {
        let mut rows = self.rows.lock().unwrap();
        rows.push(event.clone());
        Ok(rows.len() as i64)
    }

    async fn list_events(
        &self,
        _filter: &AssetEventFilter,
        _page: PageRequest,
    ) -> Result<Page<AssetEvent>> {
        Err(ChalkError::Sync(
            "list_events is unused by device sync".into(),
        ))
    }
}

#[derive(Default)]
struct FakeState {
    cursor: Mutex<Option<DeviceSyncCursor>>,
    /// Every cursor write in order — pagination durability is a *sequence*
    /// property, so the history is the assertion target, not the final row.
    cursor_writes: Mutex<Vec<DeviceSyncCursor>>,
    runs: Mutex<Vec<DeviceSyncRun>>,
}

impl FakeState {
    fn with_cursor(cursor: DeviceSyncCursor) -> Arc<Self> {
        Arc::new(Self {
            cursor: Mutex::new(Some(cursor)),
            ..Default::default()
        })
    }

    fn writes(&self) -> Vec<DeviceSyncCursor> {
        self.cursor_writes.lock().unwrap().clone()
    }

    fn run(&self) -> DeviceSyncRun {
        self.runs.lock().unwrap()[0].clone()
    }
}

#[async_trait]
impl GoogleDeviceSyncRepository for FakeState {
    async fn get_cursor(&self, resource: DeviceSyncResource) -> Result<Option<DeviceSyncCursor>> {
        Ok(self
            .cursor
            .lock()
            .unwrap()
            .clone()
            .filter(|c| c.resource == resource))
    }

    async fn upsert_cursor(&self, cursor: &DeviceSyncCursor) -> Result<()> {
        *self.cursor.lock().unwrap() = Some(cursor.clone());
        self.cursor_writes.lock().unwrap().push(cursor.clone());
        Ok(())
    }

    async fn start_run(&self, mode: DeviceSyncMode, dry_run: bool) -> Result<DeviceSyncRun> {
        let mut runs = self.runs.lock().unwrap();
        let run = DeviceSyncRun {
            id: runs.len() as i64 + 1,
            started_at: Utc::now(),
            completed_at: None,
            status: DeviceSyncRunStatus::Running,
            mode,
            counters: DeviceSyncCounters::default(),
            dry_run,
            error_message: None,
        };
        runs.push(run.clone());
        Ok(run)
    }

    async fn update_run_counters(&self, id: i64, counters: &DeviceSyncCounters) -> Result<()> {
        if let Some(run) = self.runs.lock().unwrap().iter_mut().find(|r| r.id == id) {
            run.counters = *counters;
        }
        Ok(())
    }

    async fn finish_run(
        &self,
        id: i64,
        status: DeviceSyncRunStatus,
        counters: &DeviceSyncCounters,
        error_message: Option<&str>,
    ) -> Result<()> {
        if let Some(run) = self.runs.lock().unwrap().iter_mut().find(|r| r.id == id) {
            run.status = status;
            run.counters = *counters;
            run.completed_at = Some(Utc::now());
            run.error_message = error_message.map(str::to_string);
        }
        Ok(())
    }

    async fn get_run(&self, id: i64) -> Result<Option<DeviceSyncRun>> {
        Ok(self
            .runs
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .cloned())
    }

    async fn latest_run(&self) -> Result<Option<DeviceSyncRun>> {
        Ok(self.runs.lock().unwrap().last().cloned())
    }

    async fn list_runs(&self, _page: PageRequest) -> Result<Page<DeviceSyncRun>> {
        Err(ChalkError::Sync(
            "list_runs is unused by device sync".into(),
        ))
    }
}

/// The whole reason the engine takes `Arc<dyn UserRepository>`.
struct FakeRoster {
    users: Vec<User>,
}

impl FakeRoster {
    fn new(users: Vec<User>) -> Arc<Self> {
        Arc::new(Self { users })
    }
}

#[async_trait]
impl UserRepository for FakeRoster {
    async fn upsert_user(&self, _user: &User) -> Result<()> {
        Err(ChalkError::Sync("device sync never writes users".into()))
    }

    async fn get_user(&self, sourced_id: &str) -> Result<Option<User>> {
        Ok(self
            .users
            .iter()
            .find(|u| u.sourced_id == sourced_id)
            .cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        Ok(self.users.iter().find(|u| u.username == username).cloned())
    }

    async fn list_users(&self, _filter: &UserFilter) -> Result<Vec<User>> {
        Ok(self.users.clone())
    }

    async fn delete_user(&self, _sourced_id: &str) -> Result<bool> {
        Err(ChalkError::Sync("device sync never deletes users".into()))
    }

    async fn get_user_counts(&self) -> Result<UserCounts> {
        Ok(UserCounts {
            total: self.users.len() as i64,
            students: self.users.len() as i64,
            teachers: 0,
            administrators: 0,
            other: 0,
        })
    }
}

// ------------------------------------------------------------- fixtures ---

fn user(sourced_id: &str, email: &str) -> User {
    User {
        sourced_id: sourced_id.to_string(),
        status: Status::Active,
        date_last_modified: Utc::now(),
        metadata: None,
        username: sourced_id.to_string(),
        user_ids: Vec::new(),
        enabled_user: true,
        given_name: "Test".into(),
        family_name: "User".into(),
        middle_name: None,
        role: RoleType::Student,
        identifier: None,
        email: Some(email.to_string()),
        sms: None,
        phone: None,
        agents: Vec::new(),
        orgs: Vec::new(),
        grades: Vec::new(),
    }
}

fn device(device_id: &str) -> serde_json::Value {
    serde_json::json!({
        "deviceId": device_id,
        "serialNumber": format!("SN-{device_id}"),
        "model": "Acer Chromebook 311",
        "orgUnitPath": "/Students/HS",
        "orgUnitId": "id:hs",
        "status": "ACTIVE",
        "osVersion": "126.0.6478.0",
    })
}

/// Mount the OU tree. Two OUs, one with an `&` in its name — the character
/// that breaks path-based addressing and the reason OUs are keyed by id.
async fn mount_ous(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(OUS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "organizationUnits": [
                {"name": "HS", "orgUnitPath": "/Students/HS", "orgUnitId": "id:hs"},
                {"name": "Arts & Crafts", "orgUnitPath": "/Students/Arts & Crafts",
                 "orgUnitId": "id:arts"}
            ]
        })))
        .mount(server)
        .await;
}

struct Harness {
    server: MockServer,
    assets: Arc<FakeAssets>,
    events: Arc<FakeEvents>,
    state: Arc<FakeState>,
}

impl Harness {
    async fn engine(&self, config: DeviceSyncConfig, roster: Arc<FakeRoster>) -> DeviceSyncEngine {
        let client = ChromeOsClient::new(
            Arc::new(StaticTokenProvider::new("test-token")),
            "my_customer",
        )
        .with_base_url(&self.server.uri())
        .with_retry_policy(RetryPolicy::test_fast())
        .with_rate_limiter(RateLimiter::unlimited());

        DeviceSyncEngine::new(
            self.assets.clone(),
            self.events.clone(),
            self.state.clone(),
            roster,
            client,
            config,
        )
    }
}

fn config() -> DeviceSyncConfig {
    DeviceSyncConfig {
        enabled: true,
        workspace_domain: Some("school.edu".into()),
        ..DeviceSyncConfig::default()
    }
}

async fn harness(existing: Vec<Asset>, state: Arc<FakeState>) -> Harness {
    let server = MockServer::start().await;
    mount_ous(&server).await;
    Harness {
        server,
        assets: FakeAssets::with(existing),
        events: Arc::new(FakeEvents::default()),
        state,
    }
}

// ------------------------------------------------------------ the tests ---

#[tokio::test]
async fn walks_every_page_and_persists_the_cursor_after_each_one() {
    let h = harness(Vec::new(), Arc::new(FakeState::default())).await;

    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .and(query_param("projection", "FULL"))
        .and(query_param("maxResults", "200"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [device("dev-1")],
            "nextPageToken": "page-2"
        })))
        .up_to_n_times(1)
        .mount(&h.server)
        .await;

    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .and(query_param("pageToken", "page-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [device("dev-2")]
        })))
        .mount(&h.server)
        .await;

    let engine = h.engine(config(), FakeRoster::new(Vec::new())).await;
    let summary = engine.run_sync(false).await.unwrap();

    assert_eq!(summary.counters.devices_seen, 2);
    assert_eq!(summary.counters.devices_created, 2);
    assert_eq!(h.assets.all().len(), 2);

    let writes = h.state.writes();
    assert_eq!(
        writes.len(),
        2,
        "one cursor write per page, not one per run — that is what makes a crash resumable"
    );
    assert_eq!(writes[0].page_token.as_deref(), Some("page-2"));
    assert_eq!(writes[0].status, DeviceSyncCursorStatus::Running);
    assert_eq!(writes[1].page_token, None);
    assert_eq!(writes[1].status, DeviceSyncCursorStatus::Idle);
    assert!(writes[1].last_full_sync_at.is_some());
    assert_eq!(h.state.run().status, DeviceSyncRunStatus::Succeeded);
}

#[tokio::test]
async fn a_crashed_run_resumes_mid_pagination_instead_of_restarting() {
    let mut cursor = DeviceSyncCursor::idle(DeviceSyncResource::ChromeOsDevices);
    cursor.page_token = Some("page-2".into());
    cursor.status = DeviceSyncCursorStatus::Error;
    let h = harness(Vec::new(), FakeState::with_cursor(cursor)).await;

    // Only the resumed page is served: a run that started over would 404 the
    // mock and fail this test rather than quietly re-walk 18,000 devices.
    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .and(query_param("pageToken", "page-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [device("dev-2")]
        })))
        .expect(1)
        .mount(&h.server)
        .await;

    let engine = h.engine(config(), FakeRoster::new(Vec::new())).await;
    let summary = engine.run_sync(false).await.unwrap();

    assert_eq!(summary.counters.devices_seen, 1);
    assert_eq!(h.state.writes().last().unwrap().page_token, None);
}

#[tokio::test]
async fn a_failed_page_leaves_the_token_it_failed_on() {
    let h = harness(Vec::new(), Arc::new(FakeState::default())).await;

    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [device("dev-1")],
            "nextPageToken": "page-2"
        })))
        .up_to_n_times(1)
        .mount(&h.server)
        .await;

    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .and(query_param("pageToken", "page-2"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&h.server)
        .await;

    let engine = h.engine(config(), FakeRoster::new(Vec::new())).await;
    assert!(engine.run_sync(false).await.is_err());

    let last = h.state.writes().pop().unwrap();
    assert_eq!(last.page_token.as_deref(), Some("page-2"));
    assert_eq!(last.status, DeviceSyncCursorStatus::Error);
    assert!(last.error_message.is_some());

    let run = h.state.run();
    assert_eq!(run.status, DeviceSyncRunStatus::Failed);
    assert_eq!(
        run.counters.devices_created, 1,
        "devices ingested before the failure stay ingested and counted"
    );
}

#[tokio::test]
async fn rule_1_matches_on_annotated_user_and_records_the_rule() {
    let h = harness(Vec::new(), Arc::new(FakeState::default())).await;

    let mut dev = device("dev-1");
    dev["annotatedUser"] = serde_json::json!("JDoe@School.edu");
    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [dev]
        })))
        .mount(&h.server)
        .await;

    let roster = FakeRoster::new(vec![user("u-jdoe", "jdoe@school.edu")]);
    let engine = h.engine(config(), roster).await;
    let summary = engine.run_sync(false).await.unwrap();

    assert_eq!(summary.counters.devices_matched, 1);
    assert_eq!(summary.counters.devices_unmatched, 0);

    let asset = h.assets.by_device_id("dev-1").unwrap();
    assert_eq!(asset.assigned_user_sourced_id.as_deref(), Some("u-jdoe"));
    assert_eq!(asset.match_state, MatchState::Matched);
    assert_eq!(asset.source, AssetSource::Google);

    let assigned = h.events.of_type(AssetEventType::Assigned);
    assert_eq!(assigned.len(), 1);
    assert_eq!(assigned[0].actor, "system:google-sync");
    let payload = assigned[0].payload.clone().unwrap();
    assert_eq!(payload["rule"], "annotated_user");
    assert_eq!(payload["userSourcedId"], "u-jdoe");
}

#[tokio::test]
async fn rule_2_matches_on_the_most_recent_managed_sign_in() {
    let h = harness(Vec::new(), Arc::new(FakeState::default())).await;

    let mut dev = device("dev-1");
    dev["annotatedUser"] = serde_json::json!("Cart 4");
    dev["recentUsers"] = serde_json::json!([
        {"type": "USER_TYPE_UNMANAGED", "email": "someone@gmail.com"},
        {"type": "USER_TYPE_MANAGED", "email": "mrivera@school.edu"}
    ]);
    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [dev]
        })))
        .mount(&h.server)
        .await;

    let roster = FakeRoster::new(vec![user("u-mrivera", "mrivera@school.edu")]);
    let engine = h.engine(config(), roster).await;
    engine.run_sync(false).await.unwrap();

    let asset = h.assets.by_device_id("dev-1").unwrap();
    assert_eq!(asset.assigned_user_sourced_id.as_deref(), Some("u-mrivera"));
    let payload = h.events.of_type(AssetEventType::Assigned)[0]
        .payload
        .clone()
        .unwrap();
    assert_eq!(payload["rule"], "recent_user");
}

#[tokio::test]
async fn rule_3_merges_into_an_existing_row_by_serial_rather_than_duplicating() {
    let mut existing = Asset::new("asset-csv-1");
    existing.serial_number = Some("SN-dev-1".into());
    existing.source = AssetSource::Csv;
    existing.match_state = MatchState::Unmatched;
    existing.purchase_cost_cents = Some(24_999);
    existing.funding_source = Some("Title IV".into());

    let h = harness(vec![existing], Arc::new(FakeState::default())).await;

    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [device("dev-1")]
        })))
        .mount(&h.server)
        .await;

    let engine = h.engine(config(), FakeRoster::new(Vec::new())).await;
    let summary = engine.run_sync(false).await.unwrap();

    assert_eq!(summary.counters.devices_created, 0);
    assert_eq!(summary.counters.devices_updated, 1);
    assert_eq!(
        h.assets.all().len(),
        1,
        "the CSV row must not be duplicated"
    );

    let asset = h.assets.by_device_id("dev-1").unwrap();
    assert_eq!(asset.id, "asset-csv-1");
    assert_eq!(
        asset.purchase_cost_cents,
        Some(24_999),
        "Chalk stays authoritative for purchase data across a merge"
    );
    assert_eq!(asset.funding_source.as_deref(), Some("Title IV"));
    assert_eq!(asset.os_version.as_deref(), Some("126.0.6478.0"));

    let merges: Vec<_> = h
        .events
        .of_type(AssetEventType::Imported)
        .into_iter()
        .filter(|e| {
            e.payload
                .as_ref()
                .is_some_and(|p| p.get("mergeRule").is_some())
        })
        .collect();
    assert_eq!(merges.len(), 1);
    assert_eq!(
        merges[0].payload.clone().unwrap()["mergeRule"],
        "serial_number"
    );
}

#[tokio::test]
async fn rule_3_merges_by_asset_tag_and_leading_zeros_survive() {
    let mut existing = Asset::new("asset-csv-2");
    existing.asset_tag = Some("00123".into());
    existing.source = AssetSource::Csv;
    existing.match_state = MatchState::Unmatched;

    let h = harness(vec![existing], Arc::new(FakeState::default())).await;

    let mut dev = device("dev-9");
    dev["serialNumber"] = serde_json::json!("SN-unknown");
    // The spreadsheet text guard the incumbent writes; the zeros are the data.
    dev["annotatedAssetId"] = serde_json::json!("'00123");
    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [dev]
        })))
        .mount(&h.server)
        .await;

    let engine = h.engine(config(), FakeRoster::new(Vec::new())).await;
    engine.run_sync(false).await.unwrap();

    assert_eq!(h.assets.all().len(), 1);
    let asset = h.assets.by_device_id("dev-9").unwrap();
    assert_eq!(asset.id, "asset-csv-2");
    assert_eq!(
        asset.asset_tag.as_deref(),
        Some("00123"),
        "tag 00123 must never round-trip to 123"
    );
    assert_eq!(asset.annotated_asset_id.as_deref(), Some("00123"));
}

#[tokio::test]
async fn a_new_google_device_keeps_its_leading_zero_tag() {
    let h = harness(Vec::new(), Arc::new(FakeState::default())).await;

    let mut dev = device("dev-1");
    dev["annotatedAssetId"] = serde_json::json!("00042");
    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [dev]
        })))
        .mount(&h.server)
        .await;

    let engine = h.engine(config(), FakeRoster::new(Vec::new())).await;
    engine.run_sync(false).await.unwrap();

    let asset = h.assets.by_device_id("dev-1").unwrap();
    assert_eq!(asset.asset_tag.as_deref(), Some("00042"));
}

#[tokio::test]
async fn a_manual_assignment_is_never_overridden() {
    let mut existing = Asset::new("asset-manual");
    existing.google_device_id = Some("dev-1".into());
    existing.serial_number = Some("SN-dev-1".into());
    existing.match_state = MatchState::Manual;
    existing.assigned_user_sourced_id = Some("u-teacher".into());

    let h = harness(vec![existing], Arc::new(FakeState::default())).await;

    let mut dev = device("dev-1");
    dev["annotatedUser"] = serde_json::json!("jdoe@school.edu");
    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [dev]
        })))
        .mount(&h.server)
        .await;

    let roster = FakeRoster::new(vec![user("u-jdoe", "jdoe@school.edu")]);
    let engine = h.engine(config(), roster).await;
    let summary = engine.run_sync(false).await.unwrap();

    let asset = h.assets.by_device_id("dev-1").unwrap();
    assert_eq!(
        asset.assigned_user_sourced_id.as_deref(),
        Some("u-teacher"),
        "a human's assignment outranks every rule"
    );
    assert_eq!(asset.match_state, MatchState::Manual);
    assert!(h.events.of_type(AssetEventType::Assigned).is_empty());
    assert_eq!(summary.counters.devices_matched, 0);
    assert_eq!(summary.counters.devices_unmatched, 0);
    // Hardware fields still merge — only the assignment is protected.
    assert_eq!(asset.annotated_user.as_deref(), Some("jdoe@school.edu"));
}

#[tokio::test]
async fn an_ignored_device_stays_out_of_the_queue() {
    let mut existing = Asset::new("asset-cart");
    existing.google_device_id = Some("dev-1".into());
    existing.match_state = MatchState::Ignored;

    let h = harness(vec![existing], Arc::new(FakeState::default())).await;

    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [device("dev-1")]
        })))
        .mount(&h.server)
        .await;

    let engine = h.engine(config(), FakeRoster::new(Vec::new())).await;
    let summary = engine.run_sync(false).await.unwrap();

    assert_eq!(summary.counters.devices_unmatched, 0);
    assert_eq!(
        h.assets.by_device_id("dev-1").unwrap().match_state,
        MatchState::Ignored
    );
}

#[tokio::test]
async fn an_unmatched_device_lands_in_the_queue() {
    let h = harness(Vec::new(), Arc::new(FakeState::default())).await;

    let mut dev = device("dev-1");
    dev["annotatedUser"] = serde_json::json!("Library cart 4");
    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [dev]
        })))
        .mount(&h.server)
        .await;

    let roster = FakeRoster::new(vec![user("u-jdoe", "jdoe@school.edu")]);
    let engine = h.engine(config(), roster).await;
    let summary = engine.run_sync(false).await.unwrap();

    assert_eq!(summary.counters.devices_unmatched, 1);
    let asset = h.assets.by_device_id("dev-1").unwrap();
    assert_eq!(asset.match_state, MatchState::Unmatched);
    assert!(asset.assigned_user_sourced_id.is_none());
}

#[tokio::test]
async fn a_removed_annotation_unassigns_an_automatic_match_but_keeps_the_row() {
    let mut existing = Asset::new("asset-auto");
    existing.google_device_id = Some("dev-1".into());
    existing.match_state = MatchState::Matched;
    existing.assigned_user_sourced_id = Some("u-jdoe".into());

    let h = harness(vec![existing], Arc::new(FakeState::default())).await;

    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [device("dev-1")]
        })))
        .mount(&h.server)
        .await;

    let roster = FakeRoster::new(vec![user("u-jdoe", "jdoe@school.edu")]);
    let engine = h.engine(config(), roster).await;
    engine.run_sync(false).await.unwrap();

    let asset = h.assets.by_device_id("dev-1").unwrap();
    assert!(asset.assigned_user_sourced_id.is_none());
    assert_eq!(asset.match_state, MatchState::Unmatched);
    assert_eq!(h.events.of_type(AssetEventType::Unassigned).len(), 1);
}

#[tokio::test]
async fn a_second_run_over_unchanged_devices_writes_nothing() {
    let h = harness(Vec::new(), Arc::new(FakeState::default())).await;

    let mut dev = device("dev-1");
    dev["annotatedUser"] = serde_json::json!("jdoe@school.edu");
    dev["autoUpdateExpiration"] = serde_json::json!("1906502400000");
    dev["lastSync"] = serde_json::json!("2026-07-20T13:45:00Z");
    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [dev]
        })))
        .mount(&h.server)
        .await;

    let roster = FakeRoster::new(vec![user("u-jdoe", "jdoe@school.edu")]);
    let engine = h.engine(config(), roster).await;

    let first = engine.run_sync(false).await.unwrap();
    assert_eq!(first.counters.devices_created, 1);
    let events_after_first = h.events.all().len();

    let second = engine.run_sync(false).await.unwrap();
    assert_eq!(second.counters.devices_created, 0);
    assert_eq!(
        second.counters.devices_updated, 0,
        "matching is idempotent: an unchanged device is not a write"
    );
    assert_eq!(second.counters.devices_matched, 1);
    assert_eq!(
        h.events.all().len(),
        events_after_first,
        "and it is not an event either"
    );
}

#[tokio::test]
async fn a_deprovisioned_device_is_the_one_status_google_owns() {
    let mut existing = Asset::new("asset-1");
    existing.google_device_id = Some("dev-1".into());
    existing.status = AssetStatus::Active;
    existing.match_state = MatchState::Unmatched;

    let h = harness(vec![existing], Arc::new(FakeState::default())).await;

    let mut dev = device("dev-1");
    dev["status"] = serde_json::json!("DEPROVISIONED");
    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [dev]
        })))
        .mount(&h.server)
        .await;

    let engine = h.engine(config(), FakeRoster::new(Vec::new())).await;
    engine.run_sync(false).await.unwrap();

    assert_eq!(
        h.assets.by_device_id("dev-1").unwrap().status,
        AssetStatus::Deprovisioned
    );
    assert_eq!(h.events.of_type(AssetEventType::Deprovisioned).len(), 1);
}

#[tokio::test]
async fn a_locally_set_status_survives_the_sync() {
    let mut existing = Asset::new("asset-1");
    existing.google_device_id = Some("dev-1".into());
    existing.status = AssetStatus::Repair;
    existing.match_state = MatchState::Unmatched;

    let h = harness(vec![existing], Arc::new(FakeState::default())).await;

    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [device("dev-1")]
        })))
        .mount(&h.server)
        .await;

    let engine = h.engine(config(), FakeRoster::new(Vec::new())).await;
    engine.run_sync(false).await.unwrap();

    assert_eq!(
        h.assets.by_device_id("dev-1").unwrap().status,
        AssetStatus::Repair,
        "Google reporting ACTIVE must not clear a repair ticket"
    );
}

#[tokio::test]
async fn org_units_are_keyed_by_id_so_ampersands_cannot_break_the_path() {
    let h = harness(Vec::new(), Arc::new(FakeState::default())).await;

    let mut dev = device("dev-1");
    dev["orgUnitId"] = serde_json::json!("id:arts");
    // Google's own device payload can carry a stale or mangled path; the id is
    // what resolves.
    dev["orgUnitPath"] = serde_json::json!("/Students/Arts");
    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [dev]
        })))
        .mount(&h.server)
        .await;

    let engine = h.engine(config(), FakeRoster::new(Vec::new())).await;
    engine.run_sync(false).await.unwrap();

    assert_eq!(
        h.assets
            .by_device_id("dev-1")
            .unwrap()
            .org_unit_path
            .as_deref(),
        Some("/Students/Arts & Crafts")
    );
}

#[tokio::test]
async fn the_org_unit_filter_narrows_locally_without_a_second_call() {
    let h = harness(Vec::new(), Arc::new(FakeState::default())).await;

    let mut out_of_scope = device("dev-2");
    out_of_scope["orgUnitId"] = serde_json::json!("id:arts");
    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .and(query_param("orgUnitPath", "/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [device("dev-1"), out_of_scope]
        })))
        .expect(1)
        .mount(&h.server)
        .await;

    let cfg = DeviceSyncConfig {
        org_unit_filter: Some("/Students/HS".into()),
        ..config()
    };
    let engine = h.engine(cfg, FakeRoster::new(Vec::new())).await;
    let summary = engine.run_sync(false).await.unwrap();

    assert_eq!(summary.counters.devices_seen, 1);
    assert!(h.assets.by_device_id("dev-2").is_none());
}

#[tokio::test]
async fn a_dry_run_reads_google_and_writes_nothing() {
    let mut cursor = DeviceSyncCursor::idle(DeviceSyncResource::ChromeOsDevices);
    cursor.page_token = Some("real-run-token".into());
    let h = harness(Vec::new(), FakeState::with_cursor(cursor)).await;

    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .and(query_param("pageToken", "real-run-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [device("dev-1")]
        })))
        .mount(&h.server)
        .await;

    let engine = h.engine(config(), FakeRoster::new(Vec::new())).await;
    let summary = engine.run_sync(true).await.unwrap();

    assert!(summary.dry_run);
    assert_eq!(
        summary.counters.devices_created, 1,
        "a preview still reports what it would create"
    );
    assert!(h.assets.all().is_empty(), "and creates none of it");
    assert!(h.events.all().is_empty());
    assert!(
        h.state.writes().is_empty(),
        "a preview must never consume a real run's resume point"
    );
    assert_eq!(h.state.run().status, DeviceSyncRunStatus::Succeeded);
}

#[tokio::test]
async fn throttle_events_and_api_calls_reach_the_run_row() {
    let h = harness(Vec::new(), Arc::new(FakeState::default())).await;

    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": {"errors": [{"reason": "rateLimitExceeded", "message": "slow down"}]}
        })))
        .up_to_n_times(1)
        .mount(&h.server)
        .await;

    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chromeosdevices": [device("dev-1")]
        })))
        .mount(&h.server)
        .await;

    let engine = h.engine(config(), FakeRoster::new(Vec::new())).await;
    let summary = engine.run_sync(false).await.unwrap();

    assert_eq!(summary.counters.throttle_events, 1);
    assert_eq!(
        summary.counters.api_calls, 2,
        "one OU listing plus one device page"
    );
    assert_eq!(h.state.run().counters.throttle_events, 1);
}

#[tokio::test]
async fn the_page_size_config_reaches_the_wire() {
    let h = harness(Vec::new(), Arc::new(FakeState::default())).await;

    Mock::given(method("GET"))
        .and(path(DEVICES_PATH))
        .and(query_param("maxResults", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&h.server)
        .await;

    let client = ChromeOsClient::new(
        Arc::new(StaticTokenProvider::new("test-token")),
        "my_customer",
    )
    .with_base_url(&h.server.uri())
    .with_retry_policy(RetryPolicy::test_fast())
    .with_rate_limiter(RateLimiter::unlimited())
    .with_max_results(50);

    let engine = DeviceSyncEngine::new(
        h.assets.clone(),
        h.events.clone(),
        h.state.clone(),
        FakeRoster::new(Vec::new()),
        client,
        config(),
    );
    engine.run_sync(false).await.unwrap();
}
