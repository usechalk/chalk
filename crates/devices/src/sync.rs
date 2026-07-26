//! ChromeOS fleet sync orchestration.
//!
//! Shape mirrors `chalk_google_sync::sync::GoogleSyncEngine::run_sync`: open a
//! run row, execute, close it Succeeded or Failed with counts. Two things are
//! new, and both come from the incumbent's scars:
//!
//! - **The cursor is persisted after every page.** A run that dies at device
//!   18,000 resumes at device 18,000. The incumbent restarts the whole 20k
//!   walk, because its Redis set is a cache, not a cursor.
//! - **The merge is field-level.** Google owns hardware, OS, OU and AUE;
//!   Chalk owns assignment, status and the purchase/warranty/funding block. A
//!   sync that clobbered rows would delete the data districts type in by hand,
//!   which is the data they trust least to a sync.
//!
//! Nothing here writes to Google. The client has no write method to call.

use std::collections::HashMap;
use std::sync::Arc;

use chalk_core::config::DeviceSyncConfig;
use chalk_core::db::repository::{
    AssetEventRepository, AssetRepository, GoogleDeviceSyncRepository, UserRepository,
};
use chalk_core::error::Result;
use chalk_core::models::asset::{
    ActorKind, Asset, AssetEventType, AssetFilter, AssetPatch, AssetSource, AssetStatus, AssetType,
    MatchState, NewAssetEvent, Patch,
};
use chalk_core::models::device_sync::{
    DeviceSyncCounters, DeviceSyncCursor, DeviceSyncCursorStatus, DeviceSyncMode,
    DeviceSyncResource, DeviceSyncRunStatus,
};
use chalk_core::models::page::{PageRequest, MAX_PAGE_LIMIT};
use chalk_core::models::sync::UserFilter;
use chalk_google_sync::chromeos::{ChromeOsClient, ChromeOsDevice};
use chrono::Utc;
use tracing::{info, warn};

use crate::matching::{
    match_device_to_user, normalize_asset_tag, MatchRule, RosterIndex, UserMatch,
};

/// The actor recorded on every row this engine writes.
pub const SYNC_ACTOR: &str = "system:google-sync";

/// Outcome of one sync run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSyncSummary {
    /// `google_device_sync_runs.id`.
    pub run_id: i64,
    pub counters: DeviceSyncCounters,
    pub dry_run: bool,
}

/// Ingests the ChromeOS estate into `assets` and attaches roster users.
///
/// Takes four standalone repository traits rather than `ChalkRepository`: a
/// device test then needs a small fake roster instead of the 800-line mock
/// written to test user provisioning.
pub struct DeviceSyncEngine {
    assets: Arc<dyn AssetRepository>,
    events: Arc<dyn AssetEventRepository>,
    state: Arc<dyn GoogleDeviceSyncRepository>,
    roster: Arc<dyn UserRepository>,
    client: ChromeOsClient,
    config: DeviceSyncConfig,
}

/// Everything loaded once per run, before the fleet walk starts.
struct RunContext {
    roster: RosterIndex,
    /// `orgUnitId → canonical orgUnitPath`. Keyed by id because OU *paths*
    /// break on `&` and `+`; the id is stable and safe.
    ou_paths: HashMap<String, String>,
    assets: AssetIndex,
}

/// In-memory view of the assets that already exist, so the fleet walk needs no
/// per-device query. Three keys, matching the ladder's rule 3.
#[derive(Default)]
struct AssetIndex {
    rows: HashMap<String, Asset>,
    by_device_id: HashMap<String, String>,
    by_serial: HashMap<String, String>,
    by_tag: HashMap<String, String>,
}

impl AssetIndex {
    fn insert(&mut self, asset: Asset) {
        if let Some(id) = &asset.google_device_id {
            self.by_device_id.insert(id.clone(), asset.id.clone());
        }
        if let Some(serial) = &asset.serial_number {
            self.by_serial
                .insert(serial.to_ascii_lowercase(), asset.id.clone());
        }
        if let Some(tag) = &asset.asset_tag {
            self.by_tag
                .insert(tag.to_ascii_lowercase(), asset.id.clone());
        }
        self.rows.insert(asset.id.clone(), asset);
    }

    /// Resolve a device to an already-tracked asset: `deviceId` first (the
    /// join key for anything this sync created), then serial, then asset tag —
    /// the two keys that merge a Google device into a row a CSV import or a
    /// human created.
    fn resolve(
        &self,
        device: &ChromeOsDevice,
        tag: Option<&str>,
    ) -> Option<(&Asset, Option<MatchRule>)> {
        if let Some(id) = self.by_device_id.get(&device.device_id) {
            return self.rows.get(id).map(|a| (a, None));
        }
        if let Some(serial) = device.serial_number.as_deref() {
            if let Some(id) = self.by_serial.get(&serial.to_ascii_lowercase()) {
                return self
                    .rows
                    .get(id)
                    .map(|a| (a, Some(MatchRule::SerialNumber)));
            }
        }
        if let Some(tag) = tag {
            if let Some(id) = self.by_tag.get(&tag.to_ascii_lowercase()) {
                return self.rows.get(id).map(|a| (a, Some(MatchRule::AssetTag)));
            }
        }
        None
    }
}

/// Everything derived from one device before the create/update fork: its
/// canonical OU path, its cleaned asset tag, and its roster match.
struct ResolvedDevice {
    ou_path: Option<String>,
    tag: Option<String>,
    user_match: Option<UserMatch>,
}

/// What happened to one device, folded into the run counters.
#[derive(Default)]
struct DeviceOutcome {
    created: bool,
    updated: bool,
    matched: bool,
    unmatched: bool,
}

impl DeviceSyncEngine {
    pub fn new(
        assets: Arc<dyn AssetRepository>,
        events: Arc<dyn AssetEventRepository>,
        state: Arc<dyn GoogleDeviceSyncRepository>,
        roster: Arc<dyn UserRepository>,
        client: ChromeOsClient,
        config: DeviceSyncConfig,
    ) -> Self {
        Self {
            assets,
            events,
            state,
            roster,
            client,
            config,
        }
    }

    /// Run a full sync.
    ///
    /// `dry_run` still reads from Google — the API surface is read-only, so a
    /// preview costs nothing but time — and writes nothing but the run row.
    /// In particular it does **not** touch the cursor: a preview must never
    /// consume a real run's resume point.
    pub async fn run_sync(&self, dry_run: bool) -> Result<DeviceSyncSummary> {
        let run = self.state.start_run(DeviceSyncMode::Full, dry_run).await?;
        let run_id = run.id;
        info!(run_id, dry_run, "starting ChromeOS device sync");

        let mut counters = DeviceSyncCounters::default();
        match self.execute(run_id, dry_run, &mut counters).await {
            Ok(()) => {
                self.absorb_client_counters(&mut counters);
                self.state
                    .finish_run(run_id, DeviceSyncRunStatus::Succeeded, &counters, None)
                    .await?;
                info!(
                    run_id,
                    seen = counters.devices_seen,
                    created = counters.devices_created,
                    updated = counters.devices_updated,
                    matched = counters.devices_matched,
                    unmatched = counters.devices_unmatched,
                    api_calls = counters.api_calls,
                    throttle_events = counters.throttle_events,
                    dry_run,
                    "ChromeOS device sync completed"
                );
                Ok(DeviceSyncSummary {
                    run_id,
                    counters,
                    dry_run,
                })
            }
            Err(e) => {
                let message = e.to_string();
                self.absorb_client_counters(&mut counters);
                warn!(run_id, error = %message, "ChromeOS device sync failed");
                self.state
                    .finish_run(
                        run_id,
                        DeviceSyncRunStatus::Failed,
                        &counters,
                        Some(&message),
                    )
                    .await?;
                Err(e)
            }
        }
    }

    /// Copy the client's request and throttle tallies into the run counters.
    fn absorb_client_counters(&self, counters: &mut DeviceSyncCounters) {
        counters.api_calls = self.client.api_calls() as i64;
        counters.throttle_events = self.client.throttle_events() as i64;
    }

    async fn execute(
        &self,
        run_id: i64,
        dry_run: bool,
        counters: &mut DeviceSyncCounters,
    ) -> Result<()> {
        let mut context = self.load_context().await?;

        // A page token left by an earlier run is a resume point regardless of
        // how that run ended — that is the whole point of persisting it.
        let prior = self
            .state
            .get_cursor(DeviceSyncResource::ChromeOsDevices)
            .await?;
        let mut page_token = prior.as_ref().and_then(|c| c.page_token.clone());
        if page_token.is_some() {
            info!(run_id, "resuming device pagination from the stored cursor");
        }

        loop {
            let page = match self.client.list_devices(page_token.as_deref(), None).await {
                Ok(page) => page,
                Err(e) => {
                    // Keep the token we failed on so the next run retries this
                    // page rather than the whole fleet.
                    if !dry_run {
                        self.persist_cursor(
                            prior.as_ref(),
                            page_token.clone(),
                            DeviceSyncCursorStatus::Error,
                            Some(e.to_string()),
                        )
                        .await?;
                    }
                    return Err(e);
                }
            };

            for device in &page.devices {
                let Some(outcome) = self.process_device(device, &mut context, dry_run).await?
                else {
                    continue;
                };
                counters.devices_seen += 1;
                counters.devices_created += i64::from(outcome.created);
                counters.devices_updated += i64::from(outcome.updated);
                counters.devices_matched += i64::from(outcome.matched);
                counters.devices_unmatched += i64::from(outcome.unmatched);
            }

            page_token = page.next_page_token.clone();

            if !dry_run {
                let status = if page_token.is_some() {
                    DeviceSyncCursorStatus::Running
                } else {
                    DeviceSyncCursorStatus::Idle
                };
                self.persist_cursor(prior.as_ref(), page_token.clone(), status, None)
                    .await?;
                self.absorb_client_counters(counters);
                self.state.update_run_counters(run_id, counters).await?;
            }

            if page_token.is_none() {
                break;
            }
        }

        Ok(())
    }

    /// Write the cursor row, carrying forward the timestamps of the previous
    /// one and stamping `last_full_sync_at` when the walk completes.
    async fn persist_cursor(
        &self,
        prior: Option<&DeviceSyncCursor>,
        page_token: Option<String>,
        status: DeviceSyncCursorStatus,
        error_message: Option<String>,
    ) -> Result<()> {
        let now = Utc::now();
        let finished = page_token.is_none() && status == DeviceSyncCursorStatus::Idle;
        let cursor = DeviceSyncCursor {
            resource: DeviceSyncResource::ChromeOsDevices,
            page_token,
            last_full_sync_at: if finished {
                Some(now)
            } else {
                prior.and_then(|c| c.last_full_sync_at)
            },
            last_delta_at: prior.and_then(|c| c.last_delta_at),
            status,
            error_message,
            updated_at: now,
        };
        self.state.upsert_cursor(&cursor).await
    }

    /// Load the roster index, the OU tree and the existing asset rows — the
    /// three passes ARCHITECTURE §5.6 budgets, done once per run rather than
    /// once per device.
    async fn load_context(&self) -> Result<RunContext> {
        let users = self.roster.list_users(&UserFilter::default()).await?;
        let roster = RosterIndex::build(&users);

        let mut ou_paths = HashMap::new();
        for ou in self.client.list_org_units().await? {
            if let Some(id) = ou.org_unit_id {
                ou_paths.insert(id, ou.org_unit_path);
            }
        }

        let mut assets = AssetIndex::default();
        let mut offset = 0_i64;
        loop {
            let page = self
                .assets
                .list_assets(
                    &AssetFilter::default(),
                    PageRequest::new(MAX_PAGE_LIMIT, offset),
                )
                .await?;
            let fetched = page.items.len() as i64;
            let next = page.next_offset();
            for asset in page.items {
                assets.insert(asset);
            }
            match next {
                Some(next) if fetched > 0 => offset = next,
                _ => break,
            }
        }

        info!(
            roster_users = roster.len(),
            org_units = ou_paths.len(),
            existing_assets = assets.rows.len(),
            "device sync context loaded"
        );

        Ok(RunContext {
            roster,
            ou_paths,
            assets,
        })
    }

    /// Ingest one device. Returns `None` when the device is out of the
    /// configured OU scope and was not considered at all.
    async fn process_device(
        &self,
        device: &ChromeOsDevice,
        context: &mut RunContext,
        dry_run: bool,
    ) -> Result<Option<DeviceOutcome>> {
        let ou_path = self.resolve_ou_path(device, &context.ou_paths);
        if !self.in_scope(ou_path.as_deref()) {
            return Ok(None);
        }

        let tag = device
            .annotated_asset_id
            .as_deref()
            .and_then(normalize_asset_tag);
        let user_match = match_device_to_user(
            device,
            &context.roster,
            self.config.workspace_domain.as_deref(),
        );

        let existing = context
            .assets
            .resolve(device, tag.as_deref())
            .map(|(asset, rule)| (asset.clone(), rule));

        let resolved = ResolvedDevice {
            ou_path,
            tag,
            user_match,
        };

        match existing {
            Some((asset, merge_rule)) => {
                self.update_existing(device, asset, merge_rule, &resolved, context, dry_run)
                    .await
            }
            None => self.create_asset(device, &resolved, context, dry_run).await,
        }
    }

    /// OU identity comes from `orgUnitId` when Google supplies one: OU *paths*
    /// break on `&` and `+`, so the id is the only stable key.
    fn resolve_ou_path(
        &self,
        device: &ChromeOsDevice,
        ou_paths: &HashMap<String, String>,
    ) -> Option<String> {
        device
            .org_unit_id
            .as_deref()
            .and_then(|id| ou_paths.get(id).cloned())
            .or_else(|| device.org_unit_path.clone())
    }

    /// Apply `org_unit_filter` locally. There is one root listing and one
    /// cursor; scoping is a filter over what came back, never a narrower call.
    fn in_scope(&self, ou_path: Option<&str>) -> bool {
        let Some(filter) = self.config.org_unit_filter.as_deref() else {
            return true;
        };
        let filter = filter.trim_end_matches('/');
        if filter.is_empty() {
            return true;
        }
        match ou_path {
            Some(path) => {
                let path = path.trim_end_matches('/');
                path == filter || path.starts_with(&format!("{filter}/"))
            }
            None => false,
        }
    }

    async fn create_asset(
        &self,
        device: &ChromeOsDevice,
        resolved: &ResolvedDevice,
        context: &mut RunContext,
        dry_run: bool,
    ) -> Result<Option<DeviceOutcome>> {
        let ResolvedDevice {
            ou_path,
            tag,
            user_match,
        } = resolved;
        let mut asset = Asset::new(uuid::Uuid::new_v4().to_string());
        asset.asset_type = AssetType::Chromebook;
        asset.source = AssetSource::Google;
        asset.google_device_id = Some(device.device_id.clone());
        asset.serial_number = device.serial_number.clone();
        asset.model = device.model.clone();
        asset.org_unit_path = ou_path.clone();
        asset.annotated_user = device.annotated_user.clone();
        asset.annotated_asset_id = tag.clone();
        asset.asset_tag = tag.clone();
        asset.os_version = device
            .os_version
            .clone()
            .or_else(|| device.platform_version.clone());
        asset.aue_date = device.aue_date();
        asset.last_sync_at = device.last_sync;
        asset.last_known_ip = device.last_known_ip().map(str::to_string);
        asset.status = if device.is_deprovisioned() {
            AssetStatus::Deprovisioned
        } else {
            AssetStatus::Active
        };

        match user_match {
            Some(m) => {
                asset.assigned_user_sourced_id = Some(m.sourced_id.clone());
                asset.match_state = MatchState::Matched;
            }
            None => asset.match_state = MatchState::Unmatched,
        }

        if !dry_run {
            self.assets.upsert_asset(&asset).await?;
            self.events
                .append_event(&NewAssetEvent {
                    asset_id: asset.id.clone(),
                    actor: SYNC_ACTOR.to_string(),
                    actor_kind: ActorKind::System,
                    event_type: AssetEventType::Imported,
                    payload: Some(serde_json::json!({
                        "source": "google",
                        "googleDeviceId": device.device_id,
                    })),
                })
                .await?;
            if let Some(m) = user_match {
                self.append_match_event(&asset.id, device, m).await?;
            }
        }

        let outcome = DeviceOutcome {
            created: true,
            updated: false,
            matched: user_match.is_some(),
            unmatched: user_match.is_none(),
        };
        context.assets.insert(asset);
        Ok(Some(outcome))
    }

    async fn update_existing(
        &self,
        device: &ChromeOsDevice,
        existing: Asset,
        merge_rule: Option<MatchRule>,
        resolved: &ResolvedDevice,
        context: &mut RunContext,
        dry_run: bool,
    ) -> Result<Option<DeviceOutcome>> {
        let ResolvedDevice {
            ou_path,
            tag,
            user_match,
        } = resolved;
        let mut patch = AssetPatch::default();
        let mut events: Vec<NewAssetEvent> = Vec::new();

        // ---- Fields Google is authoritative for -------------------------
        set_if_changed(
            &mut patch.google_device_id,
            Some(&device.device_id),
            existing.google_device_id.as_deref(),
        );
        set_if_changed(
            &mut patch.serial_number,
            device.serial_number.as_deref(),
            existing.serial_number.as_deref(),
        );
        set_if_changed(
            &mut patch.model,
            device.model.as_deref(),
            existing.model.as_deref(),
        );
        set_if_changed(
            &mut patch.org_unit_path,
            ou_path.as_deref(),
            existing.org_unit_path.as_deref(),
        );
        set_if_changed(
            &mut patch.annotated_user,
            device.annotated_user.as_deref(),
            existing.annotated_user.as_deref(),
        );
        set_if_changed(
            &mut patch.annotated_asset_id,
            tag.as_deref(),
            existing.annotated_asset_id.as_deref(),
        );
        let os_version = device
            .os_version
            .as_deref()
            .or(device.platform_version.as_deref());
        set_if_changed(
            &mut patch.os_version,
            os_version,
            existing.os_version.as_deref(),
        );
        set_if_changed(
            &mut patch.last_known_ip,
            device.last_known_ip(),
            existing.last_known_ip.as_deref(),
        );
        if let Some(aue) = device.aue_date() {
            if existing.aue_date != Some(aue) {
                patch.aue_date = Patch::Set(aue);
            }
        }
        if let Some(last_sync) = device.last_sync {
            if existing.last_sync_at != Some(last_sync) {
                patch.last_sync_at = Patch::Set(last_sync);
            }
        }

        // `asset_tag` is Chalk's, not Google's: it is what the district's
        // stickers say. Adopt Google's value only when there is nothing to
        // overwrite — and never rewrite it, so `00123` cannot become `123`.
        if existing.asset_tag.is_none() {
            if let Some(tag) = tag.as_deref() {
                patch.asset_tag = Patch::Set(tag.to_string());
            }
        }

        // Status is Chalk's, with exactly one exception: Google observing a
        // device as deprovisioned is ground truth Chalk cannot see.
        if device.is_deprovisioned() && existing.status != AssetStatus::Deprovisioned {
            patch.status = Some(AssetStatus::Deprovisioned);
            events.push(NewAssetEvent {
                asset_id: existing.id.clone(),
                actor: SYNC_ACTOR.to_string(),
                actor_kind: ActorKind::System,
                event_type: AssetEventType::Deprovisioned,
                payload: Some(serde_json::json!({ "observedFrom": "google" })),
            });
        }

        // A Google device merging into a CSV/manual row is worth a record: it
        // is the moment two identities became one.
        if existing.google_device_id.is_none() {
            if let Some(rule) = merge_rule {
                events.push(NewAssetEvent {
                    asset_id: existing.id.clone(),
                    actor: SYNC_ACTOR.to_string(),
                    actor_kind: ActorKind::System,
                    event_type: AssetEventType::Imported,
                    payload: Some(serde_json::json!({
                        "source": "google",
                        "mergeRule": rule.as_str(),
                        "googleDeviceId": device.device_id,
                    })),
                });
            }
        }

        // ---- Assignment: a human always wins ----------------------------
        let human_owned = matches!(
            existing.match_state,
            MatchState::Manual | MatchState::Ignored
        );
        let mut matched = false;
        let mut unmatched = false;

        if human_owned {
            // Manual and ignored devices keep their assignment forever. They
            // are neither a match nor a queue item.
        } else if let Some(m) = user_match {
            matched = true;
            if existing.assigned_user_sourced_id.as_deref() != Some(m.sourced_id.as_str()) {
                patch.assigned_user_sourced_id = Patch::Set(m.sourced_id.clone());
                events.push(match_event(&existing.id, device, m));
            }
            if existing.match_state != MatchState::Matched {
                patch.match_state = Some(MatchState::Matched);
            }
        } else {
            unmatched = true;
            if existing.assigned_user_sourced_id.is_some() {
                patch.assigned_user_sourced_id = Patch::Clear;
                events.push(NewAssetEvent {
                    asset_id: existing.id.clone(),
                    actor: SYNC_ACTOR.to_string(),
                    actor_kind: ActorKind::System,
                    event_type: AssetEventType::Unassigned,
                    payload: Some(serde_json::json!({ "reason": "no_rule_matched" })),
                });
            }
            if existing.match_state != MatchState::Unmatched {
                patch.match_state = Some(MatchState::Unmatched);
            }
        }

        let changed = !patch.is_empty();
        if changed && !dry_run {
            self.assets.update_asset(&existing.id, &patch).await?;
        }
        if !dry_run {
            for event in &events {
                self.events.append_event(event).await?;
            }
        }

        // Keep the in-memory row consistent with what was written, so a second
        // device carrying the same serial in one run sees the merged state.
        let mut merged = existing;
        apply_locally(
            &mut merged,
            &patch,
            device,
            user_match.as_ref(),
            human_owned,
        );
        context.assets.insert(merged);

        Ok(Some(DeviceOutcome {
            created: false,
            updated: changed,
            matched,
            unmatched,
        }))
    }

    async fn append_match_event(
        &self,
        asset_id: &str,
        device: &ChromeOsDevice,
        m: &UserMatch,
    ) -> Result<()> {
        self.events
            .append_event(&match_event(asset_id, device, m))
            .await?;
        Ok(())
    }
}

/// The `assigned` event every automatic match writes. The payload names the
/// rule that fired — without it, a wrong assignment across 20k devices is
/// undiagnosable.
fn match_event(asset_id: &str, device: &ChromeOsDevice, m: &UserMatch) -> NewAssetEvent {
    NewAssetEvent {
        asset_id: asset_id.to_string(),
        actor: SYNC_ACTOR.to_string(),
        actor_kind: ActorKind::System,
        event_type: AssetEventType::Assigned,
        payload: Some(serde_json::json!({
            "rule": m.rule.as_str(),
            "matchedEmail": m.email,
            "userSourcedId": m.sourced_id,
            "googleDeviceId": device.device_id,
        })),
    }
}

/// Set a nullable text column when Google has a value and it differs.
///
/// Google having *no* value never clears a column: an absent field in a
/// response is far more often a projection or permission artifact than a
/// deletion, and clearing on absence is how a sync silently empties an
/// inventory.
fn set_if_changed(target: &mut Patch<String>, incoming: Option<&str>, current: Option<&str>) {
    if let Some(value) = incoming {
        if current != Some(value) {
            *target = Patch::Set(value.to_string());
        }
    }
}

/// Mirror an applied patch onto the in-memory copy of the row.
fn apply_locally(
    asset: &mut Asset,
    patch: &AssetPatch,
    device: &ChromeOsDevice,
    user_match: Option<&UserMatch>,
    human_owned: bool,
) {
    if asset.google_device_id.is_none() {
        asset.google_device_id = Some(device.device_id.clone());
    }
    if let Patch::Set(tag) = &patch.asset_tag {
        asset.asset_tag = Some(tag.clone());
    }
    if let Some(status) = patch.status {
        asset.status = status;
    }
    if let Some(state) = patch.match_state {
        asset.match_state = state;
    }
    if !human_owned {
        asset.assigned_user_sourced_id = user_match.map(|m| m.sourced_id.clone());
    }
}

#[cfg(test)]
mod tests;
