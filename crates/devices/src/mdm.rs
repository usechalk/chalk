//! The generic MDM connector seam (WS-14).
//!
//! # One inventory, many consoles
//!
//! The ChromeOS sync in [`crate::sync`] proved the shape: a remote console is
//! authoritative for hardware facts, Chalk is authoritative for assignment and
//! status, and a human's decision (`match_state = manual`/`ignored`) is
//! untouchable by any rule forever. This module generalizes exactly that
//! discipline over a normalized [`MdmDevice`], so an Intune Windows fleet and
//! a Jamf iPad cart land in the same `assets` table the Chromebooks live in —
//! same matching, same unmatched queue, same reports, same tickets.
//!
//! # Read-only against the MDM
//!
//! [`MdmConnector`] has no write method, deliberately. The Google connector
//! earned write-back only after the change-set/preview/commit machinery
//! existed to make it defensible; Intune and Jamf will follow the same road,
//! not skip it.
//!
//! # Identity
//!
//! A connector device keys to an asset by `(source, external_id)` first, then
//! by serial, then by normalized asset tag — the same ladder the ChromeOS
//! sync uses with `google_device_id`. Merging into an existing CSV/manual row
//! is recorded as the moment two identities became one.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chalk_core::db::repository::{AssetEventRepository, AssetRepository, UserRepository};
use chalk_core::error::Result;
use chalk_core::models::asset::{
    ActorKind, Asset, AssetEventType, AssetFilter, AssetPatch, AssetSource, AssetStatus, AssetType,
    MatchState, NewAssetEvent, Patch,
};
use chalk_core::models::page::PageRequest;
use chalk_core::models::sync::UserFilter;
use chrono::Utc;

use crate::matching::{normalize_asset_tag, RosterIndex};

/// Who the audit log names for every row this engine writes.
pub const MDM_SYNC_ACTOR: &str = "system:mdm-sync";

/// Which console a connector talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdmSource {
    Intune,
    Jamf,
}

impl MdmSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            MdmSource::Intune => "intune",
            MdmSource::Jamf => "jamf",
        }
    }

    /// The `assets.source` value rows from this connector carry.
    pub fn asset_source(&self) -> AssetSource {
        match self {
            MdmSource::Intune => AssetSource::Intune,
            MdmSource::Jamf => AssetSource::Jamf,
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "intune" => Some(MdmSource::Intune),
            "jamf" => Some(MdmSource::Jamf),
            _ => None,
        }
    }
}

/// A device as every connector reports it — the narrow waist of WS-14.
///
/// Fields a console does not know stay `None` and the merge leaves the
/// existing value alone; the engine never writes an absence over a fact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdmDevice {
    /// The device's id in its own console. Required — it is the join key.
    pub external_id: String,
    pub serial_number: Option<String>,
    /// The asset tag as the console reports it, un-normalized.
    pub asset_tag: Option<String>,
    pub make: Option<String>,
    pub model: Option<String>,
    pub os_version: Option<String>,
    /// The email of the person the console says holds the device. Exact
    /// roster match or nothing — rule 1 of the ChromeOS ladder, which is the
    /// only rule that translates across consoles.
    pub user_email: Option<String>,
    /// What kind of thing this is, as the connector understands it.
    pub asset_type: AssetType,
}

/// A read-only view of one MDM console's device list.
#[async_trait]
pub trait MdmConnector: Send + Sync {
    fn source(&self) -> MdmSource;

    /// Every device the console will show us, fully paged.
    async fn fetch_devices(&self) -> Result<Vec<MdmDevice>>;
}

/// What one run did, for the CLI and the job log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MdmSyncSummary {
    pub fetched: i64,
    pub created: i64,
    pub updated: i64,
    pub matched: i64,
    pub unmatched: i64,
}

/// The generic sync engine. Construction mirrors [`crate::sync::DeviceSyncEngine`];
/// the connector replaces the ChromeOS client.
pub struct MdmSyncEngine {
    assets: Arc<dyn AssetRepository>,
    events: Arc<dyn AssetEventRepository>,
    roster: Arc<dyn UserRepository>,
    connector: Arc<dyn MdmConnector>,
}

/// In-memory index over the fleet, keyed the way the resolution ladder reads.
#[derive(Default)]
struct MdmAssetIndex {
    rows: HashMap<String, Asset>,
    /// `external_id → asset id`, only for rows from this connector's source.
    by_external: HashMap<String, String>,
    by_serial: HashMap<String, String>,
    by_tag: HashMap<String, String>,
}

impl MdmAssetIndex {
    fn insert(&mut self, source: AssetSource, asset: Asset) {
        if asset.source == source {
            if let Some(ext) = &asset.external_id {
                self.by_external.insert(ext.clone(), asset.id.clone());
            }
        }
        if let Some(serial) = &asset.serial_number {
            self.by_serial
                .insert(serial.to_ascii_lowercase(), asset.id.clone());
        }
        if let Some(tag) = &asset.asset_tag {
            if let Some(norm) = normalize_asset_tag(tag) {
                self.by_tag.insert(norm, asset.id.clone());
            }
        }
        self.rows.insert(asset.id.clone(), asset);
    }

    /// external_id → serial → tag, returning how the row was found so a merge
    /// can say which identity joined it.
    fn resolve(&self, device: &MdmDevice, tag: Option<&str>) -> Option<(&Asset, &'static str)> {
        if let Some(id) = self.by_external.get(&device.external_id) {
            return self.rows.get(id).map(|a| (a, "external_id"));
        }
        if let Some(serial) = device.serial_number.as_deref() {
            if let Some(id) = self.by_serial.get(&serial.to_ascii_lowercase()) {
                return self.rows.get(id).map(|a| (a, "serial_number"));
            }
        }
        if let Some(tag) = tag {
            if let Some(id) = self.by_tag.get(tag) {
                return self.rows.get(id).map(|a| (a, "asset_tag"));
            }
        }
        None
    }
}

impl MdmSyncEngine {
    pub fn new(
        assets: Arc<dyn AssetRepository>,
        events: Arc<dyn AssetEventRepository>,
        roster: Arc<dyn UserRepository>,
        connector: Arc<dyn MdmConnector>,
    ) -> Self {
        Self {
            assets,
            events,
            roster,
            connector,
        }
    }

    pub async fn run_sync(&self, dry_run: bool) -> Result<MdmSyncSummary> {
        let source = self.connector.source();
        let devices = self.connector.fetch_devices().await?;

        // Roster and fleet, loaded once — the walk makes no per-device query.
        let users = self.roster.list_users(&UserFilter::default()).await?;
        let roster = RosterIndex::build(&users);
        let mut index = MdmAssetIndex::default();
        let page = self
            .assets
            .list_assets(&AssetFilter::default(), PageRequest::new(i64::MAX, 0))
            .await?;
        for asset in page.items {
            index.insert(source.asset_source(), asset);
        }

        let mut summary = MdmSyncSummary {
            fetched: devices.len() as i64,
            ..Default::default()
        };

        for device in &devices {
            let tag = device.asset_tag.as_deref().and_then(normalize_asset_tag);
            let user_sourced_id = device
                .user_email
                .as_deref()
                .and_then(|e| roster.lookup(e.trim()))
                .map(str::to_string);

            let existing = index
                .resolve(device, tag.as_deref())
                .map(|(a, rule)| (a.clone(), rule));

            match existing {
                None => {
                    self.create_asset(
                        source,
                        device,
                        tag.as_deref(),
                        user_sourced_id.as_deref(),
                        &mut index,
                        &mut summary,
                        dry_run,
                    )
                    .await?;
                }
                Some((asset, found_by)) => {
                    self.update_existing(
                        source,
                        device,
                        asset,
                        found_by,
                        tag.as_deref(),
                        user_sourced_id.as_deref(),
                        &mut index,
                        &mut summary,
                        dry_run,
                    )
                    .await?;
                }
            }
        }
        Ok(summary)
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_asset(
        &self,
        source: MdmSource,
        device: &MdmDevice,
        tag: Option<&str>,
        user_sourced_id: Option<&str>,
        index: &mut MdmAssetIndex,
        summary: &mut MdmSyncSummary,
        dry_run: bool,
    ) -> Result<()> {
        let mut asset = Asset::new(uuid::Uuid::new_v4().to_string());
        asset.asset_type = device.asset_type;
        asset.source = source.asset_source();
        asset.external_id = Some(device.external_id.clone());
        asset.serial_number = device.serial_number.clone();
        asset.make = device.make.clone();
        asset.model = device.model.clone();
        asset.os_version = device.os_version.clone();
        asset.asset_tag = tag.map(str::to_string);
        asset.annotated_asset_id = tag.map(str::to_string);
        asset.annotated_user = device.user_email.clone();
        asset.last_sync_at = Some(Utc::now());
        asset.status = AssetStatus::Active;

        match user_sourced_id {
            Some(sid) => {
                asset.assigned_user_sourced_id = Some(sid.to_string());
                asset.match_state = MatchState::Matched;
                summary.matched += 1;
            }
            None => {
                asset.match_state = MatchState::Unmatched;
                summary.unmatched += 1;
            }
        }
        summary.created += 1;

        if !dry_run {
            self.assets.upsert_asset(&asset).await?;
            self.events
                .append_event(&NewAssetEvent {
                    asset_id: asset.id.clone(),
                    actor: MDM_SYNC_ACTOR.to_string(),
                    actor_kind: ActorKind::System,
                    event_type: AssetEventType::Imported,
                    payload: Some(serde_json::json!({
                        "source": source.as_str(),
                        "externalId": device.external_id,
                    })),
                })
                .await?;
            if let Some(sid) = user_sourced_id {
                self.events
                    .append_event(&mdm_match_event(&asset.id, device, sid))
                    .await?;
            }
        }
        index.insert(source.asset_source(), asset);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_existing(
        &self,
        source: MdmSource,
        device: &MdmDevice,
        existing: Asset,
        found_by: &'static str,
        tag: Option<&str>,
        user_sourced_id: Option<&str>,
        index: &mut MdmAssetIndex,
        summary: &mut MdmSyncSummary,
        dry_run: bool,
    ) -> Result<()> {
        let mut patch = AssetPatch::default();
        let mut events: Vec<NewAssetEvent> = Vec::new();

        // ---- Fields the console is authoritative for --------------------
        set_if_changed(
            &mut patch.external_id,
            Some(&device.external_id),
            existing.external_id.as_deref(),
        );
        set_if_changed(
            &mut patch.serial_number,
            device.serial_number.as_deref(),
            existing.serial_number.as_deref(),
        );
        set_if_changed(
            &mut patch.make,
            device.make.as_deref(),
            existing.make.as_deref(),
        );
        set_if_changed(
            &mut patch.model,
            device.model.as_deref(),
            existing.model.as_deref(),
        );
        set_if_changed(
            &mut patch.os_version,
            device.os_version.as_deref(),
            existing.os_version.as_deref(),
        );
        set_if_changed(
            &mut patch.annotated_user,
            device.user_email.as_deref(),
            existing.annotated_user.as_deref(),
        );
        patch.last_sync_at = Patch::Set(Utc::now());

        // `asset_type` is deliberately never patched here: on an existing row
        // it is the district's classification, not a hardware fact — a CSV row
        // filed as "chromebook" stays whatever the district called it.

        // The sticker rule, verbatim from the ChromeOS sync: adopt the
        // console's tag only into emptiness, never over what the district
        // printed.
        if existing.asset_tag.is_none() {
            if let Some(tag) = tag {
                patch.asset_tag = Patch::Set(tag.to_string());
            }
        }

        // Merging into a row that did not come from this console is the
        // moment two identities became one — worth a record.
        if existing.external_id.is_none() && found_by != "external_id" {
            events.push(NewAssetEvent {
                asset_id: existing.id.clone(),
                actor: MDM_SYNC_ACTOR.to_string(),
                actor_kind: ActorKind::System,
                event_type: AssetEventType::Imported,
                payload: Some(serde_json::json!({
                    "source": source.as_str(),
                    "mergeRule": found_by,
                    "externalId": device.external_id,
                })),
            });
        }

        // ---- Assignment: a human always wins ----------------------------
        let human_owned = matches!(
            existing.match_state,
            MatchState::Manual | MatchState::Ignored
        );
        if human_owned {
            // Untouchable, forever. Neither a match nor a queue item.
        } else if let Some(sid) = user_sourced_id {
            summary.matched += 1;
            if existing.assigned_user_sourced_id.as_deref() != Some(sid) {
                patch.assigned_user_sourced_id = Patch::Set(sid.to_string());
                events.push(mdm_match_event(&existing.id, device, sid));
            }
            if existing.match_state != MatchState::Matched {
                patch.match_state = Some(MatchState::Matched);
            }
        } else {
            summary.unmatched += 1;
            if existing.assigned_user_sourced_id.is_some() {
                patch.assigned_user_sourced_id = Patch::Clear;
                events.push(NewAssetEvent {
                    asset_id: existing.id.clone(),
                    actor: MDM_SYNC_ACTOR.to_string(),
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
        if changed {
            summary.updated += 1;
        }
        if !dry_run {
            if changed {
                self.assets.update_asset(&existing.id, &patch).await?;
            }
            for event in &events {
                self.events.append_event(event).await?;
            }
        }

        // Keep the index consistent so a second device with the same serial
        // in this run sees the merged state.
        let mut merged = existing;
        if let Patch::Set(v) = &patch.external_id {
            merged.external_id = Some(v.clone());
        }
        if let Patch::Set(v) = &patch.serial_number {
            merged.serial_number = Some(v.clone());
        }
        if let Patch::Set(v) = &patch.asset_tag {
            merged.asset_tag = Some(v.clone());
        }
        if !human_owned {
            match user_sourced_id {
                Some(sid) => {
                    merged.assigned_user_sourced_id = Some(sid.to_string());
                    merged.match_state = MatchState::Matched;
                }
                None => {
                    merged.assigned_user_sourced_id = None;
                    merged.match_state = MatchState::Unmatched;
                }
            }
        }
        index.insert(source.asset_source(), merged);
        Ok(())
    }
}

/// Rule 1 is the only rule that crosses consoles: the MDM names a user email
/// and the roster has exactly that address.
fn mdm_match_event(asset_id: &str, device: &MdmDevice, sourced_id: &str) -> NewAssetEvent {
    NewAssetEvent {
        asset_id: asset_id.to_string(),
        actor: MDM_SYNC_ACTOR.to_string(),
        actor_kind: ActorKind::System,
        event_type: AssetEventType::Assigned,
        payload: Some(serde_json::json!({
            "rule": "annotated_user",
            "matchedEmail": device.user_email,
            "userSourcedId": sourced_id,
        })),
    }
}

/// `Patch::Set` only when the remote has a value and it differs — an absent
/// remote field never erases a local fact.
fn set_if_changed(slot: &mut Patch<String>, remote: Option<&str>, local: Option<&str>) {
    if let Some(value) = remote {
        if local != Some(value) {
            *slot = Patch::Set(value.to_string());
        }
    }
}

#[cfg(test)]
mod tests;
