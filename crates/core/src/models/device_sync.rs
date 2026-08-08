//! Google ChromeOS device sync bookkeeping (migration 021).
//!
//! Deliberately separate from [`crate::models::google_sync`], which is the
//! per-*user* Workspace provisioning state from migration 002. The PRD's name
//! `google_sync_state` collides with that table; device sync gets its own.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::str_enum::str_enum;

str_enum! {
    /// Which Directory API collection a cursor tracks.
    pub enum DeviceSyncResource {
        ChromeOsDevices => "chromeosdevices",
        OrgUnits => "orgunits",
        DirectoryUsers => "directory_users",
        IntuneDevices => "intune_devices",
        JamfDevices => "jamf_devices",
    }
}

str_enum! {
    /// Cursor health.
    pub enum DeviceSyncCursorStatus {
        #[default]
        Idle => "idle",
        Running => "running",
        Error => "error",
    }
    with_default
}

str_enum! {
    /// What a run was doing.
    pub enum DeviceSyncMode {
        /// Full listing at `orgUnitPath=/` with `projection=FULL`.
        #[default]
        Full => "full",
        /// Incremental pass since the last successful run.
        Delta => "delta",
        /// Pushing local changes back to the Admin SDK.
        Writeback => "writeback",
    }
    with_default
}

str_enum! {
    /// Terminal (or in-flight) state of a run.
    pub enum DeviceSyncRunStatus {
        Running => "running",
        Succeeded => "succeeded",
        Failed => "failed",
        Cancelled => "cancelled",
    }
}

/// Resumable pagination state for one Directory API collection.
///
/// Rows are never seeded by a migration — the sync engine upserts them. A
/// seed `INSERT` in `021` would re-run on every boot (SQLite has no migration
/// version table) and clobber a live `page_token` mid-pagination.
///
/// There is exactly one `page_token` per `resource`, which is why device
/// listing is a single recursive call at `orgUnitPath=/` rather than a per-OU
/// fan-out: the schema cannot represent N concurrent per-OU cursors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSyncCursor {
    pub resource: DeviceSyncResource,
    /// Mid-pagination resume point. `None` between runs.
    pub page_token: Option<String>,
    pub last_full_sync_at: Option<DateTime<Utc>>,
    pub last_delta_at: Option<DateTime<Utc>>,
    pub status: DeviceSyncCursorStatus,
    pub error_message: Option<String>,
    pub updated_at: DateTime<Utc>,
}

impl DeviceSyncCursor {
    /// A fresh idle cursor for `resource`.
    pub fn idle(resource: DeviceSyncResource) -> Self {
        Self {
            resource,
            page_token: None,
            last_full_sync_at: None,
            last_delta_at: None,
            status: DeviceSyncCursorStatus::Idle,
            error_message: None,
            updated_at: Utc::now(),
        }
    }

    /// True when a previous run stopped mid-pagination and left a resume point.
    pub fn is_resumable(&self) -> bool {
        self.page_token.is_some()
    }
}

/// Counters for a device sync run.
///
/// Every field is `i64` and every column is `BIGINT`. The `as i32` counter
/// binds in `postgres.rs::update_google_sync_run` truncate above 2^31 — this
/// type exists partly so that pattern cannot be copied here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeviceSyncCounters {
    pub devices_seen: i64,
    pub devices_created: i64,
    pub devices_updated: i64,
    pub devices_matched: i64,
    pub devices_unmatched: i64,
    pub api_calls: i64,
    pub throttle_events: i64,
}

impl DeviceSyncCounters {
    /// Fold another set of counters in. Used to accumulate per-page totals.
    pub fn merge(&mut self, other: &DeviceSyncCounters) {
        self.devices_seen += other.devices_seen;
        self.devices_created += other.devices_created;
        self.devices_updated += other.devices_updated;
        self.devices_matched += other.devices_matched;
        self.devices_unmatched += other.devices_unmatched;
        self.api_calls += other.api_calls;
        self.throttle_events += other.throttle_events;
    }
}

/// A row of `google_device_sync_runs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSyncRun {
    pub id: i64,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: DeviceSyncRunStatus,
    pub mode: DeviceSyncMode,
    pub counters: DeviceSyncCounters,
    pub dry_run: bool,
    pub error_message: Option<String>,
}

impl DeviceSyncRun {
    /// True while the run has not reached a terminal state.
    pub fn is_running(&self) -> bool {
        self.status == DeviceSyncRunStatus::Running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_strings_match_the_ddl_comment() {
        assert_eq!(
            DeviceSyncResource::ChromeOsDevices.as_str(),
            "chromeosdevices"
        );
        assert_eq!(DeviceSyncResource::OrgUnits.as_str(), "orgunits");
        assert_eq!(
            DeviceSyncResource::DirectoryUsers.as_str(),
            "directory_users"
        );
    }

    #[test]
    fn every_enum_round_trips() {
        for v in DeviceSyncResource::ALL {
            assert_eq!(&DeviceSyncResource::parse(v.as_str()).unwrap(), v);
        }
        for v in DeviceSyncCursorStatus::ALL {
            assert_eq!(&DeviceSyncCursorStatus::parse(v.as_str()).unwrap(), v);
        }
        for v in DeviceSyncMode::ALL {
            assert_eq!(&DeviceSyncMode::parse(v.as_str()).unwrap(), v);
        }
        for v in DeviceSyncRunStatus::ALL {
            assert_eq!(&DeviceSyncRunStatus::parse(v.as_str()).unwrap(), v);
        }
    }

    #[test]
    fn defaults_match_the_ddl_defaults() {
        assert_eq!(DeviceSyncCursorStatus::default().as_str(), "idle");
        assert_eq!(DeviceSyncMode::default().as_str(), "full");
    }

    #[test]
    fn idle_cursor_has_no_resume_point() {
        let c = DeviceSyncCursor::idle(DeviceSyncResource::ChromeOsDevices);
        assert!(!c.is_resumable());
        assert_eq!(c.status, DeviceSyncCursorStatus::Idle);
    }

    #[test]
    fn cursor_with_page_token_is_resumable() {
        let mut c = DeviceSyncCursor::idle(DeviceSyncResource::ChromeOsDevices);
        c.page_token = Some("tok".to_string());
        assert!(c.is_resumable());
    }

    #[test]
    fn counters_merge_additively() {
        let mut a = DeviceSyncCounters {
            devices_seen: 3,
            api_calls: 1,
            ..Default::default()
        };
        a.merge(&DeviceSyncCounters {
            devices_seen: 4,
            devices_created: 2,
            api_calls: 1,
            ..Default::default()
        });
        assert_eq!(a.devices_seen, 7);
        assert_eq!(a.devices_created, 2);
        assert_eq!(a.api_calls, 2);
    }

    #[test]
    fn counters_hold_values_above_i32_max() {
        let big = i64::from(i32::MAX) + 1;
        let mut c = DeviceSyncCounters::default();
        c.merge(&DeviceSyncCounters {
            devices_seen: big,
            ..Default::default()
        });
        assert_eq!(c.devices_seen, big);
    }
}
