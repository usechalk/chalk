//! Active Directory sync models for user provisioning tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Status of a user's AD sync state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdSyncStatus {
    Pending,
    Synced,
    Error,
    Disabled,
}

/// Per-user AD sync state tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdSyncUserState {
    pub user_sourced_id: String,
    pub ad_dn: String,
    pub ad_sam_account_name: String,
    pub ad_upn: Option<String>,
    pub ad_ou: String,
    pub field_hash: String,
    pub sync_status: AdSyncStatus,
    pub initial_password: Option<String>,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Status of an AD Sync run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdSyncRunStatus {
    Running,
    Completed,
    Failed,
}

/// An AD Sync run record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdSyncRun {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: AdSyncRunStatus,
    pub users_created: i64,
    pub users_updated: i64,
    pub users_disabled: i64,
    pub users_skipped: i64,
    pub errors: i64,
    pub error_details: Option<String>,
    pub dry_run: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn ad_sync_status_serialization() {
        assert_eq!(
            serde_json::to_string(&AdSyncStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&AdSyncStatus::Synced).unwrap(),
            "\"synced\""
        );
        assert_eq!(
            serde_json::to_string(&AdSyncStatus::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&AdSyncStatus::Disabled).unwrap(),
            "\"disabled\""
        );
    }

    #[test]
    fn ad_sync_run_status_serialization() {
        assert_eq!(
            serde_json::to_string(&AdSyncRunStatus::Running).unwrap(),
            "\"running\""
        );
        assert_eq!(
            serde_json::to_string(&AdSyncRunStatus::Completed).unwrap(),
            "\"completed\""
        );
        assert_eq!(
            serde_json::to_string(&AdSyncRunStatus::Failed).unwrap(),
            "\"failed\""
        );
    }

    #[test]
    fn ad_sync_user_state_round_trip() {
        let state = AdSyncUserState {
            user_sourced_id: "user-001".to_string(),
            ad_dn: "CN=John Doe,OU=Students,DC=example,DC=com".to_string(),
            ad_sam_account_name: "jdoe".to_string(),
            ad_upn: Some("jdoe@example.com".to_string()),
            ad_ou: "OU=Students,DC=example,DC=com".to_string(),
            field_hash: "abc123def456".to_string(),
            sync_status: AdSyncStatus::Synced,
            initial_password: None,
            last_synced_at: Some(Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap()),
            created_at: Utc.with_ymd_and_hms(2025, 5, 1, 12, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap(),
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: AdSyncUserState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn ad_sync_run_round_trip() {
        let run = AdSyncRun {
            id: "run-001".to_string(),
            started_at: Utc.with_ymd_and_hms(2025, 6, 1, 2, 0, 0).unwrap(),
            completed_at: Some(Utc.with_ymd_and_hms(2025, 6, 1, 2, 5, 0).unwrap()),
            status: AdSyncRunStatus::Completed,
            users_created: 50,
            users_updated: 10,
            users_disabled: 3,
            users_skipped: 5,
            errors: 0,
            error_details: None,
            dry_run: false,
        };
        let json = serde_json::to_string(&run).unwrap();
        let back: AdSyncRun = serde_json::from_str(&json).unwrap();
        assert_eq!(back, run);
    }

    #[test]
    fn ad_sync_run_with_errors() {
        let run = AdSyncRun {
            id: "run-002".to_string(),
            started_at: Utc.with_ymd_and_hms(2025, 6, 1, 2, 0, 0).unwrap(),
            completed_at: Some(Utc.with_ymd_and_hms(2025, 6, 1, 2, 1, 0).unwrap()),
            status: AdSyncRunStatus::Failed,
            users_created: 5,
            users_updated: 0,
            users_disabled: 0,
            users_skipped: 0,
            errors: 2,
            error_details: Some("LDAP connection timeout".to_string()),
            dry_run: false,
        };
        assert_eq!(run.status, AdSyncRunStatus::Failed);
        assert!(run.error_details.is_some());
    }
}
