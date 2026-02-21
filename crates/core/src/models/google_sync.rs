use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Status of a user's Google Workspace sync state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GoogleSyncStatus {
    Pending,
    Synced,
    Error,
    Suspended,
}

/// Per-user Google Workspace sync state tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GoogleSyncUserState {
    pub user_sourced_id: String,
    pub google_id: Option<String>,
    pub google_email: Option<String>,
    pub google_ou: Option<String>,
    pub field_hash: String,
    pub sync_status: GoogleSyncStatus,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A Google Workspace sync run record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GoogleSyncRun {
    pub id: i64,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: GoogleSyncRunStatus,
    pub users_created: i64,
    pub users_updated: i64,
    pub users_suspended: i64,
    pub ous_created: i64,
    pub dry_run: bool,
    pub error_message: Option<String>,
}

/// Status of a Google Sync run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GoogleSyncRunStatus {
    Running,
    Completed,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn google_sync_status_serialization() {
        assert_eq!(
            serde_json::to_string(&GoogleSyncStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&GoogleSyncStatus::Synced).unwrap(),
            "\"synced\""
        );
        assert_eq!(
            serde_json::to_string(&GoogleSyncStatus::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&GoogleSyncStatus::Suspended).unwrap(),
            "\"suspended\""
        );
    }

    #[test]
    fn google_sync_run_status_serialization() {
        assert_eq!(
            serde_json::to_string(&GoogleSyncRunStatus::Running).unwrap(),
            "\"running\""
        );
        assert_eq!(
            serde_json::to_string(&GoogleSyncRunStatus::Completed).unwrap(),
            "\"completed\""
        );
        assert_eq!(
            serde_json::to_string(&GoogleSyncRunStatus::Failed).unwrap(),
            "\"failed\""
        );
    }

    #[test]
    fn google_sync_user_state_round_trip() {
        let state = GoogleSyncUserState {
            user_sourced_id: "user-001".to_string(),
            google_id: Some("112233".to_string()),
            google_email: Some("jdoe@school.edu".to_string()),
            google_ou: Some("/Students/HS/09".to_string()),
            field_hash: "abc123".to_string(),
            sync_status: GoogleSyncStatus::Synced,
            last_synced_at: Some(Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap()),
            created_at: Utc.with_ymd_and_hms(2025, 5, 1, 12, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap(),
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: GoogleSyncUserState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn google_sync_run_round_trip() {
        let run = GoogleSyncRun {
            id: 1,
            started_at: Utc.with_ymd_and_hms(2025, 6, 1, 2, 0, 0).unwrap(),
            completed_at: Some(Utc.with_ymd_and_hms(2025, 6, 1, 2, 5, 0).unwrap()),
            status: GoogleSyncRunStatus::Completed,
            users_created: 50,
            users_updated: 10,
            users_suspended: 3,
            ous_created: 5,
            dry_run: false,
            error_message: None,
        };
        let json = serde_json::to_string(&run).unwrap();
        let back: GoogleSyncRun = serde_json::from_str(&json).unwrap();
        assert_eq!(back, run);
    }

    #[test]
    fn google_sync_run_dry_run() {
        let run = GoogleSyncRun {
            id: 2,
            started_at: Utc.with_ymd_and_hms(2025, 6, 1, 2, 0, 0).unwrap(),
            completed_at: Some(Utc.with_ymd_and_hms(2025, 6, 1, 2, 1, 0).unwrap()),
            status: GoogleSyncRunStatus::Completed,
            users_created: 0,
            users_updated: 0,
            users_suspended: 0,
            ous_created: 0,
            dry_run: true,
            error_message: None,
        };
        assert!(run.dry_run);
    }
}
