use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::common::RoleType;

/// Status of a sync run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SyncStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

/// A record of a single sync operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SyncRun {
    pub id: i64,
    pub provider: String,
    pub status: SyncStatus,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub users_synced: i64,
    pub orgs_synced: i64,
    pub courses_synced: i64,
    pub classes_synced: i64,
    pub enrollments_synced: i64,
}

/// Filter for querying users.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<RoleType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_sourced_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<String>,
}

/// Aggregated user counts by role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UserCounts {
    pub total: i64,
    pub students: i64,
    pub teachers: i64,
    pub administrators: i64,
    pub other: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn sync_status_serialization() {
        assert_eq!(
            serde_json::to_string(&SyncStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&SyncStatus::Running).unwrap(),
            "\"running\""
        );
        assert_eq!(
            serde_json::to_string(&SyncStatus::Completed).unwrap(),
            "\"completed\""
        );
        assert_eq!(
            serde_json::to_string(&SyncStatus::Failed).unwrap(),
            "\"failed\""
        );
    }

    #[test]
    fn sync_status_round_trip() {
        let values = [
            SyncStatus::Pending,
            SyncStatus::Running,
            SyncStatus::Completed,
            SyncStatus::Failed,
        ];
        for v in &values {
            let json = serde_json::to_string(v).unwrap();
            let back: SyncStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    fn sample_sync_run() -> SyncRun {
        SyncRun {
            id: 1,
            provider: "clever".to_string(),
            status: SyncStatus::Completed,
            started_at: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            completed_at: Some(Utc.with_ymd_and_hms(2025, 1, 15, 12, 5, 0).unwrap()),
            error_message: None,
            users_synced: 150,
            orgs_synced: 3,
            courses_synced: 25,
            classes_synced: 40,
            enrollments_synced: 500,
        }
    }

    #[test]
    fn sync_run_round_trip() {
        let run = sample_sync_run();
        let json = serde_json::to_string(&run).unwrap();
        let back: SyncRun = serde_json::from_str(&json).unwrap();
        assert_eq!(back, run);
    }

    #[test]
    fn sync_run_camel_case_fields() {
        let run = sample_sync_run();
        let json = serde_json::to_string(&run).unwrap();
        assert!(json.contains("\"startedAt\""));
        assert!(json.contains("\"completedAt\""));
        assert!(json.contains("\"usersSynced\""));
        assert!(json.contains("\"orgsSynced\""));
        assert!(json.contains("\"coursesSynced\""));
        assert!(json.contains("\"classesSynced\""));
        assert!(json.contains("\"enrollmentsSynced\""));
        assert!(json.contains("\"errorMessage\"") || !json.contains("errorMessage"));
    }

    #[test]
    fn sync_run_failed_with_error() {
        let run = SyncRun {
            id: 2,
            provider: "classlink".to_string(),
            status: SyncStatus::Failed,
            started_at: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            completed_at: None,
            error_message: Some("Connection timeout".to_string()),
            users_synced: 0,
            orgs_synced: 0,
            courses_synced: 0,
            classes_synced: 0,
            enrollments_synced: 0,
        };
        let json = serde_json::to_string(&run).unwrap();
        let back: SyncRun = serde_json::from_str(&json).unwrap();
        assert_eq!(back.error_message, Some("Connection timeout".to_string()));
        assert_eq!(back.completed_at, None);
    }

    #[test]
    fn user_filter_default() {
        let filter = UserFilter::default();
        assert_eq!(filter.role, None);
        assert_eq!(filter.org_sourced_id, None);
        assert_eq!(filter.grade, None);
    }

    #[test]
    fn user_filter_round_trip() {
        let filter = UserFilter {
            role: Some(RoleType::Student),
            org_sourced_id: Some("org-001".to_string()),
            grade: Some("09".to_string()),
        };
        let json = serde_json::to_string(&filter).unwrap();
        let back: UserFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(back, filter);
    }

    #[test]
    fn user_filter_optional_fields_omitted() {
        let filter = UserFilter::default();
        let json = serde_json::to_string(&filter).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn user_counts_round_trip() {
        let counts = UserCounts {
            total: 150,
            students: 120,
            teachers: 20,
            administrators: 5,
            other: 5,
        };
        let json = serde_json::to_string(&counts).unwrap();
        let back: UserCounts = serde_json::from_str(&json).unwrap();
        assert_eq!(back, counts);
    }
}
