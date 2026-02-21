//! Telemetry data models — anonymous, privacy-safe report structures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An anonymous telemetry report. Contains only non-identifying, aggregate data.
/// Never includes: school names, PII, credentials, or IP addresses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelemetryReport {
    /// Chalk software version (e.g. "0.1.0").
    pub chalk_version: String,
    /// Unique identifier for this report.
    pub report_id: Uuid,
    /// SIS provider type (e.g. "powerschool"), never a school name.
    pub sis_provider: String,
    /// Bucketed student count for privacy (e.g. "101-500").
    pub student_count_bucket: String,
    /// Database driver in use ("sqlite" or "postgres").
    pub db_driver: String,
    /// List of enabled feature names (e.g. ["idp", "google_sync"]).
    pub features_enabled: Vec<String>,
    /// Number of sync operations in the last 24 hours.
    pub sync_count_24h: u32,
    /// Uptime in hours since last restart.
    pub uptime_hours: u32,
    /// Timestamp when this report was generated.
    pub reported_at: DateTime<Utc>,
}

/// Buckets a raw student count into a privacy-safe range string.
pub fn bucket_student_count(count: u64) -> String {
    match count {
        0 => "0".to_string(),
        1..=100 => "1-100".to_string(),
        101..=500 => "101-500".to_string(),
        501..=1000 => "501-1000".to_string(),
        1001..=5000 => "1001-5000".to_string(),
        5001..=10000 => "5001-10000".to_string(),
        _ => "10000+".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_student_count_zero() {
        assert_eq!(bucket_student_count(0), "0");
    }

    #[test]
    fn bucket_student_count_small() {
        assert_eq!(bucket_student_count(1), "1-100");
        assert_eq!(bucket_student_count(50), "1-100");
        assert_eq!(bucket_student_count(100), "1-100");
    }

    #[test]
    fn bucket_student_count_medium() {
        assert_eq!(bucket_student_count(101), "101-500");
        assert_eq!(bucket_student_count(500), "101-500");
    }

    #[test]
    fn bucket_student_count_large() {
        assert_eq!(bucket_student_count(501), "501-1000");
        assert_eq!(bucket_student_count(1000), "501-1000");
    }

    #[test]
    fn bucket_student_count_xlarge() {
        assert_eq!(bucket_student_count(1001), "1001-5000");
        assert_eq!(bucket_student_count(5000), "1001-5000");
    }

    #[test]
    fn bucket_student_count_xxlarge() {
        assert_eq!(bucket_student_count(5001), "5001-10000");
        assert_eq!(bucket_student_count(10000), "5001-10000");
    }

    #[test]
    fn bucket_student_count_huge() {
        assert_eq!(bucket_student_count(10001), "10000+");
        assert_eq!(bucket_student_count(999_999), "10000+");
    }

    #[test]
    fn report_serializes_to_json() {
        let report = TelemetryReport {
            chalk_version: "0.1.0".to_string(),
            report_id: Uuid::nil(),
            sis_provider: "powerschool".to_string(),
            student_count_bucket: "101-500".to_string(),
            db_driver: "sqlite".to_string(),
            features_enabled: vec!["idp".to_string(), "google_sync".to_string()],
            sync_count_24h: 3,
            uptime_hours: 48,
            reported_at: DateTime::parse_from_rfc3339("2026-01-15T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };

        let json = serde_json::to_string(&report).expect("should serialize");
        assert!(json.contains("\"chalk_version\":\"0.1.0\""));
        assert!(json.contains("\"sis_provider\":\"powerschool\""));
        assert!(json.contains("\"student_count_bucket\":\"101-500\""));
        assert!(json.contains("\"db_driver\":\"sqlite\""));
        assert!(json.contains("\"sync_count_24h\":3"));
        assert!(json.contains("\"uptime_hours\":48"));
        assert!(json.contains("\"idp\""));
        assert!(json.contains("\"google_sync\""));
    }

    #[test]
    fn report_roundtrip_serde() {
        let report = TelemetryReport {
            chalk_version: "0.2.0".to_string(),
            report_id: Uuid::new_v4(),
            sis_provider: "infinite_campus".to_string(),
            student_count_bucket: "5001-10000".to_string(),
            db_driver: "postgres".to_string(),
            features_enabled: vec!["idp".to_string()],
            sync_count_24h: 12,
            uptime_hours: 720,
            reported_at: Utc::now(),
        };

        let json = serde_json::to_string(&report).expect("should serialize");
        let deserialized: TelemetryReport =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(report, deserialized);
    }

    #[test]
    fn report_does_not_contain_pii_fields() {
        let report = TelemetryReport {
            chalk_version: "0.1.0".to_string(),
            report_id: Uuid::nil(),
            sis_provider: "powerschool".to_string(),
            student_count_bucket: "1-100".to_string(),
            db_driver: "sqlite".to_string(),
            features_enabled: vec![],
            sync_count_24h: 0,
            uptime_hours: 0,
            reported_at: Utc::now(),
        };

        let json = serde_json::to_string(&report).unwrap();
        // Must never contain PII-related field names
        assert!(!json.contains("school_name"));
        assert!(!json.contains("email"));
        assert!(!json.contains("student_name"));
        assert!(!json.contains("password"));
        assert!(!json.contains("credential"));
        assert!(!json.contains("ip_address"));
        assert!(!json.contains("instance_name"));
    }
}
