use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use super::common::{SessionType, Status};

/// OneRoster AcademicSession entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcademicSession {
    pub sourced_id: String,
    pub status: Status,
    pub date_last_modified: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub title: String,
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    #[serde(rename = "type")]
    pub session_type: SessionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub school_year: String,
    #[serde(default)]
    pub children: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_session() -> AcademicSession {
        AcademicSession {
            sourced_id: "term-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "Fall 2025".to_string(),
            start_date: NaiveDate::from_ymd_opt(2025, 8, 15).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2025, 12, 20).unwrap(),
            session_type: SessionType::Term,
            parent: None,
            school_year: "2025".to_string(),
            children: vec!["gp-001".to_string(), "gp-002".to_string()],
        }
    }

    #[test]
    fn academic_session_round_trip() {
        let session = sample_session();
        let json = serde_json::to_string(&session).unwrap();
        let back: AcademicSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back, session);
    }

    #[test]
    fn academic_session_camel_case_fields() {
        let session = sample_session();
        let json = serde_json::to_string(&session).unwrap();
        assert!(json.contains("\"sourcedId\""));
        assert!(json.contains("\"dateLastModified\""));
        assert!(json.contains("\"startDate\""));
        assert!(json.contains("\"endDate\""));
        assert!(json.contains("\"schoolYear\""));
    }

    #[test]
    fn session_type_serializes_as_type() {
        let session = sample_session();
        let v: serde_json::Value = serde_json::to_value(&session).unwrap();
        assert_eq!(v["type"], "term");
    }

    #[test]
    fn grading_period_type() {
        let mut session = sample_session();
        session.session_type = SessionType::GradingPeriod;
        let v: serde_json::Value = serde_json::to_value(&session).unwrap();
        assert_eq!(v["type"], "gradingPeriod");
    }

    #[test]
    fn academic_session_optional_fields_omitted() {
        let mut session = sample_session();
        session.parent = None;
        session.metadata = None;
        let json = serde_json::to_string(&session).unwrap();
        assert!(!json.contains("\"parent\""));
        assert!(!json.contains("\"metadata\""));
    }
}
