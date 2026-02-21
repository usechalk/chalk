use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use super::common::{EnrollmentRole, Status};

/// OneRoster Enrollment entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Enrollment {
    pub sourced_id: String,
    pub status: Status,
    pub date_last_modified: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub user: String,
    pub class: String,
    pub school: String,
    pub role: EnrollmentRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub begin_date: Option<NaiveDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date: Option<NaiveDate>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_enrollment() -> Enrollment {
        Enrollment {
            sourced_id: "enr-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            user: "user-001".to_string(),
            class: "class-001".to_string(),
            school: "org-002".to_string(),
            role: EnrollmentRole::Student,
            primary: None,
            begin_date: Some(NaiveDate::from_ymd_opt(2025, 8, 15).unwrap()),
            end_date: Some(NaiveDate::from_ymd_opt(2026, 6, 1).unwrap()),
        }
    }

    #[test]
    fn enrollment_round_trip() {
        let enrollment = sample_enrollment();
        let json = serde_json::to_string(&enrollment).unwrap();
        let back: Enrollment = serde_json::from_str(&json).unwrap();
        assert_eq!(back, enrollment);
    }

    #[test]
    fn enrollment_camel_case_fields() {
        let enrollment = sample_enrollment();
        let json = serde_json::to_string(&enrollment).unwrap();
        assert!(json.contains("\"sourcedId\""));
        assert!(json.contains("\"dateLastModified\""));
        assert!(json.contains("\"beginDate\""));
        assert!(json.contains("\"endDate\""));
    }

    #[test]
    fn enrollment_uses_enrollment_role() {
        let enrollment = sample_enrollment();
        let v: serde_json::Value = serde_json::to_value(&enrollment).unwrap();
        assert_eq!(v["role"], "student");
    }

    #[test]
    fn enrollment_teacher_primary_flag() {
        let mut enrollment = sample_enrollment();
        enrollment.role = EnrollmentRole::Teacher;
        enrollment.primary = Some(true);
        let json = serde_json::to_string(&enrollment).unwrap();
        let back: Enrollment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.primary, Some(true));
        assert_eq!(back.role, EnrollmentRole::Teacher);
    }

    #[test]
    fn enrollment_optional_fields_omitted() {
        let mut enrollment = sample_enrollment();
        enrollment.primary = None;
        enrollment.begin_date = None;
        enrollment.end_date = None;
        enrollment.metadata = None;
        let json = serde_json::to_string(&enrollment).unwrap();
        assert!(!json.contains("\"primary\""));
        assert!(!json.contains("\"beginDate\""));
        assert!(!json.contains("\"endDate\""));
        assert!(!json.contains("\"metadata\""));
    }
}
