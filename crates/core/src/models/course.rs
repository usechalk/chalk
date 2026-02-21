use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::common::Status;

/// OneRoster Course entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Course {
    pub sourced_id: String,
    pub status: Status,
    pub date_last_modified: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub school_year: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub course_code: Option<String>,
    #[serde(default)]
    pub grades: Vec<String>,
    #[serde(default)]
    pub subjects: Vec<String>,
    pub org: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_course() -> Course {
        Course {
            sourced_id: "course-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "Algebra I".to_string(),
            school_year: Some("2025".to_string()),
            course_code: Some("ALG1".to_string()),
            grades: vec!["09".to_string()],
            subjects: vec!["Mathematics".to_string()],
            org: "org-001".to_string(),
        }
    }

    #[test]
    fn course_round_trip() {
        let course = sample_course();
        let json = serde_json::to_string(&course).unwrap();
        let back: Course = serde_json::from_str(&json).unwrap();
        assert_eq!(back, course);
    }

    #[test]
    fn course_camel_case_fields() {
        let course = sample_course();
        let json = serde_json::to_string(&course).unwrap();
        assert!(json.contains("\"sourcedId\""));
        assert!(json.contains("\"dateLastModified\""));
        assert!(json.contains("\"schoolYear\""));
        assert!(json.contains("\"courseCode\""));
    }

    #[test]
    fn course_optional_fields_omitted() {
        let mut course = sample_course();
        course.school_year = None;
        course.course_code = None;
        course.metadata = None;
        let json = serde_json::to_string(&course).unwrap();
        assert!(!json.contains("\"schoolYear\""));
        assert!(!json.contains("\"courseCode\""));
        assert!(!json.contains("\"metadata\""));
    }
}
