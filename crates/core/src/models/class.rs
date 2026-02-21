use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::common::{ClassType, Status};

/// OneRoster Class entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Class {
    pub sourced_id: String,
    pub status: Status,
    pub date_last_modified: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_code: Option<String>,
    pub class_type: ClassType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default)]
    pub grades: Vec<String>,
    #[serde(default)]
    pub subjects: Vec<String>,
    pub course: String,
    pub school: String,
    pub terms: Vec<String>,
    #[serde(default)]
    pub periods: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_class() -> Class {
        Class {
            sourced_id: "class-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "Algebra I - Period 1".to_string(),
            class_code: Some("ALG1-P1".to_string()),
            class_type: ClassType::Scheduled,
            location: Some("Room 101".to_string()),
            grades: vec!["09".to_string()],
            subjects: vec!["Mathematics".to_string()],
            course: "course-001".to_string(),
            school: "org-002".to_string(),
            terms: vec!["term-001".to_string()],
            periods: vec!["1".to_string()],
        }
    }

    #[test]
    fn class_round_trip() {
        let class = sample_class();
        let json = serde_json::to_string(&class).unwrap();
        let back: Class = serde_json::from_str(&json).unwrap();
        assert_eq!(back, class);
    }

    #[test]
    fn class_camel_case_fields() {
        let class = sample_class();
        let json = serde_json::to_string(&class).unwrap();
        assert!(json.contains("\"sourcedId\""));
        assert!(json.contains("\"dateLastModified\""));
        assert!(json.contains("\"classCode\""));
        assert!(json.contains("\"classType\""));
    }

    #[test]
    fn class_optional_fields_omitted() {
        let mut class = sample_class();
        class.class_code = None;
        class.location = None;
        class.metadata = None;
        let json = serde_json::to_string(&class).unwrap();
        assert!(!json.contains("\"classCode\""));
        assert!(!json.contains("\"location\""));
        assert!(!json.contains("\"metadata\""));
    }
}
