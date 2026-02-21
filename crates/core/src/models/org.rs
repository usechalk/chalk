use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::common::{OrgType, Status};

/// OneRoster Org (organization) entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Org {
    pub sourced_id: String,
    pub status: Status,
    pub date_last_modified: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub name: String,
    #[serde(rename = "type")]
    pub org_type: OrgType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default)]
    pub children: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_org() -> Org {
        Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Springfield School District".to_string(),
            org_type: OrgType::District,
            identifier: Some("SSD001".to_string()),
            parent: None,
            children: vec!["org-002".to_string(), "org-003".to_string()],
        }
    }

    #[test]
    fn org_round_trip() {
        let org = sample_org();
        let json = serde_json::to_string(&org).unwrap();
        let back: Org = serde_json::from_str(&json).unwrap();
        assert_eq!(back, org);
    }

    #[test]
    fn org_camel_case_fields() {
        let org = sample_org();
        let json = serde_json::to_string(&org).unwrap();
        assert!(json.contains("\"sourcedId\""));
        assert!(json.contains("\"dateLastModified\""));
        // org_type should serialize as "type"
        assert!(json.contains("\"type\""));
    }

    #[test]
    fn org_type_serializes_as_type() {
        let org = sample_org();
        let v: serde_json::Value = serde_json::to_value(&org).unwrap();
        assert_eq!(v["type"], "district");
    }

    #[test]
    fn org_optional_fields_omitted() {
        let mut org = sample_org();
        org.parent = None;
        org.metadata = None;
        org.identifier = None;
        let json = serde_json::to_string(&org).unwrap();
        assert!(!json.contains("\"parent\""));
        assert!(!json.contains("\"metadata\""));
        assert!(!json.contains("\"identifier\""));
    }
}
