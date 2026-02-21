use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::common::{RoleType, Status};

/// A user identifier from an external system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserIdentifier {
    #[serde(rename = "type")]
    pub type_: String,
    pub identifier: String,
}

/// OneRoster User entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub sourced_id: String,
    pub status: Status,
    pub date_last_modified: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub username: String,
    #[serde(default)]
    pub user_ids: Vec<UserIdentifier>,
    pub enabled_user: bool,
    pub given_name: String,
    pub family_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    pub role: RoleType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sms: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(default)]
    pub agents: Vec<String>,
    pub orgs: Vec<String>,
    #[serde(default)]
    pub grades: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_user() -> User {
        User {
            sourced_id: "user-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "jdoe".to_string(),
            user_ids: vec![UserIdentifier {
                type_: "LDAP".to_string(),
                identifier: "jdoe@example.com".to_string(),
            }],
            enabled_user: true,
            given_name: "John".to_string(),
            family_name: "Doe".to_string(),
            middle_name: Some("M".to_string()),
            role: RoleType::Student,
            identifier: Some("STU001".to_string()),
            email: Some("jdoe@example.com".to_string()),
            sms: None,
            phone: None,
            agents: vec!["parent-001".to_string()],
            orgs: vec!["org-001".to_string()],
            grades: vec!["09".to_string()],
        }
    }

    #[test]
    fn user_round_trip() {
        let user = sample_user();
        let json = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(back, user);
    }

    #[test]
    fn user_camel_case_fields() {
        let user = sample_user();
        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("\"sourcedId\""));
        assert!(json.contains("\"dateLastModified\""));
        assert!(json.contains("\"enabledUser\""));
        assert!(json.contains("\"givenName\""));
        assert!(json.contains("\"familyName\""));
        assert!(json.contains("\"middleName\""));
        assert!(json.contains("\"userIds\""));
    }

    #[test]
    fn user_optional_fields_omitted() {
        let mut user = sample_user();
        user.sms = None;
        user.phone = None;
        user.metadata = None;
        let json = serde_json::to_string(&user).unwrap();
        assert!(!json.contains("\"sms\""));
        assert!(!json.contains("\"phone\""));
        assert!(!json.contains("\"metadata\""));
    }

    #[test]
    fn user_identifier_type_rename() {
        let uid = UserIdentifier {
            type_: "LDAP".to_string(),
            identifier: "jdoe".to_string(),
        };
        let json = serde_json::to_string(&uid).unwrap();
        assert!(json.contains("\"type\""));
        assert!(!json.contains("\"type_\""));
    }
}
