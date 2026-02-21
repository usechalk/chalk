//! Google Admin Directory API request/response structs.

use serde::{Deserialize, Serialize};

/// A Google Workspace user account.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleUser {
    pub primary_email: String,
    pub name: GoogleUserName,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_unit_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_password_at_next_login: Option<bool>,
}

/// Name fields for a Google Workspace user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleUserName {
    pub given_name: String,
    pub family_name: String,
}

/// Paginated list of Google users.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleUserList {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<GoogleUser>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// A Google Workspace Organizational Unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleOrgUnit {
    pub name: String,
    pub org_unit_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_org_unit_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_unit_id: Option<String>,
}

/// List of Google Workspace Organizational Units.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleOrgUnitList {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_units: Option<Vec<GoogleOrgUnit>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_user_serialization_camel_case() {
        let user = GoogleUser {
            primary_email: "jdoe@school.edu".to_string(),
            name: GoogleUserName {
                given_name: "John".to_string(),
                family_name: "Doe".to_string(),
            },
            suspended: Some(false),
            org_unit_path: Some("/Students/HS".to_string()),
            id: Some("112233".to_string()),
            password: None,
            change_password_at_next_login: Some(true),
        };
        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("\"primaryEmail\""));
        assert!(json.contains("\"givenName\""));
        assert!(json.contains("\"familyName\""));
        assert!(json.contains("\"orgUnitPath\""));
        assert!(json.contains("\"changePasswordAtNextLogin\""));
        assert!(!json.contains("\"password\""));
    }

    #[test]
    fn google_user_round_trip() {
        let user = GoogleUser {
            primary_email: "jdoe@school.edu".to_string(),
            name: GoogleUserName {
                given_name: "John".to_string(),
                family_name: "Doe".to_string(),
            },
            suspended: Some(false),
            org_unit_path: Some("/Students".to_string()),
            id: Some("abc".to_string()),
            password: Some("secret123".to_string()),
            change_password_at_next_login: Some(true),
        };
        let json = serde_json::to_string(&user).unwrap();
        let back: GoogleUser = serde_json::from_str(&json).unwrap();
        assert_eq!(back.primary_email, user.primary_email);
        assert_eq!(back.name.given_name, user.name.given_name);
        assert_eq!(back.name.family_name, user.name.family_name);
        assert_eq!(back.suspended, user.suspended);
        assert_eq!(back.org_unit_path, user.org_unit_path);
    }

    #[test]
    fn google_user_list_with_pagination() {
        let json = r#"{
            "users": [
                {
                    "primaryEmail": "a@school.edu",
                    "name": {"givenName": "A", "familyName": "User"}
                }
            ],
            "nextPageToken": "token123"
        }"#;
        let list: GoogleUserList = serde_json::from_str(json).unwrap();
        assert_eq!(list.users.as_ref().unwrap().len(), 1);
        assert_eq!(list.next_page_token.as_deref(), Some("token123"));
    }

    #[test]
    fn google_user_list_empty() {
        let json = r#"{}"#;
        let list: GoogleUserList = serde_json::from_str(json).unwrap();
        assert!(list.users.is_none());
        assert!(list.next_page_token.is_none());
    }

    #[test]
    fn google_org_unit_round_trip() {
        let ou = GoogleOrgUnit {
            name: "Grade 9".to_string(),
            org_unit_path: "/Students/HS/09".to_string(),
            parent_org_unit_path: Some("/Students/HS".to_string()),
            org_unit_id: Some("ou-123".to_string()),
        };
        let json = serde_json::to_string(&ou).unwrap();
        assert!(json.contains("\"orgUnitPath\""));
        assert!(json.contains("\"parentOrgUnitPath\""));
        let back: GoogleOrgUnit = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, ou.name);
        assert_eq!(back.org_unit_path, ou.org_unit_path);
    }

    #[test]
    fn google_org_unit_list_round_trip() {
        let list = GoogleOrgUnitList {
            organization_units: Some(vec![GoogleOrgUnit {
                name: "Students".to_string(),
                org_unit_path: "/Students".to_string(),
                parent_org_unit_path: Some("/".to_string()),
                org_unit_id: None,
            }]),
        };
        let json = serde_json::to_string(&list).unwrap();
        assert!(json.contains("\"organizationUnits\""));
        let back: GoogleOrgUnitList = serde_json::from_str(&json).unwrap();
        assert_eq!(back.organization_units.unwrap().len(), 1);
    }

    #[test]
    fn google_user_deserialize_from_api_format() {
        let json = r#"{
            "primaryEmail": "student@school.edu",
            "name": {
                "givenName": "Jane",
                "familyName": "Smith"
            },
            "suspended": false,
            "orgUnitPath": "/Students/MS",
            "id": "user-id-456",
            "changePasswordAtNextLogin": false
        }"#;
        let user: GoogleUser = serde_json::from_str(json).unwrap();
        assert_eq!(user.primary_email, "student@school.edu");
        assert_eq!(user.name.given_name, "Jane");
        assert_eq!(user.name.family_name, "Smith");
        assert_eq!(user.suspended, Some(false));
        assert_eq!(user.org_unit_path.as_deref(), Some("/Students/MS"));
        assert_eq!(user.id.as_deref(), Some("user-id-456"));
        assert!(user.password.is_none());
    }
}
