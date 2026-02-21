use serde::{Deserialize, Serialize};

/// OneRoster status for any entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Active,
    #[serde(rename = "tobedeleted")]
    ToBeDeleted,
}

/// User role type (OneRoster 1.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RoleType {
    Administrator,
    Aide,
    Guardian,
    Parent,
    Proctor,
    Student,
    Teacher,
}

/// Organization type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OrgType {
    Department,
    School,
    District,
    Local,
    State,
    National,
}

/// Class type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ClassType {
    Homeroom,
    Scheduled,
}

/// Academic session type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SessionType {
    Term,
    GradingPeriod,
}

/// Enrollment role (subset of RoleType used in enrollments).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EnrollmentRole {
    Administrator,
    Proctor,
    Student,
    Teacher,
}

/// Biological sex.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Sex {
    Male,
    Female,
}

/// A reference to another entity by sourcedId, type, and href.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidRef {
    #[serde(rename = "sourcedId")]
    pub sourced_id: String,
    #[serde(rename = "type")]
    pub ref_type: String,
    pub href: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_serialization() {
        assert_eq!(
            serde_json::to_string(&Status::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&Status::ToBeDeleted).unwrap(),
            "\"tobedeleted\""
        );
    }

    #[test]
    fn status_round_trip() {
        let values = [Status::Active, Status::ToBeDeleted];
        for v in &values {
            let json = serde_json::to_string(v).unwrap();
            let back: Status = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn role_type_serialization() {
        assert_eq!(
            serde_json::to_string(&RoleType::Administrator).unwrap(),
            "\"administrator\""
        );
        assert_eq!(
            serde_json::to_string(&RoleType::Teacher).unwrap(),
            "\"teacher\""
        );
        assert_eq!(
            serde_json::to_string(&RoleType::Student).unwrap(),
            "\"student\""
        );
    }

    #[test]
    fn role_type_round_trip() {
        let values = [
            RoleType::Administrator,
            RoleType::Aide,
            RoleType::Guardian,
            RoleType::Parent,
            RoleType::Proctor,
            RoleType::Student,
            RoleType::Teacher,
        ];
        for v in &values {
            let json = serde_json::to_string(v).unwrap();
            let back: RoleType = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn org_type_serialization() {
        assert_eq!(
            serde_json::to_string(&OrgType::District).unwrap(),
            "\"district\""
        );
        assert_eq!(
            serde_json::to_string(&OrgType::School).unwrap(),
            "\"school\""
        );
    }

    #[test]
    fn class_type_serialization() {
        assert_eq!(
            serde_json::to_string(&ClassType::Homeroom).unwrap(),
            "\"homeroom\""
        );
        assert_eq!(
            serde_json::to_string(&ClassType::Scheduled).unwrap(),
            "\"scheduled\""
        );
    }

    #[test]
    fn session_type_serialization() {
        assert_eq!(
            serde_json::to_string(&SessionType::Term).unwrap(),
            "\"term\""
        );
        assert_eq!(
            serde_json::to_string(&SessionType::GradingPeriod).unwrap(),
            "\"gradingPeriod\""
        );
    }

    #[test]
    fn enrollment_role_serialization() {
        assert_eq!(
            serde_json::to_string(&EnrollmentRole::Student).unwrap(),
            "\"student\""
        );
        assert_eq!(
            serde_json::to_string(&EnrollmentRole::Teacher).unwrap(),
            "\"teacher\""
        );
    }

    #[test]
    fn sex_serialization() {
        assert_eq!(serde_json::to_string(&Sex::Male).unwrap(), "\"male\"");
        assert_eq!(serde_json::to_string(&Sex::Female).unwrap(), "\"female\"");
    }

    #[test]
    fn guid_ref_round_trip() {
        let guid = GuidRef {
            sourced_id: "abc-123".to_string(),
            ref_type: "user".to_string(),
            href: "https://example.com/users/abc-123".to_string(),
        };
        let json = serde_json::to_string(&guid).unwrap();
        assert!(json.contains("\"sourcedId\""));
        assert!(json.contains("\"type\""));
        let back: GuidRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back, guid);
    }
}
