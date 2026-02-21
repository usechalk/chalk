use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Authentication method used for login.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    QrBadge,
    PicturePassword,
    Saml,
}

/// An active IDP session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdpSession {
    pub id: String,
    pub user_sourced_id: String,
    pub auth_method: AuthMethod,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub saml_request_id: Option<String>,
    pub relay_state: Option<String>,
}

/// A QR badge token linked to a user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QrBadge {
    pub id: i64,
    pub badge_token: String,
    pub user_sourced_id: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// A picture password configuration for a user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PicturePassword {
    pub user_sourced_id: String,
    pub image_sequence: Vec<String>,
}

/// An entry in the IDP authentication log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthLogEntry {
    pub id: i64,
    pub user_sourced_id: Option<String>,
    pub username: Option<String>,
    pub auth_method: AuthMethod,
    pub success: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn auth_method_serialization() {
        assert_eq!(
            serde_json::to_string(&AuthMethod::Password).unwrap(),
            "\"password\""
        );
        assert_eq!(
            serde_json::to_string(&AuthMethod::QrBadge).unwrap(),
            "\"qr_badge\""
        );
        assert_eq!(
            serde_json::to_string(&AuthMethod::PicturePassword).unwrap(),
            "\"picture_password\""
        );
        assert_eq!(
            serde_json::to_string(&AuthMethod::Saml).unwrap(),
            "\"saml\""
        );
    }

    #[test]
    fn auth_method_deserialization() {
        for (s, expected) in [
            ("\"password\"", AuthMethod::Password),
            ("\"qr_badge\"", AuthMethod::QrBadge),
            ("\"picture_password\"", AuthMethod::PicturePassword),
            ("\"saml\"", AuthMethod::Saml),
        ] {
            let parsed: AuthMethod = serde_json::from_str(s).unwrap();
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn idp_session_round_trip() {
        let session = IdpSession {
            id: "sess-001".to_string(),
            user_sourced_id: "user-001".to_string(),
            auth_method: AuthMethod::Password,
            created_at: Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap(),
            expires_at: Utc.with_ymd_and_hms(2025, 6, 1, 20, 0, 0).unwrap(),
            saml_request_id: None,
            relay_state: None,
        };
        let json = serde_json::to_string(&session).unwrap();
        let back: IdpSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back, session);
    }

    #[test]
    fn qr_badge_round_trip() {
        let badge = QrBadge {
            id: 1,
            badge_token: "token-abc".to_string(),
            user_sourced_id: "user-001".to_string(),
            is_active: true,
            created_at: Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap(),
            revoked_at: None,
        };
        let json = serde_json::to_string(&badge).unwrap();
        let back: QrBadge = serde_json::from_str(&json).unwrap();
        assert_eq!(back, badge);
    }

    #[test]
    fn picture_password_round_trip() {
        let pp = PicturePassword {
            user_sourced_id: "user-001".to_string(),
            image_sequence: vec!["cat".to_string(), "dog".to_string(), "fish".to_string()],
        };
        let json = serde_json::to_string(&pp).unwrap();
        let back: PicturePassword = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pp);
    }

    #[test]
    fn auth_log_entry_round_trip() {
        let entry = AuthLogEntry {
            id: 1,
            user_sourced_id: Some("user-001".to_string()),
            username: Some("jdoe".to_string()),
            auth_method: AuthMethod::Password,
            success: true,
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Chrome/120".to_string()),
            created_at: Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: AuthLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entry);
    }
}
