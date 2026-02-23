//! SSO partner models for universal SAML 2.0 and OIDC support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Protocol used by an SSO partner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SsoProtocol {
    Saml,
    Oidc,
}

impl std::fmt::Display for SsoProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsoProtocol::Saml => write!(f, "saml"),
            SsoProtocol::Oidc => write!(f, "oidc"),
        }
    }
}

/// Where the SSO partner configuration originated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SsoPartnerSource {
    Toml,
    Database,
    Marketplace,
}

impl std::fmt::Display for SsoPartnerSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsoPartnerSource::Toml => write!(f, "toml"),
            SsoPartnerSource::Database => write!(f, "database"),
            SsoPartnerSource::Marketplace => write!(f, "marketplace"),
        }
    }
}

/// An SSO partner application (SAML SP or OIDC client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoPartner {
    pub id: String,
    pub name: String,
    pub logo_url: Option<String>,
    pub protocol: SsoProtocol,
    pub enabled: bool,
    pub source: SsoPartnerSource,
    pub tenant_id: Option<String>,
    /// Roles allowed to access this partner (empty = all roles).
    pub roles: Vec<String>,
    // SAML fields
    pub saml_entity_id: Option<String>,
    pub saml_acs_url: Option<String>,
    // OIDC fields
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_uris: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SsoPartner {
    /// Check if a user with the given role can access this partner.
    pub fn is_accessible_by_role(&self, role: &str) -> bool {
        if self.roles.is_empty() {
            return true;
        }
        self.roles.iter().any(|r| r.eq_ignore_ascii_case(role))
    }
}

/// A portal session for student/teacher access to the launch portal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalSession {
    pub id: String,
    pub user_sourced_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A short-lived OIDC authorization code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcAuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_sourced_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sso_protocol_display() {
        assert_eq!(SsoProtocol::Saml.to_string(), "saml");
        assert_eq!(SsoProtocol::Oidc.to_string(), "oidc");
    }

    #[test]
    fn sso_protocol_serialization() {
        assert_eq!(
            serde_json::to_string(&SsoProtocol::Saml).unwrap(),
            "\"saml\""
        );
        assert_eq!(
            serde_json::to_string(&SsoProtocol::Oidc).unwrap(),
            "\"oidc\""
        );
    }

    #[test]
    fn sso_protocol_deserialization() {
        let saml: SsoProtocol = serde_json::from_str("\"saml\"").unwrap();
        assert_eq!(saml, SsoProtocol::Saml);
        let oidc: SsoProtocol = serde_json::from_str("\"oidc\"").unwrap();
        assert_eq!(oidc, SsoProtocol::Oidc);
    }

    #[test]
    fn sso_partner_source_display() {
        assert_eq!(SsoPartnerSource::Toml.to_string(), "toml");
        assert_eq!(SsoPartnerSource::Database.to_string(), "database");
        assert_eq!(SsoPartnerSource::Marketplace.to_string(), "marketplace");
    }

    #[test]
    fn sso_partner_source_serialization() {
        assert_eq!(
            serde_json::to_string(&SsoPartnerSource::Toml).unwrap(),
            "\"toml\""
        );
        assert_eq!(
            serde_json::to_string(&SsoPartnerSource::Database).unwrap(),
            "\"database\""
        );
        assert_eq!(
            serde_json::to_string(&SsoPartnerSource::Marketplace).unwrap(),
            "\"marketplace\""
        );
    }

    #[test]
    fn sso_partner_role_filtering_empty_roles_allows_all() {
        let partner = make_test_partner(vec![]);
        assert!(partner.is_accessible_by_role("student"));
        assert!(partner.is_accessible_by_role("teacher"));
        assert!(partner.is_accessible_by_role("administrator"));
    }

    #[test]
    fn sso_partner_role_filtering_specific_roles() {
        let partner = make_test_partner(vec!["student".to_string()]);
        assert!(partner.is_accessible_by_role("student"));
        assert!(!partner.is_accessible_by_role("teacher"));
    }

    #[test]
    fn sso_partner_role_filtering_case_insensitive() {
        let partner = make_test_partner(vec!["Student".to_string()]);
        assert!(partner.is_accessible_by_role("student"));
        assert!(partner.is_accessible_by_role("STUDENT"));
    }

    #[test]
    fn sso_partner_role_filtering_multiple_roles() {
        let partner = make_test_partner(vec!["student".to_string(), "teacher".to_string()]);
        assert!(partner.is_accessible_by_role("student"));
        assert!(partner.is_accessible_by_role("teacher"));
        assert!(!partner.is_accessible_by_role("administrator"));
    }

    #[test]
    fn sso_partner_serialization_roundtrip() {
        let partner = make_test_partner(vec!["student".to_string()]);
        let json = serde_json::to_string(&partner).unwrap();
        let deserialized: SsoPartner = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, partner.id);
        assert_eq!(deserialized.name, partner.name);
        assert_eq!(deserialized.protocol, partner.protocol);
        assert_eq!(deserialized.roles, partner.roles);
    }

    #[test]
    fn portal_session_serialization_roundtrip() {
        let session = PortalSession {
            id: "test-token-123".to_string(),
            user_sourced_id: "user-1".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(8),
        };
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: PortalSession = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "test-token-123");
        assert_eq!(deserialized.user_sourced_id, "user-1");
    }

    #[test]
    fn oidc_authorization_code_serialization_roundtrip() {
        let code = OidcAuthorizationCode {
            code: "auth-code-123".to_string(),
            client_id: "client-1".to_string(),
            user_sourced_id: "user-1".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scope: "openid profile email".to_string(),
            nonce: Some("nonce-abc".to_string()),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
        };
        let json = serde_json::to_string(&code).unwrap();
        let deserialized: OidcAuthorizationCode = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.code, "auth-code-123");
        assert_eq!(deserialized.client_id, "client-1");
        assert_eq!(deserialized.nonce.as_deref(), Some("nonce-abc"));
    }

    fn make_test_partner(roles: Vec<String>) -> SsoPartner {
        SsoPartner {
            id: "partner-1".to_string(),
            name: "Test App".to_string(),
            logo_url: None,
            protocol: SsoProtocol::Saml,
            enabled: true,
            source: SsoPartnerSource::Toml,
            tenant_id: None,
            roles,
            saml_entity_id: Some("https://app.example.com".to_string()),
            saml_acs_url: Some("https://app.example.com/saml/consume".to_string()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_redirect_uris: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}
