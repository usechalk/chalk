//! SSO partner models for universal SAML 2.0 and OIDC support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Protocol used by an SSO partner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SsoProtocol {
    Saml,
    Oidc,
    CleverCompat,
    ClassLinkCompat,
    /// A plain launcher tile: launching it redirects to `SsoPartner.launch_url`
    /// rather than performing any SSO. Used for bookmark-style tiles (e.g. the
    /// hosted Google Workspace built-ins, or self-hosted custom links).
    Link,
}

impl std::fmt::Display for SsoProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsoProtocol::Saml => write!(f, "saml"),
            SsoProtocol::Oidc => write!(f, "oidc"),
            SsoProtocol::CleverCompat => write!(f, "clever-compatible"),
            SsoProtocol::ClassLinkCompat => write!(f, "classlink-compatible"),
            SsoProtocol::Link => write!(f, "link"),
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

/// Audience scope for a partner: the set of classes and/or orgs (schools)
/// whose members may see and launch it. An unrestricted audience (or `None`
/// on the partner) means "visible to everyone in an allowed role" — preserving
/// the default behavior for self-hosted/TOML partners.
///
/// This is a generic, marketplace-agnostic primitive: the hosted marketplace
/// install path populates it from an install's data-sharing scope (a teacher
/// install sets `classes` to the teacher's sections; an admin install sets
/// `orgs`/`classes` to the chosen schools/sections) so the launch portal only
/// surfaces an app to the students and teachers actually covered by the share.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsoAudience {
    /// Allowed class `sourcedId`s. Empty = no class restriction.
    #[serde(default)]
    pub classes: Vec<String>,
    /// Allowed org (school) `sourcedId`s. Empty = no org restriction.
    #[serde(default)]
    pub orgs: Vec<String>,
    /// Allowed grade levels. Empty = no grade restriction.
    #[serde(default)]
    pub grades: Vec<String>,
}

impl SsoAudience {
    /// Whether the audience imposes no restriction (visible to all).
    pub fn is_unrestricted(&self) -> bool {
        self.classes.is_empty() && self.orgs.is_empty() && self.grades.is_empty()
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
    /// Optional audience scope (classes/orgs). `None` or an unrestricted
    /// audience = visible to all members of an allowed role. Marketplace
    /// installs set this to limit tiles to the covered sections/schools.
    #[serde(default)]
    pub audience: Option<SsoAudience>,
    // SAML fields
    pub saml_entity_id: Option<String>,
    pub saml_acs_url: Option<String>,
    // OIDC fields
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_uris: Vec<String>,
    /// Destination for `SsoProtocol::Link` launcher tiles. Launching the tile
    /// redirects here. `None` for SSO protocols.
    #[serde(default)]
    pub launch_url: Option<String>,
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

    /// Whether a user described by `user_classes`, `user_orgs`, and
    /// `user_grades` is within this partner's audience scope. An absent or
    /// unrestricted audience is visible to everyone (the role check is applied
    /// separately).
    ///
    /// Each populated dimension is a constraint that must be satisfied (an
    /// empty dimension is a wildcard), and the constraints are AND-ed — matching
    /// how an install's data-sharing scope narrows by school *and* grade. A
    /// section-scoped teacher install sets only `classes`, so it reaches exactly
    /// the students in those sections; an admin install scoped to "school A,
    /// grade 9" reaches only grade-9 students at school A.
    pub fn is_within_audience(
        &self,
        user_classes: &[String],
        user_orgs: &[String],
        user_grades: &[String],
    ) -> bool {
        match &self.audience {
            None => true,
            Some(a) if a.is_unrestricted() => true,
            Some(a) => {
                let class_ok =
                    a.classes.is_empty() || a.classes.iter().any(|c| user_classes.contains(c));
                let org_ok = a.orgs.is_empty() || a.orgs.iter().any(|o| user_orgs.contains(o));
                let grade_ok =
                    a.grades.is_empty() || a.grades.iter().any(|g| user_grades.contains(g));
                class_ok && org_ok && grade_ok
            }
        }
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
        assert_eq!(SsoProtocol::CleverCompat.to_string(), "clever-compatible");
        assert_eq!(
            SsoProtocol::ClassLinkCompat.to_string(),
            "classlink-compatible"
        );
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
        assert_eq!(
            serde_json::to_string(&SsoProtocol::CleverCompat).unwrap(),
            "\"clever_compat\""
        );
        assert_eq!(
            serde_json::to_string(&SsoProtocol::ClassLinkCompat).unwrap(),
            "\"class_link_compat\""
        );
    }

    #[test]
    fn sso_protocol_deserialization() {
        let saml: SsoProtocol = serde_json::from_str("\"saml\"").unwrap();
        assert_eq!(saml, SsoProtocol::Saml);
        let oidc: SsoProtocol = serde_json::from_str("\"oidc\"").unwrap();
        assert_eq!(oidc, SsoProtocol::Oidc);
        let clever: SsoProtocol = serde_json::from_str("\"clever_compat\"").unwrap();
        assert_eq!(clever, SsoProtocol::CleverCompat);
        let classlink: SsoProtocol = serde_json::from_str("\"class_link_compat\"").unwrap();
        assert_eq!(classlink, SsoProtocol::ClassLinkCompat);
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
            audience: None,
            saml_entity_id: Some("https://app.example.com".to_string()),
            saml_acs_url: Some("https://app.example.com/saml/consume".to_string()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_redirect_uris: vec![],
            launch_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn protocol_link_serializes_to_link() {
        assert_eq!(SsoProtocol::Link.to_string(), "link");
        // serde round-trip of a Link partner with a launch_url
        let mut p = make_test_partner(vec![]);
        p.protocol = SsoProtocol::Link;
        p.launch_url = Some("https://docs.google.com".to_string());
        let json = serde_json::to_string(&p).unwrap();
        let back: SsoPartner = serde_json::from_str(&json).unwrap();
        assert_eq!(back.protocol, SsoProtocol::Link);
        assert_eq!(back.launch_url.as_deref(), Some("https://docs.google.com"));
    }

    #[test]
    fn audience_none_is_visible_to_everyone() {
        let p = make_test_partner(vec![]);
        assert!(p.is_within_audience(&[], &[], &[]));
        assert!(p.is_within_audience(
            &["class-x".to_string()],
            &["org-x".to_string()],
            &["09".to_string()]
        ));
    }

    #[test]
    fn audience_unrestricted_is_visible_to_everyone() {
        let mut p = make_test_partner(vec![]);
        p.audience = Some(SsoAudience::default());
        assert!(p.is_within_audience(&[], &[], &[]));
    }

    #[test]
    fn audience_class_scoped_matches_only_enrolled() {
        let mut p = make_test_partner(vec![]);
        p.audience = Some(SsoAudience {
            classes: vec!["class-1".to_string()],
            orgs: vec![],
            grades: vec![],
        });
        // Student in the class sees it.
        assert!(p.is_within_audience(&["class-1".to_string()], &["org-9".to_string()], &[]));
        // Student not in the class (different section/school) does not.
        assert!(!p.is_within_audience(&["class-2".to_string()], &["org-9".to_string()], &[]));
        assert!(!p.is_within_audience(&[], &[], &[]));
    }

    #[test]
    fn audience_org_scoped_matches_whole_school() {
        let mut p = make_test_partner(vec![]);
        p.audience = Some(SsoAudience {
            classes: vec![],
            orgs: vec!["school-a".to_string()],
            grades: vec![],
        });
        assert!(p.is_within_audience(&[], &["school-a".to_string()], &[]));
        assert!(!p.is_within_audience(&[], &["school-b".to_string()], &[]));
    }

    #[test]
    fn audience_dimensions_are_anded() {
        // An admin install scoped to "school-a, grade 09" reaches only grade-9
        // students at school A — both constraints must hold.
        let mut p = make_test_partner(vec![]);
        p.audience = Some(SsoAudience {
            classes: vec![],
            orgs: vec!["school-a".to_string()],
            grades: vec!["09".to_string()],
        });
        // In school A and grade 9 → visible.
        assert!(p.is_within_audience(&[], &["school-a".to_string()], &["09".to_string()]));
        // Right school, wrong grade → hidden.
        assert!(!p.is_within_audience(&[], &["school-a".to_string()], &["11".to_string()]));
        // Right grade, wrong school → hidden.
        assert!(!p.is_within_audience(&[], &["school-b".to_string()], &["09".to_string()]));
    }

    #[test]
    fn audience_grade_only_scoped() {
        let mut p = make_test_partner(vec![]);
        p.audience = Some(SsoAudience {
            classes: vec![],
            orgs: vec![],
            grades: vec!["12".to_string()],
        });
        assert!(p.is_within_audience(&[], &["any-school".to_string()], &["12".to_string()]));
        assert!(!p.is_within_audience(&[], &["any-school".to_string()], &["10".to_string()]));
    }
}
