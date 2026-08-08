//! Admin audit log and session models for the console.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents an admin console session.
///
/// The `actor_*` fields carry the signed-in identity, captured at login so that
/// attribution needs no join. They are `None` for a shared-password login,
/// which resolves to the anonymous administrator fallback — see
/// [`crate::models::console_user::Actor`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSession {
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    /// Stable actor id, e.g. `"console_user:<id>"`. `None` = shared password.
    #[serde(default)]
    pub actor_id: Option<String>,
    /// Display name captured at login.
    #[serde(default)]
    pub actor_label: Option<String>,
    /// Role string (`admin`/`technician`/`read_only`) captured at login.
    #[serde(default)]
    pub actor_role: Option<String>,
}

impl AdminSession {
    /// Resolve the identity to act as. A session with no captured actor is the
    /// shared-password administrator.
    pub fn actor(&self) -> crate::models::console_user::Actor {
        use crate::models::console_user::{Actor, ConsoleRole};
        match (&self.actor_id, &self.actor_label) {
            (Some(id), Some(label)) => Actor {
                id: id.clone(),
                label: label.clone(),
                role: self
                    .actor_role
                    .as_deref()
                    .and_then(|s| s.parse::<ConsoleRole>().ok())
                    .unwrap_or(ConsoleRole::Admin),
            },
            _ => Actor::shared_admin(),
        }
    }
}

/// Represents an entry in the admin audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuditEntry {
    pub id: i64,
    pub action: String,
    pub details: Option<String>,
    pub admin_ip: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn admin_session_creation() {
        let session = AdminSession {
            token: "test-token".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now(),
            ip_address: Some("127.0.0.1".to_string()),
            actor_id: None,
            actor_label: None,
            actor_role: None,
        };
        assert_eq!(session.token, "test-token");
        assert_eq!(session.ip_address.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn admin_session_without_ip() {
        let session = AdminSession {
            token: "test-token".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now(),
            ip_address: None,
            actor_id: None,
            actor_label: None,
            actor_role: None,
        };
        assert!(session.ip_address.is_none());
    }

    #[test]
    fn admin_audit_entry_creation() {
        let entry = AdminAuditEntry {
            id: 1,
            action: "login".to_string(),
            details: Some("Admin logged in".to_string()),
            admin_ip: Some("192.168.1.1".to_string()),
            created_at: Utc::now(),
        };
        assert_eq!(entry.action, "login");
        assert_eq!(entry.details.as_deref(), Some("Admin logged in"));
    }

    #[test]
    fn admin_audit_entry_without_details() {
        let entry = AdminAuditEntry {
            id: 1,
            action: "logout".to_string(),
            details: None,
            admin_ip: None,
            created_at: Utc::now(),
        };
        assert!(entry.details.is_none());
        assert!(entry.admin_ip.is_none());
    }

    #[test]
    fn admin_session_serialization() {
        let session = AdminSession {
            token: "abc123".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now(),
            ip_address: Some("10.0.0.1".to_string()),
            actor_id: None,
            actor_label: None,
            actor_role: None,
        };
        let json = serde_json::to_string(&session).expect("should serialize");
        let deserialized: AdminSession = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(deserialized.token, "abc123");
        assert_eq!(deserialized.ip_address.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn admin_audit_entry_serialization() {
        let entry = AdminAuditEntry {
            id: 42,
            action: "settings_view".to_string(),
            details: Some("Viewed settings page".to_string()),
            admin_ip: Some("172.16.0.1".to_string()),
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&entry).expect("should serialize");
        let deserialized: AdminAuditEntry =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(deserialized.id, 42);
        assert_eq!(deserialized.action, "settings_view");
    }
}
