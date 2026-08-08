//! Per-person console accounts and the resolved session actor (migration 027).
//!
//! The console used to authenticate one shared district password, so every
//! action was attributed to the constant string `"console:admin"` and no one
//! could tell which technician did what. A [`ConsoleUser`] is a real person
//! with a login, a role, and a name that reaches the audit log and ticket
//! threads.
//!
//! This namespace is deliberately **separate from the SIS roster** (`users`):
//! IT technicians are frequently not in the SIS, so console identity cannot
//! depend on it. Resolves ARCHITECTURE §12's technician-identity question.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::str_enum::str_enum;

str_enum! {
    /// What a console account may do. Ordered least-to-most privileged by the
    /// [`ConsoleRole::rank`] helper, not by declaration order.
    pub enum ConsoleRole {
        /// Full access, including managing other console accounts.
        Admin => "admin",
        /// Works tickets and devices; cannot manage console accounts.
        #[default]
        Technician => "technician",
        /// Sees everything, changes nothing.
        ReadOnly => "read_only",
    }
    with_default
}

impl ConsoleRole {
    /// Higher rank = more privilege. Used so a check reads "at least
    /// technician" rather than enumerating roles.
    pub fn rank(&self) -> u8 {
        match self {
            ConsoleRole::ReadOnly => 0,
            ConsoleRole::Technician => 1,
            ConsoleRole::Admin => 2,
        }
    }

    /// May this role change state (create/edit/delete anything)? `read_only`
    /// is the only role that cannot.
    pub fn can_write(&self) -> bool {
        self.rank() >= ConsoleRole::Technician.rank()
    }

    /// May this role manage other console accounts? Admins only.
    pub fn can_manage_console_users(&self) -> bool {
        matches!(self, ConsoleRole::Admin)
    }
}

str_enum! {
    /// Whether an account may sign in at all.
    pub enum ConsoleUserStatus {
        #[default]
        Active => "active",
        Disabled => "disabled",
    }
    with_default
}

/// A person who signs in to the console.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleUser {
    pub id: String,
    /// Stored already lowercased; callers fold case before lookup and insert.
    pub email: String,
    pub display_name: String,
    /// `None` means the account cannot sign in with a password (e.g. a
    /// magic-link-only technician) — not an empty password.
    pub password_hash: Option<String>,
    pub role: ConsoleRole,
    pub status: ConsoleUserStatus,
    /// Base32 TOTP secret. Present from enrollment start; only enforced once
    /// [`totp_confirmed`](Self::totp_confirmed) is set by a correct code.
    pub totp_secret: Option<String>,
    pub totp_confirmed: bool,
    /// JSON array of SHA-256 hex digests of unused one-time recovery codes.
    pub totp_recovery: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ConsoleUser {
    pub fn is_active(&self) -> bool {
        matches!(self.status, ConsoleUserStatus::Active)
    }
}

/// The identity attached to a live session, resolved for attribution.
///
/// Every console-originated audit event and ticket comment reads its actor from
/// here. A shared-password login has no `ConsoleUser`, so it resolves to
/// [`Actor::shared_admin`] — the honest "we do not know who, but they held the
/// district password" fallback, which keeps self-host working unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// Stable machine id for the audit `actor` column, e.g.
    /// `"console_user:<id>"`, `"roster:<sourced_id>"`, or `"console:admin"`.
    pub id: String,
    /// Human name shown in threads and the log.
    pub label: String,
    pub role: ConsoleRole,
}

impl Actor {
    /// The anonymous shared-password administrator. Unchanged behavior for a
    /// self-host that never creates console users.
    pub fn shared_admin() -> Self {
        Self {
            id: "console:admin".to_string(),
            label: "Administrator".to_string(),
            role: ConsoleRole::Admin,
        }
    }

    /// The actor for a signed-in console user.
    pub fn from_console_user(user: &ConsoleUser) -> Self {
        Self {
            id: format!("console_user:{}", user.id),
            label: user.display_name.clone(),
            role: user.role,
        }
    }

    /// The bare console_user id when this actor is a real signed-in technician,
    /// or `None` for the shared-password administrator (who has no account to
    /// claim a ticket under). Lets "Claim" self-assign to the person acting.
    pub fn console_user_id(&self) -> Option<&str> {
        self.id.strip_prefix("console_user:")
    }

    /// The string written to an append-only audit `actor` column.
    ///
    /// The shared administrator keeps its historic `"console:admin"` id so old
    /// and new rows agree and the display layer's existing mapping still fires.
    /// A real person is recorded by name, which is what a district reading "who
    /// changed this" actually wants — and, being append-only, it correctly
    /// preserves the name as it was at the time of the action.
    pub fn audit_actor(&self) -> String {
        if self.id == "console:admin" {
            "console:admin".to_string()
        } else {
            self.label.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_privilege_is_ordered_by_rank_not_declaration() {
        assert!(ConsoleRole::Admin.rank() > ConsoleRole::Technician.rank());
        assert!(ConsoleRole::Technician.rank() > ConsoleRole::ReadOnly.rank());
    }

    #[test]
    fn read_only_cannot_write_others_can() {
        assert!(!ConsoleRole::ReadOnly.can_write());
        assert!(ConsoleRole::Technician.can_write());
        assert!(ConsoleRole::Admin.can_write());
    }

    #[test]
    fn only_a_real_technician_can_claim() {
        let user = ConsoleUser {
            id: "u-ana".into(),
            email: "ana@d.test".into(),
            display_name: "Ana".into(),
            password_hash: None,
            role: ConsoleRole::Technician,
            status: ConsoleUserStatus::Active,
            totp_secret: None,
            totp_confirmed: false,
            totp_recovery: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(
            Actor::from_console_user(&user).console_user_id(),
            Some("u-ana")
        );
        assert_eq!(Actor::shared_admin().console_user_id(), None);
    }

    #[test]
    fn only_admin_manages_console_users() {
        assert!(ConsoleRole::Admin.can_manage_console_users());
        assert!(!ConsoleRole::Technician.can_manage_console_users());
        assert!(!ConsoleRole::ReadOnly.can_manage_console_users());
    }

    #[test]
    fn the_shared_admin_actor_is_the_documented_fallback() {
        let a = Actor::shared_admin();
        assert_eq!(a.id, "console:admin");
        assert_eq!(a.role, ConsoleRole::Admin);
    }

    #[test]
    fn a_console_user_actor_is_namespaced_and_named() {
        let user = ConsoleUser {
            id: "u-1".into(),
            email: "ravi@district.org".into(),
            display_name: "Ravi Patel".into(),
            password_hash: None,
            role: ConsoleRole::Technician,
            status: ConsoleUserStatus::Active,
            totp_secret: None,
            totp_confirmed: false,
            totp_recovery: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let a = Actor::from_console_user(&user);
        assert_eq!(a.id, "console_user:u-1");
        assert_eq!(a.label, "Ravi Patel");
        assert_eq!(a.role, ConsoleRole::Technician);
    }
}
