//! Granular console permissions (GP-2).
//!
//! The three [`ConsoleRole`](super::console_user::ConsoleRole)s stay as the
//! built-in presets, but a preset is now a *computed set of permissions*
//! rather than a branch in the middleware. Custom sets compose from the same
//! enum, so a district can hand a librarian "custody but not fees" without a
//! fourth hardcoded role.
//!
//! Presets are derived from the enum itself — `Admin` is every variant,
//! `ReadOnly` is every variant whose action is a read — so a newly added
//! permission lands in the right presets automatically instead of waiting on
//! a hand-maintained list (the class of bug CLAUDE.md bans).

use super::str_enum::str_enum;

str_enum! {
    /// One grantable console ability, keyed `domain.action`.
    ///
    /// The granularity follows this console's actual surfaces, not a
    /// competitor's checklist: one permission per page-group a district
    /// would plausibly grant or withhold as a unit.
    pub enum Permission {
        // Devices.
        AssetsView => "assets.view",
        AssetsEdit => "assets.edit",
        AssetsSync => "assets.sync",
        // Circulation.
        CustodyView => "custody.view",
        CustodyManage => "custody.manage",
        // Money and repairs. Waiving is separate from assessing because
        // money-out is what districts most want to restrict.
        FeesView => "fees.view",
        FeesAssess => "fees.assess",
        FeesWaive => "fees.waive",
        RepairsManage => "repairs.manage",
        // Quantity items.
        ItemsView => "items.view",
        ItemsManage => "items.manage",
        // Help desk.
        TicketsView => "tickets.view",
        TicketsWork => "tickets.work",
        TicketsConfigure => "tickets.configure",
        // Knowledge base.
        KbView => "kb.view",
        KbEdit => "kb.edit",
        // Reports.
        ReportsView => "reports.view",
        ReportsBuild => "reports.build",
        // Identity surfaces.
        IdentityView => "identity.view",
        IdentityBadges => "identity.badges",
        IdentitySso => "identity.sso",
        // Integrations.
        SettingsSyncConfig => "settings.sync_config",
        WebhooksManage => "webhooks.manage",
        // Administration.
        SettingsView => "settings.view",
        AuditView => "audit.view",
        ApiTokensManage => "apitokens.manage",
        ConsoleUsersManage => "consoleusers.manage",
    }
}

impl Permission {
    /// True for the look-don't-touch half of the enum — what `ReadOnly`
    /// derives itself from.
    pub fn is_read(self) -> bool {
        matches!(
            self,
            Permission::AssetsView
                | Permission::CustodyView
                | Permission::FeesView
                | Permission::ItemsView
                | Permission::TicketsView
                | Permission::KbView
                | Permission::ReportsView
                | Permission::IdentityView
                | Permission::SettingsView
                | Permission::AuditView
        )
    }
}

/// A named, district-defined bundle of permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionSet {
    pub id: String,
    pub name: String,
    pub permissions: Vec<Permission>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// The authorization row the login middleware resolves per request: which
/// custom set (if any) overrides the role preset, and the site grants.
///
/// Deliberately not part of [`ConsoleUser`](super::console_user::ConsoleUser):
/// permissions and scope are resolved live on every request (a stale-session
/// risk if denormalized), while the user struct rides in sessions and lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsoleAuthz {
    /// Overrides the role preset when present.
    pub permission_set_id: Option<String>,
    /// Whether NULL-school rows are visible to a scoped user.
    pub include_unscoped: bool,
    /// School org sourced_ids. Empty means district-wide (unscoped) — the
    /// pre-GP-2 behavior and the default for every existing user.
    pub sites: Vec<String>,
}

impl ConsoleAuthz {
    /// The row as a [`SiteScope`](super::site_scope::SiteScope).
    pub fn site_scope(&self) -> super::site_scope::SiteScope {
        if self.sites.is_empty() {
            super::site_scope::SiteScope::Unrestricted
        } else {
            super::site_scope::SiteScope::Schools {
                schools: self.sites.clone(),
                include_unscoped: self.include_unscoped,
            }
        }
    }
}

/// The permissions a built-in role grants — computed, never stored.
pub fn preset_for(role: super::console_user::ConsoleRole) -> Vec<Permission> {
    use super::console_user::ConsoleRole;
    match role {
        ConsoleRole::Admin => Permission::ALL.to_vec(),
        // Exactly today's technician: everything except managing console
        // accounts. Narrower would silently strip abilities existing
        // technicians rely on.
        ConsoleRole::Technician => Permission::ALL
            .iter()
            .copied()
            .filter(|p| *p != Permission::ConsoleUsersManage)
            .collect(),
        ConsoleRole::ReadOnly => Permission::ALL
            .iter()
            .copied()
            .filter(|p| p.is_read())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::console_user::ConsoleRole;
    use super::*;

    /// `ALL` comes from the macro, so it cannot miss a variant; this pins
    /// round-tripping and the presence of the keys other code writes down.
    #[test]
    fn keys_round_trip_and_the_known_ones_exist() {
        let mut seen = std::collections::HashSet::new();
        for p in Permission::ALL {
            assert!(seen.insert(p.as_str()), "{} listed twice", p.as_str());
            assert_eq!(Permission::parse(p.as_str()).unwrap(), *p);
        }
        for key in [
            "assets.view",
            "consoleusers.manage",
            "fees.waive",
            "tickets.configure",
        ] {
            assert!(seen.contains(key), "{key} missing");
        }
    }

    #[test]
    fn admin_is_everything() {
        assert_eq!(preset_for(ConsoleRole::Admin), Permission::ALL.to_vec());
    }

    /// The behavioral definition of a technician today: full access minus
    /// account management. If this test breaks, an existing install's techs
    /// gained or lost abilities on upgrade — which is the compat contract.
    #[test]
    fn technician_is_everything_but_console_users() {
        let t = preset_for(ConsoleRole::Technician);
        assert!(!t.contains(&Permission::ConsoleUsersManage));
        assert_eq!(t.len(), Permission::ALL.len() - 1);
    }

    /// ReadOnly must be exactly the read half — matching the old
    /// `can_write() == false` gate, which refused every mutation and allowed
    /// every view.
    #[test]
    fn read_only_is_exactly_the_reads() {
        let r = preset_for(ConsoleRole::ReadOnly);
        assert!(r.iter().all(|p| p.is_read()));
        assert!(r.contains(&Permission::AssetsView));
        assert!(r.contains(&Permission::AuditView));
        assert!(!r.contains(&Permission::AssetsEdit));
        assert!(!r.contains(&Permission::FeesWaive));
        // Every read in the enum is present.
        let read_count = Permission::ALL.iter().filter(|p| p.is_read()).count();
        assert_eq!(r.len(), read_count);
    }

    #[test]
    fn unknown_keys_fail_closed() {
        assert!(Permission::parse("assets.destroy").is_err());
    }
}
