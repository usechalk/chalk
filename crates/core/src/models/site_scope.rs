//! Which schools' rows a console principal may see and touch (GP-2).
//!
//! The generalization of [`TicketScope`](super::ticket::TicketScope), which
//! proved the shape on the ticket API: a **required argument**, not a filter
//! field, because a filter field defaulting to "unrestricted" is a boundary
//! that fails open. `TicketScope` stays as the ticket repositories' parameter
//! type (API tokens already speak it); [`SiteScope::to_ticket_scope`] bridges.
//!
//! The one addition over `TicketScope` is [`include_unscoped`]: rows with no
//! school at all (an unassigned device fresh from Google, a district-wide
//! ticket) are *hidden* from scoped users by default — `school IN (…)`
//! excludes NULL on its own, so the conservative behavior is also the free
//! one — but a district that wants a site technician triaging the unassigned
//! pool can grant it explicitly per user.
//!
//! [`include_unscoped`]: SiteScope::Schools#structfield.include_unscoped

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteScope {
    /// The district itself: the shared admin password, magic-link and SSO
    /// sessions, the CLI, jobs — principals that have no `console_users` row
    /// to hang a grant on, plus any console user with no site grants.
    Unrestricted,
    /// A building-scoped console user. An empty list is *no* schools rather
    /// than all of them: a grant that named nothing granted nothing.
    Schools {
        schools: Vec<String>,
        /// Also show rows whose school column is NULL.
        include_unscoped: bool,
    },
}

impl SiteScope {
    /// The schools to restrict to, or `None` for no restriction.
    pub fn schools(&self) -> Option<&[String]> {
        match self {
            Self::Unrestricted => None,
            Self::Schools { schools, .. } => Some(schools),
        }
    }

    /// True when NULL-school rows are visible under this scope.
    pub fn includes_unscoped(&self) -> bool {
        match self {
            Self::Unrestricted => true,
            Self::Schools {
                include_unscoped, ..
            } => *include_unscoped,
        }
    }

    /// True when this scope can see nothing at all.
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Schools { schools, .. } if schools.is_empty())
    }

    /// True when the given (possibly absent) school column value is inside
    /// this scope — the object-level check every by-id mutation makes after
    /// loading its target.
    pub fn permits(&self, school: Option<&str>) -> bool {
        match self {
            Self::Unrestricted => true,
            Self::Schools {
                schools,
                include_unscoped,
            } => match school {
                Some(s) => schools.iter().any(|x| x == s),
                None => *include_unscoped,
            },
        }
    }

    /// The same boundary in the ticket repositories' parameter type.
    ///
    /// `include_unscoped` has no `TicketScope` equivalent; a scoped user with
    /// it set still does not see NULL-school tickets through this bridge —
    /// hide-by-default is preserved rather than widened silently.
    pub fn to_ticket_scope(&self) -> super::ticket::TicketScope {
        match self {
            Self::Unrestricted => super::ticket::TicketScope::Unrestricted,
            Self::Schools { schools, .. } => super::ticket::TicketScope::Schools(schools.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_matches_the_listing_predicate() {
        let scope = SiteScope::Schools {
            schools: vec!["org-a".into()],
            include_unscoped: false,
        };
        assert!(scope.permits(Some("org-a")));
        assert!(!scope.permits(Some("org-b")));
        assert!(!scope.permits(None), "NULL school hides by default");

        let with_pool = SiteScope::Schools {
            schools: vec!["org-a".into()],
            include_unscoped: true,
        };
        assert!(with_pool.permits(None), "the unassigned pool is a grant");
        assert!(SiteScope::Unrestricted.permits(None));
    }

    #[test]
    fn empty_grant_grants_nothing() {
        let scope = SiteScope::Schools {
            schools: vec![],
            include_unscoped: false,
        };
        assert!(scope.is_empty());
        assert!(!scope.permits(Some("org-a")));
    }

    #[test]
    fn ticket_bridge_never_widens() {
        use crate::models::ticket::TicketScope;
        let scope = SiteScope::Schools {
            schools: vec!["org-a".into()],
            include_unscoped: true,
        };
        assert_eq!(
            scope.to_ticket_scope(),
            TicketScope::Schools(vec!["org-a".into()])
        );
        assert_eq!(
            SiteScope::Unrestricted.to_ticket_scope(),
            TicketScope::Unrestricted
        );
    }
}
