//! Routing rules — auto-assignment at ticket creation (migration 034).
//!
//! A rule matches on category and/or school (`None` is a wildcard) and names
//! the technician who gets the ticket. Matching lives here, in
//! [`best_match`], rather than in SQL: the table is tens of rows at most, and
//! "most specific wins" is a judgement worth unit-testing without a database.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One auto-assignment rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingRule {
    /// UUID.
    pub id: String,
    /// `None` matches any category.
    pub category: Option<String>,
    /// `None` matches any school.
    pub school_org_sourced_id: Option<String>,
    /// The technician (console_user) who gets the ticket.
    pub assignee_console_user_id: String,
    pub created_at: DateTime<Utc>,
}

impl RoutingRule {
    /// How specific this rule is: one point per named condition. A
    /// category+school rule (2) beats either alone (1), which beats a
    /// catch-all (0).
    fn specificity(&self) -> u8 {
        u8::from(self.category.is_some()) + u8::from(self.school_org_sourced_id.is_some())
    }

    /// Whether this rule matches a ticket's category and school. Category
    /// comparison is case-insensitive, matching how tags and categories are
    /// typed by hand.
    fn matches(&self, category: Option<&str>, school: Option<&str>) -> bool {
        let category_ok = match &self.category {
            None => true,
            Some(want) => category.is_some_and(|c| c.trim().eq_ignore_ascii_case(want.trim())),
        };
        let school_ok = match &self.school_org_sourced_id {
            None => true,
            Some(want) => school == Some(want.as_str()),
        };
        category_ok && school_ok
    }
}

/// The technician the most specific matching rule names, if any.
///
/// Ties on specificity go to the **oldest** rule, so adding a new rule can
/// never silently steal traffic from one an admin set up earlier — they must
/// delete the old rule to change the outcome, which is the deliberate act it
/// should be.
pub fn best_match<'a>(
    rules: &'a [RoutingRule],
    category: Option<&str>,
    school: Option<&str>,
) -> Option<&'a RoutingRule> {
    rules
        .iter()
        .filter(|r| r.matches(category, school))
        .max_by(|a, b| {
            a.specificity()
                .cmp(&b.specificity())
                // max_by keeps the *last* of equal elements, so to prefer the
                // oldest on a tie, later created_at must compare smaller.
                .then_with(|| b.created_at.cmp(&a.created_at))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        id: &str,
        category: Option<&str>,
        school: Option<&str>,
        assignee: &str,
        minutes_ago: i64,
    ) -> RoutingRule {
        RoutingRule {
            id: id.into(),
            category: category.map(str::to_string),
            school_org_sourced_id: school.map(str::to_string),
            assignee_console_user_id: assignee.into(),
            created_at: Utc::now() - chrono::Duration::minutes(minutes_ago),
        }
    }

    #[test]
    fn the_most_specific_matching_rule_wins() {
        let rules = vec![
            rule("catch-all", None, None, "t-any", 30),
            rule("by-cat", Some("hardware"), None, "t-cat", 20),
            rule("both", Some("hardware"), Some("org-a"), "t-both", 10),
        ];
        let hit = best_match(&rules, Some("hardware"), Some("org-a")).unwrap();
        assert_eq!(hit.assignee_console_user_id, "t-both");

        let hit = best_match(&rules, Some("hardware"), Some("org-b")).unwrap();
        assert_eq!(
            hit.assignee_console_user_id, "t-cat",
            "school miss falls back"
        );

        let hit = best_match(&rules, Some("network"), None).unwrap();
        assert_eq!(hit.assignee_console_user_id, "t-any", "catch-all catches");
    }

    #[test]
    fn category_matching_ignores_case_and_padding() {
        let rules = vec![rule("r", Some("Hardware"), None, "t", 0)];
        assert!(best_match(&rules, Some("  hardware "), None).is_some());
        assert!(best_match(&rules, Some("software"), None).is_none());
        assert!(
            best_match(&rules, None, None).is_none(),
            "a category rule needs a category to match"
        );
    }

    #[test]
    fn a_tie_goes_to_the_oldest_rule() {
        let rules = vec![
            rule("old", Some("hardware"), None, "t-old", 60),
            rule("new", Some("hardware"), None, "t-new", 1),
        ];
        let hit = best_match(&rules, Some("hardware"), None).unwrap();
        assert_eq!(
            hit.assignee_console_user_id, "t-old",
            "a new rule cannot silently steal traffic from an existing one"
        );
    }

    #[test]
    fn no_match_routes_nowhere() {
        let rules = vec![rule("r", Some("hardware"), Some("org-a"), "t", 0)];
        assert!(best_match(&rules, Some("hardware"), Some("org-b")).is_none());
        assert!(best_match(&[], Some("anything"), None).is_none());
    }
}
