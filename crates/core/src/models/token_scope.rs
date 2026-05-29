//! Generic, marketplace-agnostic access scope for API tokens.
//!
//! A [`TokenScope`] narrows what a single API token may read from the
//! OneRoster API. It is a pure value object: it carries the *policy* (which
//! orgs/grades/subjects/sections are visible, which resources are allowed,
//! which fields are redacted) but knows nothing about *why* the scope exists.
//! The hosted marketplace builds scopes when a district authorizes an app, but
//! the OSS console stores `scope = NULL` on every token and behaves exactly as
//! before — an absent scope means "unrestricted".
//!
//! The predicates here are deliberately pure (no DB, no I/O) so they unit-test
//! cheaply and so the OneRoster handlers can compose them over already-fetched
//! rows. Cross-entity resolution (e.g. "which students are enrolled in an
//! in-scope section") is left to the caller: this type exposes the per-entity
//! predicates and the caller wires the row sets together.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::class::Class;
use super::enrollment::Enrollment;
use super::user::User;

/// The OneRoster resource families a token can be granted or denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OneRosterResource {
    Orgs,
    AcademicSessions,
    Users,
    Courses,
    Classes,
    Enrollments,
    Demographics,
}

/// A token's read scope over OneRoster data.
///
/// Every list field is an allow-list: **empty means "no restriction on this
/// dimension"**, not "deny all". A non-empty list restricts visibility to rows
/// matching at least one entry. Dimensions combine with AND across the
/// dimensions that apply to a given entity type (see the per-entity predicates).
///
/// `resources` is a deny-map: a resource absent from the map is allowed; a
/// resource mapped to `false` is denied. `redact_fields` lists camelCase JSON
/// field names stripped from serialized `users`/`demographics` payloads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenScope {
    #[serde(default)]
    pub orgs: Vec<String>,
    #[serde(default)]
    pub grades: Vec<String>,
    #[serde(default)]
    pub subjects: Vec<String>,
    #[serde(default)]
    pub classes: Vec<String>,
    #[serde(default)]
    pub resources: BTreeMap<OneRosterResource, bool>,
    #[serde(default)]
    pub redact_fields: Vec<String>,
}

impl TokenScope {
    /// Whether the token may touch this resource family at all. Absent from the
    /// map => allowed (the common case); explicitly `false` => denied.
    pub fn allows_resource(&self, resource: OneRosterResource) -> bool {
        self.resources.get(&resource).copied().unwrap_or(true)
    }

    /// True when any row-level dimension narrows visibility. When this is
    /// `false` the caller can skip all per-row filtering (only `redact` and
    /// `allows_resource` still apply).
    pub fn restricts_rows(&self) -> bool {
        !self.orgs.is_empty()
            || !self.grades.is_empty()
            || !self.subjects.is_empty()
            || !self.classes.is_empty()
    }

    /// True when the scope constrains by section/subject — i.e. determining a
    /// *user's* visibility requires resolving their enrollments against the
    /// in-scope class set. Org/grade alone do not need enrollment resolution.
    pub fn has_section_constraint(&self) -> bool {
        !self.subjects.is_empty() || !self.classes.is_empty()
    }

    fn intersects(a: &[String], b: &[String]) -> bool {
        a.iter().any(|x| b.iter().any(|y| y == x))
    }

    /// An org (school/district) is in scope when no org restriction is set or
    /// its sourcedId is listed.
    pub fn org_in_scope(&self, org_sourced_id: &str) -> bool {
        self.orgs.is_empty() || self.orgs.iter().any(|o| o == org_sourced_id)
    }

    /// A class is in scope when it passes every applicable dimension: its
    /// school org, its grades, its subjects, and its own sourcedId.
    pub fn class_in_scope(&self, class: &Class) -> bool {
        (self.orgs.is_empty() || self.orgs.iter().any(|o| o == &class.school))
            && (self.grades.is_empty() || Self::intersects(&self.grades, &class.grades))
            && (self.subjects.is_empty() || Self::intersects(&self.subjects, &class.subjects))
            && (self.classes.is_empty() || self.classes.iter().any(|c| c == &class.sourced_id))
    }

    /// Convenience: the sourcedIds of the classes in `classes` that fall within
    /// scope. Used by the handler to derive the in-scope section set before
    /// filtering users/enrollments by section.
    pub fn classes_in_scope(&self, classes: &[Class]) -> BTreeSet<String> {
        classes
            .iter()
            .filter(|c| self.class_in_scope(c))
            .map(|c| c.sourced_id.clone())
            .collect()
    }

    /// An enrollment is in scope when its school org and class are in scope.
    /// (Grade/subject apply to the class, resolved separately.)
    pub fn enrollment_in_scope(&self, enrollment: &Enrollment) -> bool {
        (self.orgs.is_empty() || self.orgs.iter().any(|o| o == &enrollment.school))
            && (self.classes.is_empty() || self.classes.iter().any(|c| c == &enrollment.class))
    }

    /// Whether a user passes the org + grade dimensions. Section/subject
    /// constraints are NOT checked here — see [`Self::user_in_scope`].
    pub fn user_passes_org_grade(&self, user: &User) -> bool {
        (self.orgs.is_empty() || Self::intersects(&self.orgs, &user.orgs))
            && (self.grades.is_empty() || Self::intersects(&self.grades, &user.grades))
    }

    /// Whether a user is fully in scope.
    ///
    /// `in_scope_class_ids` is the set of class sourcedIds that fall within
    /// scope (from [`Self::classes_in_scope`]); `user_enrolled_class_ids` is the
    /// set of classes the user is enrolled in. When a section/subject constraint
    /// is present, the user must be enrolled in at least one in-scope class.
    /// When no section constraint exists both arguments are ignored.
    pub fn user_in_scope(
        &self,
        user: &User,
        in_scope_class_ids: &BTreeSet<String>,
        user_enrolled_class_ids: &BTreeSet<String>,
    ) -> bool {
        if !self.user_passes_org_grade(user) {
            return false;
        }
        if self.has_section_constraint() {
            return user_enrolled_class_ids
                .iter()
                .any(|c| in_scope_class_ids.contains(c));
        }
        true
    }

    /// Strip redacted fields from a serialized entity object in place. No-op
    /// when no fields are redacted or the value isn't a JSON object.
    pub fn redact(&self, value: &mut Value) {
        if self.redact_fields.is_empty() {
            return;
        }
        if let Some(obj) = value.as_object_mut() {
            for field in &self.redact_fields {
                obj.remove(field);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::common::{ClassType, EnrollmentRole, RoleType, Status};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    fn user(id: &str, orgs: &[&str], grades: &[&str]) -> User {
        User {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            username: id.to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "A".to_string(),
            family_name: "B".to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some("a@b.com".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: orgs.iter().map(|s| s.to_string()).collect(),
            grades: grades.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn class(id: &str, school: &str, grades: &[&str], subjects: &[&str]) -> Class {
        Class {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            title: id.to_string(),
            class_code: None,
            class_type: ClassType::Scheduled,
            location: None,
            grades: grades.iter().map(|s| s.to_string()).collect(),
            subjects: subjects.iter().map(|s| s.to_string()).collect(),
            course: "course-1".to_string(),
            school: school.to_string(),
            terms: vec![],
            periods: vec![],
        }
    }

    fn enrollment(id: &str, user: &str, class: &str, school: &str) -> Enrollment {
        Enrollment {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            user: user.to_string(),
            class: class.to_string(),
            school: school.to_string(),
            role: EnrollmentRole::Student,
            primary: None,
            begin_date: None,
            end_date: None,
        }
    }

    fn ids(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_scope_allows_everything() {
        let s = TokenScope::default();
        assert!(!s.restricts_rows());
        assert!(!s.has_section_constraint());
        assert!(s.allows_resource(OneRosterResource::Users));
        assert!(s.org_in_scope("anything"));
        assert!(s.user_passes_org_grade(&user("u1", &["org-9"], &["12"])));
    }

    #[test]
    fn resource_deny_map() {
        let mut s = TokenScope::default();
        s.resources.insert(OneRosterResource::Demographics, false);
        assert!(!s.allows_resource(OneRosterResource::Demographics));
        // Unlisted resources stay allowed.
        assert!(s.allows_resource(OneRosterResource::Users));
        // Explicit true is allowed.
        s.resources.insert(OneRosterResource::Users, true);
        assert!(s.allows_resource(OneRosterResource::Users));
    }

    #[test]
    fn org_dimension_filters_users() {
        let s = TokenScope {
            orgs: vec!["school-a".to_string()],
            ..Default::default()
        };
        assert!(s.user_passes_org_grade(&user("u1", &["school-a"], &[])));
        assert!(!s.user_passes_org_grade(&user("u2", &["school-b"], &[])));
        assert!(s.org_in_scope("school-a"));
        assert!(!s.org_in_scope("school-b"));
    }

    #[test]
    fn grade_dimension_filters_users() {
        let s = TokenScope {
            grades: vec!["09".to_string(), "10".to_string()],
            ..Default::default()
        };
        assert!(s.user_passes_org_grade(&user("u1", &["x"], &["09"])));
        assert!(!s.user_passes_org_grade(&user("u2", &["x"], &["11"])));
    }

    #[test]
    fn class_dimension_combines_org_grade_subject_section() {
        let s = TokenScope {
            orgs: vec!["school-a".to_string()],
            subjects: vec!["Mathematics".to_string()],
            ..Default::default()
        };
        assert!(s.class_in_scope(&class("c1", "school-a", &["09"], &["Mathematics"])));
        // Wrong subject.
        assert!(!s.class_in_scope(&class("c2", "school-a", &["09"], &["Science"])));
        // Wrong org.
        assert!(!s.class_in_scope(&class("c3", "school-b", &["09"], &["Mathematics"])));
    }

    #[test]
    fn classes_in_scope_returns_matching_ids() {
        let s = TokenScope {
            subjects: vec!["Mathematics".to_string()],
            ..Default::default()
        };
        let classes = vec![
            class("c1", "s", &[], &["Mathematics"]),
            class("c2", "s", &[], &["Science"]),
            class("c3", "s", &[], &["Mathematics"]),
        ];
        assert_eq!(s.classes_in_scope(&classes), ids(&["c1", "c3"]));
    }

    #[test]
    fn enrollment_scope_by_org_and_class() {
        let s = TokenScope {
            classes: vec!["c1".to_string()],
            ..Default::default()
        };
        assert!(s.enrollment_in_scope(&enrollment("e1", "u1", "c1", "school-a")));
        assert!(!s.enrollment_in_scope(&enrollment("e2", "u1", "c2", "school-a")));
    }

    #[test]
    fn user_in_scope_requires_enrollment_when_section_constrained() {
        let s = TokenScope {
            classes: vec!["c1".to_string()],
            ..Default::default()
        };
        let in_scope = ids(&["c1"]);
        // Enrolled in c1 -> visible.
        assert!(s.user_in_scope(&user("u1", &[], &[]), &in_scope, &ids(&["c1", "c9"])));
        // Not enrolled in any in-scope class -> hidden.
        assert!(!s.user_in_scope(&user("u2", &[], &[]), &in_scope, &ids(&["c9"])));
    }

    #[test]
    fn user_in_scope_combines_org_grade_with_section() {
        let s = TokenScope {
            orgs: vec!["school-a".to_string()],
            classes: vec!["c1".to_string()],
            ..Default::default()
        };
        let in_scope = ids(&["c1"]);
        // Right org + enrolled -> visible.
        assert!(s.user_in_scope(&user("u1", &["school-a"], &[]), &in_scope, &ids(&["c1"])));
        // Enrolled but wrong org -> hidden (org gate fails first).
        assert!(!s.user_in_scope(&user("u2", &["school-b"], &[]), &in_scope, &ids(&["c1"])));
    }

    #[test]
    fn user_in_scope_without_section_constraint_ignores_enrollment() {
        let s = TokenScope {
            orgs: vec!["school-a".to_string()],
            ..Default::default()
        };
        let empty = BTreeSet::new();
        assert!(s.user_in_scope(&user("u1", &["school-a"], &[]), &empty, &empty));
    }

    #[test]
    fn redact_strips_listed_fields() {
        let s = TokenScope {
            redact_fields: vec!["birthDate".to_string(), "email".to_string()],
            ..Default::default()
        };
        let mut v = json!({"sourcedId": "u1", "email": "a@b.com", "birthDate": "2009-01-01"});
        s.redact(&mut v);
        assert!(v.get("email").is_none());
        assert!(v.get("birthDate").is_none());
        assert_eq!(v["sourcedId"], "u1");
    }

    #[test]
    fn redact_noop_on_non_object_or_empty() {
        let s = TokenScope::default();
        let mut v = json!({"a": 1});
        s.redact(&mut v);
        assert_eq!(v["a"], 1);

        let s2 = TokenScope {
            redact_fields: vec!["a".to_string()],
            ..Default::default()
        };
        let mut arr = json!([1, 2, 3]);
        s2.redact(&mut arr); // not an object; left untouched
        assert_eq!(arr, json!([1, 2, 3]));
    }

    #[test]
    fn round_trips_through_json() {
        let s = TokenScope {
            orgs: vec!["school-a".to_string()],
            grades: vec!["09".to_string()],
            subjects: vec!["Mathematics".to_string()],
            classes: vec!["c1".to_string()],
            resources: {
                let mut m = BTreeMap::new();
                m.insert(OneRosterResource::Demographics, false);
                m
            },
            redact_fields: vec!["birthDate".to_string()],
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: TokenScope = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn resource_enum_uses_camel_case() {
        assert_eq!(
            serde_json::to_string(&OneRosterResource::AcademicSessions).unwrap(),
            "\"academicSessions\""
        );
    }
}
