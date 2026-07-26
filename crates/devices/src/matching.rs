//! Device → roster matching (ARCHITECTURE §5.6).
//!
//! The ladder, in order:
//!
//! 1. `annotatedUser` parsed as an email → `users.email`, case-insensitive.
//!    Districts demonstrably type meaningful values here by hand; it is the
//!    only rule with field evidence behind it.
//! 2. Else the most recent `recentUsers[].email` that is a managed, in-domain
//!    account resolving to a roster user. Google returns this list newest
//!    first, so first-resolving *is* most-recent.
//! 3. Else identity, not personhood: `serial_number`, then `annotatedAssetId`
//!    against `assets.asset_tag`, matching a **pre-existing** CSV or manual
//!    row so a Google device *merges* into the asset already being tracked
//!    instead of duplicating it. Rules 3 and 4 live in [`crate::sync`], which
//!    owns the asset index; [`MatchRule`] names them so the `asset_events`
//!    payload can record which one fired.
//! 4. Else `match_state='unmatched'` — the queue a human resolves.
//!
//! Two properties matter more than the rules themselves. Matching is
//! **idempotent**: running twice changes nothing the second time. And it never
//! overrides a human — see [`crate::sync`] for where that is enforced.

use std::collections::HashMap;

use chalk_core::models::user::User;
use chalk_google_sync::chromeos::ChromeOsDevice;

/// Which rule produced a match. Recorded in the `asset_events` payload of
/// every automatic match, so a wrong assignment is diagnosable and reversible
/// rather than merely wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchRule {
    /// Rule 1 — `annotatedUser` parsed as an email.
    AnnotatedUser,
    /// Rule 2 — most recent managed `recentUsers[].email`.
    RecentUser,
    /// Rule 3a — Google `serialNumber` equals an existing `assets.serial_number`.
    SerialNumber,
    /// Rule 3b — Google `annotatedAssetId` equals an existing `assets.asset_tag`.
    AssetTag,
}

impl MatchRule {
    /// Stable identifier written into event payloads. Never change these
    /// strings — historical events are read with them.
    pub fn as_str(&self) -> &'static str {
        match self {
            MatchRule::AnnotatedUser => "annotated_user",
            MatchRule::RecentUser => "recent_user",
            MatchRule::SerialNumber => "serial_number",
            MatchRule::AssetTag => "asset_tag",
        }
    }
}

/// A resolved roster match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMatch {
    /// `users.sourced_id`.
    pub sourced_id: String,
    /// The email that matched, as it appeared on the device.
    pub email: String,
    pub rule: MatchRule,
}

/// Case-insensitive `email → users.sourced_id`, built once per sync run.
///
/// `UserRepository` has no email lookup, and adding one would mean editing a
/// supertrait with two full backend implementations and an 800-line mock. One
/// in-memory pass over the roster is both cheaper and less invasive — and for
/// 20k devices it replaces 20k round trips with one.
#[derive(Debug, Clone, Default)]
pub struct RosterIndex {
    by_email: HashMap<String, String>,
}

impl RosterIndex {
    /// Index every user carrying an email.
    ///
    /// On duplicate emails the first user wins and later ones are ignored:
    /// picking arbitrarily between two roster rows for the same address would
    /// make matching non-deterministic across runs, which is worse than
    /// leaving the device for a human.
    pub fn build(users: &[User]) -> Self {
        let mut by_email = HashMap::with_capacity(users.len());
        for user in users {
            if let Some(email) = user.email.as_deref() {
                let key = normalize_email(email);
                if key.is_empty() {
                    continue;
                }
                by_email
                    .entry(key)
                    .or_insert_with(|| user.sourced_id.clone());
            }
        }
        Self { by_email }
    }

    /// Resolve an email to a `sourced_id`, case-insensitively.
    pub fn lookup(&self, email: &str) -> Option<&str> {
        self.by_email
            .get(&normalize_email(email))
            .map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.by_email.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_email.is_empty()
    }
}

/// Lowercase and trim an address for indexing and lookup.
fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// True when `value` is shaped like an email address.
///
/// Deliberately loose: exactly one `@`, non-empty on both sides, a dot in the
/// domain, and no whitespace. `annotatedUser` is a free-text admin field, so
/// the job here is to tell "jdoe@school.edu" from "Ms. Rivera's cart", not to
/// implement RFC 5322.
fn looks_like_email(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return false;
    }
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

/// The domain part of an address, lowercased.
fn email_domain(email: &str) -> Option<String> {
    email
        .rsplit_once('@')
        .map(|(_, d)| d.trim().to_ascii_lowercase())
}

/// Apply rules 1 and 2 to one device.
///
/// `domain` is the district's Workspace domain when configured. It narrows
/// rule 2 to district accounts; a personal sign-in on a loaner must never
/// become an assignment. Unmanaged sign-ins are skipped regardless, and any
/// address that does not resolve to a roster user is skipped rather than
/// ending the walk — which is what makes service accounts a non-issue without
/// a hand-maintained deny list.
pub fn match_device_to_user(
    device: &ChromeOsDevice,
    roster: &RosterIndex,
    domain: Option<&str>,
) -> Option<UserMatch> {
    // Rule 1: annotatedUser, when it parses as an email.
    if let Some(raw) = device.annotated_user.as_deref() {
        let candidate = raw.trim();
        if looks_like_email(candidate) {
            if let Some(sourced_id) = roster.lookup(candidate) {
                return Some(UserMatch {
                    sourced_id: sourced_id.to_string(),
                    email: candidate.to_string(),
                    rule: MatchRule::AnnotatedUser,
                });
            }
        }
    }

    // Rule 2: most recent managed, in-domain sign-in that resolves.
    let wanted_domain = domain.map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase());
    for recent in &device.recent_users {
        if !recent.is_managed() {
            continue;
        }
        let Some(email) = recent.email.as_deref().map(str::trim) else {
            continue;
        };
        if !looks_like_email(email) {
            continue;
        }
        if let Some(wanted) = &wanted_domain {
            if email_domain(email).as_deref() != Some(wanted.as_str()) {
                continue;
            }
        }
        if let Some(sourced_id) = roster.lookup(email) {
            return Some(UserMatch {
                sourced_id: sourced_id.to_string(),
                email: email.to_string(),
                rule: MatchRule::RecentUser,
            });
        }
    }

    None
}

/// Clean an asset tag for storage **without ever changing its value**.
///
/// Trims whitespace and strips one leading `'`, the apostrophe spreadsheets
/// use to force text. Leading zeros survive: the incumbent's round-trip turned
/// tag `00123` into `123` and silently renamed the device, which is the
/// data-corruption class this function exists to prevent. Returns `None` for a
/// tag that is empty once trimmed, so an empty string never becomes a
/// match key.
pub fn normalize_asset_tag(raw: &str) -> Option<String> {
    let trimmed = raw.trim().strip_prefix('\'').unwrap_or(raw.trim()).trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chalk_core::models::common::{RoleType, Status};
    use chalk_google_sync::chromeos::RecentUser;
    use chrono::Utc;

    fn user(sourced_id: &str, email: Option<&str>) -> User {
        User {
            sourced_id: sourced_id.to_string(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            username: sourced_id.to_string(),
            user_ids: Vec::new(),
            enabled_user: true,
            given_name: "Test".into(),
            family_name: "User".into(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: email.map(str::to_string),
            sms: None,
            phone: None,
            agents: Vec::new(),
            orgs: Vec::new(),
            grades: Vec::new(),
        }
    }

    fn roster() -> RosterIndex {
        RosterIndex::build(&[
            user("u-jdoe", Some("JDoe@School.edu")),
            user("u-mrivera", Some("mrivera@school.edu")),
            user("u-noemail", None),
        ])
    }

    fn managed(email: &str) -> RecentUser {
        RecentUser {
            email: Some(email.to_string()),
            user_type: Some("USER_TYPE_MANAGED".to_string()),
        }
    }

    fn unmanaged(email: &str) -> RecentUser {
        RecentUser {
            email: Some(email.to_string()),
            user_type: Some("USER_TYPE_UNMANAGED".to_string()),
        }
    }

    #[test]
    fn index_is_case_insensitive_and_skips_users_without_email() {
        let index = roster();
        assert_eq!(index.len(), 2);
        assert_eq!(index.lookup("jdoe@school.edu"), Some("u-jdoe"));
        assert_eq!(index.lookup("  JDOE@SCHOOL.EDU  "), Some("u-jdoe"));
        assert_eq!(index.lookup("nobody@school.edu"), None);
    }

    #[test]
    fn index_keeps_the_first_user_on_a_duplicate_email() {
        let index = RosterIndex::build(&[
            user("u-first", Some("shared@school.edu")),
            user("u-second", Some("SHARED@school.edu")),
        ]);
        assert_eq!(index.lookup("shared@school.edu"), Some("u-first"));
    }

    #[test]
    fn rule_1_matches_annotated_user_case_insensitively() {
        let device = ChromeOsDevice {
            annotated_user: Some("  JDOE@school.edu ".to_string()),
            ..ChromeOsDevice::default()
        };
        let m = match_device_to_user(&device, &roster(), Some("school.edu")).unwrap();
        assert_eq!(m.sourced_id, "u-jdoe");
        assert_eq!(m.rule, MatchRule::AnnotatedUser);
        assert_eq!(m.rule.as_str(), "annotated_user");
    }

    #[test]
    fn rule_1_wins_over_rule_2() {
        let device = ChromeOsDevice {
            annotated_user: Some("jdoe@school.edu".to_string()),
            recent_users: vec![managed("mrivera@school.edu")],
            ..ChromeOsDevice::default()
        };
        let m = match_device_to_user(&device, &roster(), Some("school.edu")).unwrap();
        assert_eq!(m.sourced_id, "u-jdoe");
        assert_eq!(m.rule, MatchRule::AnnotatedUser);
    }

    #[test]
    fn rule_1_is_skipped_when_annotated_user_is_free_text() {
        let device = ChromeOsDevice {
            annotated_user: Some("Ms. Rivera's cart".to_string()),
            recent_users: vec![managed("mrivera@school.edu")],
            ..ChromeOsDevice::default()
        };
        let m = match_device_to_user(&device, &roster(), Some("school.edu")).unwrap();
        assert_eq!(
            m.rule,
            MatchRule::RecentUser,
            "a non-email annotation must fall through, not fail the device"
        );
        assert_eq!(m.sourced_id, "u-mrivera");
    }

    #[test]
    fn rule_2_takes_the_most_recent_resolving_sign_in() {
        // Google returns recentUsers newest first.
        let device = ChromeOsDevice {
            recent_users: vec![managed("mrivera@school.edu"), managed("jdoe@school.edu")],
            ..ChromeOsDevice::default()
        };
        let m = match_device_to_user(&device, &roster(), Some("school.edu")).unwrap();
        assert_eq!(m.sourced_id, "u-mrivera");
    }

    #[test]
    fn rule_2_skips_unmanaged_and_out_of_domain_sign_ins() {
        let device = ChromeOsDevice {
            recent_users: vec![
                unmanaged("jdoe@school.edu"),
                managed("visitor@othertown.org"),
                managed("mrivera@school.edu"),
            ],
            ..ChromeOsDevice::default()
        };
        let m = match_device_to_user(&device, &roster(), Some("school.edu")).unwrap();
        assert_eq!(
            m.sourced_id, "u-mrivera",
            "a personal sign-in on a loaner must never become an assignment"
        );
    }

    #[test]
    fn rule_2_skips_service_accounts_by_failing_to_resolve_them() {
        let device = ChromeOsDevice {
            recent_users: vec![
                managed("kiosk-service@school.edu"),
                managed("jdoe@school.edu"),
            ],
            ..ChromeOsDevice::default()
        };
        let m = match_device_to_user(&device, &roster(), Some("school.edu")).unwrap();
        assert_eq!(m.sourced_id, "u-jdoe");
    }

    #[test]
    fn no_rule_fires_for_a_cart_device() {
        let device = ChromeOsDevice {
            annotated_user: Some("Library cart 4".to_string()),
            recent_users: vec![unmanaged("someone@gmail.com")],
            ..ChromeOsDevice::default()
        };
        assert!(match_device_to_user(&device, &roster(), Some("school.edu")).is_none());
    }

    #[test]
    fn matching_is_idempotent() {
        let device = ChromeOsDevice {
            annotated_user: Some("jdoe@school.edu".to_string()),
            ..ChromeOsDevice::default()
        };
        let index = roster();
        let first = match_device_to_user(&device, &index, Some("school.edu"));
        let second = match_device_to_user(&device, &index, Some("school.edu"));
        assert_eq!(first, second);
    }

    #[test]
    fn domain_filter_is_optional_and_tolerates_a_leading_at() {
        let device = ChromeOsDevice {
            recent_users: vec![managed("jdoe@school.edu")],
            ..ChromeOsDevice::default()
        };
        assert!(match_device_to_user(&device, &roster(), None).is_some());
        assert!(match_device_to_user(&device, &roster(), Some("@school.edu")).is_some());
        assert!(match_device_to_user(&device, &roster(), Some("other.edu")).is_none());
    }

    #[test]
    fn email_shape_check_rejects_free_text() {
        assert!(looks_like_email("a@b.co"));
        assert!(!looks_like_email("a@b"));
        assert!(!looks_like_email("Ms. Rivera"));
        assert!(!looks_like_email("a@@b.co"));
        assert!(!looks_like_email("@b.co"));
        assert!(!looks_like_email("a@.co"));
        assert!(!looks_like_email(""));
    }

    #[test]
    fn asset_tags_keep_their_leading_zeros() {
        assert_eq!(normalize_asset_tag("00123").as_deref(), Some("00123"));
        assert_eq!(normalize_asset_tag("  00123 ").as_deref(), Some("00123"));
        assert_eq!(
            normalize_asset_tag("'00123").as_deref(),
            Some("00123"),
            "a spreadsheet's text-guard apostrophe is stripped, the zeros are not"
        );
        assert_eq!(normalize_asset_tag("0").as_deref(), Some("0"));
    }

    #[test]
    fn empty_asset_tags_are_not_match_keys() {
        assert_eq!(normalize_asset_tag(""), None);
        assert_eq!(normalize_asset_tag("   "), None);
        assert_eq!(normalize_asset_tag("'"), None);
    }
}
