//! Address-shape helpers shared by the device matching ladder and the console.
//!
//! These live in `chalk-core` rather than in `chalk-devices` because two
//! crates need the *same* answer and neither depends on the other. The
//! unmatched queue explains, per device, why the ladder could not place it —
//! and an explanation computed by a second, slightly different predicate is
//! worse than none: it would confidently tell a technician "that is not an
//! address" about a device the ladder rejected for another reason entirely.
//!
//! One definition, one behaviour, one place to change it.

/// True when `value` is shaped like an email address.
///
/// Deliberately loose: exactly one `@`, non-empty on both sides, a dot in the
/// domain, and no whitespace. `annotatedUser` is a free-text admin field, so
/// the job here is to tell "jdoe@school.edu" from "Ms. Rivera's cart", not to
/// implement RFC 5322.
pub fn looks_like_email(value: &str) -> bool {
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
pub fn email_domain(email: &str) -> Option<String> {
    email
        .rsplit_once('@')
        .map(|(_, d)| d.trim().to_ascii_lowercase())
}

/// Lowercase and trim an address for indexing and lookup.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_addresses() {
        assert!(looks_like_email("jdoe@school.edu"));
        assert!(looks_like_email("  jdoe@school.edu  "), "trims first");
        assert!(looks_like_email("a.b+c@sub.school.k12.us"));
    }

    /// The cases that make this a *shape* test rather than a validator. Each
    /// is a real value seen in a district's `annotatedUser` field.
    #[test]
    fn rejects_free_text_admins_type_into_annotated_user() {
        assert!(!looks_like_email(""));
        assert!(!looks_like_email("   "));
        assert!(!looks_like_email("Cart 3"));
        assert!(!looks_like_email("Ms. Rivera's cart"));
        assert!(!looks_like_email("Library Chromebook"));
        // Whitespace anywhere disqualifies, including inside.
        assert!(!looks_like_email("j doe@school.edu"));
        assert!(!looks_like_email("room 5 @school.edu"));
    }

    #[test]
    fn rejects_malformed_addresses() {
        assert!(!looks_like_email("jdoe"));
        assert!(!looks_like_email("@school.edu"), "empty local part");
        assert!(!looks_like_email("jdoe@"), "empty domain");
        assert!(!looks_like_email("jdoe@school"), "no dot in domain");
        assert!(!looks_like_email("a@b@school.edu"), "two @");
        assert!(
            !looks_like_email("jdoe@.school.edu"),
            "domain starts with ."
        );
        assert!(!looks_like_email("jdoe@school.edu."), "domain ends with .");
    }

    #[test]
    fn domain_is_lowercased() {
        assert_eq!(
            email_domain("Alice@Example.COM").as_deref(),
            Some("example.com")
        );
        assert_eq!(email_domain("no-at-sign"), None);
        // The last @ wins, so a malformed value cannot smuggle a domain past.
        assert_eq!(
            email_domain("a@b@school.edu").as_deref(),
            Some("school.edu")
        );
    }

    #[test]
    fn normalizing_is_case_and_whitespace_insensitive() {
        assert_eq!(normalize_email("  Alice@Example.COM "), "alice@example.com");
    }
}
