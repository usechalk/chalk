//! Username generation for Active Directory accounts.

/// Generate a sAMAccountName from a user's first and last name.
///
/// Algorithm: first initial + last name, lowercased, non-alphanumeric chars stripped.
/// Truncated to 20 characters (AD sAMAccountName limit).
/// If a collision exists in `existing`, an incrementing number is appended.
pub fn generate_sam_account_name(
    given_name: &str,
    family_name: &str,
    existing: &[String],
) -> String {
    let first_initial: String = given_name
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(1)
        .flat_map(|c| c.to_lowercase())
        .collect();

    let last_clean: String = family_name
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect();

    let base = format!("{first_initial}{last_clean}");
    let truncated = truncate_sam(&base, 20);

    if !existing
        .iter()
        .any(|e| e.to_lowercase() == truncated.to_lowercase())
    {
        return truncated;
    }

    let mut counter = 2u32;
    loop {
        let suffix = counter.to_string();
        let max_base_len = 20 - suffix.len();
        let candidate = format!("{}{}", truncate_sam(&base, max_base_len), suffix);
        if !existing
            .iter()
            .any(|e| e.to_lowercase() == candidate.to_lowercase())
        {
            return candidate;
        }
        counter += 1;
    }
}

/// Generate a User Principal Name (UPN) from first/last name and domain.
///
/// Format: `sam_account_name@domain`.
pub fn generate_upn(
    given_name: &str,
    family_name: &str,
    domain: &str,
    existing_sams: &[String],
) -> String {
    let sam = generate_sam_account_name(given_name, family_name, existing_sams);
    format!("{sam}@{domain}")
}

/// Truncate a string to at most `max_len` characters.
fn truncate_sam(s: &str, max_len: usize) -> String {
    s.chars().take(max_len).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_sam_generation() {
        let result = generate_sam_account_name("John", "Doe", &[]);
        assert_eq!(result, "jdoe");
    }

    #[test]
    fn collision_appends_number() {
        let existing = vec!["jdoe".to_string()];
        let result = generate_sam_account_name("John", "Doe", &existing);
        assert_eq!(result, "jdoe2");
    }

    #[test]
    fn multiple_collisions() {
        let existing = vec!["jdoe".to_string(), "jdoe2".to_string(), "jdoe3".to_string()];
        let result = generate_sam_account_name("John", "Doe", &existing);
        assert_eq!(result, "jdoe4");
    }

    #[test]
    fn special_characters_stripped() {
        let result = generate_sam_account_name("Mary-Jane", "O'Brien", &[]);
        assert_eq!(result, "mobrien");
    }

    #[test]
    fn case_insensitive_generation() {
        let result = generate_sam_account_name("JOHN", "DOE", &[]);
        assert_eq!(result, "jdoe");
    }

    #[test]
    fn spaces_in_name() {
        let result = generate_sam_account_name("Mary Jane", "Van Der Berg", &[]);
        assert_eq!(result, "mvanderberg");
    }

    #[test]
    fn truncation_at_20_chars() {
        let result = generate_sam_account_name("A", "Bartholomewsonstein", &[]);
        // "a" + "bartholomewsonstein" = 20 chars, fits exactly
        assert_eq!(result, "abartholomewsonstein");
        assert!(result.len() <= 20);
    }

    #[test]
    fn very_long_name_truncated() {
        let result = generate_sam_account_name("Alexander", "Bartholomewsonsteiner", &[]);
        assert!(result.len() <= 20);
    }

    #[test]
    fn collision_with_truncated_name() {
        let existing = vec!["abartholomewsonstein".to_string()];
        let result = generate_sam_account_name("A", "Bartholomewsonstein", &existing);
        // base is 20 chars, truncated to 19 to make room for "2" suffix
        assert_eq!(result, "abartholomewsonstei2");
        assert!(result.len() <= 20);
    }

    #[test]
    fn case_insensitive_collision_detection() {
        let existing = vec!["JDoe".to_string()];
        let result = generate_sam_account_name("John", "Doe", &existing);
        assert_eq!(result, "jdoe2");
    }

    #[test]
    fn upn_generation() {
        let result = generate_upn("John", "Doe", "example.com", &[]);
        assert_eq!(result, "jdoe@example.com");
    }

    #[test]
    fn upn_with_collision() {
        let existing = vec!["jdoe".to_string()];
        let result = generate_upn("John", "Doe", "example.com", &existing);
        assert_eq!(result, "jdoe2@example.com");
    }

    #[test]
    fn single_char_last_name() {
        let result = generate_sam_account_name("John", "X", &[]);
        assert_eq!(result, "jx");
    }
}
