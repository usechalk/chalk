//! Username generation for Google Workspace accounts.

/// Generate a unique username from first/last name and domain.
///
/// Algorithm: first_initial + last_name + optional_number@domain.
/// If a collision exists in `existing`, an incrementing number is appended.
/// Names are lowercased and non-alphanumeric characters are stripped.
pub fn generate_username(
    given_name: &str,
    family_name: &str,
    domain: &str,
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
    let candidate = format!("{base}@{domain}");

    if !existing
        .iter()
        .any(|e| e.to_lowercase() == candidate.to_lowercase())
    {
        return candidate;
    }

    let mut counter = 2u32;
    loop {
        let candidate = format!("{base}{counter}@{domain}");
        if !existing
            .iter()
            .any(|e| e.to_lowercase() == candidate.to_lowercase())
        {
            return candidate;
        }
        counter += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_username_generation() {
        let result = generate_username("John", "Doe", "school.edu", &[]);
        assert_eq!(result, "jdoe@school.edu");
    }

    #[test]
    fn collision_appends_number() {
        let existing = vec!["jdoe@school.edu".to_string()];
        let result = generate_username("John", "Doe", "school.edu", &existing);
        assert_eq!(result, "jdoe2@school.edu");
    }

    #[test]
    fn multiple_collisions() {
        let existing = vec![
            "jdoe@school.edu".to_string(),
            "jdoe2@school.edu".to_string(),
            "jdoe3@school.edu".to_string(),
        ];
        let result = generate_username("John", "Doe", "school.edu", &existing);
        assert_eq!(result, "jdoe4@school.edu");
    }

    #[test]
    fn special_characters_stripped() {
        let result = generate_username("Mary-Jane", "O'Brien", "school.edu", &[]);
        assert_eq!(result, "mobrien@school.edu");
    }

    #[test]
    fn unicode_characters_handled() {
        let result = generate_username("Jose", "Garcia", "school.edu", &[]);
        assert_eq!(result, "jgarcia@school.edu");
    }

    #[test]
    fn case_insensitive_generation() {
        let result = generate_username("JOHN", "DOE", "school.edu", &[]);
        assert_eq!(result, "jdoe@school.edu");
    }

    #[test]
    fn spaces_in_name() {
        let result = generate_username("Mary Jane", "Van Der Berg", "school.edu", &[]);
        assert_eq!(result, "mvanderberg@school.edu");
    }

    #[test]
    fn single_char_last_name() {
        let result = generate_username("John", "X", "school.edu", &[]);
        assert_eq!(result, "jx@school.edu");
    }

    #[test]
    fn case_insensitive_collision_detection() {
        // Existing entry has uppercase; generated candidate is lowercase.
        // Should detect the collision and append a number.
        let existing = vec!["JDoe@school.edu".to_string()];
        let result = generate_username("John", "Doe", "school.edu", &existing);
        assert_eq!(result, "jdoe2@school.edu");
    }

    #[test]
    fn case_insensitive_collision_detection_mixed() {
        let existing = vec![
            "JDOE@school.edu".to_string(),
            "jDoE2@school.edu".to_string(),
        ];
        let result = generate_username("John", "Doe", "school.edu", &existing);
        assert_eq!(result, "jdoe3@school.edu");
    }
}
