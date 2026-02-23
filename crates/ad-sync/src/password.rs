//! Password generation for Active Directory accounts.

use rand::Rng;

/// Generate a password from a template pattern.
///
/// Supported placeholders:
/// - `{firstName}` -- user's given name
/// - `{lastName}` -- user's family name
/// - `{birthYear}` -- user's birth year (or empty if unknown)
/// - `{grade}` -- user's grade level
/// - `{random4}` -- 4 random digits
/// - `{random6}` -- 6 random digits
pub fn generate_password(
    given_name: &str,
    family_name: &str,
    birth_year: Option<&str>,
    grade: Option<&str>,
    pattern: &str,
) -> String {
    let mut result = pattern.to_string();
    result = result.replace("{firstName}", given_name);
    result = result.replace("{lastName}", family_name);
    result = result.replace("{birthYear}", birth_year.unwrap_or(""));
    result = result.replace("{grade}", grade.unwrap_or(""));

    // Replace random digit placeholders
    if result.contains("{random4}") {
        let digits = random_digits(4);
        result = result.replace("{random4}", &digits);
    }
    if result.contains("{random6}") {
        let digits = random_digits(6);
        result = result.replace("{random6}", &digits);
    }

    result
}

/// Generate a random password of the given length using alphanumeric chars + symbols.
pub fn generate_random_password(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Generate a string of random digits.
fn random_digits(count: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| rng.gen_range(0..10).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_first_last() {
        let result = generate_password("John", "Doe", None, None, "{firstName}{lastName}");
        assert_eq!(result, "JohnDoe");
    }

    #[test]
    fn pattern_with_birth_year() {
        let result = generate_password("John", "Doe", Some("2010"), None, "{lastName}{birthYear}");
        assert_eq!(result, "Doe2010");
    }

    #[test]
    fn pattern_with_grade() {
        let result = generate_password("John", "Doe", None, Some("09"), "{lastName}{grade}!");
        assert_eq!(result, "Doe09!");
    }

    #[test]
    fn pattern_with_all_fields() {
        let result = generate_password(
            "Jane",
            "Smith",
            Some("2008"),
            Some("11"),
            "{firstName}.{lastName}{birthYear}#{grade}",
        );
        assert_eq!(result, "Jane.Smith2008#11");
    }

    #[test]
    fn pattern_missing_birth_year_replaced_empty() {
        let result = generate_password("John", "Doe", None, None, "{lastName}{birthYear}!");
        assert_eq!(result, "Doe!");
    }

    #[test]
    fn pattern_with_random4() {
        let result = generate_password("John", "Doe", None, None, "{lastName}{random4}");
        assert!(result.starts_with("Doe"));
        // "Doe" is 3 chars, plus 4 random digits = 7 chars
        assert_eq!(result.len(), 7);
        // Last 4 chars should be digits
        assert!(result[3..].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn pattern_with_random6() {
        let result = generate_password("John", "Doe", None, None, "{random6}");
        assert_eq!(result.len(), 6);
        assert!(result.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn random_password_correct_length() {
        for len in [8, 12, 16, 24] {
            let pw = generate_random_password(len);
            assert_eq!(pw.len(), len);
        }
    }

    #[test]
    fn random_password_contains_valid_chars() {
        let pw = generate_random_password(100);
        let valid: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*";
        for c in pw.chars() {
            assert!(
                valid.contains(c),
                "invalid character in random password: {c}"
            );
        }
    }

    #[test]
    fn random_password_not_all_same() {
        let pw = generate_random_password(20);
        let first = pw.chars().next().unwrap();
        // Extremely unlikely all 20 chars are the same
        assert!(pw.chars().any(|c| c != first));
    }

    #[test]
    fn literal_text_preserved() {
        let result = generate_password("John", "Doe", None, None, "Welcome123!");
        assert_eq!(result, "Welcome123!");
    }
}
