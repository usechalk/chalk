//! Picture password grid logic and verification.

/// Available picture options for picture passwords.
pub const PICTURE_OPTIONS: &[&str] = &[
    "cat", "dog", "fish", "bird", "tree", "sun", "moon", "star", "flower", "house", "car", "boat",
];

/// Verify a picture password sequence using constant-time comparison.
/// Returns true if the provided sequence matches the stored sequence.
pub fn verify_sequence(stored: &[String], provided: &[String]) -> bool {
    if stored.len() != provided.len() {
        return false;
    }

    // Constant-time comparison to prevent timing attacks
    let mut result: u8 = 0;
    for (a, b) in stored.iter().zip(provided.iter()) {
        if a.len() != b.len() {
            result |= 1;
        } else {
            for (x, y) in a.bytes().zip(b.bytes()) {
                result |= x ^ y;
            }
        }
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picture_options_not_empty() {
        assert!(!PICTURE_OPTIONS.is_empty());
        assert_eq!(PICTURE_OPTIONS.len(), 12);
    }

    #[test]
    fn picture_options_contain_expected() {
        assert!(PICTURE_OPTIONS.contains(&"cat"));
        assert!(PICTURE_OPTIONS.contains(&"dog"));
        assert!(PICTURE_OPTIONS.contains(&"star"));
    }

    #[test]
    fn verify_matching_sequence() {
        let stored = vec!["cat".to_string(), "dog".to_string(), "fish".to_string()];
        let provided = vec!["cat".to_string(), "dog".to_string(), "fish".to_string()];
        assert!(verify_sequence(&stored, &provided));
    }

    #[test]
    fn verify_mismatched_sequence() {
        let stored = vec!["cat".to_string(), "dog".to_string(), "fish".to_string()];
        let provided = vec!["cat".to_string(), "fish".to_string(), "dog".to_string()];
        assert!(!verify_sequence(&stored, &provided));
    }

    #[test]
    fn verify_different_length() {
        let stored = vec!["cat".to_string(), "dog".to_string()];
        let provided = vec!["cat".to_string(), "dog".to_string(), "fish".to_string()];
        assert!(!verify_sequence(&stored, &provided));
    }

    #[test]
    fn verify_empty_sequences() {
        let stored: Vec<String> = vec![];
        let provided: Vec<String> = vec![];
        assert!(verify_sequence(&stored, &provided));
    }

    #[test]
    fn verify_single_element_match() {
        let stored = vec!["star".to_string()];
        let provided = vec!["star".to_string()];
        assert!(verify_sequence(&stored, &provided));
    }

    #[test]
    fn verify_single_element_mismatch() {
        let stored = vec!["star".to_string()];
        let provided = vec!["moon".to_string()];
        assert!(!verify_sequence(&stored, &provided));
    }

    #[test]
    fn verify_wrong_value() {
        let stored = vec!["cat".to_string(), "dog".to_string()];
        let provided = vec!["cat".to_string(), "cat".to_string()];
        assert!(!verify_sequence(&stored, &provided));
    }
}
