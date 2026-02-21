//! Service account authentication for Google Workspace.
//!
//! Currently a simple token holder. Real service account auth with
//! yup-oauth2 can be added in a future iteration.

/// Holds an OAuth2 bearer token for Google API requests.
pub struct GoogleAuth {
    token: String,
}

impl GoogleAuth {
    /// Create a new auth instance with the given bearer token.
    pub fn new(token: String) -> Self {
        Self { token }
    }

    /// Returns the current bearer token.
    pub fn token(&self) -> &str {
        &self.token
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_stores_and_returns_token() {
        let auth = GoogleAuth::new("test-token-123".to_string());
        assert_eq!(auth.token(), "test-token-123");
    }

    #[test]
    fn auth_with_empty_token() {
        let auth = GoogleAuth::new(String::new());
        assert_eq!(auth.token(), "");
    }
}
