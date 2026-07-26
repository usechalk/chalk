//! Snapshot of a Google OAuth2 access token.
//!
//! `GoogleAuth` is a *value*: it holds one access token and the moment it
//! expires. It cannot refresh itself, which is why anything that runs longer
//! than a token lifetime — a 20,000-device fleet walk, say — must take a
//! [`crate::token::TokenProvider`] instead. It is kept because existing
//! callers (`chalk-cli`, `chalk-console`) fetch a token once and hand it to
//! `GoogleAdminClient::new`, and because for a short user-provisioning run
//! that is still adequate.
//!
//! The token exchange itself lives in [`crate::token::GoogleTokenSource`];
//! this type is a thin façade over it so there is exactly one implementation
//! of the service-account JWT flow in the crate.

use chalk_core::error::Result;
use chrono::{Duration, Utc};

use crate::token::GoogleTokenSource;

/// Holds an OAuth2 bearer token for Google API requests, with expiry tracking.
#[derive(Debug)]
pub struct GoogleAuth {
    access_token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl GoogleAuth {
    /// Create auth from a service account JSON key file.
    ///
    /// Reads the key file, builds a signed JWT, and exchanges it for an
    /// access token via Google's token endpoint using domain-wide delegation.
    pub async fn from_service_account(
        key_path: &str,
        admin_email: &str,
        scopes: &[&str],
    ) -> Result<Self> {
        let source = GoogleTokenSource::from_service_account_file(key_path, admin_email, scopes)?;
        let (access_token, expires_at) = source.token_with_expiry().await?;
        Ok(Self {
            access_token,
            expires_at,
        })
    }

    /// Create auth from a raw token (for testing/backwards compat).
    pub fn new(token: String) -> Self {
        Self {
            access_token: token,
            expires_at: Utc::now() + Duration::hours(1),
        }
    }

    /// Returns the current bearer token.
    pub fn token(&self) -> &str {
        &self.access_token
    }

    /// Returns true if the token has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::tests::{write_key_file, TEST_RSA_PRIVATE_KEY};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    #[test]
    fn new_token_is_not_expired() {
        let auth = GoogleAuth::new("token".to_string());
        assert!(!auth.is_expired());
    }

    #[test]
    fn expired_token_detected() {
        let auth = GoogleAuth {
            access_token: "old-token".to_string(),
            expires_at: Utc::now() - Duration::seconds(10),
        };
        assert!(auth.is_expired());
    }

    #[tokio::test]
    async fn from_service_account_missing_file() {
        let result =
            GoogleAuth::from_service_account("/nonexistent/sa.json", "admin@test.com", &[]).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to read service account key"));
    }

    #[tokio::test]
    async fn from_service_account_invalid_json() {
        let (_dir, key_path) = write_key_file("not valid json");

        let result = GoogleAuth::from_service_account(&key_path, "admin@test.com", &[]).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to parse service account key"));
    }

    #[tokio::test]
    async fn from_service_account_exchanges_token() {
        let mock_server = MockServer::start().await;

        // A service account key JSON pointing at the mock token endpoint.
        let (_dir, key_path) = write_key_file(
            &serde_json::json!({
                "client_email": "test@test-project.iam.gserviceaccount.com",
                "private_key": TEST_RSA_PRIVATE_KEY,
                "token_uri": format!("{}/token", mock_server.uri()),
            })
            .to_string(),
        );

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ya29.test-access-token",
                "expires_in": 3600,
                "token_type": "Bearer",
            })))
            .mount(&mock_server)
            .await;

        let auth = GoogleAuth::from_service_account(
            &key_path,
            "admin@example.com",
            &["https://www.googleapis.com/auth/admin.directory.user"],
        )
        .await
        .expect("token exchange should succeed");

        assert_eq!(auth.token(), "ya29.test-access-token");
        assert!(!auth.is_expired());
    }

    #[tokio::test]
    async fn from_service_account_handles_error_response() {
        let mock_server = MockServer::start().await;

        let (_dir, key_path) = write_key_file(
            &serde_json::json!({
                "client_email": "test@test-project.iam.gserviceaccount.com",
                "private_key": TEST_RSA_PRIVATE_KEY,
                "token_uri": format!("{}/token", mock_server.uri()),
            })
            .to_string(),
        );

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({"error": "invalid_grant"})),
            )
            .mount(&mock_server)
            .await;

        let result = GoogleAuth::from_service_account(
            &key_path,
            "admin@example.com",
            &["https://www.googleapis.com/auth/admin.directory.user"],
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("token exchange failed"));
    }
}
