//! Service account JWT-based OAuth2 authentication for Google Workspace.
//!
//! Implements the Google service account flow:
//! 1. Read the JSON key file
//! 2. Build and sign a JWT assertion with RS256
//! 3. Exchange the JWT for an access token via the token endpoint

use chalk_core::error::{ChalkError, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    token_uri: String,
}

#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    scope: String,
    aud: String,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

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
        let key_data = std::fs::read_to_string(key_path).map_err(|e| {
            ChalkError::GoogleSync(format!("failed to read service account key: {e}"))
        })?;
        let key: ServiceAccountKey = serde_json::from_str(&key_data).map_err(|e| {
            ChalkError::GoogleSync(format!("failed to parse service account key: {e}"))
        })?;

        let now = Utc::now();
        let claims = JwtClaims {
            iss: key.client_email.clone(),
            sub: admin_email.to_string(),
            scope: scopes.join(" "),
            aud: key.token_uri.clone(),
            iat: now.timestamp(),
            exp: (now + Duration::hours(1)).timestamp(),
        };

        let encoding_key = EncodingKey::from_rsa_pem(key.private_key.as_bytes())
            .map_err(|e| ChalkError::GoogleSync(format!("invalid RSA private key: {e}")))?;

        let jwt = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)
            .map_err(|e| ChalkError::GoogleSync(format!("JWT encoding failed: {e}")))?;

        let client = reqwest::Client::new();
        let resp = client
            .post(&key.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("token exchange request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChalkError::GoogleSync(format!(
                "token exchange failed ({status}): {body}"
            )));
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("token response parse failed: {e}")))?;

        Ok(Self {
            access_token: token_resp.access_token,
            expires_at: now + Duration::seconds(token_resp.expires_in),
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
        let dir = std::env::temp_dir().join("chalk_auth_test_invalid");
        std::fs::create_dir_all(&dir).unwrap();
        let key_file = dir.join("bad-sa.json");
        std::fs::write(&key_file, "not valid json").unwrap();

        let result =
            GoogleAuth::from_service_account(key_file.to_str().unwrap(), "admin@test.com", &[])
                .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to parse service account key"));

        std::fs::remove_file(&key_file).ok();
        std::fs::remove_dir(&dir).ok();
    }

    /// A pre-generated 2048-bit RSA private key for testing only.
    fn test_rsa_private_key() -> &'static str {
        "-----BEGIN PRIVATE KEY-----\n\
         MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6TfNh8SrGpclp\n\
         6HMvjy0DEf9z5PtK1zIy8nsksOORDWhDRDaarfeTBrQiinkTVJstNFLV7sJ1Q/Z3\n\
         tbMEjW2OO3L+NKdU7KSnpWEmswZlZ8EpcLHFcmnidNa47KJ2Zd/WZBGf+6oVtldw\n\
         mSu+bI6UXqdSvvwRiqj+KKQW7SdRLb2uWEPwsMGTT+DLRtyxoBkwoBqwTf63fTZl\n\
         /9X8xYxGn+j8EJh8qrqgHezDpw89CS2ddMt9KdubTmf6p2+7RJm1lG2kPTZVbxfl\n\
         x+ak0d0vvT2wlkwEHphJiAZ7S/Wzooa0KvjxkGTI+FFPB+D3Iseh7ivnWEq/sxHy\n\
         FZcQZCcnAgMBAAECggEAGndEYd9+siWPDUqGQnVWcZ826OHYiPM1IGOt9rJiQZLk\n\
         AtpH34VjLDHBmT6OoJ5eRPev5NA8M6hp9OuM+NKWg6QSW+Zi9v9/DInD2VmJSRKK\n\
         MDbgKipsvEzYzABhu+wQ9kXU8yMvMFJs7YP04OJPBujDYE/dQyithR2E4fTipvdY\n\
         HfKBwOWSqe/St6nQ06bxrn5zu6XMK+dTvw9hu/jkSX3SxwJtR8ImTX5jUMpd0raA\n\
         g6dirHw7XfjkC17elXufTdehfgqkCkMQctuMQjWXMj5OC78O8eXIKhOZfCx0APUc\n\
         SVse+y28FCL6wtr9z0WdumRIqUqGSdaWYAxBhg+esQKBgQDyZPLzHNroCTgYf+0H\n\
         68oAdXKjTy2QgqFIThiUry99aeUogtWgovBS+K+gqWb36MclCn7aExQUIcYkl7DB\n\
         3Ff5xxn9aLfUdIur/iuC6eXZ5937G1kK4pdzoeNWCeo8OPCaoW8hb0nvfMPDS9g7\n\
         WwhRlnFx8UYohnoNUafS7CC+ZQKBgQDEwwbX2w7kKrgEzXQa59RM05dvSt3kV9l3\n\
         BPREWHU4GQAlzkYfxYF72MwKdie2Lc7JN0mUsm7f4wFAPqRafT+I9WHDnQXY+NXt\n\
         o6M7s2RNawcDZInl3lwGk6G7SHepmh8NYxjiK2tFIDxIx1vYJIF+WU3lo33FDXpY\n\
         h/BV0E9gmwKBgQC6cDsOE1usraqf7YV7Wjj9MVkDk5sQU+mJm8f8VOLKK/E+v6Ng\n\
         8vK2XuF3SdURSdIjA3eedJ40/eVRr/scoUZpsGKlLy52E0568/yzrQRGHrn2sopC\n\
         fRbQsewR+X5Y49LsnM7FgLv1oJlSVbvzq4kyd+y6H0I/WW/3Xp8e9NAaoQKBgQCg\n\
         h7FkmO+cThIWsP0CGpSGHbeWcFF6xAXDagJUZIs2Ood5UMK7lysePPGzs1SQ+OyW\n\
         FApvS+jTtuRFYxY6UadteS3LJ6gmrlXzbSd3RNQXqbNuHC+5oGIaZ4ZzQxuF/x1I\n\
         kcoydFQvcK5efnA7dwVDbV71dR7ejzF7W2VEzhCE8wKBgFJ9Ro3tNIuqvc2mWZpr\n\
         0U766jN8S6RaHtMeiEiy81IL/vxWWrAAuphCAQM179VTYgOSBfaxxndmE34RlTMB\n\
         tokgaBA8flLko3cDhXlavGtHCD/VojxWUWeX4Ou9/xSy/kIbd9r868SdcBo3BZe1\n\
         6xUvIBqnkJUHjuG/cXMQaxpP\n\
         -----END PRIVATE KEY-----"
    }

    #[tokio::test]
    async fn from_service_account_exchanges_token() {
        let mock_server = MockServer::start().await;

        // Generate a test RSA key
        let private_key_pem = test_rsa_private_key().to_string();

        // Create a service account key JSON pointing to the mock server
        let sa_key = serde_json::json!({
            "client_email": "test@test-project.iam.gserviceaccount.com",
            "private_key": private_key_pem,
            "token_uri": format!("{}/token", mock_server.uri()),
        });

        let dir = std::env::temp_dir().join("chalk_auth_test_exchange");
        std::fs::create_dir_all(&dir).unwrap();
        let key_file = dir.join("test-sa.json");
        std::fs::write(&key_file, serde_json::to_string(&sa_key).unwrap()).unwrap();

        // Mock the token endpoint
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
            key_file.to_str().unwrap(),
            "admin@example.com",
            &["https://www.googleapis.com/auth/admin.directory.user"],
        )
        .await
        .expect("token exchange should succeed");

        assert_eq!(auth.token(), "ya29.test-access-token");
        assert!(!auth.is_expired());

        std::fs::remove_file(&key_file).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[tokio::test]
    async fn from_service_account_handles_error_response() {
        let mock_server = MockServer::start().await;

        let private_key_pem = test_rsa_private_key().to_string();

        let sa_key = serde_json::json!({
            "client_email": "test@test-project.iam.gserviceaccount.com",
            "private_key": private_key_pem,
            "token_uri": format!("{}/token", mock_server.uri()),
        });

        let dir = std::env::temp_dir().join("chalk_auth_test_error");
        std::fs::create_dir_all(&dir).unwrap();
        let key_file = dir.join("test-sa-err.json");
        std::fs::write(&key_file, serde_json::to_string(&sa_key).unwrap()).unwrap();

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({"error": "invalid_grant"})),
            )
            .mount(&mock_server)
            .await;

        let result = GoogleAuth::from_service_account(
            key_file.to_str().unwrap(),
            "admin@example.com",
            &["https://www.googleapis.com/auth/admin.directory.user"],
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("token exchange failed"));

        std::fs::remove_file(&key_file).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
