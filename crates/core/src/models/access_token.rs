//! Access token model for OAuth/SSO token storage.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// An OAuth access token issued to a client on behalf of a user.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AccessToken {
    pub token: String,
    pub client_id: String,
    pub user_sourced_id: String,
    pub scopes: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_token_round_trip() {
        let token = AccessToken {
            token: "tok-abc123".to_string(),
            client_id: "client-001".to_string(),
            user_sourced_id: "user-001".to_string(),
            scopes: "openid profile".to_string(),
            created_at: "2025-06-01T12:00:00Z".to_string(),
            expires_at: "2025-06-01T13:00:00Z".to_string(),
            revoked_at: None,
        };
        let json = serde_json::to_string(&token).unwrap();
        let back: AccessToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back.token, "tok-abc123");
        assert_eq!(back.client_id, "client-001");
        assert!(back.revoked_at.is_none());
    }

    #[test]
    fn access_token_with_revocation() {
        let token = AccessToken {
            token: "tok-def456".to_string(),
            client_id: "client-002".to_string(),
            user_sourced_id: "user-002".to_string(),
            scopes: "openid".to_string(),
            created_at: "2025-06-01T12:00:00Z".to_string(),
            expires_at: "2025-06-01T13:00:00Z".to_string(),
            revoked_at: Some("2025-06-01T12:30:00Z".to_string()),
        };
        assert!(token.revoked_at.is_some());
    }
}
