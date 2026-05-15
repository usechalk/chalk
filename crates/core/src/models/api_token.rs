//! API tokens for OneRoster REST API authentication.
//!
//! A token is minted as 32 random bytes hex-encoded, prefixed with `chk_`.
//! The full plaintext is shown to the admin exactly once at creation; only
//! the SHA-256 hash is persisted, alongside a short prefix for UI display.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single API token row. `token_hash` is the SHA-256 of the plaintext;
/// the plaintext is never stored. `token_prefix` is the first 8 chars of the
/// plaintext (after the `chk_` marker) so the admin can identify a token
/// in the UI without seeing the secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    pub token_prefix: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ApiToken {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// Newly-minted token — returned exactly once from `create_api_token` so the
/// admin can copy the plaintext. The plaintext is NOT persisted.
#[derive(Debug, Clone)]
pub struct NewApiToken {
    pub token: ApiToken,
    pub plaintext: String,
}
