//! Admin user bootstrap for newly activated tenants.
//!
//! Creates a single administrator `User` row and inserts a one-time password
//! reset token into the `password_reset_tokens` table. The user lands at
//! `/login?reset_token=<raw>` after verification; the console consumes the
//! token, sets a session, and redirects them to set their password.
//!
//! The `password_hash` column is left untouched here — the user has no
//! credential until they redeem the reset token.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use chalk_core::db::repository::ChalkRepository;
use chalk_core::models::common::{RoleType, Status};
use chalk_core::models::user::User;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Lifetime of a bootstrap reset token.
const RESET_TOKEN_TTL_HOURS: i64 = 24;

/// Result of bootstrapping an admin: returns the plaintext one-time reset
/// token. Only the SHA-256 hex of the raw token is persisted.
pub struct BootstrapResult {
    pub user_sourced_id: String,
    pub reset_token: String,
}

/// Bootstrap an administrator user in the tenant's repository.
///
/// - Inserts a `User` row with role=Administrator (no password set).
/// - Generates a 256-bit random reset token, SHA-256 hashes it, and stores
///   the hash in `password_reset_tokens` with a 24h expiry.
pub async fn bootstrap_admin(
    repo: &Arc<dyn ChalkRepository>,
    admin_email: &str,
    admin_name: &str,
) -> Result<BootstrapResult> {
    let (given_name, family_name) = split_name(admin_name);
    let sourced_id = format!("admin-{}", Uuid::new_v4());

    let user = User {
        sourced_id: sourced_id.clone(),
        status: Status::Active,
        date_last_modified: Utc::now(),
        metadata: None,
        username: admin_email.to_string(),
        user_ids: Vec::new(),
        enabled_user: true,
        given_name,
        family_name,
        middle_name: None,
        role: RoleType::Administrator,
        identifier: None,
        email: Some(admin_email.to_string()),
        sms: None,
        phone: None,
        agents: Vec::new(),
        orgs: Vec::new(),
        grades: Vec::new(),
    };
    repo.upsert_user(&user)
        .await
        .map_err(|e| anyhow!("failed to insert admin user: {e}"))?;

    let reset_token = generate_reset_token();
    let token_hash = sha256_hex(&reset_token);
    let expires_at = Utc::now() + Duration::hours(RESET_TOKEN_TTL_HOURS);
    repo.create_reset_token(&sourced_id, &token_hash, expires_at)
        .await
        .map_err(|e| anyhow!("failed to store reset token: {e}"))?;

    Ok(BootstrapResult {
        user_sourced_id: sourced_id,
        reset_token,
    })
}

fn split_name(full: &str) -> (String, String) {
    let trimmed = full.trim();
    if trimmed.is_empty() {
        return ("Admin".to_string(), String::new());
    }
    match trimmed.split_once(' ') {
        Some((first, rest)) => (first.to_string(), rest.trim().to_string()),
        None => (trimmed.to_string(), String::new()),
    }
}

/// Generate a 256-bit random URL-safe-ish reset token. Uses 32 random bytes
/// hex-encoded — 64 hex chars, ~256 bits of entropy.
fn generate_reset_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Lowercase hex SHA-256 of `value`. Used as the stable lookup key for
/// reset tokens (raw token is high-entropy, so a fast deterministic hash is
/// sufficient and avoids per-row argon2 verify-loops).
fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_split_basic() {
        assert_eq!(split_name("Jane Doe"), ("Jane".into(), "Doe".into()));
        assert_eq!(
            split_name("Jane Mary Doe"),
            ("Jane".into(), "Mary Doe".into())
        );
        assert_eq!(split_name("Jane"), ("Jane".into(), String::new()));
        assert_eq!(split_name(""), ("Admin".into(), String::new()));
    }

    #[test]
    fn reset_token_is_64_hex_chars() {
        let t = generate_reset_token();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn reset_tokens_are_unique() {
        let a = generate_reset_token();
        let b = generate_reset_token();
        assert_ne!(a, b);
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        let a = sha256_hex("hello");
        let b = sha256_hex("hello");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert_ne!(sha256_hex("hello"), sha256_hex("world"));
    }
}
