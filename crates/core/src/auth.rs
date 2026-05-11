//! Shared password hashing and verification helpers.
//!
//! Centralizes Argon2id `hash_password` / `verify_password` so each crate
//! does not roll its own wrapper. Callers should keep wrapping
//! [`verify_password`] in `tokio::task::spawn_blocking` — Argon2 verification
//! is CPU-bound (~100ms) and would otherwise starve the runtime under
//! concurrent login pressure.

use anyhow::Result;
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

/// Hash a password using Argon2id with a fresh random salt.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash.
///
/// Returns `Ok(true)` on match, `Ok(false)` on mismatch, and `Err` only when
/// the stored hash string fails to parse.
pub fn verify_password(stored_hash: &str, password: &str) -> Result<bool> {
    let parsed =
        PasswordHash::new(stored_hash).map_err(|e| anyhow::anyhow!("argon2 parse: {e}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(verify_password(&hash, "correct horse battery staple").unwrap());
        assert!(!verify_password(&hash, "wrong password").unwrap());
    }

    #[test]
    fn hash_uses_random_salts() {
        let h1 = hash_password("same-password").unwrap();
        let h2 = hash_password("same-password").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_invalid_hash_format_errors() {
        assert!(verify_password("not-a-real-hash", "anything").is_err());
    }

    #[test]
    fn empty_password_roundtrip() {
        let hash = hash_password("").unwrap();
        assert!(verify_password(&hash, "").unwrap());
        assert!(!verify_password(&hash, "x").unwrap());
    }
}
