//! Authentication logic for password, QR badge, and picture password login.

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use chalk_core::db::repository::ChalkRepository;
use chalk_core::error::{ChalkError, Result};
use chalk_core::models::user::User;

/// Hash a password using Argon2id.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ChalkError::Auth(format!("failed to hash password: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash.
pub fn verify_password(hash: &str, password: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| ChalkError::Auth(format!("invalid password hash: {e}")))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Authenticate a user by username and password.
pub async fn authenticate_password<R: ChalkRepository>(
    repo: &R,
    username: &str,
    password: &str,
) -> Result<User> {
    let normalized = username.to_lowercase();
    let user = repo
        .get_user_by_username(&normalized)
        .await?
        .ok_or_else(|| ChalkError::Auth("invalid credentials".into()))?;

    let hash = repo
        .get_password_hash(&user.sourced_id)
        .await?
        .ok_or_else(|| ChalkError::Auth("no password set for user".into()))?;

    if !verify_password(&hash, password)? {
        return Err(ChalkError::Auth("invalid credentials".into()));
    }

    Ok(user)
}

/// Authenticate a user by QR badge token.
pub async fn authenticate_qr_badge<R: ChalkRepository>(
    repo: &R,
    badge_token: &str,
) -> Result<User> {
    let badge = repo
        .get_badge_by_token(badge_token)
        .await?
        .ok_or_else(|| ChalkError::Auth("invalid badge token".into()))?;

    if !badge.is_active {
        return Err(ChalkError::Auth("badge has been revoked".into()));
    }

    let user = repo
        .get_user(&badge.user_sourced_id)
        .await?
        .ok_or_else(|| ChalkError::Auth("user not found for badge".into()))?;

    Ok(user)
}

/// Authenticate a user by picture password.
pub async fn authenticate_picture_password<R: ChalkRepository>(
    repo: &R,
    username: &str,
    image_sequence: &[String],
) -> Result<User> {
    let normalized = username.to_lowercase();
    let user = repo
        .get_user_by_username(&normalized)
        .await?
        .ok_or_else(|| ChalkError::Auth("invalid credentials".into()))?;

    let pp = repo
        .get_picture_password(&user.sourced_id)
        .await?
        .ok_or_else(|| ChalkError::Auth("no picture password set for user".into()))?;

    if !crate::picture::verify_sequence(&pp.image_sequence, image_sequence) {
        return Err(ChalkError::Auth("invalid picture password".into()));
    }

    Ok(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_password() {
        let hash = hash_password("mysecretpassword").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(verify_password(&hash, "mysecretpassword").unwrap());
        assert!(!verify_password(&hash, "wrongpassword").unwrap());
    }

    #[test]
    fn hash_produces_different_salts() {
        let hash1 = hash_password("password").unwrap();
        let hash2 = hash_password("password").unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn verify_invalid_hash_returns_error() {
        let result = verify_password("not-a-valid-hash", "password");
        assert!(result.is_err());
    }

    #[test]
    fn hash_empty_password() {
        let hash = hash_password("").unwrap();
        assert!(verify_password(&hash, "").unwrap());
        assert!(!verify_password(&hash, "notempty").unwrap());
    }
}
