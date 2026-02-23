//! Cryptographic utilities for webhook payload signing and encryption.
//!
//! Provides HMAC-SHA256 signing for `sign_only` mode and AES-256-GCM
//! encryption with HKDF-SHA256 key derivation for `encrypted` mode.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{ChalkError, Result};

use super::models::EncryptedPayload;

type HmacSha256 = Hmac<Sha256>;

/// Derive a 256-bit encryption key from a shared secret using HKDF-SHA256.
///
/// Uses a fixed salt (`chalk-webhook-v1`) and info string (`webhook-encryption-key`)
/// to produce a deterministic key for any given secret.
pub fn derive_key(secret: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"chalk-webhook-v1"), secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"webhook-encryption-key", &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

/// Compute an HMAC-SHA256 signature for sign-only mode.
///
/// Returns a hex-encoded signature string suitable for the `X-Chalk-Signature` header.
pub fn sign_payload(secret: &str, body: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Encrypt a payload using AES-256-GCM with an HKDF-derived key.
///
/// The returned [`EncryptedPayload`] contains base64-encoded nonce and ciphertext,
/// suitable for JSON serialization in webhook delivery.
pub fn encrypt_payload(secret: &str, body: &[u8]) -> Result<EncryptedPayload> {
    let key = derive_key(secret);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, body)
        .map_err(|e| ChalkError::Webhook(format!("encryption failed: {e}")))?;

    Ok(EncryptedPayload {
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    })
}

/// Decrypt a payload produced by [`encrypt_payload`].
///
/// Used in tests and as a reference implementation for webhook consumers.
pub fn decrypt_payload(secret: &str, encrypted: &EncryptedPayload) -> Result<Vec<u8>> {
    let key = derive_key(secret);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);

    let nonce_bytes = BASE64
        .decode(&encrypted.nonce)
        .map_err(|e| ChalkError::Webhook(format!("invalid nonce base64: {e}")))?;
    let ciphertext = BASE64
        .decode(&encrypted.ciphertext)
        .map_err(|e| ChalkError::Webhook(format!("invalid ciphertext base64: {e}")))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| ChalkError::Webhook(format!("decryption failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_payload_produces_consistent_hex_output() {
        let secret = "test-secret";
        let body = b"hello webhook";
        let sig1 = sign_payload(secret, body);
        let sig2 = sign_payload(secret, body);
        assert_eq!(sig1, sig2);
        // HMAC-SHA256 produces 64 hex characters (32 bytes)
        assert_eq!(sig1.len(), 64);
        // Must be valid hex
        assert!(sig1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sign_payload_different_secrets_produce_different_output() {
        let body = b"same body";
        let sig1 = sign_payload("secret-a", body);
        let sig2 = sign_payload("secret-b", body);
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let secret = "my-shared-secret";
        let body = b"webhook payload data";
        let encrypted = encrypt_payload(secret, body).unwrap();
        let decrypted = decrypt_payload(secret, &encrypted).unwrap();
        assert_eq!(decrypted, body);
    }

    #[test]
    fn encrypted_payload_unreadable_without_secret() {
        let secret = "correct-secret";
        let wrong_secret = "wrong-secret";
        let body = b"sensitive data";
        let encrypted = encrypt_payload(secret, body).unwrap();
        let result = decrypt_payload(wrong_secret, &encrypted);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("decryption failed"));
    }

    #[test]
    fn derive_key_deterministic() {
        let secret = "deterministic-test";
        let key1 = derive_key(secret);
        let key2 = derive_key(secret);
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn derive_key_different_secrets() {
        let key1 = derive_key("secret-one");
        let key2 = derive_key("secret-two");
        assert_ne!(key1, key2);
    }

    #[test]
    fn encrypt_produces_valid_base64() {
        let encrypted = encrypt_payload("base64-test", b"test data").unwrap();
        // Both fields should decode without error
        assert!(BASE64.decode(&encrypted.nonce).is_ok());
        assert!(BASE64.decode(&encrypted.ciphertext).is_ok());
        // Nonce should decode to 12 bytes (AES-GCM nonce size)
        let nonce_bytes = BASE64.decode(&encrypted.nonce).unwrap();
        assert_eq!(nonce_bytes.len(), 12);
    }

    #[test]
    fn empty_payload_roundtrip() {
        let secret = "empty-test";
        let body = b"";
        let encrypted = encrypt_payload(secret, body).unwrap();
        let decrypted = decrypt_payload(secret, &encrypted).unwrap();
        assert_eq!(decrypted, body.to_vec());
    }

    #[test]
    fn sign_payload_different_bodies_produce_different_output() {
        let secret = "same-secret";
        let sig1 = sign_payload(secret, b"body-a");
        let sig2 = sign_payload(secret, b"body-b");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn encrypt_same_plaintext_produces_different_ciphertext() {
        let secret = "nonce-test";
        let body = b"same payload";
        let enc1 = encrypt_payload(secret, body).unwrap();
        let enc2 = encrypt_payload(secret, body).unwrap();
        // Different random nonces should produce different ciphertext
        assert_ne!(enc1.nonce, enc2.nonce);
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
        // Both should decrypt correctly
        assert_eq!(decrypt_payload(secret, &enc1).unwrap(), body);
        assert_eq!(decrypt_payload(secret, &enc2).unwrap(), body);
    }

    #[test]
    fn decrypt_with_invalid_base64_nonce_fails() {
        let encrypted = EncryptedPayload {
            nonce: "not-valid-base64!!!".into(),
            ciphertext: BASE64.encode(b"anything"),
        };
        let result = decrypt_payload("secret", &encrypted);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid nonce base64"));
    }

    #[test]
    fn decrypt_with_invalid_base64_ciphertext_fails() {
        let encrypted = EncryptedPayload {
            nonce: BASE64.encode(b"twelve_bytes"),
            ciphertext: "not-valid-base64!!!".into(),
        };
        let result = decrypt_payload("secret", &encrypted);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid ciphertext base64"));
    }

    #[test]
    fn large_payload_roundtrip() {
        let secret = "large-payload-test";
        let body = vec![0xABu8; 100_000];
        let encrypted = encrypt_payload(secret, &body).unwrap();
        let decrypted = decrypt_payload(secret, &encrypted).unwrap();
        assert_eq!(decrypted, body);
    }
}
