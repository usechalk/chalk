//! Cryptographic utilities for webhook payload signing and encryption.
//!
//! Provides HMAC-SHA256 signing for `sign_only` mode and AES-256-GCM
//! encryption with HKDF-SHA256 key derivation for `encrypted` mode.

use aes_gcm::{
    aead::{Aead, Generate, KeyInit},
    Aes256Gcm, Key, Nonce,
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
    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(secret.as_bytes())
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
    let cipher_key = Key::<Aes256Gcm>::from(key);
    let cipher = Aes256Gcm::new(&cipher_key);
    // aes-gcm 0.11 replaced `Aes256Gcm::generate_nonce(&mut OsRng)` with
    // `Nonce::generate()`, which draws from the OS RNG itself. A fresh nonce per
    // encryption is the whole security property of GCM — reuse under the same
    // key leaks the plaintext XOR — so this stays a per-call random draw and is
    // never derived from the message or a counter.
    let nonce = Nonce::generate();

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
    let cipher_key = Key::<Aes256Gcm>::from(key);
    let cipher = Aes256Gcm::new(&cipher_key);

    let nonce_bytes = BASE64
        .decode(&encrypted.nonce)
        .map_err(|e| ChalkError::Webhook(format!("invalid nonce base64: {e}")))?;
    let ciphertext = BASE64
        .decode(&encrypted.ciphertext)
        .map_err(|e| ChalkError::Webhook(format!("invalid ciphertext base64: {e}")))?;

    // Was `Nonce::from_slice`, which panics on the wrong length — and this
    // nonce arrives base64-decoded from the payload with nothing checking it is
    // twelve bytes. A malformed delivery could take the process down. `TryFrom`
    // turns that into the error the caller already handles.
    let nonce = Nonce::try_from(nonce_bytes.as_slice())
        .map_err(|_| ChalkError::Webhook("nonce is not 12 bytes".to_string()))?;
    cipher
        .decrypt(&nonce, ciphertext.as_ref())
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

    /// Both values below were computed by an independent HMAC/HKDF
    /// implementation, not captured from this code, so they pin us to the
    /// standard rather than to whatever we happened to emit last release.
    ///
    /// They are wire-visible and belong to somebody else: the signature is the
    /// `X-Chalk-Signature` header every receiver verifies, and the derived key
    /// decrypts payloads a receiver already holds. If a dependency bump changed
    /// either, every integration would start rejecting deliveries at once, and
    /// determinism tests would not notice — they only prove we agree with
    /// ourselves.
    #[test]
    fn the_signature_and_derived_key_match_the_standard() {
        assert_eq!(
            sign_payload(
                "chalk-webhook-secret",
                br#"{"event":"user.created","id":"u-1"}"#
            ),
            "145e4056416f9ab56e223ecee4d2a2755a72983d892ee72386ae59bc775d90d2",
            "HMAC-SHA256 no longer matches a reference implementation"
        );

        let expected = "ad9ed02e259f71c9e4e0d627b632dd75df765a018c58c07714b1173c7b36ee2c";
        let got: String = derive_key("deterministic-test")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(got, expected, "HKDF-SHA256 output changed");
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

    /// A nonce of the wrong length used to reach `Nonce::from_slice`, which
    /// panics rather than returning an error — and nothing between the base64
    /// decode and that call checked the length. Valid base64 of the wrong size
    /// is trivial to send, so this was a malformed delivery away from taking
    /// the process down.
    #[test]
    fn a_nonce_of_the_wrong_length_is_an_error_and_not_a_panic() {
        for wrong in [0usize, 1, 11, 13, 64] {
            let payload = EncryptedPayload {
                nonce: BASE64.encode(vec![0u8; wrong]),
                ciphertext: BASE64.encode([0u8; 32]),
            };
            let err = decrypt_payload("a-secret", &payload)
                .expect_err("a {wrong}-byte nonce must not decrypt");
            assert!(
                err.to_string().contains("nonce") || err.to_string().contains("decryption"),
                "unexpected error for a {wrong}-byte nonce: {err}"
            );
        }
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
