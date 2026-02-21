//! AES-256-GCM encryption utilities for protecting secrets at rest.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Key, Nonce,
};

use crate::error::{ChalkError, Result};

/// Generate a new random 256-bit encryption key.
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Encrypt plaintext using AES-256-GCM.
///
/// Returns nonce (12 bytes) || ciphertext.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| ChalkError::Crypto(format!("encryption failed: {e}")))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt ciphertext produced by [`encrypt`].
///
/// Expects input format: nonce (12 bytes) || ciphertext.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(ChalkError::Crypto(
            "ciphertext too short: missing nonce".to_string(),
        ));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| ChalkError::Crypto(format!("decryption failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_returns_32_bytes() {
        let key = generate_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn generate_key_is_random() {
        let key1 = generate_key();
        let key2 = generate_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = b"hello world";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_data() {
        let key = generate_key();
        let plaintext = b"";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_large_data() {
        let key = generate_key();
        let plaintext = vec![0x42u8; 10_000];
        let encrypted = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"secret data";
        let encrypted = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &encrypted);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("decryption failed"));
    }

    #[test]
    fn decrypt_with_short_data_fails() {
        let key = generate_key();
        let result = decrypt(&key, &[0u8; 5]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("ciphertext too short"));
    }

    #[test]
    fn decrypt_with_tampered_data_fails() {
        let key = generate_key();
        let plaintext = b"important secret";
        let mut encrypted = encrypt(&key, plaintext).unwrap();
        // Tamper with the ciphertext (not the nonce)
        if let Some(byte) = encrypted.last_mut() {
            *byte ^= 0xFF;
        }
        let result = decrypt(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn encrypted_output_has_nonce_prefix() {
        let key = generate_key();
        let plaintext = b"test";
        let encrypted = encrypt(&key, plaintext).unwrap();
        // AES-GCM nonce is 12 bytes, ciphertext is plaintext_len + 16 bytes tag
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);
    }

    #[test]
    fn same_plaintext_produces_different_ciphertext() {
        let key = generate_key();
        let plaintext = b"deterministic?";
        let encrypted1 = encrypt(&key, plaintext).unwrap();
        let encrypted2 = encrypt(&key, plaintext).unwrap();
        // Different nonces should produce different ciphertext
        assert_ne!(encrypted1, encrypted2);
        // But both should decrypt to the same thing
        assert_eq!(
            decrypt(&key, &encrypted1).unwrap(),
            decrypt(&key, &encrypted2).unwrap()
        );
    }
}
