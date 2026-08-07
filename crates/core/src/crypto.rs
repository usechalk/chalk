//! AES-256-GCM encryption utilities for protecting secrets at rest.

use aes_gcm::{
    aead::{Aead, Generate, KeyInit},
    Aes256Gcm, Key, Nonce,
};

use crate::error::{ChalkError, Result};

/// Generate a new random 256-bit encryption key.
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    use rand::RngCore;
    rand::rng().fill_bytes(&mut key);
    key
}

/// Encrypt plaintext using AES-256-GCM.
///
/// Returns nonce (12 bytes) || ciphertext.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher_key = Key::<Aes256Gcm>::from(*key);
    let cipher = Aes256Gcm::new(&cipher_key);
    // aes-gcm 0.11 replaced `Aes256Gcm::generate_nonce(&mut OsRng)` with
    // `Nonce::generate()`, which draws from the OS RNG itself. A fresh nonce per
    // encryption is the whole security property of GCM — reuse under the same
    // key leaks the plaintext XOR — so this stays a per-call random draw and is
    // never derived from the message or a counter.
    let nonce = Nonce::generate();

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
    // `from_slice` is deprecated in favour of `TryFrom`, which is the better
    // shape anyway: the length guard above and this conversion now agree by
    // construction instead of by a hand-checked constant.
    let nonce = Nonce::try_from(nonce_bytes)
        .map_err(|_| ChalkError::Crypto("ciphertext has a malformed nonce".to_string()))?;

    let cipher_key = Key::<Aes256Gcm>::from(*key);
    let cipher = Aes256Gcm::new(&cipher_key);

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| ChalkError::Crypto(format!("decryption failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ciphertext produced by aes-gcm 0.10, before the 0.11 upgrade.
    ///
    /// Every sealed secret a district already has on disk — SIS passwords,
    /// Google service-account keys, LDAP binds — was written by that version.
    /// A round-trip test cannot catch a format change, because it encrypts and
    /// decrypts with the same code and would pass just as happily if both ends
    /// moved together. Only a vector from the old version can fail.
    ///
    /// If this ever breaks, the upgrade silently bricks every stored
    /// credential, and the operator finds out when sync stops authenticating.
    #[test]
    fn ciphertext_written_by_the_previous_aes_gcm_still_decrypts() {
        let key = [7u8; 32];
        let vector = "e3f14fe2709b7afd0526144b4445e61f9425bcd1e3b189c5b7e02bd6c5\
                      2748a84183945367f07afbb06e057f4d6cece6d8bd6ceb13d38df070";
        let bytes: Vec<u8> = (0..vector.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&vector[i..i + 2], 16).expect("valid hex"))
            .collect();

        assert_eq!(
            decrypt(&key, &bytes).expect("aes-gcm 0.11 could not read an 0.10 ciphertext"),
            b"chalk-crypto-format-vector-v1"
        );
    }

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
