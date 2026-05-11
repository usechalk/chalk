//! Master-key sealing/unsealing for per-tenant secret material.
//!
//! Sealed format: `nonce(12) || ciphertext || tag(16)` where the tag is
//! produced by AES-256-GCM. The master key is a 32-byte key supplied at
//! startup via `MASTER_ENCRYPTION_KEY` (base64 standard, padded).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};

const NONCE_LEN: usize = 12;

/// 32-byte symmetric master key used to seal per-tenant secrets.
#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Decode a 32-byte key from a base64 (standard) string.
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = B64
            .decode(s.trim())
            .map_err(|e| anyhow!("invalid MASTER_ENCRYPTION_KEY base64: {e}"))?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "MASTER_ENCRYPTION_KEY must decode to 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    /// Generate a fresh random key. Intended for tests and operator tooling.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// Seal a plaintext blob: returns `nonce(12) || ciphertext || tag(16)`.
pub fn seal(master: &MasterKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&master.0)
        .map_err(|e| anyhow!("invalid master key length: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("seal failed: {e}"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unseal a blob produced by `seal`. Returns an error on tamper / wrong key.
pub fn unseal(master: &MasterKey, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err(anyhow!("sealed blob too short"));
    }
    let cipher = Aes256Gcm::new_from_slice(&master.0)
        .map_err(|e| anyhow!("invalid master key length: {e}"))?;
    let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow!("unseal failed (tamper or wrong key): {e}"))
}

/// On-disk representation of a SAML keypair. We store cert + key as PEM so we
/// can hand them straight to the OSS IDP state.
#[derive(Serialize, Deserialize)]
pub struct SealedSamlKeypair {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generate a new SAML keypair (delegates to `chalk_idp::certs`) and return
/// the cert+key as a JSON-encoded blob ready to be sealed.
pub fn generate_saml_blob(common_name: &str) -> Result<Vec<u8>> {
    let (cert_pem, key_pem) = chalk_idp::certs::generate_saml_keypair(common_name)
        .map_err(|e| anyhow!("saml keypair generation failed: {e}"))?;
    let blob = SealedSamlKeypair { cert_pem, key_pem };
    Ok(serde_json::to_vec(&blob)?)
}

/// Decode a SAML blob produced by `generate_saml_blob`.
pub fn decode_saml_blob(bytes: &[u8]) -> Result<SealedSamlKeypair> {
    Ok(serde_json::from_slice(bytes)?)
}

/// Generate a fresh RSA-2048 signing key and return its PKCS#1 PEM bytes
/// (the format expected by the OSS `OidcState::signing_key`).
pub fn generate_oidc_signing_key() -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| anyhow!("rsa key generation failed: {e}"))?;
    let pem = key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .map_err(|e| anyhow!("rsa pem encoding failed: {e}"))?;
    Ok(pem.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = MasterKey::generate();
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let sealed = seal(&key, plaintext).unwrap();
        assert_ne!(&sealed[NONCE_LEN..], plaintext);
        let opened = unseal(&key, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn tamper_detected() {
        let key = MasterKey::generate();
        let mut sealed = seal(&key, b"secret").unwrap();
        // Flip a bit in the ciphertext region (after the nonce).
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(unseal(&key, &sealed).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = MasterKey::generate();
        let k2 = MasterKey::generate();
        let sealed = seal(&k1, b"secret").unwrap();
        assert!(unseal(&k2, &sealed).is_err());
    }

    #[test]
    fn from_base64_validates_length() {
        let good = B64.encode([0u8; 32]);
        assert!(MasterKey::from_base64(&good).is_ok());
        let bad = B64.encode([0u8; 16]);
        assert!(MasterKey::from_base64(&bad).is_err());
        assert!(MasterKey::from_base64("not base64!!").is_err());
    }

    #[test]
    fn saml_blob_round_trip() {
        let blob = generate_saml_blob("acme.test").unwrap();
        let key = MasterKey::generate();
        let sealed = seal(&key, &blob).unwrap();
        let opened = unseal(&key, &sealed).unwrap();
        let pair = decode_saml_blob(&opened).unwrap();
        assert!(pair.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(pair.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn oidc_key_is_pkcs1_pem() {
        let bytes = generate_oidc_signing_key().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("BEGIN RSA PRIVATE KEY"));
    }
}
