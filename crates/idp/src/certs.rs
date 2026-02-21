//! Self-signed certificate generation for SAML signing.

use chalk_core::error::{ChalkError, Result};
use rcgen::{CertificateParams, KeyPair};

/// Generate a self-signed SAML keypair.
/// Returns (cert_pem, key_pem).
pub fn generate_saml_keypair(common_name: &str) -> Result<(String, String)> {
    let mut params = CertificateParams::new(vec![common_name.to_string()])
        .map_err(|e| ChalkError::Idp(format!("failed to create cert params: {e}")))?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String(common_name.to_string()),
    );

    let key_pair = KeyPair::generate()
        .map_err(|e| ChalkError::Idp(format!("failed to generate key pair: {e}")))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ChalkError::Idp(format!("failed to self-sign certificate: {e}")))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    Ok((cert_pem, key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_pem_cert() {
        let (cert_pem, _key_pem) = generate_saml_keypair("chalk.example.com").unwrap();
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert_pem.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn generates_valid_pem_key() {
        let (_cert_pem, key_pem) = generate_saml_keypair("chalk.example.com").unwrap();
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key_pem.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn different_calls_produce_different_keys() {
        let (cert1, key1) = generate_saml_keypair("test1.com").unwrap();
        let (cert2, key2) = generate_saml_keypair("test2.com").unwrap();
        assert_ne!(cert1, cert2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn cert_and_key_are_nonempty() {
        let (cert_pem, key_pem) = generate_saml_keypair("test.com").unwrap();
        assert!(cert_pem.len() > 100);
        assert!(key_pem.len() > 100);
    }
}
