//! Self-signed certificate generation for SAML signing.

use chalk_core::error::{ChalkError, Result};
use rcgen::{CertificateParams, KeyPair};

/// Generate a self-signed SAML keypair.
/// Returns (cert_pem, key_pem).
///
/// # Why this generates RSA explicitly
///
/// `rcgen::KeyPair::generate()` defaults to **ECDSA P-256**, and every keypair
/// this function produced was therefore ECDSA. But `build_signed_saml_response`
/// signs with `rsa::pkcs1v15`, and the `<ds:SignatureMethod>` it writes
/// advertises `rsa-sha256`, so it could never load one of these keys — it
/// failed with "unknown/unsupported algorithm OID" every single time.
///
/// That failure was not visible. The caller in `routes.rs` catches it, logs a
/// warning, and falls back to `build_saml_response` — the **unsigned** builder.
/// So every SAML assertion Chalk issued from a generated keypair went out with
/// no `<ds:Signature>` at all: rejected by any Service Provider that validates
/// them, and accepted without authentication by any that does not.
///
/// rcgen cannot generate RSA keys itself, so the key comes from the `rsa` crate
/// and is handed to rcgen as PEM — the same thing the SAML tests were already
/// doing to produce a key they could actually sign with.
pub fn generate_saml_keypair(common_name: &str) -> Result<(String, String)> {
    use rsa::pkcs8::EncodePrivateKey;

    let mut params = CertificateParams::new(vec![common_name.to_string()])
        .map_err(|e| ChalkError::Idp(format!("failed to create cert params: {e}")))?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String(common_name.to_string()),
    );

    // 2048 bits: the floor every SAML Service Provider accepts, and what the
    // signer's SHA-256 pairing expects.
    let mut rng = rsa::rand_core::OsRng;
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| ChalkError::Idp(format!("failed to generate RSA key: {e}")))?;
    let key_pem = private
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| ChalkError::Idp(format!("failed to encode RSA key: {e}")))?
        .to_string();

    let key_pair = KeyPair::from_pem(&key_pem)
        .map_err(|e| ChalkError::Idp(format!("failed to load generated key: {e}")))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ChalkError::Idp(format!("failed to self-sign certificate: {e}")))?;

    Ok((cert.pem(), key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keypair this function generates must be one the SAML signer can
    /// actually use.
    ///
    /// Nothing asserted this before. The existing tests checked the PEM headers
    /// and that the strings were non-empty, which an ECDSA key satisfies
    /// perfectly — so a keypair the signer could never load looked correct to
    /// the entire suite, and the only symptom in production was a `warn!` line
    /// followed by every assertion going out unsigned.
    ///
    /// This is the seam that matters: generation and signing live in different
    /// modules and each was internally consistent. Only using one against the
    /// other catches it.
    #[test]
    fn a_generated_keypair_can_actually_sign_a_saml_assertion() {
        let (cert_pem, key_pem) = generate_saml_keypair("idp.example.com").unwrap();

        let xml = crate::saml::build_signed_saml_response(
            "student@example.com",
            "https://idp.example.com",
            "https://sp.example.com/acs",
            "https://sp.example.com",
            Some("req-1"),
            key_pem.as_bytes(),
            &cert_pem,
        )
        .expect("a freshly generated keypair must be usable by the signer");

        // And the result is genuinely signed, not the unsigned builder's output.
        assert!(
            xml.contains("<ds:Signature"),
            "assertion carries no signature"
        );
        assert!(
            xml.contains("<ds:SignatureValue>"),
            "no SignatureValue element"
        );
        assert!(
            xml.contains("rsa-sha256"),
            "SignatureMethod should advertise rsa-sha256"
        );
    }

    /// The key must be RSA specifically, because `<ds:SignatureMethod>` says so.
    #[test]
    fn the_generated_key_is_rsa() {
        use rsa::pkcs8::DecodePrivateKey;
        let (_, key_pem) = generate_saml_keypair("idp.example.com").unwrap();
        rsa::RsaPrivateKey::from_pkcs8_pem(&key_pem)
            .expect("the generated key must parse as RSA, matching the advertised rsa-sha256");
    }

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
