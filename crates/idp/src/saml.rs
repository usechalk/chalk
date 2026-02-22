//! SAML 2.0 metadata and response XML generation, signing, and AuthnRequest parsing.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::SignatureEncoding;
use rsa::{pkcs1v15::SigningKey, signature::Signer};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Parsed SAML AuthnRequest fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAuthnRequest {
    pub issuer: String,
    pub request_id: String,
    pub acs_url: Option<String>,
}

/// Generate IDP metadata XML.
pub fn generate_metadata(entity_id: &str, sso_url: &str, cert_pem: &str) -> String {
    // Strip PEM headers/footers and whitespace for the X509Certificate element
    let cert_base64 = cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{entity_id}">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
                       protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>{cert_base64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="{sso_url}"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="{sso_url}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#
    )
}

/// Build an unsigned SAML 2.0 response XML, returning both full response and the assertion XML.
fn build_saml_response_parts(
    user_email: &str,
    entity_id: &str,
    acs_url: &str,
    audience: &str,
    request_id: Option<&str>,
) -> (String, String, String) {
    let response_id = format!("_resp_{}", Uuid::new_v4());
    let assertion_id = format!("_assert_{}", Uuid::new_v4());
    let now = Utc::now();
    let issue_instant = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_before = issue_instant.clone();
    let not_on_or_after = (now + chrono::Duration::minutes(5))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let session_not_on_or_after = (now + chrono::Duration::hours(8))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let in_response_to = request_id
        .map(|id| format!(r#" InResponseTo="{id}""#))
        .unwrap_or_default();

    let assertion = format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"
                  ID="{assertion_id}"
                  IssueInstant="{issue_instant}">
    <saml:Issuer>{entity_id}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user_email}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}"
                                      Recipient="{acs_url}"{in_response_to}/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
      <saml:AudienceRestriction>
        <saml:Audience>{audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{issue_instant}"
                         SessionNotOnOrAfter="{session_not_on_or_after}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>"#
    );

    let full = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{response_id}"
                Version="2.0"
                IssueInstant="{issue_instant}"
                Destination="{acs_url}"{in_response_to}>
  <saml:Issuer>{entity_id}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  {assertion}
</samlp:Response>"#
    );

    (full, assertion, assertion_id)
}

/// Build an unsigned SAML 2.0 response XML.
pub fn build_saml_response(
    user_email: &str,
    entity_id: &str,
    acs_url: &str,
    audience: &str,
    request_id: Option<&str>,
) -> String {
    let (full, _, _) = build_saml_response_parts(user_email, entity_id, acs_url, audience, request_id);
    full
}

/// Build a signed SAML 2.0 response with an enveloped XML signature in the Assertion.
///
/// The signing uses RSA-SHA256 with an enveloped signature per the XML-DSig spec.
pub fn build_signed_saml_response(
    user_email: &str,
    entity_id: &str,
    acs_url: &str,
    audience: &str,
    request_id: Option<&str>,
    signing_key_pem: &[u8],
    signing_cert_pem: &str,
) -> Result<String, String> {
    let (_, assertion_xml, assertion_id) =
        build_saml_response_parts(user_email, entity_id, acs_url, audience, request_id);

    // Parse RSA private key
    let key_str = std::str::from_utf8(signing_key_pem)
        .map_err(|e| format!("invalid UTF-8 in signing key: {e}"))?;
    let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(key_str)
        .map_err(|e| format!("failed to parse RSA private key: {e}"))?;

    // Compute SHA-256 digest of the assertion XML
    let digest_value = {
        let mut hasher = Sha256::new();
        hasher.update(assertion_xml.as_bytes());
        BASE64.encode(hasher.finalize())
    };

    // Build SignedInfo (canonical form for signing)
    let reference_uri = format!("#{assertion_id}");
    let signed_info = format!(
        r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="{reference_uri}">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>{digest_value}</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>"##
    );

    // Sign the SignedInfo
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(signed_info.as_bytes());
    let signature_value = BASE64.encode(signature.to_bytes());

    // Strip PEM headers from cert for KeyInfo
    let cert_base64 = signing_cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("");

    // Build the Signature element
    let signature_block = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    {signed_info}
    <ds:SignatureValue>{signature_value}</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>{cert_base64}</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>"##
    );

    // Insert signature after <saml:Issuer> inside the Assertion
    // Find the closing </saml:Issuer> tag within the assertion
    let issuer_close = "</saml:Issuer>";
    let signed_assertion = if let Some(pos) = assertion_xml.find(issuer_close) {
        let insert_pos = pos + issuer_close.len();
        format!(
            "{}\n    {}{}",
            &assertion_xml[..insert_pos],
            signature_block,
            &assertion_xml[insert_pos..]
        )
    } else {
        return Err("could not find Issuer element in assertion".to_string());
    };

    // Build the full response with the signed assertion
    let response_id = format!("_resp_{}", Uuid::new_v4());
    let now = Utc::now();
    let issue_instant = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let in_response_to = request_id
        .map(|id| format!(r#" InResponseTo="{id}""#))
        .unwrap_or_default();

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{response_id}"
                Version="2.0"
                IssueInstant="{issue_instant}"
                Destination="{acs_url}"{in_response_to}>
  <saml:Issuer>{entity_id}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  {signed_assertion}
</samlp:Response>"#
    ))
}

/// Parse a SAML AuthnRequest from a base64-encoded, optionally DEFLATE-compressed string.
///
/// Supports both plain base64 and base64(deflate(xml)) formats as used in HTTP-Redirect binding.
pub fn parse_authn_request(saml_request: &str) -> Result<ParsedAuthnRequest, String> {
    let decoded = BASE64
        .decode(saml_request.trim())
        .map_err(|e| format!("base64 decode failed: {e}"))?;

    // Try DEFLATE decompression first, fall back to raw XML
    let xml_bytes = match try_inflate(&decoded) {
        Some(inflated) => inflated,
        None => decoded,
    };

    let xml_str = std::str::from_utf8(&xml_bytes)
        .map_err(|e| format!("invalid UTF-8 in AuthnRequest: {e}"))?;

    parse_authn_request_xml(xml_str)
}

/// Try to inflate DEFLATE-compressed data. Returns None if not valid DEFLATE.
fn try_inflate(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    let mut decoder = DeflateDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).ok()?;
    // Only return if we got valid XML-like output
    if result.starts_with(b"<") || result.starts_with(b"<?") {
        Some(result)
    } else {
        None
    }
}

/// Parse AuthnRequest XML using quick-xml to extract issuer, request ID, and ACS URL.
fn parse_authn_request_xml(xml: &str) -> Result<ParsedAuthnRequest, String> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut request_id = String::new();
    let mut acs_url: Option<String> = None;
    let mut issuer = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local_name = e.local_name();
                let name_bytes = local_name.as_ref();

                if name_bytes == b"AuthnRequest" {
                    for attr in e.attributes().flatten() {
                        let local = attr.key.local_name();
                        let key_bytes = local.as_ref();
                        let val = attr.unescape_value().unwrap_or_default().to_string();
                        if key_bytes == b"ID" {
                            request_id = val;
                        } else if key_bytes == b"AssertionConsumerServiceURL"
                            || key_bytes == b"AssertionConsumerServiceUrl"
                        {
                            acs_url = Some(val);
                        } else {
                            // Check full attribute name (with namespace prefix)
                            let full_key = attr.key.as_ref();
                            if full_key == b"AssertionConsumerServiceURL"
                                || full_key.ends_with(b"AssertionConsumerServiceURL")
                            {
                                acs_url = Some(val);
                            }
                        }
                    }
                }
                if name_bytes == b"Issuer" {
                    if let Ok(Event::Text(ref t)) = reader.read_event() {
                        issuer = t.unescape().unwrap_or_default().to_string();
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {e}")),
            _ => {}
        }
    }

    if request_id.is_empty() {
        return Err("AuthnRequest missing ID attribute".to_string());
    }
    if issuer.is_empty() {
        return Err("AuthnRequest missing Issuer element".to_string());
    }

    Ok(ParsedAuthnRequest {
        issuer,
        request_id,
        acs_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBkTCCATagAwIBAgIUAbcdefg=\n\
        -----END CERTIFICATE-----";

    #[test]
    fn metadata_contains_entity_id() {
        let xml = generate_metadata(
            "https://chalk.example.com",
            "https://chalk.example.com/saml/sso",
            SAMPLE_CERT,
        );
        assert!(xml.contains(r#"entityID="https://chalk.example.com""#));
    }

    #[test]
    fn metadata_contains_sso_url() {
        let xml = generate_metadata(
            "https://chalk.example.com",
            "https://chalk.example.com/saml/sso",
            SAMPLE_CERT,
        );
        assert!(xml.contains(r#"Location="https://chalk.example.com/saml/sso""#));
    }

    #[test]
    fn metadata_contains_certificate() {
        let xml = generate_metadata(
            "https://chalk.example.com",
            "https://chalk.example.com/saml/sso",
            SAMPLE_CERT,
        );
        assert!(xml.contains("MIIBkTCCATagAwIBAgIUAbcdefg="));
        // PEM headers should be stripped
        assert!(!xml.contains("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn metadata_contains_name_id_format() {
        let xml = generate_metadata("eid", "sso", SAMPLE_CERT);
        assert!(xml.contains("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"));
    }

    #[test]
    fn saml_response_contains_email() {
        let xml = build_saml_response(
            "student@school.edu",
            "https://chalk.example.com",
            "https://accounts.google.com/samlrp/acs",
            "google.com",
            None,
        );
        assert!(xml.contains("student@school.edu"));
    }

    #[test]
    fn saml_response_contains_issuer() {
        let xml = build_saml_response(
            "user@test.com",
            "https://chalk.example.com",
            "https://acs.example.com",
            "audience",
            None,
        );
        assert!(xml.contains("<saml:Issuer>https://chalk.example.com</saml:Issuer>"));
    }

    #[test]
    fn saml_response_contains_destination() {
        let xml = build_saml_response(
            "user@test.com",
            "entity",
            "https://acs.example.com",
            "audience",
            None,
        );
        assert!(xml.contains(r#"Destination="https://acs.example.com""#));
    }

    #[test]
    fn saml_response_contains_audience() {
        let xml = build_saml_response("user@test.com", "entity", "acs", "google.com", None);
        assert!(xml.contains("<saml:Audience>google.com</saml:Audience>"));
    }

    #[test]
    fn saml_response_with_request_id() {
        let xml = build_saml_response(
            "user@test.com",
            "entity",
            "acs",
            "audience",
            Some("req-123"),
        );
        assert!(xml.contains(r#"InResponseTo="req-123""#));
    }

    #[test]
    fn saml_response_without_request_id() {
        let xml = build_saml_response("user@test.com", "entity", "acs", "audience", None);
        assert!(!xml.contains("InResponseTo"));
    }

    #[test]
    fn saml_response_has_unique_ids() {
        let xml1 = build_saml_response("u@t.com", "e", "a", "aud", None);
        let xml2 = build_saml_response("u@t.com", "e", "a", "aud", None);
        // Each response should have unique IDs
        assert_ne!(xml1, xml2);
    }

    #[test]
    fn saml_response_contains_success_status() {
        let xml = build_saml_response("u@t.com", "e", "a", "aud", None);
        assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success"));
    }

    #[test]
    fn saml_response_contains_authn_statement() {
        let xml = build_saml_response("u@t.com", "e", "a", "aud", None);
        assert!(xml.contains("AuthnStatement"));
        assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"));
    }

    // -- Signing tests --

    fn generate_test_key_and_cert() -> (Vec<u8>, String) {
        use rsa::pkcs8::EncodePrivateKey;

        // Generate an RSA key pair for signing
        let mut rng = rand::rngs::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let key_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
            .into_bytes();

        // Use rcgen with the RSA key to generate a self-signed cert
        let key_pair = rcgen::KeyPair::from_pem(&String::from_utf8(key_pem.clone()).unwrap()).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["chalk.test".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let cert_pem = cert.pem();

        (key_pem, cert_pem)
    }

    #[test]
    fn signed_response_contains_signature_element() {
        let (key, cert) = generate_test_key_and_cert();
        let xml = build_signed_saml_response(
            "user@test.com",
            "https://chalk.test",
            "https://acs.test/saml",
            "audience",
            None,
            &key,
            &cert,
        )
        .unwrap();

        assert!(xml.contains("<ds:Signature"));
        assert!(xml.contains("<ds:SignedInfo"));
        assert!(xml.contains("<ds:SignatureValue>"));
        assert!(xml.contains("<ds:DigestValue>"));
        assert!(xml.contains("<ds:X509Certificate>"));
        assert!(xml.contains("<ds:KeyInfo>"));
    }

    #[test]
    fn signed_response_contains_correct_algorithms() {
        let (key, cert) = generate_test_key_and_cert();
        let xml = build_signed_saml_response(
            "user@test.com",
            "entity",
            "acs",
            "audience",
            None,
            &key,
            &cert,
        )
        .unwrap();

        assert!(xml.contains("rsa-sha256"));
        assert!(xml.contains("xml-exc-c14n#"));
        assert!(xml.contains("enveloped-signature"));
    }

    #[test]
    fn signed_response_preserves_saml_content() {
        let (key, cert) = generate_test_key_and_cert();
        let xml = build_signed_saml_response(
            "user@test.com",
            "https://chalk.test",
            "https://acs.test",
            "audience",
            Some("req-456"),
            &key,
            &cert,
        )
        .unwrap();

        assert!(xml.contains("user@test.com"));
        assert!(xml.contains("<saml:Issuer>https://chalk.test</saml:Issuer>"));
        assert!(xml.contains(r#"InResponseTo="req-456""#));
        assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success"));
    }

    #[test]
    fn signed_response_invalid_key_returns_error() {
        let result = build_signed_saml_response(
            "user@test.com",
            "entity",
            "acs",
            "audience",
            None,
            b"not-a-valid-key",
            "not-a-cert",
        );
        assert!(result.is_err());
    }

    // -- AuthnRequest parsing tests --

    #[test]
    fn parse_authn_request_plain_base64() {
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                             xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                             ID="_req_abc123"
                             Version="2.0"
                             IssueInstant="2024-01-01T00:00:00Z"
                             AssertionConsumerServiceURL="https://app.example.com/saml/consume">
          <saml:Issuer>https://app.example.com</saml:Issuer>
        </samlp:AuthnRequest>"#;

        let encoded = BASE64.encode(xml.as_bytes());
        let parsed = parse_authn_request(&encoded).unwrap();

        assert_eq!(parsed.issuer, "https://app.example.com");
        assert_eq!(parsed.request_id, "_req_abc123");
        assert_eq!(
            parsed.acs_url.as_deref(),
            Some("https://app.example.com/saml/consume")
        );
    }

    #[test]
    fn parse_authn_request_deflated() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;

        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                             xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                             ID="_req_deflated"
                             Version="2.0"
                             IssueInstant="2024-01-01T00:00:00Z">
          <saml:Issuer>https://sp.example.com</saml:Issuer>
        </samlp:AuthnRequest>"#;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let encoded = BASE64.encode(&compressed);

        let parsed = parse_authn_request(&encoded).unwrap();
        assert_eq!(parsed.issuer, "https://sp.example.com");
        assert_eq!(parsed.request_id, "_req_deflated");
        assert!(parsed.acs_url.is_none());
    }

    #[test]
    fn parse_authn_request_without_acs_url() {
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                             xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                             ID="_req_no_acs"
                             Version="2.0">
          <saml:Issuer>https://sp.example.com</saml:Issuer>
        </samlp:AuthnRequest>"#;

        let encoded = BASE64.encode(xml.as_bytes());
        let parsed = parse_authn_request(&encoded).unwrap();

        assert_eq!(parsed.issuer, "https://sp.example.com");
        assert_eq!(parsed.request_id, "_req_no_acs");
        assert!(parsed.acs_url.is_none());
    }

    #[test]
    fn parse_authn_request_missing_id_returns_error() {
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                             xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                             Version="2.0">
          <saml:Issuer>https://sp.example.com</saml:Issuer>
        </samlp:AuthnRequest>"#;

        let encoded = BASE64.encode(xml.as_bytes());
        let result = parse_authn_request(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing ID"));
    }

    #[test]
    fn parse_authn_request_missing_issuer_returns_error() {
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                             ID="_req_no_issuer"
                             Version="2.0">
        </samlp:AuthnRequest>"#;

        let encoded = BASE64.encode(xml.as_bytes());
        let result = parse_authn_request(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing Issuer"));
    }

    #[test]
    fn parse_authn_request_invalid_base64_returns_error() {
        let result = parse_authn_request("!!!not-base64!!!");
        assert!(result.is_err());
    }
}
