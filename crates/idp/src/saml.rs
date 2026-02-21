//! SAML 2.0 metadata and response XML generation.

use chrono::Utc;
use uuid::Uuid;

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

/// Build an unsigned SAML 2.0 response XML.
pub fn build_saml_response(
    user_email: &str,
    entity_id: &str,
    acs_url: &str,
    audience: &str,
    request_id: Option<&str>,
) -> String {
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

    format!(
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
  <saml:Assertion Version="2.0"
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
  </saml:Assertion>
</samlp:Response>"#
    )
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
}
