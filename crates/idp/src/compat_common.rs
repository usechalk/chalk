//! Shared helper functions used across SSO compatibility modules.
//!
//! These helpers are used by the OIDC, Clever-compat, ClassLink-compat,
//! portal, and routes modules. Centralised here to avoid duplication.

use axum::http::{header, HeaderMap};
use base64::Engine;
use rand::RngCore;

/// Extract a named cookie value from request headers.
pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|pair| {
            let pair = pair.trim();
            let (k, v) = pair.split_once('=')?;
            if k.trim() == name {
                Some(v.trim().to_string())
            } else {
                None
            }
        })
}

/// Generate a cryptographically random hex string of `byte_count` bytes.
pub fn generate_random_hex(byte_count: usize) -> String {
    let mut bytes = vec![0u8; byte_count];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Extract client credentials from HTTP Basic auth header or form body.
///
/// Tries HTTP Basic authentication first, falling back to form body parameters.
pub fn extract_client_credentials(
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Option<(String, String)> {
    // Try HTTP Basic first
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                    if let Ok(cred_str) = String::from_utf8(decoded) {
                        if let Some((id, secret)) = cred_str.split_once(':') {
                            return Some((id.to_string(), secret.to_string()));
                        }
                    }
                }
            }
        }
    }

    // Fall back to form body
    match (form_client_id, form_client_secret) {
        (Some(id), Some(secret)) if !id.is_empty() && !secret.is_empty() => {
            Some((id.to_string(), secret.to_string()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    // -- extract_cookie tests --

    #[test]
    fn extract_cookie_parses_correctly() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "session=abc123; chalk_portal=portal-456; other=val"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            extract_cookie(&headers, "chalk_portal"),
            Some("portal-456".to_string())
        );
        assert_eq!(
            extract_cookie(&headers, "session"),
            Some("abc123".to_string())
        );
        assert_eq!(extract_cookie(&headers, "missing"), None);
    }

    #[test]
    fn extract_cookie_returns_none_for_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_cookie(&headers, "chalk_portal"), None);
    }

    #[test]
    fn extract_cookie_handles_single_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "chalk_portal=only-one".parse().unwrap());
        assert_eq!(
            extract_cookie(&headers, "chalk_portal"),
            Some("only-one".to_string())
        );
    }

    #[test]
    fn extract_cookie_handles_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "  chalk_portal = spaced-value ; other = x "
                .parse()
                .unwrap(),
        );
        assert_eq!(
            extract_cookie(&headers, "chalk_portal"),
            Some("spaced-value".to_string())
        );
    }

    // -- generate_random_hex tests --

    #[test]
    fn generate_random_hex_correct_length() {
        let hex = generate_random_hex(32);
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
        let hex2 = generate_random_hex(64);
        assert_eq!(hex2.len(), 128);
    }

    #[test]
    fn generate_random_hex_produces_valid_hex() {
        let hex = generate_random_hex(16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_random_hex_produces_unique_values() {
        let a = generate_random_hex(32);
        let b = generate_random_hex(32);
        assert_ne!(a, b);
    }

    // -- extract_client_credentials tests --

    #[test]
    fn client_credentials_from_basic_auth() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("my-client:my-secret");
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        let creds = extract_client_credentials(&headers, None, None);
        assert_eq!(
            creds,
            Some(("my-client".to_string(), "my-secret".to_string()))
        );
    }

    #[test]
    fn client_credentials_from_form_body() {
        let headers = HeaderMap::new();
        let creds = extract_client_credentials(&headers, Some("form-client"), Some("form-secret"));
        assert_eq!(
            creds,
            Some(("form-client".to_string(), "form-secret".to_string()))
        );
    }

    #[test]
    fn client_credentials_basic_auth_takes_precedence() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("basic-client:basic-secret");
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        let creds = extract_client_credentials(&headers, Some("form-client"), Some("form-secret"));
        assert_eq!(
            creds,
            Some(("basic-client".to_string(), "basic-secret".to_string()))
        );
    }

    #[test]
    fn client_credentials_returns_none_with_no_credentials() {
        let headers = HeaderMap::new();
        let creds = extract_client_credentials(&headers, None, None);
        assert_eq!(creds, None);
    }

    #[test]
    fn client_credentials_returns_none_with_empty_form_values() {
        let headers = HeaderMap::new();
        let creds = extract_client_credentials(&headers, Some(""), Some(""));
        assert_eq!(creds, None);
    }

    #[test]
    fn client_credentials_returns_none_with_partial_form() {
        let headers = HeaderMap::new();
        assert_eq!(extract_client_credentials(&headers, Some("id"), None), None);
        assert_eq!(
            extract_client_credentials(&headers, None, Some("secret")),
            None
        );
    }

    #[test]
    fn client_credentials_ignores_non_basic_auth() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer some-token".parse().unwrap());
        let creds = extract_client_credentials(&headers, Some("form-id"), Some("form-secret"));
        assert_eq!(
            creds,
            Some(("form-id".to_string(), "form-secret".to_string()))
        );
    }
}
