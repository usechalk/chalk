//! CSRF (Cross-Site Request Forgery) protection for the admin console.
//!
//! Generates per-request CSRF tokens stored in cookies and validates them
//! on state-changing requests via the `X-CSRF-Token` header (HTMX compatible).

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rand::Rng;
use sha2::{Digest, Sha256};

const CSRF_COOKIE_NAME: &str = "chalk_csrf";
const CSRF_HEADER_NAME: &str = "x-csrf-token";

/// Generate a random CSRF token (64 hex characters).
pub fn generate_csrf_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hash a CSRF token for comparison (prevents timing attacks).
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Extract CSRF token from cookie.
fn extract_csrf_cookie(req: &Request<Body>) -> Option<String> {
    let cookie_header = req.headers().get(header::COOKIE)?;
    let cookie_str = cookie_header.to_str().ok()?;
    for cookie in cookie_str.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&format!("{CSRF_COOKIE_NAME}=")) {
            return Some(value.to_string());
        }
    }
    None
}

/// Paths that skip CSRF validation.
const CSRF_EXEMPT_PREFIXES: &[&str] = &["/health", "/api/"];

fn is_csrf_exempt(path: &str) -> bool {
    CSRF_EXEMPT_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// CSRF protection middleware.
///
/// For GET requests: sets a CSRF cookie if not present.
/// For POST/PUT/DELETE requests: validates X-CSRF-Token header matches cookie.
pub async fn csrf_middleware(req: Request<Body>, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Skip CSRF for exempt paths
    if is_csrf_exempt(&path) {
        return next.run(req).await;
    }

    // For state-changing methods, validate the token
    if matches!(method, Method::POST | Method::PUT | Method::DELETE) {
        // Skip CSRF for login and logout forms
        if path == "/login" || path == "/logout" {
            return next.run(req).await;
        }

        let cookie_token = extract_csrf_cookie(&req);
        let header_token = req
            .headers()
            .get(CSRF_HEADER_NAME)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        match (cookie_token, header_token) {
            (Some(cookie), Some(header_val)) => {
                if hash_token(&cookie) != hash_token(&header_val) {
                    return (StatusCode::FORBIDDEN, "CSRF token mismatch").into_response();
                }
            }
            _ => {
                return (StatusCode::FORBIDDEN, "CSRF token missing").into_response();
            }
        }
    }

    let mut response = next.run(req).await;

    // For GET requests, ensure CSRF cookie is set
    if method == Method::GET {
        let token = generate_csrf_token();
        let cookie = format!("{CSRF_COOKIE_NAME}={token}; Path=/; SameSite=Strict; Max-Age=86400");
        response
            .headers_mut()
            .append(header::SET_COOKIE, cookie.parse().unwrap());
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_csrf_token_is_64_hex_chars() {
        let token = generate_csrf_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_csrf_token_is_unique() {
        let t1 = generate_csrf_token();
        let t2 = generate_csrf_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn hash_token_is_deterministic() {
        let token = "test-token-123";
        assert_eq!(hash_token(token), hash_token(token));
    }

    #[test]
    fn hash_token_differs_for_different_inputs() {
        assert_ne!(hash_token("token-a"), hash_token("token-b"));
    }

    #[test]
    fn is_csrf_exempt_for_health() {
        assert!(is_csrf_exempt("/health"));
    }

    #[test]
    fn is_csrf_exempt_for_api() {
        assert!(is_csrf_exempt("/api/v1/users"));
    }

    #[test]
    fn is_not_csrf_exempt_for_regular_paths() {
        assert!(!is_csrf_exempt("/sync/trigger"));
        assert!(!is_csrf_exempt("/settings"));
    }

    #[test]
    fn extract_csrf_cookie_present() {
        let req = Request::builder()
            .header(header::COOKIE, "chalk_csrf=mytoken; other=val")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_csrf_cookie(&req), Some("mytoken".to_string()));
    }

    #[test]
    fn extract_csrf_cookie_missing() {
        let req = Request::builder()
            .header(header::COOKIE, "other=val")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_csrf_cookie(&req), None);
    }

    #[test]
    fn extract_csrf_cookie_no_header() {
        let req = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(extract_csrf_cookie(&req), None);
    }
}
