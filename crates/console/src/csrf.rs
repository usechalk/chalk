//! CSRF (Cross-Site Request Forgery) protection for the admin console.
//!
//! Generates per-request CSRF tokens stored in cookies and validates them on
//! state-changing requests. Accepts either:
//!
//! - an `X-CSRF-Token` header (HTMX uses `hx-headers`), or
//! - a `csrf_token` form field on `application/x-www-form-urlencoded` POSTs
//!   (the classic Synchronizer Token Pattern).
//!
//! The cookie value must match in both cases.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chalk_core::cookies::{set_cookie, CookieAttrs, SameSite};
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::AppState;

const CSRF_COOKIE_NAME: &str = "chalk_csrf";
const CSRF_HEADER_NAME: &str = "x-csrf-token";

/// Generate a random CSRF token (64 hex characters).
pub fn generate_csrf_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Per-request CSRF token, attached to request extensions by `csrf_middleware`
/// on GET requests and read by handlers that render forms.
///
/// Reusing the value the middleware set ensures the token embedded in the
/// HTML form matches the cookie the browser sends back on POST. Handlers
/// previously called `generate_csrf_token()` directly, which produced a
/// different token than the middleware's cookie and broke every form submit.
#[derive(Clone, Debug)]
pub struct CsrfToken(pub String);

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
pub async fn csrf_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Skip CSRF for exempt paths
    if is_csrf_exempt(&path) {
        return next.run(req).await;
    }

    // For GETs, surface the existing (or freshly generated) cookie token via
    // request extensions so handlers can embed the *same* value in their
    // forms. `set_cookie_if_new` tracks whether we need to mint a cookie.
    let mut set_cookie_if_new: Option<String> = None;
    if method == Method::GET {
        let token = match extract_csrf_cookie(&req) {
            Some(t) => t,
            None => {
                let t = generate_csrf_token();
                set_cookie_if_new = Some(t.clone());
                t
            }
        };
        req.extensions_mut().insert(CsrfToken(token));
    }

    // For state-changing methods, validate the token
    if matches!(method, Method::POST | Method::PUT | Method::DELETE) {
        // Skip CSRF for login, logout, and set-password forms (no session yet).
        if path == "/login" || path == "/logout" || path == "/set-password" {
            return next.run(req).await;
        }

        let cookie_token = match extract_csrf_cookie(&req) {
            Some(c) => c,
            None => return (StatusCode::FORBIDDEN, "CSRF token missing").into_response(),
        };

        let header_token = req
            .headers()
            .get(CSRF_HEADER_NAME)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if let Some(header_val) = header_token {
            if hash_token(&cookie_token) != hash_token(&header_val) {
                return (StatusCode::FORBIDDEN, "CSRF token mismatch").into_response();
            }
            return next.run(req).await;
        }

        // No header — check for a form-encoded body with `csrf_token` field.
        // We buffer the body, validate, then rebuild the request so downstream
        // handlers see the same body. Capped at 64KiB to bound memory.
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if content_type.starts_with("application/x-www-form-urlencoded") {
            let (parts, body) = req.into_parts();
            let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
                Ok(b) => b,
                Err(_) => return (StatusCode::BAD_REQUEST, "Body too large").into_response(),
            };
            let form_token = serde_urlencoded::from_bytes::<Vec<(String, String)>>(&bytes)
                .ok()
                .and_then(|pairs| {
                    pairs
                        .into_iter()
                        .find(|(k, _)| k == "csrf_token")
                        .map(|(_, v)| v)
                });
            match form_token {
                Some(t) if hash_token(&cookie_token) == hash_token(&t) => {
                    let req = Request::from_parts(parts, Body::from(bytes));
                    return next.run(req).await;
                }
                Some(_) => {
                    return (StatusCode::FORBIDDEN, "CSRF token mismatch").into_response();
                }
                None => {
                    return (StatusCode::FORBIDDEN, "CSRF token missing").into_response();
                }
            }
        }

        return (StatusCode::FORBIDDEN, "CSRF token missing").into_response();
    }

    let mut response = next.run(req).await;

    // Only set the CSRF cookie when there wasn't one already; otherwise the
    // browser keeps re-receiving fresh tokens that invalidate older form
    // renders served by other tabs.
    if let Some(token) = set_cookie_if_new {
        let cookie = set_cookie(
            CSRF_COOKIE_NAME,
            &token,
            &CookieAttrs {
                same_site: SameSite::Strict,
                http_only: false,
                secure: state.config.chalk.cookies_secure(),
                path: "/",
                max_age_secs: Some(86400),
            },
        );
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
