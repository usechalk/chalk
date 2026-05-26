//! CSRF (Cross-Site Request Forgery) protection for the admin console.
//!
//! Generates per-request CSRF tokens stored in cookies and validates them on
//! state-changing requests. Accepts either:
//!
//! - an `X-CSRF-Token` header (HTMX uses `hx-headers`), or
//! - a `csrf_token` form field on `application/x-www-form-urlencoded` POSTs
//!   (the classic Synchronizer Token Pattern), or
//! - a `csrf_token` form part on `multipart/form-data` POSTs (used by the
//!   settings pages that accept file uploads).
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

/// Pull the `boundary=…` token out of a `multipart/form-data` Content-Type.
/// The attribute name is case-insensitive per RFC 7231; the value is
/// case-sensitive and must be returned verbatim. The value may be quoted.
fn multipart_boundary(content_type: &str) -> Option<String> {
    for part in content_type.split(';') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("boundary") {
            let trimmed = value.trim().trim_matches('"');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Find a `csrf_token` part in a buffered multipart body and return its value.
///
/// Scans for the part whose header line includes `name="csrf_token"`, then
/// returns the bytes between the blank-line terminator and the next boundary
/// marker. Returns `None` if the field is missing, malformed, or non-UTF-8.
/// Deliberately lightweight — we only need the one field; the route handler
/// re-parses the full body via `axum::extract::Multipart`.
fn extract_multipart_csrf(body: &[u8], boundary: &str) -> Option<String> {
    let delim = format!("--{boundary}");
    let mut cursor = 0usize;
    while cursor < body.len() {
        let next = find_subslice(&body[cursor..], delim.as_bytes())?;
        let part_start = cursor + next + delim.len();
        // Headers run until the blank line (\r\n\r\n).
        let headers_end =
            find_subslice(&body[part_start..], b"\r\n\r\n").map(|i| part_start + i)?;
        let header_str = std::str::from_utf8(&body[part_start..headers_end]).ok()?;
        let value_start = headers_end + 4;
        let next_boundary =
            find_subslice(&body[value_start..], delim.as_bytes()).map(|i| value_start + i)?;
        // The value ends with a CRLF before the next boundary.
        let value_end = next_boundary.saturating_sub(2);
        if header_str
            .lines()
            .any(|line| line.to_ascii_lowercase().contains("name=\"csrf_token\""))
        {
            return std::str::from_utf8(&body[value_start..value_end])
                .ok()
                .map(|s| s.trim().to_string());
        }
        cursor = next_boundary;
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Paths that skip CSRF validation.
const CSRF_EXEMPT_PREFIXES: &[&str] = &["/health", "/api/", "/static/"];

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
        let content_type_raw = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        // Use the lowercased copy only for the type-token comparison; the
        // boundary attribute is case-sensitive and must be read from the
        // raw header value.
        let content_type_lower = content_type_raw.to_ascii_lowercase();
        // Buffer the body so we can both validate the embedded token AND
        // hand the original bytes to the downstream handler. Cap depends on
        // the body type — multipart forms with file uploads (settings pages)
        // can legitimately exceed the urlencoded cap.
        let (form_token, bytes) = if content_type_lower
            .starts_with("application/x-www-form-urlencoded")
        {
            let (parts, body) = req.into_parts();
            let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
                Ok(b) => b,
                Err(_) => return (StatusCode::BAD_REQUEST, "Body too large").into_response(),
            };
            let token = serde_urlencoded::from_bytes::<Vec<(String, String)>>(&bytes)
                .ok()
                .and_then(|pairs| {
                    pairs
                        .into_iter()
                        .find(|(k, _)| k == "csrf_token")
                        .map(|(_, v)| v)
                });
            req = Request::from_parts(parts, Body::from(bytes.clone()));
            (token, bytes)
        } else if content_type_lower.starts_with("multipart/form-data") {
            // Boundary value is case-sensitive — extract from the original
            // header text, not the lowercased copy. (The attribute *name*
            // `boundary=` is case-insensitive per RFC 7231 §3.1.1.5, but
            // boundary values commonly contain mixed-case browser-generated
            // markers like `----WebKitFormBoundary...`.)
            let boundary = match multipart_boundary(&content_type_raw) {
                Some(b) => b,
                None => {
                    return (StatusCode::BAD_REQUEST, "missing multipart boundary").into_response()
                }
            };
            let (parts, body) = req.into_parts();
            // Cap matches the per-route DefaultBodyLimit on the settings
            // upload pages (4 MiB) — the middleware buffers the body, the
            // handler re-reads it.
            let bytes = match axum::body::to_bytes(body, 4 * 1024 * 1024).await {
                Ok(b) => b,
                Err(_) => return (StatusCode::BAD_REQUEST, "Body too large").into_response(),
            };
            let token = extract_multipart_csrf(&bytes, &boundary);
            req = Request::from_parts(parts, Body::from(bytes.clone()));
            (token, bytes)
        } else {
            return (StatusCode::FORBIDDEN, "CSRF token missing").into_response();
        };

        let _ = bytes; // body already attached to `req` above
        return match form_token {
            Some(t) if hash_token(&cookie_token) == hash_token(&t) => next.run(req).await,
            Some(_) => (StatusCode::FORBIDDEN, "CSRF token mismatch").into_response(),
            None => (StatusCode::FORBIDDEN, "CSRF token missing").into_response(),
        };
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

    #[test]
    fn multipart_boundary_unquoted_and_quoted() {
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=abc123"),
            Some("abc123".into())
        );
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=\"ab cd\""),
            Some("ab cd".into())
        );
        assert_eq!(multipart_boundary("multipart/form-data"), None);
    }

    /// Browsers (Chrome / Firefox / Safari) emit mixed-case boundaries like
    /// `----WebKitFormBoundaryAbc123`. The middleware caller passes the raw
    /// header value (not lowercased), so we must preserve case here.
    #[test]
    fn multipart_boundary_preserves_value_case() {
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=----WebKitFormBoundaryAbCdEf123"),
            Some("----WebKitFormBoundaryAbCdEf123".into())
        );
        // Attribute name is case-insensitive per RFC 7231.
        assert_eq!(
            multipart_boundary("multipart/form-data; Boundary=xyz"),
            Some("xyz".into())
        );
    }

    #[test]
    fn extract_multipart_csrf_finds_first_part() {
        let boundary = "----X";
        let body = b"------X\r\n\
Content-Disposition: form-data; name=\"csrf_token\"\r\n\
\r\n\
abc123\r\n\
------X\r\n\
Content-Disposition: form-data; name=\"enabled\"\r\n\
\r\n\
true\r\n\
------X--\r\n";
        assert_eq!(
            extract_multipart_csrf(body, boundary),
            Some("abc123".into())
        );
    }

    #[test]
    fn extract_multipart_csrf_missing_returns_none() {
        let boundary = "----X";
        let body = b"------X\r\n\
Content-Disposition: form-data; name=\"enabled\"\r\n\
\r\n\
true\r\n\
------X--\r\n";
        assert_eq!(extract_multipart_csrf(body, boundary), None);
    }

    #[test]
    fn extract_multipart_csrf_finds_token_not_in_first_position() {
        let boundary = "----X";
        let body = b"------X\r\n\
Content-Disposition: form-data; name=\"enabled\"\r\n\
\r\n\
true\r\n\
------X\r\n\
Content-Disposition: form-data; name=\"csrf_token\"\r\n\
\r\n\
deadbeef\r\n\
------X--\r\n";
        assert_eq!(
            extract_multipart_csrf(body, boundary),
            Some("deadbeef".into())
        );
    }
}
