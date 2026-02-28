//! Shared HTTP utilities for Chalk crates.

/// Extract the first client IP from an X-Forwarded-For header value.
///
/// Pass the raw header value (e.g., `headers.get("x-forwarded-for")`).
/// Returns the first (leftmost) IP, which is the original client.
///
/// **Security note:** `X-Forwarded-For` is trivially spoofable by clients.
/// Use this for audit/informational logging only — never for authorization.
pub fn extract_client_ip(forwarded_for: Option<&str>) -> Option<String> {
    forwarded_for
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_first_ip_from_chain() {
        let result = extract_client_ip(Some("203.0.113.50, 70.41.3.18, 150.172.238.178"));
        assert_eq!(result, Some("203.0.113.50".to_string()));
    }

    #[test]
    fn returns_single_ip() {
        let result = extract_client_ip(Some("192.168.1.1"));
        assert_eq!(result, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn trims_whitespace() {
        let result = extract_client_ip(Some("  10.0.0.1 , 10.0.0.2"));
        assert_eq!(result, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn returns_none_when_missing() {
        let result = extract_client_ip(None);
        assert_eq!(result, None);
    }

    #[test]
    fn returns_none_for_empty_string() {
        let result = extract_client_ip(Some(""));
        assert_eq!(result, None);
    }
}
