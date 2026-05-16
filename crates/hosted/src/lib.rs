//! Hosted multi-tenant runtime for chalk.
//!
//! This crate is for the operator running a multi-tenant chalk service
//! (e.g. chalk.app). Self-hosters should use the OSS `chalk` binary.

pub mod admin;
pub mod commands;
pub mod context;
pub mod keys;
pub mod meta;
pub mod middleware;
pub mod notify;
pub mod scheduler;
pub mod signup;
pub mod state_cache;
pub mod tenant;
pub mod tenant_assert;

/// Reserved subdomain slugs that must not be used as tenant identifiers.
pub const RESERVED_SLUGS: &[&str] = &[
    "www",
    "api",
    "admin",
    "app",
    "mail",
    "static",
    "marketing",
    "signup",
    "docs",
    "pricing",
    "blog",
];

/// Validates a tenant slug: lowercase letter start, lowercase alnum + hyphens,
/// length 3..=31. Rejects reserved slugs.
pub fn is_valid_slug(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 3 || bytes.len() > 31 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    if !bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return false;
    }
    if RESERVED_SLUGS.contains(&s) {
        return false;
    }
    true
}

/// Compute the Postgres schema name for a slug. Hyphens are mapped to
/// underscores. The result is guaranteed to be a valid `is_valid_pg_schema`
/// identifier for any slug that passed `is_valid_slug`.
pub fn schema_for_slug(slug: &str) -> String {
    format!("tenant_{}", slug.replace('-', "_"))
}

/// Build an externally-facing URL for the hosted service.
///
/// Slug=Some → `{scheme}://{slug}.{apex}[:port]`; Slug=None → apex itself.
/// Used by the signup verify redirect, the verification email link, and
/// per-tenant `public_url` (OIDC issuer, SAML entity ID).
pub fn public_url(scheme: &str, slug: Option<&str>, apex: &str, port: Option<u16>) -> String {
    let host = match slug {
        Some(s) => format!("{s}.{apex}"),
        None => apex.to_string(),
    };
    match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_validation() {
        assert!(is_valid_slug("acme"));
        assert!(is_valid_slug("acme-school"));
        assert!(is_valid_slug("a12-b34"));
        assert!(!is_valid_slug("ab"));
        assert!(!is_valid_slug("Acme"));
        assert!(!is_valid_slug("-acme"));
        assert!(!is_valid_slug("9acme"));
        assert!(!is_valid_slug("acme_school"));
        assert!(!is_valid_slug("www"));
        assert!(!is_valid_slug("admin"));
    }

    #[test]
    fn schema_mapping() {
        assert_eq!(schema_for_slug("acme"), "tenant_acme");
        assert_eq!(schema_for_slug("acme-school"), "tenant_acme_school");
    }
}
