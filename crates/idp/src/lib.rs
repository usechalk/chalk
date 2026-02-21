//! Chalk IDP — Identity provider with SAML 2.0/OIDC, badge login, and picture passwords.
//!
//! Planned for Phase 1c. This crate will handle ChromeOS SAML integration,
//! QR code badge login, and picture password authentication for young students.

/// Returns whether the IDP feature is enabled.
pub fn is_enabled() -> bool {
    false
}
