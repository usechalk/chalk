//! Chalk Google Sync — Google Workspace user provisioning and OU management.
//!
//! Planned for Phase 1c. This crate will handle creating/suspending Google Workspace
//! accounts, managing Organizational Units, and delta-only sync via the Admin SDK.

/// Returns whether the Google Sync feature is enabled.
pub fn is_enabled() -> bool {
    false
}
