//! Chalk Telemetry — Optional, anonymous telemetry (opt-in only).
//!
//! Planned for future implementation. When enabled, reports anonymous usage
//! statistics (version, enabled features, student count ranges) to help
//! prioritize development. Never reports PII or identifying information.

/// Returns whether the telemetry feature is enabled.
pub fn is_enabled() -> bool {
    false
}
