//! Chalk Telemetry — Optional, anonymous telemetry (opt-in only).
//!
//! When enabled, reports anonymous usage statistics (version, enabled features,
//! student count ranges) to help prioritize development. Never reports PII or
//! identifying information.

pub mod collector;
pub mod models;
pub mod reporter;

pub use collector::{TelemetryCollector, TelemetryInput};
pub use models::TelemetryReport;
pub use reporter::TelemetryReporter;

/// Returns whether the telemetry feature is enabled by default.
pub fn is_enabled() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_enabled_returns_false_by_default() {
        assert!(!is_enabled());
    }
}
