//! Telemetry data collection — gathers anonymous, non-identifying usage data.

use chrono::Utc;
use uuid::Uuid;

use crate::models::{bucket_student_count, TelemetryReport};

/// Configuration inputs for telemetry collection.
/// This is intentionally independent of chalk-core's config types so the
/// telemetry crate remains a standalone leaf dependency.
pub struct TelemetryInput {
    /// SIS provider type string (e.g. "powerschool"). Must never be a school name.
    pub sis_provider: String,
    /// Database driver string (e.g. "sqlite" or "postgres").
    pub db_driver: String,
    /// Whether IDP feature is enabled.
    pub idp_enabled: bool,
    /// Whether Google Sync feature is enabled.
    pub google_sync_enabled: bool,
    /// Whether the agent feature is enabled.
    pub agent_enabled: bool,
    /// Whether the marketplace feature is enabled.
    pub marketplace_enabled: bool,
}

/// Collects anonymous telemetry data into a report.
pub struct TelemetryCollector {
    chalk_version: String,
}

impl TelemetryCollector {
    /// Create a new collector for the given Chalk version.
    pub fn new(chalk_version: String) -> Self {
        Self { chalk_version }
    }

    /// Collect a telemetry report from the given inputs.
    ///
    /// The report contains only anonymous, aggregate data:
    /// - Software version
    /// - SIS provider *type* (never a school name)
    /// - Bucketed student count (never exact)
    /// - Database driver
    /// - Enabled feature flags
    /// - Sync count and uptime
    ///
    /// It NEVER includes: school names, PII, credentials, or IP addresses.
    pub fn collect_report(
        &self,
        input: &TelemetryInput,
        student_count: u64,
        sync_count: u32,
        uptime_hours: u32,
    ) -> TelemetryReport {
        let mut features = Vec::new();
        if input.idp_enabled {
            features.push("idp".to_string());
        }
        if input.google_sync_enabled {
            features.push("google_sync".to_string());
        }
        if input.agent_enabled {
            features.push("agent".to_string());
        }
        if input.marketplace_enabled {
            features.push("marketplace".to_string());
        }

        TelemetryReport {
            chalk_version: self.chalk_version.clone(),
            report_id: Uuid::new_v4(),
            sis_provider: input.sis_provider.clone(),
            student_count_bucket: bucket_student_count(student_count),
            db_driver: input.db_driver.clone(),
            features_enabled: features,
            sync_count_24h: sync_count,
            uptime_hours,
            reported_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> TelemetryInput {
        TelemetryInput {
            sis_provider: "powerschool".to_string(),
            db_driver: "sqlite".to_string(),
            idp_enabled: true,
            google_sync_enabled: true,
            agent_enabled: false,
            marketplace_enabled: false,
        }
    }

    #[test]
    fn collector_produces_valid_report() {
        let collector = TelemetryCollector::new("0.1.0".to_string());
        let report = collector.collect_report(&sample_input(), 250, 5, 24);

        assert_eq!(report.chalk_version, "0.1.0");
        assert_eq!(report.sis_provider, "powerschool");
        assert_eq!(report.student_count_bucket, "101-500");
        assert_eq!(report.db_driver, "sqlite");
        assert_eq!(report.sync_count_24h, 5);
        assert_eq!(report.uptime_hours, 24);
    }

    #[test]
    fn collector_identifies_enabled_features() {
        let collector = TelemetryCollector::new("0.1.0".to_string());

        // Only idp and google_sync enabled
        let report = collector.collect_report(&sample_input(), 0, 0, 0);
        assert_eq!(report.features_enabled, vec!["idp", "google_sync"]);

        // All features enabled
        let all_input = TelemetryInput {
            sis_provider: "skyward".to_string(),
            db_driver: "postgres".to_string(),
            idp_enabled: true,
            google_sync_enabled: true,
            agent_enabled: true,
            marketplace_enabled: true,
        };
        let report = collector.collect_report(&all_input, 0, 0, 0);
        assert_eq!(
            report.features_enabled,
            vec!["idp", "google_sync", "agent", "marketplace"]
        );

        // No features enabled
        let none_input = TelemetryInput {
            sis_provider: "powerschool".to_string(),
            db_driver: "sqlite".to_string(),
            idp_enabled: false,
            google_sync_enabled: false,
            agent_enabled: false,
            marketplace_enabled: false,
        };
        let report = collector.collect_report(&none_input, 0, 0, 0);
        assert!(report.features_enabled.is_empty());
    }

    #[test]
    fn collector_never_includes_pii() {
        let collector = TelemetryCollector::new("0.1.0".to_string());
        let input = TelemetryInput {
            sis_provider: "powerschool".to_string(),
            db_driver: "sqlite".to_string(),
            idp_enabled: true,
            google_sync_enabled: false,
            agent_enabled: false,
            marketplace_enabled: false,
        };
        let report = collector.collect_report(&input, 1234, 10, 100);

        let json = serde_json::to_string(&report).unwrap();
        // Must not contain any PII patterns
        assert!(!json.contains("@")); // no email addresses
        assert!(!json.contains("school_name"));
        assert!(!json.contains("instance_name"));
        assert!(!json.contains("password"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("credential"));
        // Student count must be bucketed, not exact
        assert!(!json.contains("\"1234\""));
        assert!(json.contains("1001-5000"));
    }

    #[test]
    fn collector_report_does_not_contain_ip_addresses() {
        let collector = TelemetryCollector::new("0.1.0".to_string());
        let report = collector.collect_report(&sample_input(), 500, 2, 48);

        let json = serde_json::to_string(&report).unwrap();
        // Simple check: no IPv4-like patterns (digit.digit.digit.digit)
        let ip_pattern = regex_lite_free_ip_check(&json);
        assert!(!ip_pattern, "Report JSON should not contain IP addresses");
    }

    /// Check if the string contains anything that looks like an IPv4 address.
    fn regex_lite_free_ip_check(s: &str) -> bool {
        // Look for patterns like "N.N.N.N" where N is 1-3 digits
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i].is_ascii_digit() {
                // Try to match digit+.digit+.digit+.digit+
                let mut dots = 0;
                let mut j = i;
                while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '.') {
                    if chars[j] == '.' {
                        dots += 1;
                    }
                    j += 1;
                }
                if dots == 3 && j > i + 6 {
                    // Minimum "1.1.1.1" is 7 chars
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    #[test]
    fn collector_generates_unique_report_ids() {
        let collector = TelemetryCollector::new("0.1.0".to_string());
        let input = sample_input();
        let r1 = collector.collect_report(&input, 100, 1, 1);
        let r2 = collector.collect_report(&input, 100, 1, 1);
        assert_ne!(r1.report_id, r2.report_id);
    }
}
