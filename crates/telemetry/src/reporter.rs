//! Telemetry reporting — sends anonymous reports via HTTP POST.

use crate::models::TelemetryReport;
use std::time::Duration;

/// Default telemetry endpoint.
const DEFAULT_ENDPOINT: &str = "https://telemetry.chalk.dev/v1/report";

/// HTTP timeout for telemetry submissions.
const REPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// Sends telemetry reports to a configured endpoint.
/// Fire-and-forget: errors are logged but never propagated to callers.
pub struct TelemetryReporter {
    endpoint: String,
    client: reqwest::Client,
}

impl TelemetryReporter {
    /// Create a reporter targeting the default endpoint.
    pub fn new() -> Self {
        Self::with_endpoint(DEFAULT_ENDPOINT.to_string())
    }

    /// Create a reporter targeting a custom endpoint.
    pub fn with_endpoint(endpoint: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(REPORT_TIMEOUT)
            .build()
            .expect("failed to build HTTP client");

        Self { endpoint, client }
    }

    /// Submit a telemetry report via HTTP POST.
    ///
    /// This is fire-and-forget: errors are logged via `tracing::warn` but
    /// never returned to the caller. Telemetry failures must not affect
    /// normal application operation.
    pub async fn report(&self, report: &TelemetryReport) {
        match self.client.post(&self.endpoint).json(report).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    tracing::warn!(
                        status = %response.status(),
                        "telemetry report rejected by server"
                    );
                } else {
                    tracing::debug!("telemetry report submitted successfully");
                }
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to submit telemetry report"
                );
            }
        }
    }

    /// Returns the configured endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl Default for TelemetryReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_report() -> TelemetryReport {
        TelemetryReport {
            chalk_version: "0.1.0".to_string(),
            report_id: Uuid::new_v4(),
            sis_provider: "powerschool".to_string(),
            student_count_bucket: "101-500".to_string(),
            db_driver: "sqlite".to_string(),
            features_enabled: vec!["idp".to_string()],
            sync_count_24h: 3,
            uptime_hours: 24,
            reported_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn reporter_sends_http_post() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/report"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let reporter = TelemetryReporter::with_endpoint(format!("{}/v1/report", server.uri()));
        reporter.report(&sample_report()).await;

        // wiremock will verify the expectation on drop
    }

    #[tokio::test]
    async fn reporter_handles_server_error_gracefully() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/report"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let reporter = TelemetryReporter::with_endpoint(format!("{}/v1/report", server.uri()));

        // Should not panic on server error
        reporter.report(&sample_report()).await;
    }

    #[tokio::test]
    async fn reporter_handles_connection_refused() {
        // Point to a port that nothing is listening on
        let reporter = TelemetryReporter::with_endpoint("http://127.0.0.1:1/v1/report".to_string());

        // Should not panic on connection failure
        reporter.report(&sample_report()).await;
    }

    #[tokio::test]
    async fn reporter_respects_timeout() {
        let server = MockServer::start().await;

        // Respond with a 10-second delay (longer than our 5s timeout)
        Mock::given(method("POST"))
            .and(path("/v1/report"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("ok")
                    .set_delay(Duration::from_secs(10)),
            )
            .mount(&server)
            .await;

        let reporter = TelemetryReporter::with_endpoint(format!("{}/v1/report", server.uri()));

        let start = std::time::Instant::now();
        reporter.report(&sample_report()).await;
        let elapsed = start.elapsed();

        // Should have timed out around 5s, definitely less than 10s
        assert!(
            elapsed < Duration::from_secs(8),
            "reporter should have timed out, but took {:?}",
            elapsed
        );
    }

    #[test]
    fn reporter_default_endpoint() {
        let reporter = TelemetryReporter::new();
        assert_eq!(reporter.endpoint(), "https://telemetry.chalk.dev/v1/report");
    }

    #[test]
    fn reporter_custom_endpoint() {
        let reporter =
            TelemetryReporter::with_endpoint("https://custom.example.com/tel".to_string());
        assert_eq!(reporter.endpoint(), "https://custom.example.com/tel");
    }
}
