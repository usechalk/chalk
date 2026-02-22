//! Webhook delivery engine with retry logic.
//!
//! Handles sending webhook events to configured endpoints, recording delivery
//! status, and scheduling retries with exponential backoff.

use chrono::{Duration, Utc};
use reqwest::Client;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::WebhookConfig;
use crate::db::repository::ChalkRepository;
use crate::error::Result;

use super::crypto::{encrypt_payload, sign_payload};
use super::models::{
    DeliveryStatus, SyncChangeset, WebhookDelivery, WebhookEndpoint, WebhookEvent,
    WebhookEventData, WebhookMode, WebhookScoping, WebhookSecurityMode, WebhookSource,
};
use super::scoping::apply_scoping;

/// Maximum number of delivery attempts before permanently failing.
const MAX_ATTEMPTS: i32 = 5;

/// Backoff intervals in seconds: 1min, 5min, 30min, 2hr, 12hr.
const BACKOFF_SECONDS: [i64; 5] = [60, 300, 1800, 7200, 43200];

/// Webhook delivery engine.
pub struct WebhookDeliveryEngine {
    client: Client,
}

impl WebhookDeliveryEngine {
    /// Create a new delivery engine with a 30-second HTTP timeout.
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("Chalk-Webhook/1.0")
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    /// Create a delivery engine with a custom reqwest client (for testing).
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }

    /// Deliver a single webhook event to an endpoint.
    ///
    /// Signs or encrypts the payload based on the endpoint's security mode,
    /// sends the HTTP request, and records the delivery result.
    pub async fn deliver(
        &self,
        endpoint: &WebhookEndpoint,
        event: &WebhookEvent,
        repo: &(dyn ChalkRepository + Send + Sync),
    ) -> Result<()> {
        let event_json = serde_json::to_vec(event).map_err(|e| {
            crate::error::ChalkError::Webhook(format!("failed to serialize event: {e}"))
        })?;

        let (body, signature) = match endpoint.security_mode {
            WebhookSecurityMode::SignOnly => {
                let sig = sign_payload(&endpoint.secret, &event_json);
                (event_json, Some(sig))
            }
            WebhookSecurityMode::Encrypted => {
                let encrypted = encrypt_payload(&endpoint.secret, &event_json)?;
                let body = serde_json::to_vec(&encrypted).map_err(|e| {
                    crate::error::ChalkError::Webhook(format!(
                        "failed to serialize encrypted payload: {e}"
                    ))
                })?;
                (body, None)
            }
        };

        let mut request = self
            .client
            .post(&endpoint.url)
            .header("Content-Type", "application/json")
            .header("X-Chalk-Event-Id", &event.event_id)
            .header("X-Chalk-Webhook-Id", &endpoint.id)
            .header("X-Chalk-Timestamp", event.timestamp.to_rfc3339())
            .header(
                "X-Chalk-Security-Mode",
                match endpoint.security_mode {
                    WebhookSecurityMode::SignOnly => "sign_only",
                    WebhookSecurityMode::Encrypted => "encrypted",
                },
            );

        if let Some(sig) = &signature {
            request = request.header("X-Chalk-Signature", format!("sha256={sig}"));
        }

        let response = request.body(body).send().await;

        let (status, http_status, response_body) = match response {
            Ok(resp) => {
                let http_code = resp.status().as_u16() as i32;
                let resp_body = resp.text().await.unwrap_or_default();
                if (200..300).contains(&http_code) {
                    (DeliveryStatus::Delivered, Some(http_code), Some(resp_body))
                } else if (400..500).contains(&http_code) {
                    // Client error: permanent failure, do not retry
                    (DeliveryStatus::Failed, Some(http_code), Some(resp_body))
                } else {
                    // Server error: schedule retry
                    (DeliveryStatus::Retrying, Some(http_code), Some(resp_body))
                }
            }
            Err(e) => {
                // Network error: schedule retry
                (
                    DeliveryStatus::Retrying,
                    None,
                    Some(format!("request failed: {e}")),
                )
            }
        };

        let next_retry = if status == DeliveryStatus::Retrying {
            Some(Utc::now() + Duration::seconds(BACKOFF_SECONDS[0]))
        } else {
            None
        };

        let delivery = WebhookDelivery {
            id: 0,
            webhook_endpoint_id: endpoint.id.clone(),
            event_id: event.event_id.clone(),
            sync_run_id: event.sync_run_id,
            status,
            http_status,
            response_body,
            attempt_count: 1,
            next_retry_at: next_retry,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        repo.create_webhook_delivery(&delivery).await?;

        match delivery.status {
            DeliveryStatus::Delivered => {
                info!(
                    webhook_id = %endpoint.id,
                    event_id = %event.event_id,
                    "Webhook delivered successfully"
                );
            }
            DeliveryStatus::Failed => {
                error!(
                    webhook_id = %endpoint.id,
                    event_id = %event.event_id,
                    http_status = ?delivery.http_status,
                    "Webhook delivery permanently failed"
                );
            }
            DeliveryStatus::Retrying => {
                warn!(
                    webhook_id = %endpoint.id,
                    event_id = %event.event_id,
                    http_status = ?delivery.http_status,
                    "Webhook delivery failed, will retry"
                );
            }
            _ => {}
        }

        Ok(())
    }

    /// Deliver a changeset to all configured endpoints.
    ///
    /// For each endpoint, applies scoping filters, builds events according
    /// to the endpoint's mode (batched or per-entity), and delivers them.
    pub async fn deliver_all(
        &self,
        endpoints: &[WebhookEndpoint],
        changeset: &SyncChangeset,
        repo: &(dyn ChalkRepository + Send + Sync),
    ) -> Result<()> {
        for endpoint in endpoints {
            if !endpoint.enabled {
                continue;
            }

            let scoped_changes = apply_scoping(&endpoint.scoping, &changeset.changes);
            if scoped_changes.is_empty() {
                continue;
            }

            match endpoint.mode {
                WebhookMode::Batched => {
                    let event = WebhookEvent {
                        webhook_id: endpoint.id.clone(),
                        event_id: Uuid::new_v4().to_string(),
                        event_type: "sync.changes".to_string(),
                        timestamp: Utc::now(),
                        tenant_id: endpoint.tenant_id.clone(),
                        sync_run_id: changeset.sync_run_id,
                        data: WebhookEventData::Batch {
                            changes: scoped_changes,
                        },
                    };
                    if let Err(e) = self.deliver(endpoint, &event, repo).await {
                        error!(
                            webhook_id = %endpoint.id,
                            error = %e,
                            "Failed to deliver batched webhook"
                        );
                    }
                }
                WebhookMode::PerEntity => {
                    for change in scoped_changes {
                        let event = WebhookEvent {
                            webhook_id: endpoint.id.clone(),
                            event_id: Uuid::new_v4().to_string(),
                            event_type: format!(
                                "entity.{}",
                                serde_json::to_value(&change.action)
                                    .ok()
                                    .and_then(|v| v.as_str().map(String::from))
                                    .unwrap_or_else(|| "changed".to_string())
                            ),
                            timestamp: Utc::now(),
                            tenant_id: endpoint.tenant_id.clone(),
                            sync_run_id: changeset.sync_run_id,
                            data: WebhookEventData::Single(change),
                        };
                        if let Err(e) = self.deliver(endpoint, &event, repo).await {
                            error!(
                                webhook_id = %endpoint.id,
                                event_id = %event.event_id,
                                error = %e,
                                "Failed to deliver per-entity webhook"
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Process pending webhook retries.
    ///
    /// Fetches deliveries in `pending` or `retrying` status that are due for
    /// retry, resends them, and updates the delivery record.
    pub async fn process_pending_retries(
        &self,
        repo: &(dyn ChalkRepository + Send + Sync),
    ) -> Result<()> {
        let pending = repo.list_pending_retries(50).await?;

        for delivery in &pending {
            if delivery.attempt_count >= MAX_ATTEMPTS {
                repo.update_delivery_status(delivery.id, DeliveryStatus::Failed, None, Some("max retries exceeded"))
                    .await?;
                continue;
            }

            let endpoint = match repo.get_webhook_endpoint(&delivery.webhook_endpoint_id).await? {
                Some(ep) => ep,
                None => {
                    repo.update_delivery_status(
                        delivery.id,
                        DeliveryStatus::Failed,
                        None,
                        Some("endpoint not found"),
                    )
                    .await?;
                    continue;
                }
            };

            // Re-send the request (we don't have the original event, so we send
            // a minimal retry ping that the consumer can use to re-fetch)
            let retry_body = serde_json::json!({
                "retry": true,
                "event_id": delivery.event_id,
                "attempt": delivery.attempt_count + 1,
                "webhook_id": endpoint.id,
            });
            let body_bytes = serde_json::to_vec(&retry_body).unwrap_or_default();

            let sig = sign_payload(&endpoint.secret, &body_bytes);

            let response = self
                .client
                .post(&endpoint.url)
                .header("Content-Type", "application/json")
                .header("X-Chalk-Event-Id", &delivery.event_id)
                .header("X-Chalk-Webhook-Id", &endpoint.id)
                .header("X-Chalk-Signature", format!("sha256={sig}"))
                .header("X-Chalk-Retry-Attempt", delivery.attempt_count.to_string())
                .body(body_bytes)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let code = resp.status().as_u16() as i32;
                    let resp_body = resp.text().await.unwrap_or_default();
                    if (200..300).contains(&code) {
                        repo.update_delivery_status(
                            delivery.id,
                            DeliveryStatus::Delivered,
                            Some(code),
                            Some(&resp_body),
                        )
                        .await?;
                    } else if (400..500).contains(&code) {
                        repo.update_delivery_status(
                            delivery.id,
                            DeliveryStatus::Failed,
                            Some(code),
                            Some(&resp_body),
                        )
                        .await?;
                    } else {
                        // Still failing, update with incremented attempt
                        repo.update_delivery_status(
                            delivery.id,
                            DeliveryStatus::Retrying,
                            Some(code),
                            Some(&resp_body),
                        )
                        .await?;
                    }
                }
                Err(e) => {
                    repo.update_delivery_status(
                        delivery.id,
                        DeliveryStatus::Retrying,
                        None,
                        Some(&format!("retry failed: {e}")),
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }
}

impl Default for WebhookDeliveryEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Load all webhook endpoints from both TOML config and the database.
///
/// TOML endpoints are upserted into the DB with source `toml`, then all
/// endpoints are returned. Deduplication is by endpoint ID.
pub async fn load_all_endpoints(
    config_endpoints: &[WebhookConfig],
    repo: &(dyn ChalkRepository + Send + Sync),
) -> Result<Vec<WebhookEndpoint>> {
    // Upsert TOML-configured endpoints
    for wc in config_endpoints {
        let id = format!("toml-{}", slug_from_name(&wc.name));
        let endpoint = WebhookEndpoint {
            id,
            name: wc.name.clone(),
            url: wc.url.clone(),
            secret: wc.secret.clone(),
            enabled: wc.enabled,
            mode: wc.mode.clone(),
            security_mode: wc.security.clone(),
            source: WebhookSource::Toml,
            tenant_id: None,
            scoping: WebhookScoping {
                entity_types: wc
                    .entity_types
                    .iter()
                    .filter_map(|s| serde_json::from_value(serde_json::Value::String(s.clone())).ok())
                    .collect(),
                org_sourced_ids: wc.org_sourced_ids.clone(),
                roles: wc.roles.clone(),
                excluded_fields: wc.excluded_fields.clone(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        repo.upsert_webhook_endpoint(&endpoint).await?;
    }

    // Return all endpoints
    repo.list_webhook_endpoints().await
}

/// Generate a URL-safe slug from a webhook name.
fn slug_from_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// Compute the next retry time based on the current attempt count.
pub fn next_retry_at(attempt: i32) -> chrono::DateTime<Utc> {
    let idx = (attempt as usize).min(BACKOFF_SECONDS.len() - 1);
    Utc::now() + Duration::seconds(BACKOFF_SECONDS[idx])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repository::{WebhookDeliveryRepository, WebhookEndpointRepository};
    use crate::db::DatabasePool;
    use crate::db::sqlite::SqliteRepository;
    use crate::webhooks::models::{
        ChangeAction, EntityChange, EntityType, WebhookMode, WebhookSecurityMode, WebhookSource,
    };
    use wiremock::matchers::{header, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup() -> (SqliteRepository, MockServer) {
        let pool = DatabasePool::new_sqlite_memory().await.unwrap();
        let repo = match pool {
            DatabasePool::Sqlite(p) => SqliteRepository::new(p),
        };
        let mock_server = MockServer::start().await;
        (repo, mock_server)
    }

    fn sample_endpoint(url: &str) -> WebhookEndpoint {
        WebhookEndpoint {
            id: "wh-test".to_string(),
            name: "Test".to_string(),
            url: url.to_string(),
            secret: "test-secret".to_string(),
            enabled: true,
            mode: WebhookMode::Batched,
            security_mode: WebhookSecurityMode::SignOnly,
            source: WebhookSource::Database,
            tenant_id: None,
            scoping: WebhookScoping::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn sample_event() -> WebhookEvent {
        WebhookEvent {
            webhook_id: "wh-test".to_string(),
            event_id: "evt-001".to_string(),
            event_type: "sync.changes".to_string(),
            timestamp: Utc::now(),
            tenant_id: None,
            sync_run_id: 1,
            data: WebhookEventData::Batch {
                changes: vec![EntityChange {
                    entity_type: EntityType::User,
                    action: ChangeAction::Created,
                    sourced_id: "user-1".to_string(),
                    entity: serde_json::json!({"givenName": "Alice"}),
                }],
            },
        }
    }

    fn sample_changeset() -> SyncChangeset {
        SyncChangeset {
            changes: vec![EntityChange {
                entity_type: EntityType::User,
                action: ChangeAction::Created,
                sourced_id: "user-1".to_string(),
                entity: serde_json::json!({"givenName": "Alice", "role": "student"}),
            }],
            sync_run_id: 1,
        }
    }

    #[tokio::test]
    async fn successful_delivery_records_success() {
        let (repo, mock_server) = setup().await;
        let endpoint = sample_endpoint(&format!("{}/webhook", mock_server.uri()));
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        Mock::given(method("POST"))
            .and(path("/webhook"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&mock_server)
            .await;

        let engine = WebhookDeliveryEngine::new();
        engine.deliver(&endpoint, &sample_event(), &repo).await.unwrap();

        let deliveries = repo
            .list_deliveries_by_webhook("wh-test", 10)
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].status, DeliveryStatus::Delivered);
        assert_eq!(deliveries[0].http_status, Some(200));
    }

    #[tokio::test]
    async fn server_error_schedules_retry() {
        let (repo, mock_server) = setup().await;
        let endpoint = sample_endpoint(&format!("{}/webhook", mock_server.uri()));
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        Mock::given(method("POST"))
            .and(path("/webhook"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let engine = WebhookDeliveryEngine::new();
        engine.deliver(&endpoint, &sample_event(), &repo).await.unwrap();

        let deliveries = repo
            .list_deliveries_by_webhook("wh-test", 10)
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].status, DeliveryStatus::Retrying);
        assert_eq!(deliveries[0].http_status, Some(500));
    }

    #[tokio::test]
    async fn client_error_marks_permanent_failure() {
        let (repo, mock_server) = setup().await;
        let endpoint = sample_endpoint(&format!("{}/webhook", mock_server.uri()));
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        Mock::given(method("POST"))
            .and(path("/webhook"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
            .mount(&mock_server)
            .await;

        let engine = WebhookDeliveryEngine::new();
        engine.deliver(&endpoint, &sample_event(), &repo).await.unwrap();

        let deliveries = repo
            .list_deliveries_by_webhook("wh-test", 10)
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].status, DeliveryStatus::Failed);
        assert_eq!(deliveries[0].http_status, Some(400));
    }

    #[tokio::test]
    async fn sign_only_sends_correct_headers() {
        let (repo, mock_server) = setup().await;
        let endpoint = sample_endpoint(&format!("{}/webhook", mock_server.uri()));
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        Mock::given(method("POST"))
            .and(path("/webhook"))
            .and(header("X-Chalk-Security-Mode", "sign_only"))
            .and(header("X-Chalk-Event-Id", "evt-001"))
            .and(header("X-Chalk-Webhook-Id", "wh-test"))
            .and(header("Content-Type", "application/json"))
            .and(header_exists("X-Chalk-Signature"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let engine = WebhookDeliveryEngine::new();
        engine.deliver(&endpoint, &sample_event(), &repo).await.unwrap();
    }

    #[tokio::test]
    async fn encrypted_mode_sends_encrypted_body() {
        let (repo, mock_server) = setup().await;
        let mut endpoint = sample_endpoint(&format!("{}/webhook", mock_server.uri()));
        endpoint.security_mode = WebhookSecurityMode::Encrypted;
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        Mock::given(method("POST"))
            .and(path("/webhook"))
            .and(header("X-Chalk-Security-Mode", "encrypted"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let engine = WebhookDeliveryEngine::new();
        engine.deliver(&endpoint, &sample_event(), &repo).await.unwrap();

        let deliveries = repo
            .list_deliveries_by_webhook("wh-test", 10)
            .await
            .unwrap();
        assert_eq!(deliveries[0].status, DeliveryStatus::Delivered);
    }

    #[tokio::test]
    async fn deliver_all_batched_mode() {
        let (repo, mock_server) = setup().await;
        let endpoint = sample_endpoint(&format!("{}/webhook", mock_server.uri()));
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        Mock::given(method("POST"))
            .and(path("/webhook"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let engine = WebhookDeliveryEngine::new();
        engine
            .deliver_all(&[endpoint], &sample_changeset(), &repo)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn deliver_all_per_entity_mode() {
        let (repo, mock_server) = setup().await;
        let mut endpoint = sample_endpoint(&format!("{}/webhook", mock_server.uri()));
        endpoint.mode = WebhookMode::PerEntity;
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        let changeset = SyncChangeset {
            changes: vec![
                EntityChange {
                    entity_type: EntityType::User,
                    action: ChangeAction::Created,
                    sourced_id: "user-1".to_string(),
                    entity: serde_json::json!({"givenName": "Alice"}),
                },
                EntityChange {
                    entity_type: EntityType::User,
                    action: ChangeAction::Updated,
                    sourced_id: "user-2".to_string(),
                    entity: serde_json::json!({"givenName": "Bob"}),
                },
            ],
            sync_run_id: 1,
        };

        Mock::given(method("POST"))
            .and(path("/webhook"))
            .respond_with(ResponseTemplate::new(200))
            .expect(2) // one per entity
            .mount(&mock_server)
            .await;

        let engine = WebhookDeliveryEngine::new();
        engine
            .deliver_all(&[endpoint], &changeset, &repo)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn deliver_all_skips_disabled_endpoints() {
        let (repo, mock_server) = setup().await;
        let mut endpoint = sample_endpoint(&format!("{}/webhook", mock_server.uri()));
        endpoint.enabled = false;
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        let engine = WebhookDeliveryEngine::new();
        engine
            .deliver_all(&[endpoint], &sample_changeset(), &repo)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn deliver_all_skips_empty_after_scoping() {
        let (repo, mock_server) = setup().await;
        let mut endpoint = sample_endpoint(&format!("{}/webhook", mock_server.uri()));
        endpoint.scoping = WebhookScoping {
            entity_types: vec![EntityType::Org], // won't match User changes
            ..WebhookScoping::default()
        };
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        let engine = WebhookDeliveryEngine::new();
        engine
            .deliver_all(&[endpoint], &sample_changeset(), &repo)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn process_pending_retries_succeeds() {
        let (repo, mock_server) = setup().await;
        let endpoint = sample_endpoint(&format!("{}/webhook", mock_server.uri()));
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        // Create a pending delivery
        let delivery = WebhookDelivery {
            id: 0,
            webhook_endpoint_id: "wh-test".to_string(),
            event_id: "evt-retry".to_string(),
            sync_run_id: 1,
            status: DeliveryStatus::Pending,
            http_status: None,
            response_body: None,
            attempt_count: 0,
            next_retry_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        repo.create_webhook_delivery(&delivery).await.unwrap();

        Mock::given(method("POST"))
            .and(path("/webhook"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&mock_server)
            .await;

        let engine = WebhookDeliveryEngine::new();
        engine.process_pending_retries(&repo).await.unwrap();

        let deliveries = repo
            .list_deliveries_by_webhook("wh-test", 10)
            .await
            .unwrap();
        assert_eq!(deliveries[0].status, DeliveryStatus::Delivered);
    }

    #[tokio::test]
    async fn load_all_endpoints_merges_toml_and_db() {
        let (repo, _mock_server) = setup().await;

        // Add a DB endpoint directly
        let db_ep = sample_endpoint("https://db-endpoint.example.com/webhook");
        repo.upsert_webhook_endpoint(&db_ep).await.unwrap();

        // Load with TOML config
        let toml_configs = vec![WebhookConfig {
            name: "TOML Hook".to_string(),
            url: "https://toml-endpoint.example.com/webhook".to_string(),
            secret: "toml-secret".to_string(),
            security: WebhookSecurityMode::SignOnly,
            mode: WebhookMode::Batched,
            enabled: true,
            entity_types: vec![],
            roles: vec![],
            excluded_fields: vec![],
            org_sourced_ids: vec![],
        }];

        let all = load_all_endpoints(&toml_configs, &repo).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn slug_from_name_generates_clean_slug() {
        assert_eq!(slug_from_name("My LMS"), "my-lms");
        assert_eq!(slug_from_name("Analytics System"), "analytics-system");
        assert_eq!(slug_from_name("test"), "test");
        assert_eq!(slug_from_name(" Spaces "), "spaces");
    }

    #[test]
    fn next_retry_at_uses_backoff() {
        let before = Utc::now();
        let retry = next_retry_at(0);
        assert!(retry >= before + Duration::seconds(59));
        assert!(retry <= before + Duration::seconds(61));

        let retry2 = next_retry_at(1);
        assert!(retry2 >= before + Duration::seconds(299));

        // Test clamping at max
        let retry_max = next_retry_at(100);
        assert!(retry_max >= before + Duration::seconds(43199));
    }
}
