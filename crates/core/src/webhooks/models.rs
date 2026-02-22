//! Webhook domain models and types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How webhook events are grouped for delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookMode {
    Batched,
    PerEntity,
}

/// Security mode for webhook payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookSecurityMode {
    SignOnly,
    Encrypted,
}

/// Where the webhook endpoint configuration originated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookSource {
    Toml,
    Database,
    Marketplace,
}

/// OneRoster entity types that can trigger webhook events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Org,
    AcademicSession,
    User,
    Course,
    Class,
    Enrollment,
    Demographics,
}

/// The action that occurred on an entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeAction {
    Created,
    Updated,
    Deleted,
}

/// Filters that limit which changes a webhook receives.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WebhookScoping {
    /// Entity types to include. Empty means all.
    #[serde(default)]
    pub entity_types: Vec<EntityType>,
    /// Org sourced IDs to include. Empty means all.
    #[serde(default)]
    pub org_sourced_ids: Vec<String>,
    /// Roles to include. Empty means all.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Fields to exclude from payloads (e.g., "demographics.birthDate").
    #[serde(default)]
    pub excluded_fields: Vec<String>,
}

/// A configured webhook endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub id: String,
    pub name: String,
    pub url: String,
    pub secret: String,
    pub enabled: bool,
    pub mode: WebhookMode,
    pub security_mode: WebhookSecurityMode,
    pub source: WebhookSource,
    pub tenant_id: Option<String>,
    pub scoping: WebhookScoping,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A webhook event ready for delivery.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub webhook_id: String,
    pub event_id: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub tenant_id: Option<String>,
    pub sync_run_id: i64,
    pub data: WebhookEventData,
}

/// Payload variants for webhook events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventData {
    Batch { changes: Vec<EntityChange> },
    Single(EntityChange),
}

/// A single entity change record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityChange {
    pub entity_type: EntityType,
    pub action: ChangeAction,
    pub sourced_id: String,
    pub entity: serde_json::Value,
}

/// A collected set of changes from a sync run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncChangeset {
    pub changes: Vec<EntityChange>,
    pub sync_run_id: i64,
}

/// An AES-256-GCM encrypted payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// Base64-encoded nonce.
    pub nonce: String,
    /// Base64-encoded ciphertext.
    pub ciphertext: String,
}

/// Delivery status for a webhook event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Retrying,
}

/// A record of a webhook delivery attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub id: i64,
    pub webhook_endpoint_id: String,
    pub event_id: String,
    pub sync_run_id: i64,
    pub status: DeliveryStatus,
    pub http_status: Option<i32>,
    pub response_body: Option<String>,
    pub attempt_count: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_mode_serialization_roundtrip() {
        let modes = vec![WebhookMode::Batched, WebhookMode::PerEntity];
        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let parsed: WebhookMode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, mode);
        }
    }

    #[test]
    fn webhook_mode_snake_case() {
        assert_eq!(
            serde_json::to_string(&WebhookMode::Batched).unwrap(),
            "\"batched\""
        );
        assert_eq!(
            serde_json::to_string(&WebhookMode::PerEntity).unwrap(),
            "\"per_entity\""
        );
    }

    #[test]
    fn webhook_security_mode_serialization_roundtrip() {
        let modes = vec![
            WebhookSecurityMode::SignOnly,
            WebhookSecurityMode::Encrypted,
        ];
        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let parsed: WebhookSecurityMode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, mode);
        }
    }

    #[test]
    fn webhook_security_mode_snake_case() {
        assert_eq!(
            serde_json::to_string(&WebhookSecurityMode::SignOnly).unwrap(),
            "\"sign_only\""
        );
        assert_eq!(
            serde_json::to_string(&WebhookSecurityMode::Encrypted).unwrap(),
            "\"encrypted\""
        );
    }

    #[test]
    fn webhook_source_serialization_roundtrip() {
        let sources = vec![
            WebhookSource::Toml,
            WebhookSource::Database,
            WebhookSource::Marketplace,
        ];
        for source in sources {
            let json = serde_json::to_string(&source).unwrap();
            let parsed: WebhookSource = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, source);
        }
    }

    #[test]
    fn entity_type_serialization_roundtrip() {
        let types = vec![
            EntityType::Org,
            EntityType::AcademicSession,
            EntityType::User,
            EntityType::Course,
            EntityType::Class,
            EntityType::Enrollment,
            EntityType::Demographics,
        ];
        for et in types {
            let json = serde_json::to_string(&et).unwrap();
            let parsed: EntityType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, et);
        }
    }

    #[test]
    fn entity_type_snake_case() {
        assert_eq!(
            serde_json::to_string(&EntityType::AcademicSession).unwrap(),
            "\"academic_session\""
        );
    }

    #[test]
    fn change_action_serialization_roundtrip() {
        let actions = vec![
            ChangeAction::Created,
            ChangeAction::Updated,
            ChangeAction::Deleted,
        ];
        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: ChangeAction = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, action);
        }
    }

    #[test]
    fn delivery_status_serialization_roundtrip() {
        let statuses = vec![
            DeliveryStatus::Pending,
            DeliveryStatus::Delivered,
            DeliveryStatus::Failed,
            DeliveryStatus::Retrying,
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: DeliveryStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn webhook_scoping_default_is_empty() {
        let scoping = WebhookScoping::default();
        assert!(scoping.entity_types.is_empty());
        assert!(scoping.org_sourced_ids.is_empty());
        assert!(scoping.roles.is_empty());
        assert!(scoping.excluded_fields.is_empty());
    }

    #[test]
    fn webhook_scoping_serialization_roundtrip() {
        let scoping = WebhookScoping {
            entity_types: vec![EntityType::User, EntityType::Enrollment],
            org_sourced_ids: vec!["org-1".into()],
            roles: vec!["student".into()],
            excluded_fields: vec!["demographics.birthDate".into()],
        };
        let json = serde_json::to_string(&scoping).unwrap();
        let parsed: WebhookScoping = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, scoping);
    }

    #[test]
    fn entity_change_serialization_roundtrip() {
        let change = EntityChange {
            entity_type: EntityType::User,
            action: ChangeAction::Created,
            sourced_id: "user-123".into(),
            entity: serde_json::json!({"givenName": "Alice"}),
        };
        let json = serde_json::to_string(&change).unwrap();
        let parsed: EntityChange = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, change);
    }

    #[test]
    fn webhook_event_data_batch_roundtrip() {
        let data = WebhookEventData::Batch {
            changes: vec![EntityChange {
                entity_type: EntityType::Class,
                action: ChangeAction::Updated,
                sourced_id: "class-1".into(),
                entity: serde_json::json!({"title": "Math 101"}),
            }],
        };
        let json = serde_json::to_string(&data).unwrap();
        let parsed: WebhookEventData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn webhook_event_data_single_roundtrip() {
        let data = WebhookEventData::Single(EntityChange {
            entity_type: EntityType::Enrollment,
            action: ChangeAction::Deleted,
            sourced_id: "enr-1".into(),
            entity: serde_json::json!({}),
        });
        let json = serde_json::to_string(&data).unwrap();
        let parsed: WebhookEventData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn sync_changeset_serialization_roundtrip() {
        let changeset = SyncChangeset {
            changes: vec![EntityChange {
                entity_type: EntityType::Org,
                action: ChangeAction::Created,
                sourced_id: "org-1".into(),
                entity: serde_json::json!({"name": "Springfield"}),
            }],
            sync_run_id: 42,
        };
        let json = serde_json::to_string(&changeset).unwrap();
        let parsed: SyncChangeset = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, changeset);
    }

    #[test]
    fn encrypted_payload_serialization_roundtrip() {
        let payload = EncryptedPayload {
            nonce: "dGVzdG5vbmNl".into(),
            ciphertext: "ZW5jcnlwdGVk".into(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: EncryptedPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn webhook_endpoint_serialization_roundtrip() {
        let endpoint = WebhookEndpoint {
            id: "wh-1".into(),
            name: "Test Hook".into(),
            url: "https://example.com/webhook".into(),
            secret: "secret123".into(),
            enabled: true,
            mode: WebhookMode::Batched,
            security_mode: WebhookSecurityMode::SignOnly,
            source: WebhookSource::Database,
            tenant_id: Some("tenant-1".into()),
            scoping: WebhookScoping::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&endpoint).unwrap();
        let parsed: WebhookEndpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, endpoint.id);
        assert_eq!(parsed.name, endpoint.name);
        assert_eq!(parsed.url, endpoint.url);
        assert_eq!(parsed.mode, endpoint.mode);
        assert_eq!(parsed.security_mode, endpoint.security_mode);
        assert_eq!(parsed.source, endpoint.source);
    }

    #[test]
    fn webhook_delivery_serialization_roundtrip() {
        let delivery = WebhookDelivery {
            id: 1,
            webhook_endpoint_id: "wh-1".into(),
            event_id: "evt-1".into(),
            sync_run_id: 10,
            status: DeliveryStatus::Pending,
            http_status: None,
            response_body: None,
            attempt_count: 0,
            next_retry_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&delivery).unwrap();
        let parsed: WebhookDelivery = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, delivery.id);
        assert_eq!(parsed.webhook_endpoint_id, delivery.webhook_endpoint_id);
        assert_eq!(parsed.status, delivery.status);
    }
}
