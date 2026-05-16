//! Webhook admin UI handlers.
//!
//! Exposes a `/webhooks` admin section that lists, creates, edits, deletes,
//! and tests webhook endpoints stored in the database. TOML-sourced
//! endpoints are surfaced but rendered read-only — they're managed via
//! `chalk.toml` and the UI refuses to mutate them.

use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Path, State},
    response::{Html, Redirect},
};
use chalk_core::webhooks::models::{
    DeliveryStatus, EntityType, WebhookDelivery, WebhookEndpoint, WebhookEvent, WebhookEventData,
    WebhookMode, WebhookScoping, WebhookSecurityMode, WebhookSource,
};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::AppState;

/// Maximum deliveries shown on the detail page.
const DELIVERY_HISTORY_LIMIT: i64 = 50;

/// Length of the URL field rendered on the list page before truncation.
const URL_TRUNCATE_LEN: usize = 56;

// ---------------------------------------------------------------------------
// Secret handling
// ---------------------------------------------------------------------------

/// Wrapper around a 32-byte HMAC secret rendered as a 64-character lowercase
/// hex string. The custom `Debug` impl avoids leaking the secret if a struct
/// containing it is ever traced or panicked over.
#[derive(Clone)]
pub struct HmacSecret(String);

impl HmacSecret {
    /// Generate a new random 32-byte secret using the operating system's
    /// cryptographically secure RNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Borrow the hex-encoded secret value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the underlying hex string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for HmacSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HmacSecret(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// View models
// ---------------------------------------------------------------------------

/// Row data for the webhook list page.
pub struct WebhookRowView {
    pub id: String,
    pub name: String,
    pub url_truncated: String,
    pub events: String,
    pub security_mode: String,
    pub enabled: bool,
    pub is_toml: bool,
    pub is_marketplace: bool,
    pub last_status: String,
    pub last_status_class: String,
    pub created_at: String,
}

impl WebhookRowView {
    fn from_model(endpoint: &WebhookEndpoint, last: Option<&WebhookDelivery>) -> Self {
        let url_truncated = truncate_url(&endpoint.url, URL_TRUNCATE_LEN);
        let events = format_entity_types(&endpoint.scoping.entity_types);
        let (last_status, last_status_class) = last
            .map(|d| {
                let label = delivery_status_label(&d.status);
                let class = delivery_status_class(&d.status);
                (label.to_string(), class.to_string())
            })
            .unwrap_or_default();
        Self {
            id: endpoint.id.clone(),
            name: endpoint.name.clone(),
            url_truncated,
            events,
            security_mode: security_mode_to_str(&endpoint.security_mode).to_string(),
            enabled: endpoint.enabled,
            is_toml: endpoint.source == WebhookSource::Toml,
            is_marketplace: endpoint.source == WebhookSource::Marketplace,
            last_status,
            last_status_class,
            created_at: endpoint.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
        }
    }
}

/// Form/detail data for a single webhook endpoint.
pub struct WebhookEndpointView {
    pub id: String,
    pub name: String,
    pub url: String,
    pub mode: String,
    pub security_mode: String,
    pub enabled: bool,
    pub is_toml: bool,
    pub is_marketplace: bool,
    pub entity_types: String,
    pub org_sourced_ids: String,
    pub roles: String,
    pub excluded_fields: String,
    pub created_at: String,
    pub updated_at: String,
}

impl WebhookEndpointView {
    fn from_model(endpoint: &WebhookEndpoint) -> Self {
        Self {
            id: endpoint.id.clone(),
            name: endpoint.name.clone(),
            url: endpoint.url.clone(),
            mode: mode_to_str(&endpoint.mode).to_string(),
            security_mode: security_mode_to_str(&endpoint.security_mode).to_string(),
            enabled: endpoint.enabled,
            is_toml: endpoint.source == WebhookSource::Toml,
            is_marketplace: endpoint.source == WebhookSource::Marketplace,
            entity_types: format_entity_types(&endpoint.scoping.entity_types),
            org_sourced_ids: endpoint.scoping.org_sourced_ids.join(", "),
            roles: endpoint.scoping.roles.join(", "),
            excluded_fields: endpoint.scoping.excluded_fields.join(", "),
            created_at: endpoint.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            updated_at: endpoint.updated_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        }
    }

    fn empty() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            url: String::new(),
            mode: "batched".to_string(),
            security_mode: "sign_only".to_string(),
            enabled: true,
            is_toml: false,
            is_marketplace: false,
            entity_types: String::new(),
            org_sourced_ids: String::new(),
            roles: String::new(),
            excluded_fields: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }
}

/// Row data for the delivery history table.
pub struct DeliveryRowView {
    pub event_id: String,
    pub status: String,
    pub status_class: String,
    pub http_status: String,
    pub attempt_count: i32,
    pub next_retry_at: String,
    pub created_at: String,
}

impl DeliveryRowView {
    fn from_model(delivery: &WebhookDelivery) -> Self {
        Self {
            event_id: delivery.event_id.clone(),
            status: delivery_status_label(&delivery.status).to_string(),
            status_class: delivery_status_class(&delivery.status).to_string(),
            http_status: delivery
                .http_status
                .map(|c| c.to_string())
                .unwrap_or_default(),
            attempt_count: delivery.attempt_count,
            next_retry_at: delivery
                .next_retry_at
                .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_default(),
            created_at: delivery
                .created_at
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        }
    }
}

/// Checkbox option for the entity-type multi-select on the form.
pub struct EntityTypeOption {
    pub value: &'static str,
    pub label: &'static str,
    pub checked: bool,
}

fn entity_type_options(selected: &[EntityType]) -> Vec<EntityTypeOption> {
    let all: &[(EntityType, &str, &str)] = &[
        (EntityType::Org, "org", "Org"),
        (
            EntityType::AcademicSession,
            "academic_session",
            "Academic Session",
        ),
        (EntityType::User, "user", "User"),
        (EntityType::Course, "course", "Course"),
        (EntityType::Class, "class", "Class"),
        (EntityType::Enrollment, "enrollment", "Enrollment"),
        (EntityType::Demographics, "demographics", "Demographics"),
    ];
    all.iter()
        .map(|(et, value, label)| EntityTypeOption {
            value,
            label,
            checked: selected.contains(et),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "webhooks/list.html")]
pub struct WebhooksListTemplate {
    pub active_page: &'static str,
    pub endpoints: Vec<WebhookRowView>,
    pub csrf_token: String,
}

#[derive(Template)]
#[template(path = "webhooks/form.html")]
pub struct WebhookFormTemplate {
    pub active_page: &'static str,
    pub is_edit: bool,
    pub endpoint: WebhookEndpointView,
    pub entity_type_options: Vec<EntityTypeOption>,
    pub new_secret: String,
    pub csrf_token: String,
}

#[derive(Template)]
#[template(path = "webhooks/detail.html")]
pub struct WebhookDetailTemplate {
    pub active_page: &'static str,
    pub endpoint: WebhookEndpointView,
    pub deliveries: Vec<DeliveryRowView>,
    pub test_message: String,
    pub csrf_token: String,
}

// ---------------------------------------------------------------------------
// Form payload
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct WebhookForm {
    pub name: String,
    pub url: String,
    pub security_mode: String,
    pub mode: String,
    #[serde(default)]
    pub entity_types: Vec<String>,
    #[serde(default)]
    pub org_sourced_ids: String,
    #[serde(default)]
    pub roles: String,
    #[serde(default)]
    pub excluded_fields: String,
    #[serde(default)]
    pub enabled: String,
    #[serde(default)]
    pub regenerate_secret: String,
    #[serde(default)]
    pub csrf_token: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /webhooks`
pub async fn webhooks_list(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> WebhooksListTemplate {
    let endpoints = state.repo.list_webhook_endpoints().await.unwrap_or_default();
    let mut rows = Vec::with_capacity(endpoints.len());
    for endpoint in &endpoints {
        let deliveries = state
            .repo
            .list_deliveries_by_webhook(&endpoint.id, 1)
            .await
            .unwrap_or_default();
        rows.push(WebhookRowView::from_model(endpoint, deliveries.first()));
    }
    WebhooksListTemplate {
        active_page: "webhooks",
        endpoints: rows,
        csrf_token: csrf.0,
    }
}

/// `GET /webhooks/new`
pub async fn webhooks_new_form(
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> WebhookFormTemplate {
    WebhookFormTemplate {
        active_page: "webhooks",
        is_edit: false,
        endpoint: WebhookEndpointView::empty(),
        entity_type_options: entity_type_options(&[]),
        new_secret: String::new(),
        csrf_token: csrf.0,
    }
}

/// `POST /webhooks/new`
pub async fn webhooks_create(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<WebhookForm>,
) -> Redirect {
    let secret = HmacSecret::generate();
    let now = chrono::Utc::now();
    let endpoint = WebhookEndpoint {
        id: uuid::Uuid::new_v4().to_string(),
        name: form.name,
        url: form.url,
        secret: secret.into_string(),
        enabled: form.enabled == "true",
        mode: parse_mode(&form.mode),
        security_mode: parse_security_mode(&form.security_mode),
        source: WebhookSource::Database,
        tenant_id: None,
        scoping: parse_scoping(&form),
        created_at: now,
        updated_at: now,
    };

    let id = endpoint.id.clone();
    if let Err(e) = state.repo.upsert_webhook_endpoint(&endpoint).await {
        tracing::error!("Failed to create webhook endpoint: {e}");
        return Redirect::to("/webhooks");
    }
    let _ = state
        .repo
        .log_admin_action(
            "webhook_created",
            Some(&format!("id={id} name={} url={}", endpoint.name, endpoint.url)),
            None,
        )
        .await;

    // Land on the detail page; the secret was just persisted but is not shown
    // again. (Operators that want to reveal it must regenerate via the edit
    // form.)
    Redirect::to(&format!("/webhooks/{id}"))
}

/// `GET /webhooks/:id`
pub async fn webhooks_detail(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Path(id): Path<String>,
) -> axum::response::Result<WebhookDetailTemplate, Html<String>> {
    let endpoint = match state.repo.get_webhook_endpoint(&id).await {
        Ok(Some(e)) => e,
        _ => {
            return Err(Html(
                "<h1>Webhook not found</h1><a href=\"/webhooks\">Back to Webhooks</a>".to_string(),
            ))
        }
    };
    let deliveries = state
        .repo
        .list_deliveries_by_webhook(&id, DELIVERY_HISTORY_LIMIT)
        .await
        .unwrap_or_default();
    let delivery_rows = deliveries.iter().map(DeliveryRowView::from_model).collect();
    Ok(WebhookDetailTemplate {
        active_page: "webhooks",
        endpoint: WebhookEndpointView::from_model(&endpoint),
        deliveries: delivery_rows,
        test_message: String::new(),
        csrf_token: csrf.0,
    })
}

/// `GET /webhooks/:id/edit`
pub async fn webhooks_edit_form(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Path(id): Path<String>,
) -> axum::response::Result<WebhookFormTemplate, Redirect> {
    match state.repo.get_webhook_endpoint(&id).await {
        Ok(Some(endpoint)) => {
            if endpoint.source == WebhookSource::Toml {
                return Err(Redirect::to(&format!("/webhooks/{id}")));
            }
            Ok(WebhookFormTemplate {
                active_page: "webhooks",
                is_edit: true,
                entity_type_options: entity_type_options(&endpoint.scoping.entity_types),
                endpoint: WebhookEndpointView::from_model(&endpoint),
                new_secret: String::new(),
                csrf_token: csrf.0,
            })
        }
        _ => Err(Redirect::to("/webhooks")),
    }
}

/// `POST /webhooks/:id/edit`
pub async fn webhooks_update(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<WebhookForm>,
) -> axum::response::Result<Redirect, Html<String>> {
    let existing = match state.repo.get_webhook_endpoint(&id).await {
        Ok(Some(e)) => e,
        _ => {
            return Err(Html(
                "<h1>Webhook not found</h1><a href=\"/webhooks\">Back</a>".to_string(),
            ))
        }
    };

    if existing.source == WebhookSource::Toml {
        return Err(Html(
            "<h1>Cannot edit TOML-managed webhook</h1><a href=\"/webhooks\">Back</a>".to_string(),
        ));
    }

    let secret = if form.regenerate_secret == "true" {
        HmacSecret::generate().into_string()
    } else {
        existing.secret.clone()
    };

    let updated = WebhookEndpoint {
        id: existing.id.clone(),
        name: form.name.clone(),
        url: form.url.clone(),
        secret,
        enabled: form.enabled == "true",
        mode: parse_mode(&form.mode),
        security_mode: parse_security_mode(&form.security_mode),
        source: existing.source.clone(),
        tenant_id: existing.tenant_id.clone(),
        scoping: parse_scoping(&form),
        created_at: existing.created_at,
        updated_at: chrono::Utc::now(),
    };

    if let Err(e) = state.repo.upsert_webhook_endpoint(&updated).await {
        tracing::error!("Failed to update webhook endpoint: {e}");
        return Err(Html(
            "<h1>Failed to save webhook</h1><a href=\"/webhooks\">Back</a>".to_string(),
        ));
    }
    let detail = if form.regenerate_secret == "true" {
        format!("id={} secret_regenerated=true", updated.id)
    } else {
        format!("id={}", updated.id)
    };
    let _ = state
        .repo
        .log_admin_action("webhook_updated", Some(&detail), None)
        .await;

    Ok(Redirect::to(&format!("/webhooks/{}", existing.id)))
}

/// `POST /webhooks/:id/delete`
pub async fn webhooks_delete(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Result<Redirect, (axum::http::StatusCode, &'static str)> {
    let existing = match state.repo.get_webhook_endpoint(&id).await {
        Ok(Some(e)) => e,
        Ok(None) => return Err((axum::http::StatusCode::NOT_FOUND, "not found")),
        Err(e) => {
            tracing::error!("Failed to load webhook for delete: {e}");
            return Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, "db error"));
        }
    };

    if existing.source != WebhookSource::Database {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            "non-database webhook endpoints cannot be deleted via the admin UI",
        ));
    }

    match state.repo.delete_webhook_endpoint(&id).await {
        Ok(_) => {
            let _ = state
                .repo
                .log_admin_action(
                    "webhook_deleted",
                    Some(&format!("id={id} name={}", existing.name)),
                    None,
                )
                .await;
            Ok(Redirect::to("/webhooks"))
        }
        Err(e) => {
            tracing::error!("Failed to delete webhook endpoint: {e}");
            Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, "db error"))
        }
    }
}

/// `POST /webhooks/:id/test` — fire a synthetic ping event through the
/// delivery engine so the operator can verify their receiver is reachable.
pub async fn webhooks_test(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Redirect {
    let endpoint = match state.repo.get_webhook_endpoint(&id).await {
        Ok(Some(e)) => e,
        _ => return Redirect::to("/webhooks"),
    };

    let event = WebhookEvent {
        webhook_id: endpoint.id.clone(),
        event_id: format!("ping-{}", uuid::Uuid::new_v4()),
        event_type: "ping".to_string(),
        timestamp: chrono::Utc::now(),
        tenant_id: endpoint.tenant_id.clone(),
        sync_run_id: 0,
        data: WebhookEventData::Batch { changes: vec![] },
    };

    let engine = chalk_core::webhooks::delivery::WebhookDeliveryEngine::new();
    if let Err(e) = engine.deliver(&endpoint, &event, state.repo.as_ref()).await {
        tracing::warn!("Test webhook delivery error: {e}");
    }

    Redirect::to(&format!("/webhooks/{id}"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn truncate_url(url: &str, max: usize) -> String {
    if url.len() <= max {
        return url.to_string();
    }
    let mut s: String = url.chars().take(max.saturating_sub(1)).collect();
    s.push('…');
    s
}

fn parse_mode(s: &str) -> WebhookMode {
    match s {
        "per_entity" => WebhookMode::PerEntity,
        _ => WebhookMode::Batched,
    }
}

fn parse_security_mode(s: &str) -> WebhookSecurityMode {
    match s {
        "encrypted" => WebhookSecurityMode::Encrypted,
        _ => WebhookSecurityMode::SignOnly,
    }
}

fn parse_entity_type(s: &str) -> Option<EntityType> {
    match s {
        "org" => Some(EntityType::Org),
        "academic_session" => Some(EntityType::AcademicSession),
        "user" => Some(EntityType::User),
        "course" => Some(EntityType::Course),
        "class" => Some(EntityType::Class),
        "enrollment" => Some(EntityType::Enrollment),
        "demographics" => Some(EntityType::Demographics),
        _ => None,
    }
}

fn parse_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

fn parse_scoping(form: &WebhookForm) -> WebhookScoping {
    WebhookScoping {
        entity_types: form
            .entity_types
            .iter()
            .filter_map(|s| parse_entity_type(s))
            .collect(),
        org_sourced_ids: parse_csv(&form.org_sourced_ids),
        roles: parse_csv(&form.roles),
        excluded_fields: parse_csv(&form.excluded_fields),
    }
}

fn entity_type_label(et: &EntityType) -> &'static str {
    match et {
        EntityType::Org => "org",
        EntityType::AcademicSession => "academic_session",
        EntityType::User => "user",
        EntityType::Course => "course",
        EntityType::Class => "class",
        EntityType::Enrollment => "enrollment",
        EntityType::Demographics => "demographics",
    }
}

fn format_entity_types(types: &[EntityType]) -> String {
    if types.is_empty() {
        "All".to_string()
    } else {
        types
            .iter()
            .map(entity_type_label)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn mode_to_str(m: &WebhookMode) -> &'static str {
    match m {
        WebhookMode::Batched => "batched",
        WebhookMode::PerEntity => "per_entity",
    }
}

fn security_mode_to_str(m: &WebhookSecurityMode) -> &'static str {
    match m {
        WebhookSecurityMode::SignOnly => "sign_only",
        WebhookSecurityMode::Encrypted => "encrypted",
    }
}

fn delivery_status_label(s: &DeliveryStatus) -> &'static str {
    match s {
        DeliveryStatus::Pending => "Pending",
        DeliveryStatus::Delivered => "Delivered",
        DeliveryStatus::Failed => "Failed",
        DeliveryStatus::Retrying => "Retrying",
    }
}

fn delivery_status_class(s: &DeliveryStatus) -> &'static str {
    match s {
        DeliveryStatus::Pending => "pending",
        DeliveryStatus::Delivered => "completed",
        DeliveryStatus::Failed => "failed",
        DeliveryStatus::Retrying => "running",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_secret_is_32_bytes_64_hex_chars() {
        let secret = HmacSecret::generate();
        assert_eq!(secret.as_str().len(), 64);
        assert!(secret.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hmac_secret_is_unique_per_call() {
        let a = HmacSecret::generate();
        let b = HmacSecret::generate();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn hmac_secret_debug_does_not_leak_value() {
        let secret = HmacSecret::generate();
        let dbg = format!("{secret:?}");
        assert!(!dbg.contains(secret.as_str()));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn truncate_url_short_unchanged() {
        assert_eq!(truncate_url("https://x.example", 32), "https://x.example");
    }

    #[test]
    fn truncate_url_long_truncated() {
        let long = "https://example.com/this/is/quite/a/long/webhook/receiver/path";
        let t = truncate_url(long, 20);
        assert_eq!(t.chars().count(), 20);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn parse_mode_round_trip() {
        assert_eq!(parse_mode("batched"), WebhookMode::Batched);
        assert_eq!(parse_mode("per_entity"), WebhookMode::PerEntity);
        assert_eq!(parse_mode("garbage"), WebhookMode::Batched);
    }

    #[test]
    fn parse_security_mode_round_trip() {
        assert_eq!(
            parse_security_mode("sign_only"),
            WebhookSecurityMode::SignOnly
        );
        assert_eq!(
            parse_security_mode("encrypted"),
            WebhookSecurityMode::Encrypted
        );
        assert_eq!(
            parse_security_mode("garbage"),
            WebhookSecurityMode::SignOnly
        );
    }

    #[test]
    fn parse_csv_trims_and_filters_empty() {
        let v = parse_csv(" a , b ,, c ");
        assert_eq!(v, vec!["a", "b", "c"]);
    }

    #[test]
    fn parse_entity_type_covers_all_variants() {
        for v in [
            "org",
            "academic_session",
            "user",
            "course",
            "class",
            "enrollment",
            "demographics",
        ] {
            assert!(parse_entity_type(v).is_some(), "missing variant: {v}");
        }
        assert!(parse_entity_type("nope").is_none());
    }

    #[test]
    fn format_entity_types_handles_empty_and_some() {
        assert_eq!(format_entity_types(&[]), "All");
        assert_eq!(
            format_entity_types(&[EntityType::User, EntityType::Enrollment]),
            "user, enrollment"
        );
    }

    #[test]
    fn entity_type_options_marks_selected() {
        let opts = entity_type_options(&[EntityType::User]);
        let user = opts.iter().find(|o| o.value == "user").unwrap();
        assert!(user.checked);
        let org = opts.iter().find(|o| o.value == "org").unwrap();
        assert!(!org.checked);
    }

    #[test]
    fn delivery_status_label_and_class() {
        assert_eq!(delivery_status_label(&DeliveryStatus::Delivered), "Delivered");
        assert_eq!(delivery_status_class(&DeliveryStatus::Delivered), "completed");
        assert_eq!(delivery_status_class(&DeliveryStatus::Retrying), "running");
        assert_eq!(delivery_status_class(&DeliveryStatus::Failed), "failed");
        assert_eq!(delivery_status_class(&DeliveryStatus::Pending), "pending");
    }
}
