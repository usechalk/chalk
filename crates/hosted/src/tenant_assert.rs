//! Defense-in-depth schema assertion wrapper for `ChalkRepository`.
//!
//! The hosted runtime opens a per-tenant Postgres pool with `search_path`
//! pinned to a tenant schema. To catch a class of bugs where a request
//! handler accidentally uses the wrong tenant's `Arc<dyn ChalkRepository>`
//! (e.g. a stale clone smuggled across requests), every call into the
//! repository validates the request-scoped `CURRENT_TENANT_SCHEMA`
//! task-local against the schema the pool was opened with.
//!
//! Outside any task-local scope (e.g. CLI subcommands, scheduler bootstrap),
//! the assertion is a no-op so out-of-band tooling continues to work.
//!
//! Implementation note: the wrapper delegates ~115 methods across 28
//! sub-traits. We attempted to compress this with a `macro_rules!`-based
//! delegator, but `#[async_trait]`'s lifetime synthesis does not survive
//! `:ty`-based macro expansion (E0195 on every method). Hand-rolled
//! delegators avoid that and keep the file mechanical.

use std::sync::Arc;

use async_trait::async_trait;
use chalk_core::db::repository::{
    AcademicSessionRepository, AccessTokenRepository, AdSyncRunRepository, AdSyncStateRepository,
    AdminAuditRepository, AdminSessionRepository, ApiTokenRepository, ChalkRepository,
    ClassRepository, ConfigRepository, CourseRepository, DemographicsRepository,
    EnrollmentRepository, ExternalIdRepository, GoogleSyncRunRepository, GoogleSyncStateRepository,
    IdpAuthLogRepository, IdpSessionRepository, OidcCodeRepository, OrgRepository,
    PasswordRepository, PasswordResetTokenRepository, PicturePasswordRepository,
    PortalSessionRepository, QrBadgeRepository, SsoPartnerRepository, SyncRepository,
    UserRepository, WebhookDeliveryRepository, WebhookEndpointRepository,
};
use chalk_core::error::{ChalkError, Result};
use chalk_core::models::{
    academic_session::AcademicSession,
    access_token::AccessToken,
    ad_sync::{AdSyncRun, AdSyncRunStatus, AdSyncUserState},
    audit::{AdminAuditEntry, AdminSession},
    class::Class,
    course::Course,
    demographics::Demographics,
    enrollment::Enrollment,
    google_sync::{GoogleSyncRun, GoogleSyncRunStatus, GoogleSyncUserState},
    idp::{AuthLogEntry, IdpSession, PicturePassword, QrBadge},
    org::Org,
    sso::{OidcAuthorizationCode, PortalSession, SsoPartner},
    sync::{SyncRun, SyncStatus, UserCounts, UserFilter},
    user::User,
};
use chalk_core::webhooks::models::{DeliveryStatus, WebhookDelivery, WebhookEndpoint};
use chrono::{DateTime, Utc};

tokio::task_local! {
    /// Schema name of the tenant whose request is currently in flight on
    /// this task. Set by `resolve_tenant` middleware and by the multi-tenant
    /// scheduler before invoking sync engines.
    pub static CURRENT_TENANT_SCHEMA: String;
}

/// `Arc<dyn ChalkRepository>` wrapper that asserts the in-flight tenant
/// schema matches the schema the wrapped repository was opened with.
pub struct TenantScopedRepository {
    inner: Arc<dyn ChalkRepository>,
    expected_schema: String,
}

impl TenantScopedRepository {
    pub fn new(inner: Arc<dyn ChalkRepository>, expected_schema: String) -> Self {
        Self {
            inner,
            expected_schema,
        }
    }

    pub fn expected_schema(&self) -> &str {
        &self.expected_schema
    }

    fn assert_schema(&self) -> Result<()> {
        // Compare inside the closure to avoid allocating a `String` on the hot
        // path. Only on mismatch (rare) do we clone the actual schema for the
        // error message.
        let outcome = CURRENT_TENANT_SCHEMA.try_with(|s| {
            if s == &self.expected_schema {
                Ok(())
            } else {
                Err(s.clone())
            }
        });
        match outcome {
            Ok(Ok(())) => Ok(()),
            Ok(Err(other)) => {
                tracing::error!(
                    expected = %self.expected_schema,
                    actual = %other,
                    "tenant schema mismatch on repository call"
                );
                Err(ChalkError::Auth(format!(
                    "tenant schema mismatch: ctx={other}, expected={}",
                    self.expected_schema
                )))
            }
            // Outside any task-local scope (CLI / scheduler bootstrap) — no-op.
            Err(_) => Ok(()),
        }
    }
}

#[async_trait]
impl OrgRepository for TenantScopedRepository {
    async fn upsert_org(&self, org: &Org) -> Result<()> {
        self.assert_schema()?;
        self.inner.upsert_org(org).await
    }
    async fn get_org(&self, sourced_id: &str) -> Result<Option<Org>> {
        self.assert_schema()?;
        self.inner.get_org(sourced_id).await
    }
    async fn list_orgs(&self) -> Result<Vec<Org>> {
        self.assert_schema()?;
        self.inner.list_orgs().await
    }
    async fn delete_org(&self, sourced_id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_org(sourced_id).await
    }
}

#[async_trait]
impl AcademicSessionRepository for TenantScopedRepository {
    async fn upsert_academic_session(&self, session: &AcademicSession) -> Result<()> {
        self.assert_schema()?;
        self.inner.upsert_academic_session(session).await
    }
    async fn get_academic_session(&self, sourced_id: &str) -> Result<Option<AcademicSession>> {
        self.assert_schema()?;
        self.inner.get_academic_session(sourced_id).await
    }
    async fn list_academic_sessions(&self) -> Result<Vec<AcademicSession>> {
        self.assert_schema()?;
        self.inner.list_academic_sessions().await
    }
    async fn delete_academic_session(&self, sourced_id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_academic_session(sourced_id).await
    }
}

#[async_trait]
impl UserRepository for TenantScopedRepository {
    async fn upsert_user(&self, user: &User) -> Result<()> {
        self.assert_schema()?;
        self.inner.upsert_user(user).await
    }
    async fn get_user(&self, sourced_id: &str) -> Result<Option<User>> {
        self.assert_schema()?;
        self.inner.get_user(sourced_id).await
    }
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        self.assert_schema()?;
        self.inner.get_user_by_username(username).await
    }
    async fn list_users(&self, filter: &UserFilter) -> Result<Vec<User>> {
        self.assert_schema()?;
        self.inner.list_users(filter).await
    }
    async fn delete_user(&self, sourced_id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_user(sourced_id).await
    }
    async fn get_user_counts(&self) -> Result<UserCounts> {
        self.assert_schema()?;
        self.inner.get_user_counts().await
    }
}

#[async_trait]
impl CourseRepository for TenantScopedRepository {
    async fn upsert_course(&self, course: &Course) -> Result<()> {
        self.assert_schema()?;
        self.inner.upsert_course(course).await
    }
    async fn get_course(&self, sourced_id: &str) -> Result<Option<Course>> {
        self.assert_schema()?;
        self.inner.get_course(sourced_id).await
    }
    async fn list_courses(&self) -> Result<Vec<Course>> {
        self.assert_schema()?;
        self.inner.list_courses().await
    }
    async fn delete_course(&self, sourced_id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_course(sourced_id).await
    }
}

#[async_trait]
impl ClassRepository for TenantScopedRepository {
    async fn upsert_class(&self, class: &Class) -> Result<()> {
        self.assert_schema()?;
        self.inner.upsert_class(class).await
    }
    async fn get_class(&self, sourced_id: &str) -> Result<Option<Class>> {
        self.assert_schema()?;
        self.inner.get_class(sourced_id).await
    }
    async fn list_classes(&self) -> Result<Vec<Class>> {
        self.assert_schema()?;
        self.inner.list_classes().await
    }
    async fn delete_class(&self, sourced_id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_class(sourced_id).await
    }
}

#[async_trait]
impl EnrollmentRepository for TenantScopedRepository {
    async fn upsert_enrollment(&self, enrollment: &Enrollment) -> Result<()> {
        self.assert_schema()?;
        self.inner.upsert_enrollment(enrollment).await
    }
    async fn get_enrollment(&self, sourced_id: &str) -> Result<Option<Enrollment>> {
        self.assert_schema()?;
        self.inner.get_enrollment(sourced_id).await
    }
    async fn list_enrollments(&self) -> Result<Vec<Enrollment>> {
        self.assert_schema()?;
        self.inner.list_enrollments().await
    }
    async fn list_enrollments_for_user(&self, user_sourced_id: &str) -> Result<Vec<Enrollment>> {
        self.assert_schema()?;
        self.inner.list_enrollments_for_user(user_sourced_id).await
    }
    async fn list_enrollments_for_class(&self, class_sourced_id: &str) -> Result<Vec<Enrollment>> {
        self.assert_schema()?;
        self.inner
            .list_enrollments_for_class(class_sourced_id)
            .await
    }
    async fn delete_enrollment(&self, sourced_id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_enrollment(sourced_id).await
    }
}

#[async_trait]
impl DemographicsRepository for TenantScopedRepository {
    async fn upsert_demographics(&self, demographics: &Demographics) -> Result<()> {
        self.assert_schema()?;
        self.inner.upsert_demographics(demographics).await
    }
    async fn get_demographics(&self, sourced_id: &str) -> Result<Option<Demographics>> {
        self.assert_schema()?;
        self.inner.get_demographics(sourced_id).await
    }
    async fn list_demographics(&self) -> Result<Vec<Demographics>> {
        self.assert_schema()?;
        self.inner.list_demographics().await
    }
    async fn delete_demographics(&self, sourced_id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_demographics(sourced_id).await
    }
}

#[async_trait]
impl SyncRepository for TenantScopedRepository {
    async fn create_sync_run(&self, provider: &str) -> Result<SyncRun> {
        self.assert_schema()?;
        self.inner.create_sync_run(provider).await
    }
    async fn update_sync_status(
        &self,
        id: i64,
        status: SyncStatus,
        error_message: Option<&str>,
    ) -> Result<()> {
        self.assert_schema()?;
        self.inner
            .update_sync_status(id, status, error_message)
            .await
    }
    async fn update_sync_counts(
        &self,
        id: i64,
        users: i64,
        orgs: i64,
        courses: i64,
        classes: i64,
        enrollments: i64,
    ) -> Result<()> {
        self.assert_schema()?;
        self.inner
            .update_sync_counts(id, users, orgs, courses, classes, enrollments)
            .await
    }
    async fn get_sync_run(&self, id: i64) -> Result<Option<SyncRun>> {
        self.assert_schema()?;
        self.inner.get_sync_run(id).await
    }
    async fn get_latest_sync_run(&self, provider: &str) -> Result<Option<SyncRun>> {
        self.assert_schema()?;
        self.inner.get_latest_sync_run(provider).await
    }
}

#[async_trait]
impl IdpSessionRepository for TenantScopedRepository {
    async fn create_session(&self, session: &IdpSession) -> Result<()> {
        self.assert_schema()?;
        self.inner.create_session(session).await
    }
    async fn get_session(&self, id: &str) -> Result<Option<IdpSession>> {
        self.assert_schema()?;
        self.inner.get_session(id).await
    }
    async fn delete_session(&self, id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_session(id).await
    }
    async fn delete_expired_sessions(&self) -> Result<u64> {
        self.assert_schema()?;
        self.inner.delete_expired_sessions().await
    }
    async fn list_sessions_for_user(&self, user_sourced_id: &str) -> Result<Vec<IdpSession>> {
        self.assert_schema()?;
        self.inner.list_sessions_for_user(user_sourced_id).await
    }
}

#[async_trait]
impl QrBadgeRepository for TenantScopedRepository {
    async fn create_badge(&self, badge: &QrBadge) -> Result<i64> {
        self.assert_schema()?;
        self.inner.create_badge(badge).await
    }
    async fn get_badge_by_token(&self, token: &str) -> Result<Option<QrBadge>> {
        self.assert_schema()?;
        self.inner.get_badge_by_token(token).await
    }
    async fn list_badges_for_user(&self, user_sourced_id: &str) -> Result<Vec<QrBadge>> {
        self.assert_schema()?;
        self.inner.list_badges_for_user(user_sourced_id).await
    }
    async fn revoke_badge(&self, id: i64) -> Result<bool> {
        self.assert_schema()?;
        self.inner.revoke_badge(id).await
    }
}

#[async_trait]
impl PicturePasswordRepository for TenantScopedRepository {
    async fn upsert_picture_password(&self, pp: &PicturePassword) -> Result<()> {
        self.assert_schema()?;
        self.inner.upsert_picture_password(pp).await
    }
    async fn get_picture_password(&self, user_sourced_id: &str) -> Result<Option<PicturePassword>> {
        self.assert_schema()?;
        self.inner.get_picture_password(user_sourced_id).await
    }
    async fn delete_picture_password(&self, user_sourced_id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_picture_password(user_sourced_id).await
    }
}

#[async_trait]
impl IdpAuthLogRepository for TenantScopedRepository {
    async fn log_auth_attempt(&self, entry: &AuthLogEntry) -> Result<i64> {
        self.assert_schema()?;
        self.inner.log_auth_attempt(entry).await
    }
    async fn list_auth_log(&self, limit: i64) -> Result<Vec<AuthLogEntry>> {
        self.assert_schema()?;
        self.inner.list_auth_log(limit).await
    }
    async fn list_auth_log_for_user(
        &self,
        user_sourced_id: &str,
        limit: i64,
    ) -> Result<Vec<AuthLogEntry>> {
        self.assert_schema()?;
        self.inner
            .list_auth_log_for_user(user_sourced_id, limit)
            .await
    }
}

#[async_trait]
impl GoogleSyncStateRepository for TenantScopedRepository {
    async fn upsert_sync_state(&self, state: &GoogleSyncUserState) -> Result<()> {
        self.assert_schema()?;
        self.inner.upsert_sync_state(state).await
    }
    async fn get_sync_state(&self, user_sourced_id: &str) -> Result<Option<GoogleSyncUserState>> {
        self.assert_schema()?;
        self.inner.get_sync_state(user_sourced_id).await
    }
    async fn list_sync_states(&self) -> Result<Vec<GoogleSyncUserState>> {
        self.assert_schema()?;
        self.inner.list_sync_states().await
    }
    async fn delete_sync_state(&self, user_sourced_id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_sync_state(user_sourced_id).await
    }
}

#[async_trait]
impl GoogleSyncRunRepository for TenantScopedRepository {
    async fn create_google_sync_run(&self, dry_run: bool) -> Result<GoogleSyncRun> {
        self.assert_schema()?;
        self.inner.create_google_sync_run(dry_run).await
    }
    async fn update_google_sync_run(
        &self,
        id: i64,
        status: GoogleSyncRunStatus,
        users_created: i64,
        users_updated: i64,
        users_suspended: i64,
        ous_created: i64,
        error_message: Option<&str>,
    ) -> Result<()> {
        self.assert_schema()?;
        self.inner
            .update_google_sync_run(
                id,
                status,
                users_created,
                users_updated,
                users_suspended,
                ous_created,
                error_message,
            )
            .await
    }
    async fn get_google_sync_run(&self, id: i64) -> Result<Option<GoogleSyncRun>> {
        self.assert_schema()?;
        self.inner.get_google_sync_run(id).await
    }
    async fn get_latest_google_sync_run(&self) -> Result<Option<GoogleSyncRun>> {
        self.assert_schema()?;
        self.inner.get_latest_google_sync_run().await
    }
    async fn list_google_sync_runs(&self, limit: i64) -> Result<Vec<GoogleSyncRun>> {
        self.assert_schema()?;
        self.inner.list_google_sync_runs(limit).await
    }
}

#[async_trait]
impl AdSyncStateRepository for TenantScopedRepository {
    async fn upsert_ad_sync_state(&self, state: &AdSyncUserState) -> Result<()> {
        self.assert_schema()?;
        self.inner.upsert_ad_sync_state(state).await
    }
    async fn get_ad_sync_state(&self, user_sourced_id: &str) -> Result<Option<AdSyncUserState>> {
        self.assert_schema()?;
        self.inner.get_ad_sync_state(user_sourced_id).await
    }
    async fn list_ad_sync_states(&self) -> Result<Vec<AdSyncUserState>> {
        self.assert_schema()?;
        self.inner.list_ad_sync_states().await
    }
    async fn delete_ad_sync_state(&self, user_sourced_id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_ad_sync_state(user_sourced_id).await
    }
}

#[async_trait]
impl AdSyncRunRepository for TenantScopedRepository {
    async fn create_ad_sync_run(&self, dry_run: bool) -> Result<AdSyncRun> {
        self.assert_schema()?;
        self.inner.create_ad_sync_run(dry_run).await
    }
    async fn update_ad_sync_run(
        &self,
        id: &str,
        status: AdSyncRunStatus,
        users_created: i64,
        users_updated: i64,
        users_disabled: i64,
        users_skipped: i64,
        groups_created: i64,
        groups_updated: i64,
        errors: i64,
        error_details: Option<&str>,
    ) -> Result<()> {
        self.assert_schema()?;
        self.inner
            .update_ad_sync_run(
                id,
                status,
                users_created,
                users_updated,
                users_disabled,
                users_skipped,
                groups_created,
                groups_updated,
                errors,
                error_details,
            )
            .await
    }
    async fn get_ad_sync_run(&self, id: &str) -> Result<Option<AdSyncRun>> {
        self.assert_schema()?;
        self.inner.get_ad_sync_run(id).await
    }
    async fn get_latest_ad_sync_run(&self) -> Result<Option<AdSyncRun>> {
        self.assert_schema()?;
        self.inner.get_latest_ad_sync_run().await
    }
    async fn list_ad_sync_runs(&self, limit: i64) -> Result<Vec<AdSyncRun>> {
        self.assert_schema()?;
        self.inner.list_ad_sync_runs(limit).await
    }
}

#[async_trait]
impl ExternalIdRepository for TenantScopedRepository {
    async fn get_external_ids(
        &self,
        user_sourced_id: &str,
    ) -> Result<serde_json::Map<String, serde_json::Value>> {
        self.assert_schema()?;
        self.inner.get_external_ids(user_sourced_id).await
    }
    async fn set_external_ids(
        &self,
        user_sourced_id: &str,
        ids: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<()> {
        self.assert_schema()?;
        self.inner.set_external_ids(user_sourced_id, ids).await
    }
    async fn find_user_by_external_id(
        &self,
        provider: &str,
        external_id: &str,
    ) -> Result<Option<User>> {
        self.assert_schema()?;
        self.inner
            .find_user_by_external_id(provider, external_id)
            .await
    }
}

#[async_trait]
impl PasswordRepository for TenantScopedRepository {
    async fn get_password_hash(&self, user_sourced_id: &str) -> Result<Option<String>> {
        self.assert_schema()?;
        self.inner.get_password_hash(user_sourced_id).await
    }
    async fn set_password_hash(&self, user_sourced_id: &str, hash: &str) -> Result<()> {
        self.assert_schema()?;
        self.inner.set_password_hash(user_sourced_id, hash).await
    }
}

#[async_trait]
impl AdminSessionRepository for TenantScopedRepository {
    async fn create_admin_session(&self, session: &AdminSession) -> Result<()> {
        self.assert_schema()?;
        self.inner.create_admin_session(session).await
    }
    async fn get_admin_session(&self, token: &str) -> Result<Option<AdminSession>> {
        self.assert_schema()?;
        self.inner.get_admin_session(token).await
    }
    async fn delete_admin_session(&self, token: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_admin_session(token).await
    }
    async fn delete_expired_admin_sessions(&self) -> Result<u64> {
        self.assert_schema()?;
        self.inner.delete_expired_admin_sessions().await
    }
}

#[async_trait]
impl AdminAuditRepository for TenantScopedRepository {
    async fn log_admin_action(
        &self,
        action: &str,
        details: Option<&str>,
        admin_ip: Option<&str>,
    ) -> Result<i64> {
        self.assert_schema()?;
        self.inner.log_admin_action(action, details, admin_ip).await
    }
    async fn list_admin_audit_log(&self, limit: i64) -> Result<Vec<AdminAuditEntry>> {
        self.assert_schema()?;
        self.inner.list_admin_audit_log(limit).await
    }
    async fn prune_admin_audit_log(
        &self,
        older_than: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64> {
        self.assert_schema()?;
        self.inner.prune_admin_audit_log(older_than).await
    }
}

#[async_trait]
impl ConfigRepository for TenantScopedRepository {
    async fn get_config_override(&self, key: &str) -> Result<Option<String>> {
        self.assert_schema()?;
        self.inner.get_config_override(key).await
    }
    async fn set_config_override(&self, key: &str, value: &str) -> Result<()> {
        self.assert_schema()?;
        self.inner.set_config_override(key, value).await
    }
}

#[async_trait]
impl WebhookEndpointRepository for TenantScopedRepository {
    async fn upsert_webhook_endpoint(&self, endpoint: &WebhookEndpoint) -> Result<()> {
        self.assert_schema()?;
        self.inner.upsert_webhook_endpoint(endpoint).await
    }
    async fn get_webhook_endpoint(&self, id: &str) -> Result<Option<WebhookEndpoint>> {
        self.assert_schema()?;
        self.inner.get_webhook_endpoint(id).await
    }
    async fn list_webhook_endpoints(&self) -> Result<Vec<WebhookEndpoint>> {
        self.assert_schema()?;
        self.inner.list_webhook_endpoints().await
    }
    async fn list_webhook_endpoints_by_source(&self, source: &str) -> Result<Vec<WebhookEndpoint>> {
        self.assert_schema()?;
        self.inner.list_webhook_endpoints_by_source(source).await
    }
    async fn delete_webhook_endpoint(&self, id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_webhook_endpoint(id).await
    }
}

#[async_trait]
impl WebhookDeliveryRepository for TenantScopedRepository {
    async fn create_webhook_delivery(&self, delivery: &WebhookDelivery) -> Result<i64> {
        self.assert_schema()?;
        self.inner.create_webhook_delivery(delivery).await
    }
    async fn update_delivery_status(
        &self,
        id: i64,
        status: DeliveryStatus,
        http_status: Option<i32>,
        response_body: Option<&str>,
    ) -> Result<()> {
        self.assert_schema()?;
        self.inner
            .update_delivery_status(id, status, http_status, response_body)
            .await
    }
    async fn list_pending_retries(&self, limit: i64) -> Result<Vec<WebhookDelivery>> {
        self.assert_schema()?;
        self.inner.list_pending_retries(limit).await
    }
    async fn list_deliveries_by_webhook(
        &self,
        webhook_endpoint_id: &str,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>> {
        self.assert_schema()?;
        self.inner
            .list_deliveries_by_webhook(webhook_endpoint_id, limit)
            .await
    }
    async fn list_deliveries_by_sync_run(&self, sync_run_id: i64) -> Result<Vec<WebhookDelivery>> {
        self.assert_schema()?;
        self.inner.list_deliveries_by_sync_run(sync_run_id).await
    }
}

#[async_trait]
impl SsoPartnerRepository for TenantScopedRepository {
    async fn upsert_sso_partner(&self, partner: &SsoPartner) -> Result<()> {
        self.assert_schema()?;
        self.inner.upsert_sso_partner(partner).await
    }
    async fn get_sso_partner(&self, id: &str) -> Result<Option<SsoPartner>> {
        self.assert_schema()?;
        self.inner.get_sso_partner(id).await
    }
    async fn get_sso_partner_by_entity_id(&self, entity_id: &str) -> Result<Option<SsoPartner>> {
        self.assert_schema()?;
        self.inner.get_sso_partner_by_entity_id(entity_id).await
    }
    async fn get_sso_partner_by_client_id(&self, client_id: &str) -> Result<Option<SsoPartner>> {
        self.assert_schema()?;
        self.inner.get_sso_partner_by_client_id(client_id).await
    }
    async fn list_sso_partners(&self) -> Result<Vec<SsoPartner>> {
        self.assert_schema()?;
        self.inner.list_sso_partners().await
    }
    async fn list_sso_partners_for_role(&self, role: &str) -> Result<Vec<SsoPartner>> {
        self.assert_schema()?;
        self.inner.list_sso_partners_for_role(role).await
    }
    async fn delete_sso_partner(&self, id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_sso_partner(id).await
    }
}

#[async_trait]
impl OidcCodeRepository for TenantScopedRepository {
    async fn create_oidc_code(&self, code: &OidcAuthorizationCode) -> Result<()> {
        self.assert_schema()?;
        self.inner.create_oidc_code(code).await
    }
    async fn get_oidc_code(&self, code: &str) -> Result<Option<OidcAuthorizationCode>> {
        self.assert_schema()?;
        self.inner.get_oidc_code(code).await
    }
    async fn delete_oidc_code(&self, code: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_oidc_code(code).await
    }
    async fn delete_expired_oidc_codes(&self) -> Result<u64> {
        self.assert_schema()?;
        self.inner.delete_expired_oidc_codes().await
    }
}

#[async_trait]
impl PortalSessionRepository for TenantScopedRepository {
    async fn create_portal_session(&self, session: &PortalSession) -> Result<()> {
        self.assert_schema()?;
        self.inner.create_portal_session(session).await
    }
    async fn get_portal_session(&self, id: &str) -> Result<Option<PortalSession>> {
        self.assert_schema()?;
        self.inner.get_portal_session(id).await
    }
    async fn delete_portal_session(&self, id: &str) -> Result<bool> {
        self.assert_schema()?;
        self.inner.delete_portal_session(id).await
    }
    async fn delete_expired_portal_sessions(&self) -> Result<u64> {
        self.assert_schema()?;
        self.inner.delete_expired_portal_sessions().await
    }
}

#[async_trait]
impl ApiTokenRepository for TenantScopedRepository {
    async fn create_api_token(
        &self,
        token: &chalk_core::models::api_token::ApiToken,
    ) -> Result<()> {
        self.assert_schema()?;
        self.inner.create_api_token(token).await
    }
    async fn list_api_tokens(&self) -> Result<Vec<chalk_core::models::api_token::ApiToken>> {
        self.assert_schema()?;
        self.inner.list_api_tokens().await
    }
    async fn find_active_api_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<chalk_core::models::api_token::ApiToken>> {
        self.assert_schema()?;
        self.inner.find_active_api_token_by_hash(token_hash).await
    }
    async fn touch_api_token(&self, id: &str) -> Result<()> {
        self.assert_schema()?;
        self.inner.touch_api_token(id).await
    }
    async fn revoke_api_token(&self, id: &str) -> Result<()> {
        self.assert_schema()?;
        self.inner.revoke_api_token(id).await
    }
}

#[async_trait]
impl AccessTokenRepository for TenantScopedRepository {
    async fn create_access_token(&self, token: &AccessToken) -> Result<()> {
        self.assert_schema()?;
        self.inner.create_access_token(token).await
    }
    async fn get_access_token(&self, token: &str) -> Result<Option<AccessToken>> {
        self.assert_schema()?;
        self.inner.get_access_token(token).await
    }
    async fn revoke_access_token(&self, token: &str) -> Result<()> {
        self.assert_schema()?;
        self.inner.revoke_access_token(token).await
    }
    async fn delete_expired_access_tokens(&self) -> Result<u64> {
        self.assert_schema()?;
        self.inner.delete_expired_access_tokens().await
    }
}

#[async_trait]
impl PasswordResetTokenRepository for TenantScopedRepository {
    async fn create_reset_token(
        &self,
        user_sourced_id: &str,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        self.assert_schema()?;
        self.inner
            .create_reset_token(user_sourced_id, token_hash, expires_at)
            .await
    }
    async fn consume_reset_token(&self, raw_token: &str) -> Result<Option<String>> {
        self.assert_schema()?;
        self.inner.consume_reset_token(raw_token).await
    }
    async fn delete_expired_reset_tokens(&self) -> Result<u64> {
        self.assert_schema()?;
        self.inner.delete_expired_reset_tokens().await
    }
}

impl ChalkRepository for TenantScopedRepository {}

#[cfg(test)]
mod tests {
    use super::*;
    use chalk_core::db::sqlite::SqliteRepository;
    use chalk_core::db::DatabasePool;

    async fn make_repo() -> Arc<dyn ChalkRepository> {
        let pool = DatabasePool::new_sqlite_memory().await.unwrap();
        match pool {
            DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
            DatabasePool::Postgres(_) => unreachable!(),
        }
    }

    #[tokio::test]
    async fn matching_schema_succeeds() {
        let inner = make_repo().await;
        let scoped = TenantScopedRepository::new(inner, "tenant_acme".to_string());
        let res = CURRENT_TENANT_SCHEMA
            .scope("tenant_acme".to_string(), async {
                scoped.list_orgs().await
            })
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn mismatched_schema_returns_err() {
        let inner = make_repo().await;
        let scoped = TenantScopedRepository::new(inner, "tenant_acme".to_string());
        let res = CURRENT_TENANT_SCHEMA
            .scope("tenant_other".to_string(), async {
                scoped.list_orgs().await
            })
            .await;
        let err = res.expect_err("expected schema mismatch error");
        let msg = err.to_string();
        assert!(msg.contains("tenant_other"), "msg = {msg}");
        assert!(msg.contains("tenant_acme"), "msg = {msg}");
    }

    #[tokio::test]
    async fn outside_scope_succeeds() {
        // No CURRENT_TENANT_SCHEMA scope wrapping — represents CLI / scheduler
        // bootstrap path. Should not error.
        let inner = make_repo().await;
        let scoped = TenantScopedRepository::new(inner, "tenant_acme".to_string());
        let res = scoped.list_orgs().await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn assertion_propagates_for_multiple_methods() {
        let inner = make_repo().await;
        let scoped = TenantScopedRepository::new(inner, "tenant_a".to_string());
        let res = CURRENT_TENANT_SCHEMA
            .scope("tenant_b".to_string(), async {
                let r1 = scoped.list_users(&UserFilter::default()).await;
                let r2 = scoped.list_courses().await;
                let r3 = scoped.list_classes().await;
                (r1, r2, r3)
            })
            .await;
        assert!(res.0.is_err());
        assert!(res.1.is_err());
        assert!(res.2.is_err());
    }
}
