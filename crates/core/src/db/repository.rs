use async_trait::async_trait;

use crate::error::Result;
use crate::webhooks::models::{DeliveryStatus, WebhookDelivery, WebhookEndpoint};

use crate::models::{
    academic_session::AcademicSession,
    audit::{AdminAuditEntry, AdminSession},
    class::Class,
    course::Course,
    demographics::Demographics,
    enrollment::Enrollment,
    google_sync::{GoogleSyncRun, GoogleSyncRunStatus, GoogleSyncUserState},
    idp::{AuthLogEntry, IdpSession, PicturePassword, QrBadge},
    org::Org,
    sync::{SyncRun, SyncStatus, UserCounts, UserFilter},
    user::User,
};

#[async_trait]
pub trait OrgRepository: Send + Sync {
    async fn upsert_org(&self, org: &Org) -> Result<()>;
    async fn get_org(&self, sourced_id: &str) -> Result<Option<Org>>;
    async fn list_orgs(&self) -> Result<Vec<Org>>;
    async fn delete_org(&self, sourced_id: &str) -> Result<bool>;
}

#[async_trait]
pub trait AcademicSessionRepository: Send + Sync {
    async fn upsert_academic_session(&self, session: &AcademicSession) -> Result<()>;
    async fn get_academic_session(&self, sourced_id: &str) -> Result<Option<AcademicSession>>;
    async fn list_academic_sessions(&self) -> Result<Vec<AcademicSession>>;
    async fn delete_academic_session(&self, sourced_id: &str) -> Result<bool>;
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn upsert_user(&self, user: &User) -> Result<()>;
    async fn get_user(&self, sourced_id: &str) -> Result<Option<User>>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn list_users(&self, filter: &UserFilter) -> Result<Vec<User>>;
    async fn delete_user(&self, sourced_id: &str) -> Result<bool>;
    async fn get_user_counts(&self) -> Result<UserCounts>;
}

#[async_trait]
pub trait CourseRepository: Send + Sync {
    async fn upsert_course(&self, course: &Course) -> Result<()>;
    async fn get_course(&self, sourced_id: &str) -> Result<Option<Course>>;
    async fn list_courses(&self) -> Result<Vec<Course>>;
    async fn delete_course(&self, sourced_id: &str) -> Result<bool>;
}

#[async_trait]
pub trait ClassRepository: Send + Sync {
    async fn upsert_class(&self, class: &Class) -> Result<()>;
    async fn get_class(&self, sourced_id: &str) -> Result<Option<Class>>;
    async fn list_classes(&self) -> Result<Vec<Class>>;
    async fn delete_class(&self, sourced_id: &str) -> Result<bool>;
}

#[async_trait]
pub trait EnrollmentRepository: Send + Sync {
    async fn upsert_enrollment(&self, enrollment: &Enrollment) -> Result<()>;
    async fn get_enrollment(&self, sourced_id: &str) -> Result<Option<Enrollment>>;
    async fn list_enrollments(&self) -> Result<Vec<Enrollment>>;
    async fn delete_enrollment(&self, sourced_id: &str) -> Result<bool>;
}

#[async_trait]
pub trait DemographicsRepository: Send + Sync {
    async fn upsert_demographics(&self, demographics: &Demographics) -> Result<()>;
    async fn get_demographics(&self, sourced_id: &str) -> Result<Option<Demographics>>;
    async fn list_demographics(&self) -> Result<Vec<Demographics>>;
    async fn delete_demographics(&self, sourced_id: &str) -> Result<bool>;
}

#[async_trait]
pub trait SyncRepository: Send + Sync {
    async fn create_sync_run(&self, provider: &str) -> Result<SyncRun>;
    async fn update_sync_status(
        &self,
        id: i64,
        status: SyncStatus,
        error_message: Option<&str>,
    ) -> Result<()>;
    async fn update_sync_counts(
        &self,
        id: i64,
        users: i64,
        orgs: i64,
        courses: i64,
        classes: i64,
        enrollments: i64,
    ) -> Result<()>;
    async fn get_sync_run(&self, id: i64) -> Result<Option<SyncRun>>;
    async fn get_latest_sync_run(&self, provider: &str) -> Result<Option<SyncRun>>;
}

#[async_trait]
pub trait IdpSessionRepository: Send + Sync {
    async fn create_session(&self, session: &IdpSession) -> Result<()>;
    async fn get_session(&self, id: &str) -> Result<Option<IdpSession>>;
    async fn delete_session(&self, id: &str) -> Result<bool>;
    async fn delete_expired_sessions(&self) -> Result<u64>;
    async fn list_sessions_for_user(&self, user_sourced_id: &str) -> Result<Vec<IdpSession>>;
}

#[async_trait]
pub trait QrBadgeRepository: Send + Sync {
    async fn create_badge(&self, badge: &QrBadge) -> Result<i64>;
    async fn get_badge_by_token(&self, token: &str) -> Result<Option<QrBadge>>;
    async fn list_badges_for_user(&self, user_sourced_id: &str) -> Result<Vec<QrBadge>>;
    async fn revoke_badge(&self, id: i64) -> Result<bool>;
}

#[async_trait]
pub trait PicturePasswordRepository: Send + Sync {
    async fn upsert_picture_password(&self, pp: &PicturePassword) -> Result<()>;
    async fn get_picture_password(&self, user_sourced_id: &str) -> Result<Option<PicturePassword>>;
    async fn delete_picture_password(&self, user_sourced_id: &str) -> Result<bool>;
}

#[async_trait]
pub trait IdpAuthLogRepository: Send + Sync {
    async fn log_auth_attempt(&self, entry: &AuthLogEntry) -> Result<i64>;
    async fn list_auth_log(&self, limit: i64) -> Result<Vec<AuthLogEntry>>;
    async fn list_auth_log_for_user(
        &self,
        user_sourced_id: &str,
        limit: i64,
    ) -> Result<Vec<AuthLogEntry>>;
}

#[async_trait]
pub trait GoogleSyncStateRepository: Send + Sync {
    async fn upsert_sync_state(&self, state: &GoogleSyncUserState) -> Result<()>;
    async fn get_sync_state(&self, user_sourced_id: &str) -> Result<Option<GoogleSyncUserState>>;
    async fn list_sync_states(&self) -> Result<Vec<GoogleSyncUserState>>;
    async fn delete_sync_state(&self, user_sourced_id: &str) -> Result<bool>;
}

#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait GoogleSyncRunRepository: Send + Sync {
    async fn create_google_sync_run(&self, dry_run: bool) -> Result<GoogleSyncRun>;
    async fn update_google_sync_run(
        &self,
        id: i64,
        status: GoogleSyncRunStatus,
        users_created: i64,
        users_updated: i64,
        users_suspended: i64,
        ous_created: i64,
        error_message: Option<&str>,
    ) -> Result<()>;
    async fn get_google_sync_run(&self, id: i64) -> Result<Option<GoogleSyncRun>>;
    async fn get_latest_google_sync_run(&self) -> Result<Option<GoogleSyncRun>>;
    async fn list_google_sync_runs(&self, limit: i64) -> Result<Vec<GoogleSyncRun>>;
}

#[async_trait]
pub trait AdminSessionRepository: Send + Sync {
    async fn create_admin_session(&self, session: &AdminSession) -> Result<()>;
    async fn get_admin_session(&self, token: &str) -> Result<Option<AdminSession>>;
    async fn delete_admin_session(&self, token: &str) -> Result<bool>;
    async fn delete_expired_admin_sessions(&self) -> Result<u64>;
}

#[async_trait]
pub trait AdminAuditRepository: Send + Sync {
    async fn log_admin_action(
        &self,
        action: &str,
        details: Option<&str>,
        admin_ip: Option<&str>,
    ) -> Result<i64>;
    async fn list_admin_audit_log(&self, limit: i64) -> Result<Vec<AdminAuditEntry>>;
}

#[async_trait]
pub trait PasswordRepository: Send + Sync {
    async fn get_password_hash(&self, user_sourced_id: &str) -> Result<Option<String>>;
    async fn set_password_hash(&self, user_sourced_id: &str, hash: &str) -> Result<()>;
}

#[async_trait]
pub trait ConfigRepository: Send + Sync {
    async fn get_config_override(&self, key: &str) -> Result<Option<String>>;
    async fn set_config_override(&self, key: &str, value: &str) -> Result<()>;
}

#[async_trait]
pub trait WebhookEndpointRepository: Send + Sync {
    async fn upsert_webhook_endpoint(&self, endpoint: &WebhookEndpoint) -> Result<()>;
    async fn get_webhook_endpoint(&self, id: &str) -> Result<Option<WebhookEndpoint>>;
    async fn list_webhook_endpoints(&self) -> Result<Vec<WebhookEndpoint>>;
    async fn list_webhook_endpoints_by_source(&self, source: &str) -> Result<Vec<WebhookEndpoint>>;
    async fn delete_webhook_endpoint(&self, id: &str) -> Result<bool>;
}

#[async_trait]
pub trait WebhookDeliveryRepository: Send + Sync {
    async fn create_webhook_delivery(&self, delivery: &WebhookDelivery) -> Result<i64>;
    async fn update_delivery_status(
        &self,
        id: i64,
        status: DeliveryStatus,
        http_status: Option<i32>,
        response_body: Option<&str>,
    ) -> Result<()>;
    async fn list_pending_retries(&self, limit: i64) -> Result<Vec<WebhookDelivery>>;
    async fn list_deliveries_by_webhook(
        &self,
        webhook_endpoint_id: &str,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>>;
    async fn list_deliveries_by_sync_run(&self, sync_run_id: i64) -> Result<Vec<WebhookDelivery>>;
}

/// Combined repository trait for all entity types.
pub trait ChalkRepository:
    OrgRepository
    + AcademicSessionRepository
    + UserRepository
    + CourseRepository
    + ClassRepository
    + EnrollmentRepository
    + DemographicsRepository
    + SyncRepository
    + IdpSessionRepository
    + QrBadgeRepository
    + PicturePasswordRepository
    + IdpAuthLogRepository
    + GoogleSyncStateRepository
    + GoogleSyncRunRepository
    + PasswordRepository
    + AdminSessionRepository
    + AdminAuditRepository
    + ConfigRepository
    + WebhookEndpointRepository
    + WebhookDeliveryRepository
{
}
