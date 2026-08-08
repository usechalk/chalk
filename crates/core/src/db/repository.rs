use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::error::Result;
use crate::webhooks::models::{DeliveryStatus, WebhookDelivery, WebhookEndpoint};

use crate::models::{
    academic_session::AcademicSession,
    access_token::AccessToken,
    ad_sync::{AdSyncRun, AdSyncRunStatus, AdSyncUserState},
    audit::{AdminAuditEntry, AdminSession},
    class::Class,
    course::Course,
    demographics::Demographics,
    enrollment::Enrollment,
    entra::{EntraRunStatus, EntraSyncRun, EntraUserState},
    google_sync::{GoogleSyncRun, GoogleSyncRunStatus, GoogleSyncUserState},
    idp::{AuthLogEntry, IdpSession, PicturePassword, QrBadge},
    org::Org,
    sso::{OidcAuthorizationCode, PortalSession, SsoPartner},
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
    async fn list_enrollments_for_user(&self, user_sourced_id: &str) -> Result<Vec<Enrollment>>;
    async fn list_enrollments_for_class(&self, class_sourced_id: &str) -> Result<Vec<Enrollment>>;
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
    /// Every unexpired session, newest first — the `/identity/sessions` page.
    async fn list_active_sessions(&self) -> Result<Vec<IdpSession>>;
}

#[async_trait]
pub trait QrBadgeRepository: Send + Sync {
    async fn create_badge(&self, badge: &QrBadge) -> Result<i64>;
    async fn get_badge_by_token(&self, token: &str) -> Result<Option<QrBadge>>;
    async fn list_badges_for_user(&self, user_sourced_id: &str) -> Result<Vec<QrBadge>>;
    /// Every badge ever issued, newest first — the `/identity/badges` page.
    async fn list_badges(&self) -> Result<Vec<QrBadge>>;
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

    /// Delete audit-log rows older than `older_than`. Returns the number
    /// of rows removed. Used by the periodic retention pruner per the
    /// privacy policy commitment ("audit logs retained for 13 months").
    /// Default implementation does nothing so concrete backends opt in.
    async fn prune_admin_audit_log(
        &self,
        older_than: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64> {
        let _ = older_than;
        Ok(0)
    }
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
    /// Schedule (or clear) the next retry timestamp for a delivery without
    /// touching status/attempt counters. Used by the delivery engine after
    /// `update_delivery_status` to space out retries per the configured
    /// backoff schedule.
    async fn set_delivery_next_retry_at(
        &self,
        id: i64,
        next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<()>;
    async fn list_deliveries_by_webhook(
        &self,
        webhook_endpoint_id: &str,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>>;
    async fn list_deliveries_by_sync_run(&self, sync_run_id: i64) -> Result<Vec<WebhookDelivery>>;
}

#[async_trait]
pub trait SsoPartnerRepository: Send + Sync {
    async fn upsert_sso_partner(&self, partner: &SsoPartner) -> Result<()>;
    async fn get_sso_partner(&self, id: &str) -> Result<Option<SsoPartner>>;
    async fn get_sso_partner_by_entity_id(&self, entity_id: &str) -> Result<Option<SsoPartner>>;
    async fn get_sso_partner_by_client_id(&self, client_id: &str) -> Result<Option<SsoPartner>>;
    async fn list_sso_partners(&self) -> Result<Vec<SsoPartner>>;
    async fn list_sso_partners_for_role(&self, role: &str) -> Result<Vec<SsoPartner>>;
    async fn delete_sso_partner(&self, id: &str) -> Result<bool>;
}

#[async_trait]
pub trait OidcCodeRepository: Send + Sync {
    async fn create_oidc_code(&self, code: &OidcAuthorizationCode) -> Result<()>;
    async fn get_oidc_code(&self, code: &str) -> Result<Option<OidcAuthorizationCode>>;
    async fn delete_oidc_code(&self, code: &str) -> Result<bool>;
    async fn delete_expired_oidc_codes(&self) -> Result<u64>;
}

#[async_trait]
pub trait PortalSessionRepository: Send + Sync {
    async fn create_portal_session(&self, session: &PortalSession) -> Result<()>;
    async fn get_portal_session(&self, id: &str) -> Result<Option<PortalSession>>;
    async fn delete_portal_session(&self, id: &str) -> Result<bool>;
    async fn delete_expired_portal_sessions(&self) -> Result<u64>;
}

#[async_trait]
pub trait AdSyncStateRepository: Send + Sync {
    async fn upsert_ad_sync_state(&self, state: &AdSyncUserState) -> Result<()>;
    async fn get_ad_sync_state(&self, user_sourced_id: &str) -> Result<Option<AdSyncUserState>>;
    async fn list_ad_sync_states(&self) -> Result<Vec<AdSyncUserState>>;
    async fn delete_ad_sync_state(&self, user_sourced_id: &str) -> Result<bool>;
}

#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait AdSyncRunRepository: Send + Sync {
    async fn create_ad_sync_run(&self, dry_run: bool) -> Result<AdSyncRun>;
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
    ) -> Result<()>;
    async fn get_ad_sync_run(&self, id: &str) -> Result<Option<AdSyncRun>>;
    async fn get_latest_ad_sync_run(&self) -> Result<Option<AdSyncRun>>;
    async fn list_ad_sync_runs(&self, limit: i64) -> Result<Vec<AdSyncRun>>;
}

#[async_trait]
pub trait EntraSyncStateRepository: Send + Sync {
    async fn upsert_entra_sync_state(&self, state: &EntraUserState) -> Result<()>;
    async fn get_entra_sync_state(&self, user_sourced_id: &str) -> Result<Option<EntraUserState>>;
    async fn list_entra_sync_states(&self) -> Result<Vec<EntraUserState>>;
    async fn delete_entra_sync_state(&self, user_sourced_id: &str) -> Result<bool>;
}

#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait EntraSyncRunRepository: Send + Sync {
    async fn create_entra_sync_run(&self, dry_run: bool) -> Result<EntraSyncRun>;
    async fn update_entra_sync_run(
        &self,
        id: &str,
        status: EntraRunStatus,
        users_created: i64,
        users_updated: i64,
        users_disabled: i64,
        users_skipped: i64,
        errors: i64,
        error_details: Option<&str>,
    ) -> Result<()>;
    async fn get_latest_entra_sync_run(&self) -> Result<Option<EntraSyncRun>>;
    async fn list_entra_sync_runs(&self, limit: i64) -> Result<Vec<EntraSyncRun>>;
}

#[async_trait]
pub trait ExternalIdRepository: Send + Sync {
    async fn get_external_ids(
        &self,
        user_sourced_id: &str,
    ) -> Result<serde_json::Map<String, serde_json::Value>>;
    async fn set_external_ids(
        &self,
        user_sourced_id: &str,
        ids: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<()>;
    async fn find_user_by_external_id(
        &self,
        provider: &str,
        external_id: &str,
    ) -> Result<Option<User>>;
}

/// Repository for one-time password reset tokens.
///
/// Tokens are high-entropy random values from a CSPRNG. Storage uses the
/// SHA-256 of the raw token as `token_hash` (the primary key), avoiding the
/// need for argon2 verify-loops while still preventing leakage of usable
/// tokens via DB compromise.
#[async_trait]
pub trait PasswordResetTokenRepository: Send + Sync {
    /// Insert a reset token row. `token_hash` should be the lowercase hex
    /// SHA-256 of the raw token.
    async fn create_reset_token(
        &self,
        user_sourced_id: &str,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()>;

    /// Atomically consume a reset token. Returns `Some(user_sourced_id)` on
    /// success; `None` if the token is unknown, expired, or already consumed.
    async fn consume_reset_token(&self, raw_token: &str) -> Result<Option<String>>;

    /// Delete tokens whose `expires_at` is in the past. Returns the number
    /// of rows removed. Used for periodic GC.
    async fn delete_expired_reset_tokens(&self) -> Result<u64>;
}

/// One-time magic-link login tokens (passwordless login). Like reset tokens,
/// only the SHA-256 hash is persisted; redemption creates a session rather than
/// setting a password.
#[async_trait]
pub trait MagicLoginRepository: Send + Sync {
    /// Insert a magic-login token. `token_hash` is the lowercase hex SHA-256 of
    /// the raw token sent in the link.
    async fn create_magic_login_token(
        &self,
        user_sourced_id: &str,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()>;

    /// Atomically consume a magic-login token. Returns `Some(user_sourced_id)`
    /// on success; `None` if unknown, expired, or already consumed.
    async fn consume_magic_login_token(&self, raw_token: &str) -> Result<Option<String>>;
}

#[async_trait]
pub trait AccessTokenRepository: Send + Sync {
    async fn create_access_token(&self, token: &AccessToken) -> Result<()>;
    async fn get_access_token(&self, token: &str) -> Result<Option<AccessToken>>;
    async fn revoke_access_token(&self, token: &str) -> Result<()>;
    async fn delete_expired_access_tokens(&self) -> Result<u64>;
}

#[async_trait]
pub trait ApiTokenRepository: Send + Sync {
    /// Persist a newly-minted API token. Callers pass the hashed form; the
    /// plaintext should never reach this trait.
    async fn create_api_token(&self, token: &crate::models::api_token::ApiToken) -> Result<()>;

    /// List every API token (active and revoked). The hash is included; the
    /// plaintext is not stored anywhere.
    async fn list_api_tokens(&self) -> Result<Vec<crate::models::api_token::ApiToken>>;

    /// Look up an unrevoked token by its SHA-256 hash. Returns `Ok(None)` if
    /// no row matches, or the row is revoked.
    async fn find_active_api_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<crate::models::api_token::ApiToken>>;

    /// Stamp `last_used_at = now()` on the matching row. Fire-and-forget from
    /// the middleware so an authenticated request never blocks on this write.
    async fn touch_api_token(&self, id: &str) -> Result<()>;

    /// Set `revoked_at = now()`. Idempotent — revoking an already-revoked
    /// token is a no-op success.
    async fn revoke_api_token(&self, id: &str) -> Result<()>;
}

/// Plain record for `tenant_config_sis`. Secrets are carried as
/// `Option<Vec<u8>>` — backend impls decide whether those bytes are sealed
/// (postgres goes through `crates/hosted/src/keys.rs`) or plaintext (sqlite,
/// for tests).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SisConfigRecord {
    pub enabled: bool,
    pub provider: Option<String>,
    pub powerschool_base_url: Option<String>,
    pub powerschool_token_url: Option<String>,
    pub powerschool_client_id: Option<String>,
    pub powerschool_client_secret: Option<Vec<u8>>,
    pub infinite_campus_base_url: Option<String>,
    /// OAuth token endpoint. Unlike PowerSchool's, this is **required** for
    /// Infinite Campus — `InfiniteCampusConnector::new` errors without it.
    pub infinite_campus_token_url: Option<String>,
    pub infinite_campus_client_id: Option<String>,
    pub infinite_campus_client_secret: Option<Vec<u8>>,
    pub skyward_base_url: Option<String>,
    /// OAuth token endpoint. Required for Skyward — `SkywardConnector::new`
    /// errors without it.
    pub skyward_token_url: Option<String>,
    pub skyward_client_id: Option<String>,
    pub skyward_client_secret: Option<Vec<u8>>,
    pub oneroster_csv_dir: Option<String>,
    pub sync_schedule: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<String>,
}

/// Plain record for `tenant_config_google_sync`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GoogleSyncConfigRecord {
    pub enabled: bool,
    pub workspace_domain: Option<String>,
    pub admin_email: Option<String>,
    pub service_account_key: Option<Vec<u8>>,
    pub provision_users: bool,
    pub manage_ous: bool,
    pub suspend_inactive: bool,
    pub sync_schedule: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<String>,
}

/// Plain record for `tenant_config_devices`.
///
/// `service_account_key` holds **plaintext** JSON at this boundary. The raw
/// repository stores whatever bytes it is handed; a sealing wrapper is what
/// encrypts on the way in and decrypts on the way out, which is why the field
/// name carries no `_sealed` suffix while the column does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceConfigRecord {
    pub enabled: bool,
    /// Whether this tenant has agreed to let Chalk *write* to Google.
    ///
    /// Separate from `enabled` because reading a district's fleet and changing
    /// it are different levels of trust, and it decides which scopes are
    /// requested — domain-wide delegation matches the literal scope string, so
    /// the two cannot be conflated.
    pub write_back_enabled: bool,
    pub customer_id: Option<String>,
    pub admin_email: Option<String>,
    pub service_account_key: Option<Vec<u8>>,
    pub page_size: Option<i64>,
    pub requests_per_minute: Option<i64>,
    pub sync_schedule: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<String>,
}

/// Plain record for `tenant_config_idp`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdpConfigRecord {
    pub enabled: bool,
    pub qr_badge_login: bool,
    pub picture_passwords: bool,
    pub session_timeout_minutes: Option<i32>,
    pub default_password_pattern: Option<String>,
    pub default_password_roles: Option<serde_json::Value>,
    pub saml_cert: Option<Vec<u8>>,
    pub saml_signing_key: Option<Vec<u8>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<String>,
}

/// Plain record for `tenant_config_ad_sync`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AdSyncConfigRecord {
    pub enabled: bool,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub bind_dn: Option<String>,
    pub bind_password: Option<Vec<u8>>,
    pub base_dn: Option<String>,
    pub user_filter: Option<String>,
    pub use_tls: bool,
    pub tls_ca_cert: Option<Vec<u8>>,
    pub sync_schedule: Option<String>,
    pub ou_mapping: Option<serde_json::Value>,
    pub groups: Option<serde_json::Value>,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<String>,
}

/// Per-tenant config rows — singleton per section. `put_*` upserts the single
/// row identified by the `(id = TRUE)` primary key and writes an audit row via
/// the existing `admin_audit_log` table (see `AdminAuditRepository`). Secrets
/// are passed as `Option<Vec<u8>>` and stored verbatim by the backend; the
/// sealing/unsealing boundary lives at the `chalk-hosted` postgres wrapper.
#[async_trait]
pub trait TenantConfigRepo: Send + Sync {
    async fn get_sis_config(&self) -> Result<Option<SisConfigRecord>>;
    async fn put_sis_config(&self, record: SisConfigRecord, actor: &str) -> Result<()>;

    async fn get_google_sync_config(&self) -> Result<Option<GoogleSyncConfigRecord>>;
    async fn put_google_sync_config(
        &self,
        record: GoogleSyncConfigRecord,
        actor: &str,
    ) -> Result<()>;

    async fn get_device_config(&self) -> Result<Option<DeviceConfigRecord>>;
    async fn put_device_config(&self, record: DeviceConfigRecord, actor: &str) -> Result<()>;

    async fn get_idp_config(&self) -> Result<Option<IdpConfigRecord>>;
    async fn put_idp_config(&self, record: IdpConfigRecord, actor: &str) -> Result<()>;

    async fn get_ad_sync_config(&self) -> Result<Option<AdSyncConfigRecord>>;
    async fn put_ad_sync_config(&self, record: AdSyncConfigRecord, actor: &str) -> Result<()>;
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
    + AdSyncStateRepository
    + AdSyncRunRepository
    + EntraSyncStateRepository
    + EntraSyncRunRepository
    + ExternalIdRepository
    + PasswordRepository
    + AdminSessionRepository
    + AdminAuditRepository
    + ConfigRepository
    + WebhookEndpointRepository
    + WebhookDeliveryRepository
    + SsoPartnerRepository
    + OidcCodeRepository
    + PortalSessionRepository
    + AccessTokenRepository
    + ApiTokenRepository
    + PasswordResetTokenRepository
    + MagicLoginRepository
{
}

// ---------------------------------------------------------------------------
// Device / asset repositories (migrations 019, 021, 022)
//
// These four traits are DELIBERATELY NOT members of the `ChalkRepository`
// supertrait above. They follow the `TenantConfigRepo` precedent: consumers
// take `Arc<dyn AssetRepository>` and friends directly.
//
// The reason is concrete. `ChalkRepository` has two full implementations plus
// the hand-written ~800-line `MockRepo` in `google-sync/src/sync.rs`, which
// exists to test *user provisioning*. Adding four traits x ~10 methods to the
// supertrait would force ~40 `unimplemented!()` stubs into a mock that will
// never call `list_assets`. Standalone traits also mean a device test can
// substitute a 30-line fake instead of that mock.
// ---------------------------------------------------------------------------

use crate::models::asset::{
    Asset, AssetEvent, AssetEventFilter, AssetFilter, AssetGroupCount, AssetPatch, AssetRow,
    NewAssetEvent,
};
use crate::models::canned_response::CannedResponse;
use crate::models::change_set::{
    ChangeSet, ChangeSetFilter, ChangeSetItem, ChangeSetItemStatus, ChangeSetProgress, CommitClaim,
    NewChangeSetItem,
};
use crate::models::charge::{Charge, NewCharge};
use crate::models::console_user::ConsoleUser;
use crate::models::device_sync::{
    DeviceSyncCounters, DeviceSyncCursor, DeviceSyncMode, DeviceSyncResource, DeviceSyncRun,
    DeviceSyncRunStatus,
};
use crate::models::job::{Job, JobFilter, JobStatus, NewJob};
use crate::models::page::{Page, PageRequest};
use crate::models::ticket::{
    NewTicketComment, Ticket, TicketAttachment, TicketComment, TicketFilter, TicketPatch,
    TicketScope,
};

/// Asset inventory (`assets`, migration 019).
///
/// There is no delete method, by design: assets are never hard-deleted.
/// Retirement is an [`AssetStatus`](crate::models::asset::AssetStatus) change,
/// which is what lets `asset_events.asset_id` be `ON DELETE RESTRICT`.
///
/// **Every list method paginates and filters in SQL.** `console/src/lib.rs`
/// currently fetches every user and filters in Rust; at 20k devices that is a
/// timeout, not a slow page. Nothing here returns an unbounded `Vec`.
#[async_trait]
pub trait AssetRepository: Send + Sync {
    /// Insert a new asset. Fails on a duplicate `id`, `serial_number` or
    /// `google_device_id`.
    async fn create_asset(&self, asset: &Asset) -> Result<()>;

    /// Insert or replace by primary key. Used by the device sync, which owns
    /// the whole row for Google-sourced assets.
    async fn upsert_asset(&self, asset: &Asset) -> Result<()>;

    async fn get_asset(&self, id: &str) -> Result<Option<Asset>>;

    /// Look up by Directory API `deviceId` — the device sync's join key.
    async fn get_asset_by_google_device_id(&self, google_device_id: &str) -> Result<Option<Asset>>;

    /// Look up by serial number, the CSV import's join key.
    async fn get_asset_by_serial(&self, serial_number: &str) -> Result<Option<Asset>>;

    /// Every asset carrying this tag.
    ///
    /// Returns a list, not an `Option`, because `asset_tag` has no unique
    /// index — serials do, tags do not, and districts reuse tags across refresh
    /// cycles. A CSV row that matches two devices is genuinely ambiguous and
    /// the import says so; silently taking the first would write to whichever
    /// row the query planner happened to return.
    async fn find_assets_by_asset_tag(&self, asset_tag: &str) -> Result<Vec<Asset>>;

    /// One page of assets matching `filter`, plus the total matching count.
    /// Both the filter and the sort are pushed into SQL.
    async fn list_assets(&self, filter: &AssetFilter, page: PageRequest) -> Result<Page<Asset>>;

    /// The same page as [`list_assets`](Self::list_assets), with each row's
    /// assigned user and school resolved by a `LEFT JOIN`.
    ///
    /// This is what the device inventory table renders: student and school sit
    /// beside the device, which is the whole product argument. It is a separate
    /// method rather than the default because the join is only worth paying for
    /// when those columns are on screen — the sync engine and the CLI want the
    /// bare rows.
    ///
    /// **The join is applied to the page window, not the table.** The filter,
    /// sort, `LIMIT` and `OFFSET` all run against `assets` alone and the join
    /// wraps the result, so the cost is bounded by the page size no matter how
    /// large the fleet or the roster. Sorting by a joined column is therefore
    /// deliberately not offered — it would push the join under the window.
    async fn list_assets_with_roster(
        &self,
        filter: &AssetFilter,
        page: PageRequest,
    ) -> Result<Page<AssetRow>>;

    /// Total assets matching `filter`, without fetching any rows.
    async fn count_assets(&self, filter: &AssetFilter) -> Result<i64>;

    /// Counts grouped by school and lifecycle status, in **one** query.
    ///
    /// A report over twenty schools and six statuses is a hundred and twenty
    /// numbers; asking for them one `count_assets` at a time is a hundred and
    /// twenty round trips for a page that has to render while someone waits.
    ///
    /// Takes the same filter as every other listing, so a scoped API token or
    /// a narrowed view produces a report over exactly what that caller may
    /// see — the boundary cannot be forgotten here because it is the same
    /// argument.
    async fn count_assets_by_school_and_status(
        &self,
        filter: &AssetFilter,
    ) -> Result<Vec<AssetGroupCount>>;

    /// Apply a partial update and stamp `updated_at`. Returns `false` when no
    /// row has that id. An empty patch is a no-op that still returns whether
    /// the asset exists.
    async fn update_asset(&self, id: &str, patch: &AssetPatch) -> Result<bool>;

    /// Apply a patch **and** append its audit event in one transaction.
    /// Returns `false` when no row has that id, in which case neither the
    /// update nor the event is written.
    ///
    /// This exists because [`update_asset`](Self::update_asset) and
    /// [`AssetEventRepository::append_event`] sit on two different traits, and
    /// a transaction cannot span two `Arc<dyn _>`s. Calling them in sequence
    /// leaves a window where the asset has changed and the history has no
    /// record of it — and for the queue that resolves devices to students, an
    /// unexplained assignment is worse than no assignment: the audit trail is
    /// the product feature, not decoration around it.
    ///
    /// Every operator-initiated mutation goes through here. `update_asset`
    /// stays for the sync engine, which reconciles machine state that Google
    /// remains the record of.
    async fn apply_patch_with_event(
        &self,
        id: &str,
        patch: &AssetPatch,
        event: &NewAssetEvent,
    ) -> Result<bool>;
}

/// Immutable asset history (`asset_events`, migration 019).
///
/// **Append and read only.** There is deliberately no update and no delete
/// anywhere on this trait — the immutability is the product feature, not an
/// oversight. If a correction is needed, it is a new event.
#[async_trait]
pub trait AssetEventRepository: Send + Sync {
    /// Append one event. Returns the assigned row id. The database owns both
    /// `id` and `created_at`.
    async fn append_event(&self, event: &NewAssetEvent) -> Result<i64>;

    /// One page of events, newest first, filtered in SQL.
    async fn list_events(
        &self,
        filter: &AssetEventFilter,
        page: PageRequest,
    ) -> Result<Page<AssetEvent>>;
}

/// Per-person console accounts (migration 027).
///
/// A standalone trait rather than a member of [`ChalkRepository`] on purpose:
/// the ~800-line `MockRepo` used to test user provisioning has no business
/// growing a dozen console-account stubs it will never call. Follows the
/// [`AssetRepository`] / [`TicketRepository`] precedent.
///
/// Emails are stored and compared already lowercased — callers fold case before
/// every lookup and insert, so the unique index is a plain one.
#[async_trait]
pub trait ConsoleUserRepository: Send + Sync {
    async fn create_console_user(&self, user: &ConsoleUser) -> Result<()>;

    /// By lowercased email. Used at login.
    async fn get_console_user_by_email(&self, email: &str) -> Result<Option<ConsoleUser>>;

    async fn get_console_user(&self, id: &str) -> Result<Option<ConsoleUser>>;

    /// All accounts, newest first — the management list is never large.
    async fn list_console_users(&self) -> Result<Vec<ConsoleUser>>;

    /// Full upsert of the mutable fields (display_name, password_hash, role,
    /// status). `id` and `email` are immutable once created.
    async fn update_console_user(&self, user: &ConsoleUser) -> Result<()>;

    /// How many accounts exist — lets the bootstrap decide whether the console
    /// still needs its first real admin.
    async fn count_console_users(&self) -> Result<i64>;
}

/// Fees and fines (migration 028, F3). Standalone, like the other module
/// repositories, to keep `MockRepo` out of it.
///
/// Assessment and record only — there is no payment operation here, by design
/// (D14/D22).
#[async_trait]
pub trait ChargeRepository: Send + Sync {
    /// Record a charge. Returns the assigned id.
    async fn create_charge(&self, charge: &NewCharge) -> Result<String>;

    async fn get_charge(&self, id: &str) -> Result<Option<Charge>>;

    /// A person's charges, newest first — the family balance view.
    async fn list_charges_for_user(&self, user_sourced_id: &str) -> Result<Vec<Charge>>;

    /// A device's charges, newest first — the device history view.
    async fn list_charges_for_asset(&self, asset_id: &str) -> Result<Vec<Charge>>;

    /// Change a charge's disposition (waive, mark settled) and whether a
    /// protection plan was applied. The amount is immutable once recorded — a
    /// correction is a new charge, so the ledger stays honest.
    async fn update_charge_status(
        &self,
        id: &str,
        status: crate::models::charge::ChargeStatus,
        insurance_applied: bool,
    ) -> Result<()>;
}

/// Shared reply templates for the help desk. Standalone, like the other
/// help-desk repositories, so a mock does not have to grow a method for it.
#[async_trait]
pub trait CannedResponseRepository: Send + Sync {
    async fn create_canned_response(&self, response: &CannedResponse) -> Result<()>;

    /// All templates, newest first — the library is small and shown in full.
    async fn list_canned_responses(&self) -> Result<Vec<CannedResponse>>;

    async fn get_canned_response(&self, id: &str) -> Result<Option<CannedResponse>>;

    async fn delete_canned_response(&self, id: &str) -> Result<()>;
}

/// Background jobs (`jobs`, migration 023). ARCHITECTURE.md §6.
///
/// A standalone trait, not a `ChalkRepository` member, for the same reason the
/// asset traits are: folding it in would force stub methods into the
/// hand-written mock that exists to test user provisioning and will never
/// enqueue a job.
///
/// **The console only ever needs this trait.** Requesting a sync is
/// `enqueue`; running one is the worker's problem, in a process that owns the
/// handlers. That is what keeps `chalk-console` free of any dependency on
/// `chalk-devices`.
#[async_trait]
pub trait JobRepository: Send + Sync {
    /// Add a job to the queue. Returns the row as stored, with its assigned id
    /// and timestamps.
    async fn enqueue(&self, job: &NewJob) -> Result<Job>;

    async fn get_job(&self, id: &str) -> Result<Option<Job>>;

    /// The next job a worker may claim: `queued`, with `run_after` in the past
    /// or unset, oldest first. Returns the candidate **without** claiming it —
    /// [`claim`](Self::claim) is what makes the decision atomic.
    async fn next_claimable(&self, now: DateTime<Utc>) -> Result<Option<Job>>;

    /// Take ownership of a job. `true` when this caller won it.
    ///
    /// Implemented as one conditional `UPDATE ... WHERE id = ? AND status =
    /// 'queued'`, and the caller proceeds only when exactly one row changed.
    /// That is correct on both drivers with no `SKIP LOCKED`, which matters
    /// because SQLite has none — two workers racing the same row means one of
    /// them sees zero rows affected and moves on. ARCHITECTURE §6.2.
    ///
    /// Increments `attempt`, so the retry budget is spent by *claiming*, not
    /// by finishing. A handler that panics the process still consumed one.
    async fn claim(&self, id: &str, now: DateTime<Utc>) -> Result<bool>;

    /// Record a terminal outcome. `error` is `None` on success.
    async fn finish(&self, id: &str, status: JobStatus, error: Option<&str>) -> Result<bool>;

    /// Put a failed-but-retryable job back on the queue, optionally delayed.
    async fn requeue(
        &self,
        id: &str,
        run_after: Option<DateTime<Utc>>,
        error: &str,
    ) -> Result<bool>;

    /// Fail every job left `running` since before `cutoff`, marking it
    /// abandoned. Returns how many.
    ///
    /// Called once at startup. A `running` row can only exist because a worker
    /// claimed it and the process then died, so there is nobody to finish it
    /// and it would otherwise sit `running` forever, blocking nothing but
    /// lying to every operator who reads the list.
    ///
    /// **It is never silently re-queued.** A job that writes to Google may
    /// have applied some of its work before the process died, and re-running it
    /// is exactly the fleet-wide double-apply `max_attempts = 1` exists to
    /// prevent. Recovery marks it failed and a human decides.
    async fn fail_abandoned(&self, cutoff: DateTime<Utc>) -> Result<u64>;

    async fn list_jobs(&self, filter: &JobFilter, page: PageRequest) -> Result<Page<Job>>;
}

/// Google ChromeOS device sync bookkeeping (migration 021).
#[async_trait]
pub trait GoogleDeviceSyncRepository: Send + Sync {
    /// The cursor for one Directory API collection, or `None` if never synced.
    async fn get_cursor(&self, resource: DeviceSyncResource) -> Result<Option<DeviceSyncCursor>>;

    /// Insert or update the cursor. Migrations never seed these rows — a seed
    /// `INSERT` would re-run on every boot and clobber a live `page_token`.
    async fn upsert_cursor(&self, cursor: &DeviceSyncCursor) -> Result<()>;

    /// Open a run row in `running` state and return it with its assigned id.
    async fn start_run(&self, mode: DeviceSyncMode, dry_run: bool) -> Result<DeviceSyncRun>;

    /// Overwrite the counters of an in-flight run, for live progress. All
    /// counters are `i64` bound to `BIGINT` — never narrowed to `i32`.
    async fn update_run_counters(&self, id: i64, counters: &DeviceSyncCounters) -> Result<()>;

    /// Set the terminal status, `completed_at`, final counters and error.
    async fn finish_run(
        &self,
        id: i64,
        status: DeviceSyncRunStatus,
        counters: &DeviceSyncCounters,
        error_message: Option<&str>,
    ) -> Result<()>;

    async fn get_run(&self, id: i64) -> Result<Option<DeviceSyncRun>>;

    /// The most recent run by id, whatever its status.
    async fn latest_run(&self) -> Result<Option<DeviceSyncRun>>;

    /// One page of runs, newest first.
    async fn list_runs(&self, page: PageRequest) -> Result<Page<DeviceSyncRun>>;
}

/// Diff-preview-then-commit staging (migration 022).
///
/// The compound methods here are not a convenience. You cannot span a database
/// transaction across two `Arc<dyn>` objects, and ARCHITECTURE §6.3 requires
/// the asset update, the `asset_events` append and the item status change to
/// be one atom. Splitting them across `AssetRepository` + `AssetEventRepository`
/// would ship as three separate awaits with two crash windows between them.
/// Tickets, their comments and their attachments.
///
/// Standalone rather than part of [`ChalkRepository`], following the
/// `AssetRepository` precedent: adding it to the supertrait would force a
/// dozen stub methods into hand-written mocks that will never file a ticket.
#[async_trait]
pub trait TicketRepository: Send + Sync {
    /// Insert a ticket, allocating its number **inside the same transaction**.
    ///
    /// Returns the stored ticket with its number filled in. The number cannot
    /// be chosen by the caller: allocating outside the insert is how two
    /// simultaneous submissions end up sharing one, and two teachers filing at
    /// once is a Monday morning rather than an edge case.
    async fn create_ticket(&self, ticket: &Ticket) -> Result<Ticket>;

    async fn get_ticket(&self, id: &str) -> Result<Option<Ticket>>;

    /// Look up by the number a human quotes.
    async fn get_ticket_by_number(&self, number: i64) -> Result<Option<Ticket>>;

    /// Look up by the `Message-ID` of the mail that created it.
    ///
    /// The dedup path for email ingestion. The unique index means a racing
    /// insert conflicts rather than duplicating, but a lookup first gives the
    /// ingestor something to thread a reply onto.
    async fn get_ticket_by_message_id(&self, message_id: &str) -> Result<Option<Ticket>>;

    /// One page of tickets matching `filter`, plus the total matching count.
    /// Both the filter and the sort are pushed into SQL.
    async fn list_tickets(
        &self,
        filter: &TicketFilter,
        scope: &TicketScope,
        page: PageRequest,
    ) -> Result<Page<Ticket>>;

    async fn count_tickets(&self, filter: &TicketFilter, scope: &TicketScope) -> Result<i64>;

    /// Apply a partial update and stamp `updated_at`. Returns `false` when no
    /// row has that id.
    async fn update_ticket(&self, id: &str, patch: &TicketPatch) -> Result<bool>;

    /// Append a comment and, when it is the first visible reply from someone
    /// other than the requester, stamp `first_response_at` **in the same
    /// transaction**.
    ///
    /// One operation because first-response time is the number a district is
    /// measured on, and computing it from a separate write leaves a window
    /// where a comment exists and the clock says nobody has answered.
    async fn append_comment(&self, comment: &NewTicketComment) -> Result<TicketComment>;

    /// Comments on a ticket, oldest first.
    ///
    /// `include_internal` is false for the requester's own view. Filtering in
    /// SQL rather than after the fetch, so an internal note never travels to a
    /// caller who must not see it.
    async fn list_comments(
        &self,
        ticket_id: &str,
        include_internal: bool,
    ) -> Result<Vec<TicketComment>>;

    /// The ticket a previously-ingested email comment belongs to.
    ///
    /// The other half of email idempotency. `get_ticket_by_message_id` covers
    /// a redelivered *first* message; a redelivered **reply** stores its id on
    /// the comment, so without this the second delivery hits the unique index,
    /// errors, and the provider retries forever.
    async fn ticket_id_for_comment_message_id(&self, message_id: &str) -> Result<Option<String>>;

    async fn add_attachment(&self, attachment: &TicketAttachment) -> Result<()>;

    async fn list_attachments(&self, ticket_id: &str) -> Result<Vec<TicketAttachment>>;

    /// One attachment by id, for serving it.
    ///
    /// Returns the row and nothing else: whether the caller may *have* it is
    /// decided by the ticket it hangs off, which the handler checks with the
    /// same ownership rule the thread uses. A repository method that took a
    /// requester would invite a second, subtly different, copy of that rule.
    async fn get_attachment(&self, id: &str) -> Result<Option<TicketAttachment>>;

    /// Replace a ticket's tags wholesale. The edit form submits the full set,
    /// so replace-all is the honest write — add/remove deltas would invent a
    /// merge nobody asked for. Tags are stored trimmed and lowercased.
    async fn set_ticket_tags(&self, ticket_id: &str, tags: &[String]) -> Result<()>;

    /// A ticket's tags, sorted.
    async fn get_ticket_tags(&self, ticket_id: &str) -> Result<Vec<String>>;

    /// `(ticket_id, tag)` for a set of tickets, one query — the queue labels a
    /// page of rows without N lookups.
    async fn get_tags_for_tickets(&self, ticket_ids: &[String]) -> Result<Vec<(String, String)>>;

    /// Every distinct tag in use, sorted — the filter dropdown.
    async fn list_all_tags(&self) -> Result<Vec<String>>;
}

/// Repair records (migration 038).
#[async_trait]
pub trait RepairRepository: Send + Sync {
    async fn create_repair(&self, record: &crate::models::repair::RepairRecord) -> Result<()>;

    /// The open repair for an asset, if any. One at a time is a policy the
    /// console enforces in words, not a schema constraint — a device genuinely
    /// can be at two vendors, but a desk asking for that is almost always a
    /// mistake.
    async fn open_repair_for_asset(
        &self,
        asset_id: &str,
    ) -> Result<Option<crate::models::repair::RepairRecord>>;

    /// Close a repair: stamp `closed_at` and the final cost. Returns `false`
    /// when it does not exist or is already closed.
    async fn close_repair(&self, id: &str, cost_cents: Option<i64>) -> Result<bool>;

    /// Every repair of one asset, newest first.
    async fn repair_history_for_asset(
        &self,
        asset_id: &str,
    ) -> Result<Vec<crate::models::repair::RepairRecord>>;
}

/// Custody records — the 1:1 circulation loop (migration 037).
#[async_trait]
pub trait CustodyRepository: Send + Sync {
    /// Open a loan. Fails (unique index) when the asset already has an open
    /// one — the desk must check it in first, because two open custodies for
    /// one device means one of them is a lie.
    async fn create_custody(&self, record: &crate::models::custody::CustodyRecord) -> Result<()>;

    /// The open loan for an asset, if any.
    async fn open_custody_for_asset(
        &self,
        asset_id: &str,
    ) -> Result<Option<crate::models::custody::CustodyRecord>>;

    /// One loan by id, open or closed.
    async fn get_custody(&self, id: &str) -> Result<Option<crate::models::custody::CustodyRecord>>;

    /// Close a loan: stamp `checked_in_at` and the return condition. Returns
    /// `false` when the record does not exist or is already closed.
    async fn close_custody(
        &self,
        id: &str,
        condition_in: Option<&str>,
        actor: &str,
    ) -> Result<bool>;

    /// Every loan of one asset, newest first — the device page history.
    async fn custody_history_for_asset(
        &self,
        asset_id: &str,
    ) -> Result<Vec<crate::models::custody::CustodyRecord>>;

    /// Every open loan, oldest due first — the circulation view. Nulls (no due
    /// date) sort last.
    async fn list_open_custody(&self) -> Result<Vec<crate::models::custody::CustodyRecord>>;
}

/// Knowledge-base articles (migration 036).
#[async_trait]
pub trait KbRepository: Send + Sync {
    async fn create_kb_article(&self, article: &crate::models::kb::KbArticle) -> Result<()>;

    /// Full update of title/body/published, stamping `updated_at`.
    async fn update_kb_article(&self, article: &crate::models::kb::KbArticle) -> Result<()>;

    async fn get_kb_article(&self, id: &str) -> Result<Option<crate::models::kb::KbArticle>>;

    /// Newest first. `published_only` is what the portal passes — the filter
    /// is SQL, so a draft never travels to a surface that must not show it.
    async fn list_kb_articles(
        &self,
        published_only: bool,
    ) -> Result<Vec<crate::models::kb::KbArticle>>;

    async fn delete_kb_article(&self, id: &str) -> Result<()>;
}

/// Auto-assignment rules (migration 034). Matching lives in
/// [`crate::models::routing::best_match`] over the full list — the table is
/// tens of rows, and the "most specific wins" judgement is unit-tested in Rust
/// rather than encoded twice in SQL.
#[async_trait]
pub trait RoutingRuleRepository: Send + Sync {
    async fn create_routing_rule(&self, rule: &crate::models::routing::RoutingRule) -> Result<()>;

    /// All rules, oldest first — the order ties are broken in.
    async fn list_routing_rules(&self) -> Result<Vec<crate::models::routing::RoutingRule>>;

    async fn delete_routing_rule(&self, id: &str) -> Result<()>;
}

/// CSAT surveys (migration 035).
#[async_trait]
pub trait AttestationRepository: Send + Sync {
    /// Create one ask. Returns `false` when the loan already has an
    /// unanswered attestation — a campaign re-run must nag, not duplicate.
    async fn create_attestation(&self, a: &crate::models::attestation::Attestation)
        -> Result<bool>;

    async fn get_attestation_by_token(
        &self,
        token: &str,
    ) -> Result<Option<crate::models::attestation::Attestation>>;

    /// Record the holder's answer. Returns `false` when the token is unknown
    /// or already answered — first answer wins, exactly like CSAT.
    async fn respond_attestation(
        &self,
        token: &str,
        has_item: bool,
        condition: crate::models::attestation::AttestCondition,
        note: Option<&str>,
    ) -> Result<bool>;

    /// Every attestation, newest ask first.
    async fn list_attestations(&self) -> Result<Vec<crate::models::attestation::Attestation>>;
}

#[async_trait]
pub trait CsatRepository: Send + Sync {
    /// Create the survey row for a ticket at send time. Returns `false` when
    /// one already exists — a re-resolved ticket must not send a second survey.
    async fn create_csat(&self, csat: &crate::models::csat::CsatResponse) -> Result<bool>;

    async fn get_csat_by_token(
        &self,
        token: &str,
    ) -> Result<Option<crate::models::csat::CsatResponse>>;

    /// Record the first response for this token. Returns `false` when the
    /// survey was already answered (the score is left untouched) or the token
    /// is unknown.
    async fn record_csat_score(&self, token: &str, score: i64) -> Result<bool>;

    /// Sent/responded/average for the analytics page.
    async fn csat_stats(&self) -> Result<crate::models::csat::CsatStats>;
}

/// Named bookmarks over the ticket queue (migration 033). Standalone, like the
/// other help-desk repositories, so a mock does not have to grow methods.
#[async_trait]
pub trait SavedViewRepository: Send + Sync {
    async fn create_saved_view(&self, view: &crate::models::saved_view::SavedView) -> Result<()>;

    /// All views, newest first — the list is small and shown in full.
    async fn list_saved_views(&self) -> Result<Vec<crate::models::saved_view::SavedView>>;

    async fn delete_saved_view(&self, id: &str) -> Result<()>;
}

#[async_trait]
pub trait ChangeSetRepository: Send + Sync {
    /// Insert the set and all its items in **one transaction**. A change set
    /// with a partial item list would silently under-apply.
    async fn create_change_set(&self, set: &ChangeSet, items: &[NewChangeSetItem]) -> Result<()>;

    async fn get_change_set(&self, id: &str) -> Result<Option<ChangeSet>>;

    async fn list_change_sets(
        &self,
        filter: &ChangeSetFilter,
        page: PageRequest,
    ) -> Result<Page<ChangeSet>>;

    /// One page of items, optionally narrowed to a single status.
    async fn list_items(
        &self,
        change_set_id: &str,
        status: Option<ChangeSetItemStatus>,
        page: PageRequest,
    ) -> Result<Page<ChangeSetItem>>;

    /// Item counts by status. The caller derives the display status from this
    /// plus the stored status — `partial` is never stored, only computed.
    async fn item_status_counts(&self, change_set_id: &str) -> Result<ChangeSetProgress>;

    /// Move `planned` -> `committing`, but only if the plan still matches what
    /// the operator previewed.
    ///
    /// Implemented as a single conditional `UPDATE` inside a transaction, so
    /// exactly one caller can win the claim. `plan_hash` and
    /// `expected_item_count` are compared against the stored columns and the
    /// live item count — this is the plan->commit staleness guard, and it is
    /// why those two are columns rather than `summary` JSON keys.
    async fn claim_for_commit(
        &self,
        id: &str,
        plan_hash: &str,
        expected_item_count: i64,
    ) -> Result<CommitClaim>;

    /// **The atom.** In one transaction: apply `asset_patch` to the item's
    /// asset (stamping `updated_at`), append `event` to `asset_events`, and set
    /// the item to `applied` with `applied_at = now`.
    ///
    /// ARCHITECTURE §6.3 requires each item's outcome to be persisted before
    /// the next remote call. Either all three writes land or none do — there is
    /// no state where an asset moved but its history and item status disagree.
    ///
    /// `asset_patch` may be `None` for an item whose effect is purely remote.
    async fn mark_item_applied(
        &self,
        item_id: i64,
        asset_patch: Option<&AssetPatch>,
        event: &NewAssetEvent,
    ) -> Result<()>;

    /// **The atom, for an item that brings a device into existence.** In one
    /// transaction: insert `asset`, point the item at it, append `event`, and
    /// set the item to `applied`.
    ///
    /// Separate from [`mark_item_applied`](Self::mark_item_applied) because a
    /// create is an `INSERT`, not a patch, and because the item's `asset_id` is
    /// necessarily NULL until the row exists — the foreign key forbids naming
    /// an asset that has not been written yet.
    ///
    /// The asset's id is fixed at plan time and carried in the item, so a
    /// commit that runs twice collides on the primary key and fails loudly
    /// rather than creating the device a second time.
    async fn mark_item_created(
        &self,
        item_id: i64,
        asset: &Asset,
        event: &NewAssetEvent,
    ) -> Result<()>;

    /// Record a non-applied outcome: `failed`, `indeterminate` or `skipped`.
    ///
    /// Passing [`ChangeSetItemStatus::Applied`] is rejected — `applied` must go
    /// through [`mark_item_applied`](Self::mark_item_applied) so the asset
    /// write and the audit event cannot be skipped.
    async fn mark_item_outcome(
        &self,
        item_id: i64,
        status: ChangeSetItemStatus,
        error: Option<&str>,
    ) -> Result<()>;

    /// Move `committing` -> `committed` and stamp `committed_at`. Called once
    /// the commit loop has run to completion, regardless of per-item outcomes.
    async fn finish_commit(&self, id: &str) -> Result<()>;

    /// Move `planned` -> `discarded`. Returns `false` if the set was not
    /// `planned` — a set already committing or committed is never discardable.
    async fn discard_change_set(&self, id: &str) -> Result<bool>;

    /// Re-arm items in `('pending','failed','indeterminate')` back to
    /// `pending` and move the set back to `planned`, so a new commit job can
    /// run over only those items. Returns the number of items re-armed.
    ///
    /// This is the explicit human re-arm from §6.3 — nothing auto-resumes.
    async fn rearm_failed_items(&self, change_set_id: &str) -> Result<i64>;
}
