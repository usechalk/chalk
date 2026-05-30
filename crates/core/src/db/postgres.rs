//! PostgreSQL implementation of `ChalkRepository`.
//!
//! Behavior parity with `SqliteRepository`. Differences from SQLite:
//! - Placeholder syntax: `$1, $2, …` instead of `?1, ?2, …`.
//! - Timestamps: `TIMESTAMPTZ` columns are read/written as `DateTime<Utc>`
//!   directly. Two exceptions, both unchanged from SQLite for compatibility:
//!     - `access_tokens` columns are accessed as `String` because the
//!       `AccessToken` model declares string fields with `FromRow`.
//!     - `admin_sessions` and `admin_audit_log.created_at` columns: in SQLite
//!       these are TEXT formatted as `%Y-%m-%d %H:%M:%S`. The Postgres
//!       migration uses `TIMESTAMPTZ NOT NULL DEFAULT now()`. We bind/read
//!       `DateTime<Utc>` here.
//! - Booleans: native `BOOLEAN`, no integer coercion.
//! - JSON: columns declared `JSONB` in the migrations are read as
//!   `serde_json::Value` and written via the same.
//! - Auto-increment: `BIGSERIAL` columns return their id via `RETURNING id`.
//! - Conflict resolution: `INSERT … ON CONFLICT (pk) DO UPDATE SET …`.

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use sqlx::{PgPool, Row};
use std::collections::HashMap;

use crate::error::Result;
use crate::models::access_token::AccessToken;
use crate::models::sso::{
    OidcAuthorizationCode, PortalSession, SsoPartner, SsoPartnerSource, SsoProtocol,
};
use crate::models::{
    academic_session::AcademicSession,
    ad_sync::{AdSyncRun, AdSyncRunStatus, AdSyncStatus, AdSyncUserState},
    audit::{AdminAuditEntry, AdminSession},
    class::Class,
    common::{ClassType, EnrollmentRole, OrgType, RoleType, SessionType, Sex, Status},
    course::Course,
    demographics::Demographics,
    enrollment::Enrollment,
    google_sync::{GoogleSyncRun, GoogleSyncRunStatus, GoogleSyncStatus, GoogleSyncUserState},
    idp::{AuthLogEntry, AuthMethod, IdpSession, PicturePassword, QrBadge},
    org::Org,
    sync::{SyncRun, SyncStatus, UserCounts, UserFilter},
    user::{User, UserIdentifier},
};
use crate::webhooks::models::{
    DeliveryStatus, WebhookDelivery, WebhookEndpoint, WebhookMode, WebhookScoping,
    WebhookSecurityMode, WebhookSource,
};

use super::repository::{
    AcademicSessionRepository, AccessTokenRepository, AdSyncConfigRecord, AdSyncRunRepository,
    AdSyncStateRepository, AdminAuditRepository, AdminSessionRepository, ApiTokenRepository,
    ChalkRepository, ClassRepository, ConfigRepository, CourseRepository, DemographicsRepository,
    EnrollmentRepository, ExternalIdRepository, GoogleSyncConfigRecord, GoogleSyncRunRepository,
    GoogleSyncStateRepository, IdpAuthLogRepository, IdpConfigRecord, IdpSessionRepository,
    MagicLoginRepository, OidcCodeRepository, OrgRepository, PasswordRepository,
    PasswordResetTokenRepository, PicturePasswordRepository, PortalSessionRepository,
    QrBadgeRepository, SisConfigRecord, SsoPartnerRepository, SyncRepository, TenantConfigRepo,
    UserRepository, WebhookDeliveryRepository, WebhookEndpointRepository,
};

use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct PostgresRepository {
    pool: PgPool,
    #[allow(dead_code)]
    schema: String,
}

impl PostgresRepository {
    pub fn new(pool: PgPool, schema: String) -> Self {
        Self { pool, schema }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn row_to_user(&self, row: Option<sqlx::postgres::PgRow>) -> Result<Option<User>> {
        match row {
            Some(r) => {
                let sid: String = r.get("sourced_id");
                let (orgs, agents, user_ids, grades) =
                    load_user_junction_data(&self.pool, &sid).await?;
                Ok(Some(User {
                    sourced_id: sid,
                    status: parse_status(r.get("status")),
                    date_last_modified: r.get("date_last_modified"),
                    metadata: r.get("metadata"),
                    username: r.get("username"),
                    enabled_user: r.get("enabled_user"),
                    given_name: r.get("given_name"),
                    family_name: r.get("family_name"),
                    middle_name: r.get("middle_name"),
                    role: parse_role_type(r.get("role")),
                    identifier: r.get("identifier"),
                    email: r.get("email"),
                    sms: r.get("sms"),
                    phone: r.get("phone"),
                    orgs,
                    agents,
                    user_ids,
                    grades,
                }))
            }
            None => Ok(None),
        }
    }
}

impl ChalkRepository for PostgresRepository {}

// -- Helper functions for parsing enums from DB strings --

fn parse_status(s: &str) -> Status {
    match s {
        "active" => Status::Active,
        "tobedeleted" => Status::ToBeDeleted,
        _ => Status::Active,
    }
}

fn status_to_str(s: &Status) -> &'static str {
    match s {
        Status::Active => "active",
        Status::ToBeDeleted => "tobedeleted",
    }
}

fn parse_org_type(s: &str) -> OrgType {
    match s {
        "department" => OrgType::Department,
        "school" => OrgType::School,
        "district" => OrgType::District,
        "local" => OrgType::Local,
        "state" => OrgType::State,
        "national" => OrgType::National,
        _ => OrgType::School,
    }
}

fn org_type_to_str(t: &OrgType) -> &'static str {
    match t {
        OrgType::Department => "department",
        OrgType::School => "school",
        OrgType::District => "district",
        OrgType::Local => "local",
        OrgType::State => "state",
        OrgType::National => "national",
    }
}

fn parse_session_type(s: &str) -> SessionType {
    match s {
        "term" => SessionType::Term,
        "gradingPeriod" => SessionType::GradingPeriod,
        _ => SessionType::Term,
    }
}

fn session_type_to_str(t: &SessionType) -> &'static str {
    match t {
        SessionType::Term => "term",
        SessionType::GradingPeriod => "gradingPeriod",
    }
}

fn parse_role_type(s: &str) -> RoleType {
    match s {
        "administrator" => RoleType::Administrator,
        "aide" => RoleType::Aide,
        "guardian" => RoleType::Guardian,
        "parent" => RoleType::Parent,
        "proctor" => RoleType::Proctor,
        "student" => RoleType::Student,
        "teacher" => RoleType::Teacher,
        _ => RoleType::Student,
    }
}

fn role_type_to_str(r: &RoleType) -> &'static str {
    match r {
        RoleType::Administrator => "administrator",
        RoleType::Aide => "aide",
        RoleType::Guardian => "guardian",
        RoleType::Parent => "parent",
        RoleType::Proctor => "proctor",
        RoleType::Student => "student",
        RoleType::Teacher => "teacher",
    }
}

fn parse_class_type(s: &str) -> ClassType {
    match s {
        "homeroom" => ClassType::Homeroom,
        "scheduled" => ClassType::Scheduled,
        _ => ClassType::Scheduled,
    }
}

fn class_type_to_str(t: &ClassType) -> &'static str {
    match t {
        ClassType::Homeroom => "homeroom",
        ClassType::Scheduled => "scheduled",
    }
}

fn parse_enrollment_role(s: &str) -> EnrollmentRole {
    match s {
        "administrator" => EnrollmentRole::Administrator,
        "proctor" => EnrollmentRole::Proctor,
        "student" => EnrollmentRole::Student,
        "teacher" => EnrollmentRole::Teacher,
        _ => EnrollmentRole::Student,
    }
}

fn enrollment_role_to_str(r: &EnrollmentRole) -> &'static str {
    match r {
        EnrollmentRole::Administrator => "administrator",
        EnrollmentRole::Proctor => "proctor",
        EnrollmentRole::Student => "student",
        EnrollmentRole::Teacher => "teacher",
    }
}

fn parse_sex(s: &str) -> Sex {
    match s {
        "male" => Sex::Male,
        "female" => Sex::Female,
        _ => Sex::Male,
    }
}

fn sex_to_str(s: &Sex) -> &'static str {
    match s {
        Sex::Male => "male",
        Sex::Female => "female",
    }
}

fn parse_sync_status(s: &str) -> SyncStatus {
    match s {
        "pending" => SyncStatus::Pending,
        "running" => SyncStatus::Running,
        "completed" => SyncStatus::Completed,
        "failed" => SyncStatus::Failed,
        _ => SyncStatus::Pending,
    }
}

fn sync_status_to_str(s: &SyncStatus) -> &'static str {
    match s {
        SyncStatus::Pending => "pending",
        SyncStatus::Running => "running",
        SyncStatus::Completed => "completed",
        SyncStatus::Failed => "failed",
    }
}

fn parse_naive_date(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .unwrap_or_else(|_| NaiveDate::from_ymd_opt(2000, 1, 1).unwrap())
}

fn naive_date_to_str(d: &NaiveDate) -> String {
    d.format("%Y-%m-%d").to_string()
}

fn parse_auth_method(s: &str) -> AuthMethod {
    match s {
        "password" => AuthMethod::Password,
        "qr_badge" => AuthMethod::QrBadge,
        "picture_password" => AuthMethod::PicturePassword,
        "saml" => AuthMethod::Saml,
        _ => AuthMethod::Password,
    }
}

fn auth_method_to_str(m: &AuthMethod) -> &'static str {
    match m {
        AuthMethod::Password => "password",
        AuthMethod::QrBadge => "qr_badge",
        AuthMethod::PicturePassword => "picture_password",
        AuthMethod::Saml => "saml",
    }
}

fn parse_google_sync_status(s: &str) -> GoogleSyncStatus {
    match s {
        "pending" => GoogleSyncStatus::Pending,
        "synced" => GoogleSyncStatus::Synced,
        "error" => GoogleSyncStatus::Error,
        "suspended" => GoogleSyncStatus::Suspended,
        _ => GoogleSyncStatus::Pending,
    }
}

fn google_sync_status_to_str(s: &GoogleSyncStatus) -> &'static str {
    match s {
        GoogleSyncStatus::Pending => "pending",
        GoogleSyncStatus::Synced => "synced",
        GoogleSyncStatus::Error => "error",
        GoogleSyncStatus::Suspended => "suspended",
    }
}

fn parse_google_sync_run_status(s: &str) -> GoogleSyncRunStatus {
    match s {
        "running" => GoogleSyncRunStatus::Running,
        "completed" => GoogleSyncRunStatus::Completed,
        "failed" => GoogleSyncRunStatus::Failed,
        _ => GoogleSyncRunStatus::Running,
    }
}

fn google_sync_run_status_to_str(s: &GoogleSyncRunStatus) -> &'static str {
    match s {
        GoogleSyncRunStatus::Running => "running",
        GoogleSyncRunStatus::Completed => "completed",
        GoogleSyncRunStatus::Failed => "failed",
    }
}

fn parse_sso_protocol(s: &str) -> SsoProtocol {
    match s {
        "oidc" => SsoProtocol::Oidc,
        "clever_compat" => SsoProtocol::CleverCompat,
        "classlink_compat" => SsoProtocol::ClassLinkCompat,
        _ => SsoProtocol::Saml,
    }
}

fn sso_protocol_to_str(p: &SsoProtocol) -> &'static str {
    match p {
        SsoProtocol::Saml => "saml",
        SsoProtocol::Oidc => "oidc",
        SsoProtocol::CleverCompat => "clever_compat",
        SsoProtocol::ClassLinkCompat => "classlink_compat",
    }
}

fn parse_sso_source(s: &str) -> SsoPartnerSource {
    match s {
        "toml" => SsoPartnerSource::Toml,
        "marketplace" => SsoPartnerSource::Marketplace,
        _ => SsoPartnerSource::Database,
    }
}

fn sso_source_to_str(s: &SsoPartnerSource) -> &'static str {
    match s {
        SsoPartnerSource::Toml => "toml",
        SsoPartnerSource::Database => "database",
        SsoPartnerSource::Marketplace => "marketplace",
    }
}

fn parse_webhook_mode(s: &str) -> WebhookMode {
    match s {
        "per_entity" => WebhookMode::PerEntity,
        _ => WebhookMode::Batched,
    }
}

fn webhook_mode_to_str(m: &WebhookMode) -> &'static str {
    match m {
        WebhookMode::Batched => "batched",
        WebhookMode::PerEntity => "per_entity",
    }
}

fn parse_webhook_security_mode(s: &str) -> WebhookSecurityMode {
    match s {
        "encrypted" => WebhookSecurityMode::Encrypted,
        _ => WebhookSecurityMode::SignOnly,
    }
}

fn webhook_security_mode_to_str(m: &WebhookSecurityMode) -> &'static str {
    match m {
        WebhookSecurityMode::SignOnly => "sign_only",
        WebhookSecurityMode::Encrypted => "encrypted",
    }
}

fn parse_webhook_source(s: &str) -> WebhookSource {
    match s {
        "toml" => WebhookSource::Toml,
        "marketplace" => WebhookSource::Marketplace,
        _ => WebhookSource::Database,
    }
}

fn webhook_source_to_str(s: &WebhookSource) -> &'static str {
    match s {
        WebhookSource::Toml => "toml",
        WebhookSource::Database => "database",
        WebhookSource::Marketplace => "marketplace",
    }
}

fn parse_delivery_status(s: &str) -> DeliveryStatus {
    match s {
        "delivered" => DeliveryStatus::Delivered,
        "failed" => DeliveryStatus::Failed,
        "retrying" => DeliveryStatus::Retrying,
        _ => DeliveryStatus::Pending,
    }
}

fn delivery_status_to_str(s: &DeliveryStatus) -> &'static str {
    match s {
        DeliveryStatus::Pending => "pending",
        DeliveryStatus::Delivered => "delivered",
        DeliveryStatus::Failed => "failed",
        DeliveryStatus::Retrying => "retrying",
    }
}

fn parse_ad_sync_status(s: &str) -> AdSyncStatus {
    match s {
        "synced" => AdSyncStatus::Synced,
        "error" => AdSyncStatus::Error,
        "disabled" => AdSyncStatus::Disabled,
        _ => AdSyncStatus::Pending,
    }
}

fn ad_sync_status_to_str(s: &AdSyncStatus) -> &'static str {
    match s {
        AdSyncStatus::Pending => "pending",
        AdSyncStatus::Synced => "synced",
        AdSyncStatus::Error => "error",
        AdSyncStatus::Disabled => "disabled",
    }
}

fn parse_ad_sync_run_status(s: &str) -> AdSyncRunStatus {
    match s {
        "completed" => AdSyncRunStatus::Completed,
        "failed" => AdSyncRunStatus::Failed,
        _ => AdSyncRunStatus::Running,
    }
}

fn ad_sync_run_status_to_str(s: &AdSyncRunStatus) -> &'static str {
    match s {
        AdSyncRunStatus::Running => "running",
        AdSyncRunStatus::Completed => "completed",
        AdSyncRunStatus::Failed => "failed",
    }
}

// -- OrgRepository --

#[async_trait]
impl OrgRepository for PostgresRepository {
    async fn upsert_org(&self, org: &Org) -> Result<()> {
        sqlx::query(
            "INSERT INTO orgs (sourced_id, status, date_last_modified, metadata, name, org_type, identifier, parent_sourced_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (sourced_id) DO UPDATE SET
                status = EXCLUDED.status,
                date_last_modified = EXCLUDED.date_last_modified,
                metadata = EXCLUDED.metadata,
                name = EXCLUDED.name,
                org_type = EXCLUDED.org_type,
                identifier = EXCLUDED.identifier,
                parent_sourced_id = EXCLUDED.parent_sourced_id"
        )
        .bind(&org.sourced_id)
        .bind(status_to_str(&org.status))
        .bind(org.date_last_modified)
        .bind(&org.metadata)
        .bind(&org.name)
        .bind(org_type_to_str(&org.org_type))
        .bind(&org.identifier)
        .bind(&org.parent)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_org(&self, sourced_id: &str) -> Result<Option<Org>> {
        let row = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, name, org_type, identifier, parent_sourced_id FROM orgs WHERE sourced_id = $1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let sid: String = r.get("sourced_id");
                let children_rows =
                    sqlx::query("SELECT sourced_id FROM orgs WHERE parent_sourced_id = $1")
                        .bind(&sid)
                        .fetch_all(&self.pool)
                        .await?;
                let children: Vec<String> = children_rows
                    .iter()
                    .map(|cr| cr.get("sourced_id"))
                    .collect();

                Ok(Some(Org {
                    sourced_id: sid,
                    status: parse_status(r.get("status")),
                    date_last_modified: r.get("date_last_modified"),
                    metadata: r.get("metadata"),
                    name: r.get("name"),
                    org_type: parse_org_type(r.get("org_type")),
                    identifier: r.get("identifier"),
                    parent: r.get("parent_sourced_id"),
                    children,
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_orgs(&self) -> Result<Vec<Org>> {
        let rows = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, name, org_type, identifier, parent_sourced_id FROM orgs"
        )
        .fetch_all(&self.pool)
        .await?;

        // Batch-load children: one query that buckets each org's children by
        // its parent_sourced_id. Replaces N per-parent SELECTs with a single
        // SELECT-and-group pass.
        let parent_ids: Vec<String> = rows.iter().map(|r| r.get("sourced_id")).collect();
        let child_rows = sqlx::query(
            "SELECT sourced_id, parent_sourced_id FROM orgs WHERE parent_sourced_id = ANY($1::text[])"
        )
        .bind(&parent_ids)
        .fetch_all(&self.pool)
        .await?;
        let mut children_by_parent: HashMap<String, Vec<String>> = HashMap::new();
        for cr in &child_rows {
            let parent: String = cr.get("parent_sourced_id");
            let child: String = cr.get("sourced_id");
            children_by_parent.entry(parent).or_default().push(child);
        }

        let mut orgs = Vec::with_capacity(rows.len());
        for r in &rows {
            let sid: String = r.get("sourced_id");
            let children = children_by_parent.remove(&sid).unwrap_or_default();
            orgs.push(Org {
                sourced_id: sid,
                status: parse_status(r.get("status")),
                date_last_modified: r.get("date_last_modified"),
                metadata: r.get("metadata"),
                name: r.get("name"),
                org_type: parse_org_type(r.get("org_type")),
                identifier: r.get("identifier"),
                parent: r.get("parent_sourced_id"),
                children,
            });
        }
        Ok(orgs)
    }

    async fn delete_org(&self, sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM orgs WHERE sourced_id = $1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- AcademicSessionRepository --

#[async_trait]
impl AcademicSessionRepository for PostgresRepository {
    async fn upsert_academic_session(&self, session: &AcademicSession) -> Result<()> {
        sqlx::query(
            "INSERT INTO academic_sessions (sourced_id, status, date_last_modified, metadata, title, start_date, end_date, session_type, parent_sourced_id, school_year)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (sourced_id) DO UPDATE SET
                status = EXCLUDED.status,
                date_last_modified = EXCLUDED.date_last_modified,
                metadata = EXCLUDED.metadata,
                title = EXCLUDED.title,
                start_date = EXCLUDED.start_date,
                end_date = EXCLUDED.end_date,
                session_type = EXCLUDED.session_type,
                parent_sourced_id = EXCLUDED.parent_sourced_id,
                school_year = EXCLUDED.school_year"
        )
        .bind(&session.sourced_id)
        .bind(status_to_str(&session.status))
        .bind(session.date_last_modified)
        .bind(&session.metadata)
        .bind(&session.title)
        .bind(naive_date_to_str(&session.start_date))
        .bind(naive_date_to_str(&session.end_date))
        .bind(session_type_to_str(&session.session_type))
        .bind(&session.parent)
        .bind(&session.school_year)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_academic_session(&self, sourced_id: &str) -> Result<Option<AcademicSession>> {
        let row = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, title, start_date, end_date, session_type, parent_sourced_id, school_year FROM academic_sessions WHERE sourced_id = $1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let sid: String = r.get("sourced_id");
                let children_rows = sqlx::query(
                    "SELECT sourced_id FROM academic_sessions WHERE parent_sourced_id = $1",
                )
                .bind(&sid)
                .fetch_all(&self.pool)
                .await?;
                let children: Vec<String> = children_rows
                    .iter()
                    .map(|cr| cr.get("sourced_id"))
                    .collect();

                let start_date_str: String = r.get("start_date");
                let end_date_str: String = r.get("end_date");
                Ok(Some(AcademicSession {
                    sourced_id: sid,
                    status: parse_status(r.get("status")),
                    date_last_modified: r.get("date_last_modified"),
                    metadata: r.get("metadata"),
                    title: r.get("title"),
                    start_date: parse_naive_date(&start_date_str),
                    end_date: parse_naive_date(&end_date_str),
                    session_type: parse_session_type(r.get("session_type")),
                    parent: r.get("parent_sourced_id"),
                    school_year: r.get("school_year"),
                    children,
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_academic_sessions(&self) -> Result<Vec<AcademicSession>> {
        let rows = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, title, start_date, end_date, session_type, parent_sourced_id, school_year FROM academic_sessions"
        )
        .fetch_all(&self.pool)
        .await?;

        // Batch-load children grouped by parent_sourced_id.
        let parent_ids: Vec<String> = rows.iter().map(|r| r.get("sourced_id")).collect();
        let child_rows = sqlx::query(
            "SELECT sourced_id, parent_sourced_id FROM academic_sessions WHERE parent_sourced_id = ANY($1::text[])"
        )
        .bind(&parent_ids)
        .fetch_all(&self.pool)
        .await?;
        let mut children_by_parent: HashMap<String, Vec<String>> = HashMap::new();
        for cr in &child_rows {
            let parent: String = cr.get("parent_sourced_id");
            let child: String = cr.get("sourced_id");
            children_by_parent.entry(parent).or_default().push(child);
        }

        let mut sessions = Vec::with_capacity(rows.len());
        for r in &rows {
            let sid: String = r.get("sourced_id");
            let children = children_by_parent.remove(&sid).unwrap_or_default();
            let start_date_str: String = r.get("start_date");
            let end_date_str: String = r.get("end_date");
            sessions.push(AcademicSession {
                sourced_id: sid,
                status: parse_status(r.get("status")),
                date_last_modified: r.get("date_last_modified"),
                metadata: r.get("metadata"),
                title: r.get("title"),
                start_date: parse_naive_date(&start_date_str),
                end_date: parse_naive_date(&end_date_str),
                session_type: parse_session_type(r.get("session_type")),
                parent: r.get("parent_sourced_id"),
                school_year: r.get("school_year"),
                children,
            });
        }
        Ok(sessions)
    }

    async fn delete_academic_session(&self, sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM academic_sessions WHERE sourced_id = $1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- UserRepository --

async fn load_user_junction_data(
    pool: &PgPool,
    user_sourced_id: &str,
) -> Result<(Vec<String>, Vec<String>, Vec<UserIdentifier>, Vec<String>)> {
    let org_rows = sqlx::query("SELECT org_sourced_id FROM user_orgs WHERE user_sourced_id = $1")
        .bind(user_sourced_id)
        .fetch_all(pool)
        .await?;
    let orgs: Vec<String> = org_rows.iter().map(|r| r.get("org_sourced_id")).collect();

    let agent_rows =
        sqlx::query("SELECT agent_sourced_id FROM user_agents WHERE user_sourced_id = $1")
            .bind(user_sourced_id)
            .fetch_all(pool)
            .await?;
    let agents: Vec<String> = agent_rows
        .iter()
        .map(|r| r.get("agent_sourced_id"))
        .collect();

    let id_rows =
        sqlx::query("SELECT type, identifier FROM user_identifiers WHERE user_sourced_id = $1")
            .bind(user_sourced_id)
            .fetch_all(pool)
            .await?;
    let user_ids: Vec<UserIdentifier> = id_rows
        .iter()
        .map(|r| UserIdentifier {
            type_: r.get("type"),
            identifier: r.get("identifier"),
        })
        .collect();

    let grade_rows = sqlx::query("SELECT grade FROM user_grades WHERE user_sourced_id = $1")
        .bind(user_sourced_id)
        .fetch_all(pool)
        .await?;
    let grades: Vec<String> = grade_rows.iter().map(|r| r.get("grade")).collect();

    Ok((orgs, agents, user_ids, grades))
}

/// Batch-load all four user junction tables with one query per table,
/// regardless of how many users are involved. Returns four maps keyed by
/// user_sourced_id. Replaces the per-user 4-query fan-out for `list_users`.
type UserJunctionMaps = (
    HashMap<String, Vec<String>>,
    HashMap<String, Vec<String>>,
    HashMap<String, Vec<UserIdentifier>>,
    HashMap<String, Vec<String>>,
);

async fn batch_load_user_junctions(pool: &PgPool, user_ids: &[String]) -> Result<UserJunctionMaps> {
    let mut orgs_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut agents_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut ids_map: HashMap<String, Vec<UserIdentifier>> = HashMap::new();
    let mut grades_map: HashMap<String, Vec<String>> = HashMap::new();

    if user_ids.is_empty() {
        return Ok((orgs_map, agents_map, ids_map, grades_map));
    }

    let org_rows = sqlx::query(
        "SELECT user_sourced_id, org_sourced_id FROM user_orgs WHERE user_sourced_id = ANY($1::text[])",
    )
    .bind(user_ids)
    .fetch_all(pool)
    .await?;
    for r in &org_rows {
        let k: String = r.get("user_sourced_id");
        let v: String = r.get("org_sourced_id");
        orgs_map.entry(k).or_default().push(v);
    }

    let agent_rows = sqlx::query(
        "SELECT user_sourced_id, agent_sourced_id FROM user_agents WHERE user_sourced_id = ANY($1::text[])",
    )
    .bind(user_ids)
    .fetch_all(pool)
    .await?;
    for r in &agent_rows {
        let k: String = r.get("user_sourced_id");
        let v: String = r.get("agent_sourced_id");
        agents_map.entry(k).or_default().push(v);
    }

    let id_rows = sqlx::query(
        "SELECT user_sourced_id, type, identifier FROM user_identifiers WHERE user_sourced_id = ANY($1::text[])",
    )
    .bind(user_ids)
    .fetch_all(pool)
    .await?;
    for r in &id_rows {
        let k: String = r.get("user_sourced_id");
        ids_map.entry(k).or_default().push(UserIdentifier {
            type_: r.get("type"),
            identifier: r.get("identifier"),
        });
    }

    let grade_rows = sqlx::query(
        "SELECT user_sourced_id, grade FROM user_grades WHERE user_sourced_id = ANY($1::text[])",
    )
    .bind(user_ids)
    .fetch_all(pool)
    .await?;
    for r in &grade_rows {
        let k: String = r.get("user_sourced_id");
        let v: String = r.get("grade");
        grades_map.entry(k).or_default().push(v);
    }

    Ok((orgs_map, agents_map, ids_map, grades_map))
}

#[async_trait]
impl UserRepository for PostgresRepository {
    async fn upsert_user(&self, user: &User) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO users (sourced_id, status, date_last_modified, metadata, username, enabled_user, given_name, family_name, middle_name, role, identifier, email, sms, phone)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT(sourced_id) DO UPDATE SET
                status = EXCLUDED.status,
                date_last_modified = EXCLUDED.date_last_modified,
                metadata = EXCLUDED.metadata,
                username = EXCLUDED.username,
                enabled_user = EXCLUDED.enabled_user,
                given_name = EXCLUDED.given_name,
                family_name = EXCLUDED.family_name,
                middle_name = EXCLUDED.middle_name,
                role = EXCLUDED.role,
                identifier = EXCLUDED.identifier,
                email = EXCLUDED.email,
                sms = EXCLUDED.sms,
                phone = EXCLUDED.phone"
        )
        .bind(&user.sourced_id)
        .bind(status_to_str(&user.status))
        .bind(user.date_last_modified)
        .bind(&user.metadata)
        .bind(&user.username)
        .bind(user.enabled_user)
        .bind(&user.given_name)
        .bind(&user.family_name)
        .bind(&user.middle_name)
        .bind(role_type_to_str(&user.role))
        .bind(&user.identifier)
        .bind(&user.email)
        .bind(&user.sms)
        .bind(&user.phone)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM user_orgs WHERE user_sourced_id = $1")
            .bind(&user.sourced_id)
            .execute(&mut *tx)
            .await?;
        for org_id in &user.orgs {
            sqlx::query("INSERT INTO user_orgs (user_sourced_id, org_sourced_id) VALUES ($1, $2)")
                .bind(&user.sourced_id)
                .bind(org_id)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("DELETE FROM user_agents WHERE user_sourced_id = $1")
            .bind(&user.sourced_id)
            .execute(&mut *tx)
            .await?;
        for agent_id in &user.agents {
            sqlx::query(
                "INSERT INTO user_agents (user_sourced_id, agent_sourced_id) VALUES ($1, $2)",
            )
            .bind(&user.sourced_id)
            .bind(agent_id)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query("DELETE FROM user_identifiers WHERE user_sourced_id = $1")
            .bind(&user.sourced_id)
            .execute(&mut *tx)
            .await?;
        for uid in &user.user_ids {
            sqlx::query("INSERT INTO user_identifiers (user_sourced_id, type, identifier) VALUES ($1, $2, $3)")
                .bind(&user.sourced_id)
                .bind(&uid.type_)
                .bind(&uid.identifier)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("DELETE FROM user_grades WHERE user_sourced_id = $1")
            .bind(&user.sourced_id)
            .execute(&mut *tx)
            .await?;
        for grade in &user.grades {
            sqlx::query("INSERT INTO user_grades (user_sourced_id, grade) VALUES ($1, $2)")
                .bind(&user.sourced_id)
                .bind(grade)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_user(&self, sourced_id: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, username, enabled_user, given_name, family_name, middle_name, role, identifier, email, sms, phone FROM users WHERE sourced_id = $1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;
        self.row_to_user(row).await
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, username, enabled_user, given_name, family_name, middle_name, role, identifier, email, sms, phone FROM users WHERE LOWER(username) = LOWER($1)"
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        self.row_to_user(row).await
    }

    async fn list_users(&self, filter: &UserFilter) -> Result<Vec<User>> {
        let mut sql = String::from(
            "SELECT sourced_id, status, date_last_modified, metadata, username, enabled_user, given_name, family_name, middle_name, role, identifier, email, sms, phone FROM users WHERE 1=1"
        );
        let mut binds: Vec<String> = Vec::new();
        let mut idx = 1usize;

        // role uses a fixed enum-derived string today (`role_type_to_str`)
        // so SQL injection is not currently possible, but switch to a $N
        // bind for defense-in-depth.
        if let Some(ref role) = filter.role {
            sql.push_str(&format!(" AND role = ${idx}"));
            idx += 1;
            binds.push(role_type_to_str(role).to_string());
        }
        if let Some(ref org_id) = filter.org_sourced_id {
            sql.push_str(&format!(
                " AND sourced_id IN (SELECT user_sourced_id FROM user_orgs WHERE org_sourced_id = ${idx})"
            ));
            idx += 1;
            binds.push(org_id.clone());
        }
        if let Some(ref grade) = filter.grade {
            sql.push_str(&format!(
                " AND sourced_id IN (SELECT user_sourced_id FROM user_grades WHERE grade = ${idx})"
            ));
            #[allow(unused_assignments)]
            {
                idx += 1;
            }
            binds.push(grade.clone());
        }

        let mut query = sqlx::query(&sql);
        for b in &binds {
            query = query.bind(b);
        }
        let rows = query.fetch_all(&self.pool).await?;

        // Batch-load all 4 user junction tables: a constant 4 queries
        // regardless of N (was 4*N before).
        let user_ids_vec: Vec<String> = rows.iter().map(|r| r.get("sourced_id")).collect();
        let (mut orgs_map, mut agents_map, mut ids_map, mut grades_map) =
            batch_load_user_junctions(&self.pool, &user_ids_vec).await?;

        let mut users = Vec::with_capacity(rows.len());
        for r in &rows {
            let sid: String = r.get("sourced_id");
            let orgs = orgs_map.remove(&sid).unwrap_or_default();
            let agents = agents_map.remove(&sid).unwrap_or_default();
            let user_ids = ids_map.remove(&sid).unwrap_or_default();
            let grades = grades_map.remove(&sid).unwrap_or_default();
            users.push(User {
                sourced_id: sid,
                status: parse_status(r.get("status")),
                date_last_modified: r.get("date_last_modified"),
                metadata: r.get("metadata"),
                username: r.get("username"),
                enabled_user: r.get("enabled_user"),
                given_name: r.get("given_name"),
                family_name: r.get("family_name"),
                middle_name: r.get("middle_name"),
                role: parse_role_type(r.get("role")),
                identifier: r.get("identifier"),
                email: r.get("email"),
                sms: r.get("sms"),
                phone: r.get("phone"),
                orgs,
                agents,
                user_ids,
                grades,
            });
        }
        Ok(users)
    }

    async fn delete_user(&self, sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM users WHERE sourced_id = $1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_user_counts(&self) -> Result<UserCounts> {
        let row = sqlx::query(
            "SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE role = 'student') as students,
                COUNT(*) FILTER (WHERE role = 'teacher') as teachers,
                COUNT(*) FILTER (WHERE role = 'administrator') as administrators,
                COUNT(*) FILTER (WHERE role NOT IN ('student', 'teacher', 'administrator')) as other
             FROM users",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(UserCounts {
            total: row.get::<i64, _>("total"),
            students: row.get::<i64, _>("students"),
            teachers: row.get::<i64, _>("teachers"),
            administrators: row.get::<i64, _>("administrators"),
            other: row.get::<i64, _>("other"),
        })
    }
}

// -- CourseRepository --

#[async_trait]
impl CourseRepository for PostgresRepository {
    async fn upsert_course(&self, course: &Course) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO courses (sourced_id, status, date_last_modified, metadata, title, school_year, course_code, org_sourced_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (sourced_id) DO UPDATE SET
                status = EXCLUDED.status,
                date_last_modified = EXCLUDED.date_last_modified,
                metadata = EXCLUDED.metadata,
                title = EXCLUDED.title,
                school_year = EXCLUDED.school_year,
                course_code = EXCLUDED.course_code,
                org_sourced_id = EXCLUDED.org_sourced_id"
        )
        .bind(&course.sourced_id)
        .bind(status_to_str(&course.status))
        .bind(course.date_last_modified)
        .bind(&course.metadata)
        .bind(&course.title)
        .bind(&course.school_year)
        .bind(&course.course_code)
        .bind(&course.org)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM course_grades WHERE course_sourced_id = $1")
            .bind(&course.sourced_id)
            .execute(&mut *tx)
            .await?;
        for grade in &course.grades {
            sqlx::query("INSERT INTO course_grades (course_sourced_id, grade) VALUES ($1, $2)")
                .bind(&course.sourced_id)
                .bind(grade)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("DELETE FROM course_subjects WHERE course_sourced_id = $1")
            .bind(&course.sourced_id)
            .execute(&mut *tx)
            .await?;
        for subject in &course.subjects {
            sqlx::query("INSERT INTO course_subjects (course_sourced_id, subject) VALUES ($1, $2)")
                .bind(&course.sourced_id)
                .bind(subject)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_course(&self, sourced_id: &str) -> Result<Option<Course>> {
        let row = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, title, school_year, course_code, org_sourced_id FROM courses WHERE sourced_id = $1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let sid: String = r.get("sourced_id");
                let grade_rows =
                    sqlx::query("SELECT grade FROM course_grades WHERE course_sourced_id = $1")
                        .bind(&sid)
                        .fetch_all(&self.pool)
                        .await?;
                let grades: Vec<String> = grade_rows.iter().map(|gr| gr.get("grade")).collect();

                let subject_rows =
                    sqlx::query("SELECT subject FROM course_subjects WHERE course_sourced_id = $1")
                        .bind(&sid)
                        .fetch_all(&self.pool)
                        .await?;
                let subjects: Vec<String> =
                    subject_rows.iter().map(|sr| sr.get("subject")).collect();

                Ok(Some(Course {
                    sourced_id: sid,
                    status: parse_status(r.get("status")),
                    date_last_modified: r.get("date_last_modified"),
                    metadata: r.get("metadata"),
                    title: r.get("title"),
                    school_year: r.get("school_year"),
                    course_code: r.get("course_code"),
                    grades,
                    subjects,
                    org: r.get("org_sourced_id"),
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_courses(&self) -> Result<Vec<Course>> {
        let rows = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, title, school_year, course_code, org_sourced_id FROM courses"
        )
        .fetch_all(&self.pool)
        .await?;

        // Batch-load both junction tables; constant 2 queries regardless of N.
        let course_ids: Vec<String> = rows.iter().map(|r| r.get("sourced_id")).collect();
        let mut grades_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut subjects_map: HashMap<String, Vec<String>> = HashMap::new();
        if !course_ids.is_empty() {
            let grade_rows = sqlx::query(
                "SELECT course_sourced_id, grade FROM course_grades WHERE course_sourced_id = ANY($1::text[])",
            )
            .bind(&course_ids)
            .fetch_all(&self.pool)
            .await?;
            for gr in &grade_rows {
                let k: String = gr.get("course_sourced_id");
                let v: String = gr.get("grade");
                grades_map.entry(k).or_default().push(v);
            }

            let subject_rows = sqlx::query(
                "SELECT course_sourced_id, subject FROM course_subjects WHERE course_sourced_id = ANY($1::text[])",
            )
            .bind(&course_ids)
            .fetch_all(&self.pool)
            .await?;
            for sr in &subject_rows {
                let k: String = sr.get("course_sourced_id");
                let v: String = sr.get("subject");
                subjects_map.entry(k).or_default().push(v);
            }
        }

        let mut courses = Vec::with_capacity(rows.len());
        for r in &rows {
            let sid: String = r.get("sourced_id");
            let grades = grades_map.remove(&sid).unwrap_or_default();
            let subjects = subjects_map.remove(&sid).unwrap_or_default();
            courses.push(Course {
                sourced_id: sid,
                status: parse_status(r.get("status")),
                date_last_modified: r.get("date_last_modified"),
                metadata: r.get("metadata"),
                title: r.get("title"),
                school_year: r.get("school_year"),
                course_code: r.get("course_code"),
                grades,
                subjects,
                org: r.get("org_sourced_id"),
            });
        }
        Ok(courses)
    }

    async fn delete_course(&self, sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM courses WHERE sourced_id = $1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- ClassRepository --

async fn load_class_junction_data(
    pool: &PgPool,
    class_sourced_id: &str,
) -> Result<(Vec<String>, Vec<String>, Vec<String>, Vec<String>)> {
    let term_rows = sqlx::query(
        "SELECT academic_session_sourced_id FROM class_terms WHERE class_sourced_id = $1",
    )
    .bind(class_sourced_id)
    .fetch_all(pool)
    .await?;
    let terms: Vec<String> = term_rows
        .iter()
        .map(|r| r.get("academic_session_sourced_id"))
        .collect();

    let grade_rows = sqlx::query("SELECT grade FROM class_grades WHERE class_sourced_id = $1")
        .bind(class_sourced_id)
        .fetch_all(pool)
        .await?;
    let grades: Vec<String> = grade_rows.iter().map(|r| r.get("grade")).collect();

    let subject_rows =
        sqlx::query("SELECT subject FROM class_subjects WHERE class_sourced_id = $1")
            .bind(class_sourced_id)
            .fetch_all(pool)
            .await?;
    let subjects: Vec<String> = subject_rows.iter().map(|r| r.get("subject")).collect();

    let period_rows = sqlx::query("SELECT period FROM class_periods WHERE class_sourced_id = $1")
        .bind(class_sourced_id)
        .fetch_all(pool)
        .await?;
    let periods: Vec<String> = period_rows.iter().map(|r| r.get("period")).collect();

    Ok((terms, grades, subjects, periods))
}

/// Batch-load all four class junction tables. One query per table (4 total)
/// regardless of how many classes are involved. Returns four maps keyed by
/// class_sourced_id.
type ClassJunctionMaps = (
    HashMap<String, Vec<String>>,
    HashMap<String, Vec<String>>,
    HashMap<String, Vec<String>>,
    HashMap<String, Vec<String>>,
);

async fn batch_load_class_junctions(
    pool: &PgPool,
    class_ids: &[String],
) -> Result<ClassJunctionMaps> {
    let mut terms_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut grades_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut subjects_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut periods_map: HashMap<String, Vec<String>> = HashMap::new();

    if class_ids.is_empty() {
        return Ok((terms_map, grades_map, subjects_map, periods_map));
    }

    let term_rows = sqlx::query(
        "SELECT class_sourced_id, academic_session_sourced_id FROM class_terms WHERE class_sourced_id = ANY($1::text[])",
    )
    .bind(class_ids)
    .fetch_all(pool)
    .await?;
    for r in &term_rows {
        let k: String = r.get("class_sourced_id");
        let v: String = r.get("academic_session_sourced_id");
        terms_map.entry(k).or_default().push(v);
    }

    let grade_rows = sqlx::query(
        "SELECT class_sourced_id, grade FROM class_grades WHERE class_sourced_id = ANY($1::text[])",
    )
    .bind(class_ids)
    .fetch_all(pool)
    .await?;
    for r in &grade_rows {
        let k: String = r.get("class_sourced_id");
        let v: String = r.get("grade");
        grades_map.entry(k).or_default().push(v);
    }

    let subject_rows = sqlx::query(
        "SELECT class_sourced_id, subject FROM class_subjects WHERE class_sourced_id = ANY($1::text[])",
    )
    .bind(class_ids)
    .fetch_all(pool)
    .await?;
    for r in &subject_rows {
        let k: String = r.get("class_sourced_id");
        let v: String = r.get("subject");
        subjects_map.entry(k).or_default().push(v);
    }

    let period_rows = sqlx::query(
        "SELECT class_sourced_id, period FROM class_periods WHERE class_sourced_id = ANY($1::text[])",
    )
    .bind(class_ids)
    .fetch_all(pool)
    .await?;
    for r in &period_rows {
        let k: String = r.get("class_sourced_id");
        let v: String = r.get("period");
        periods_map.entry(k).or_default().push(v);
    }

    Ok((terms_map, grades_map, subjects_map, periods_map))
}

#[async_trait]
impl ClassRepository for PostgresRepository {
    async fn upsert_class(&self, class: &Class) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO classes (sourced_id, status, date_last_modified, metadata, title, class_code, class_type, location, course_sourced_id, school_sourced_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (sourced_id) DO UPDATE SET
                status = EXCLUDED.status,
                date_last_modified = EXCLUDED.date_last_modified,
                metadata = EXCLUDED.metadata,
                title = EXCLUDED.title,
                class_code = EXCLUDED.class_code,
                class_type = EXCLUDED.class_type,
                location = EXCLUDED.location,
                course_sourced_id = EXCLUDED.course_sourced_id,
                school_sourced_id = EXCLUDED.school_sourced_id"
        )
        .bind(&class.sourced_id)
        .bind(status_to_str(&class.status))
        .bind(class.date_last_modified)
        .bind(&class.metadata)
        .bind(&class.title)
        .bind(&class.class_code)
        .bind(class_type_to_str(&class.class_type))
        .bind(&class.location)
        .bind(&class.course)
        .bind(&class.school)
        .execute(&mut *tx)
        .await?;

        for (table, values) in [
            ("class_terms", &class.terms),
            ("class_grades", &class.grades),
            ("class_subjects", &class.subjects),
            ("class_periods", &class.periods),
        ] {
            let col = match table {
                "class_terms" => "academic_session_sourced_id",
                "class_grades" => "grade",
                "class_subjects" => "subject",
                "class_periods" => "period",
                _ => unreachable!(),
            };
            let del = format!("DELETE FROM {table} WHERE class_sourced_id = $1");
            sqlx::query(&del)
                .bind(&class.sourced_id)
                .execute(&mut *tx)
                .await?;
            let ins = format!("INSERT INTO {table} (class_sourced_id, {col}) VALUES ($1, $2)");
            for v in values {
                sqlx::query(&ins)
                    .bind(&class.sourced_id)
                    .bind(v)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_class(&self, sourced_id: &str) -> Result<Option<Class>> {
        let row = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, title, class_code, class_type, location, course_sourced_id, school_sourced_id FROM classes WHERE sourced_id = $1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let sid: String = r.get("sourced_id");
                let (terms, grades, subjects, periods) =
                    load_class_junction_data(&self.pool, &sid).await?;
                Ok(Some(Class {
                    sourced_id: sid,
                    status: parse_status(r.get("status")),
                    date_last_modified: r.get("date_last_modified"),
                    metadata: r.get("metadata"),
                    title: r.get("title"),
                    class_code: r.get("class_code"),
                    class_type: parse_class_type(r.get("class_type")),
                    location: r.get("location"),
                    course: r.get("course_sourced_id"),
                    school: r.get("school_sourced_id"),
                    terms,
                    grades,
                    subjects,
                    periods,
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_classes(&self) -> Result<Vec<Class>> {
        let rows = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, title, class_code, class_type, location, course_sourced_id, school_sourced_id FROM classes"
        )
        .fetch_all(&self.pool)
        .await?;

        // Batch-load all 4 class junction tables: constant 4 queries
        // regardless of N (was 4*N before).
        let class_ids: Vec<String> = rows.iter().map(|r| r.get("sourced_id")).collect();
        let (mut terms_map, mut grades_map, mut subjects_map, mut periods_map) =
            batch_load_class_junctions(&self.pool, &class_ids).await?;

        let mut classes = Vec::with_capacity(rows.len());
        for r in &rows {
            let sid: String = r.get("sourced_id");
            let terms = terms_map.remove(&sid).unwrap_or_default();
            let grades = grades_map.remove(&sid).unwrap_or_default();
            let subjects = subjects_map.remove(&sid).unwrap_or_default();
            let periods = periods_map.remove(&sid).unwrap_or_default();
            classes.push(Class {
                sourced_id: sid,
                status: parse_status(r.get("status")),
                date_last_modified: r.get("date_last_modified"),
                metadata: r.get("metadata"),
                title: r.get("title"),
                class_code: r.get("class_code"),
                class_type: parse_class_type(r.get("class_type")),
                location: r.get("location"),
                course: r.get("course_sourced_id"),
                school: r.get("school_sourced_id"),
                terms,
                grades,
                subjects,
                periods,
            });
        }
        Ok(classes)
    }

    async fn delete_class(&self, sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM classes WHERE sourced_id = $1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- EnrollmentRepository --

fn enrollment_from_row(r: &sqlx::postgres::PgRow) -> Enrollment {
    Enrollment {
        sourced_id: r.get("sourced_id"),
        status: parse_status(r.get("status")),
        date_last_modified: r.get("date_last_modified"),
        metadata: r.get("metadata"),
        user: r.get("user_sourced_id"),
        class: r.get("class_sourced_id"),
        school: r.get("school_sourced_id"),
        role: parse_enrollment_role(r.get("role")),
        primary: r.get("is_primary"),
        begin_date: r
            .get::<Option<String>, _>("begin_date")
            .map(|s| parse_naive_date(&s)),
        end_date: r
            .get::<Option<String>, _>("end_date")
            .map(|s| parse_naive_date(&s)),
    }
}

#[async_trait]
impl EnrollmentRepository for PostgresRepository {
    async fn upsert_enrollment(&self, enrollment: &Enrollment) -> Result<()> {
        sqlx::query(
            "INSERT INTO enrollments (sourced_id, status, date_last_modified, metadata, user_sourced_id, class_sourced_id, school_sourced_id, role, is_primary, begin_date, end_date)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (sourced_id) DO UPDATE SET
                status = EXCLUDED.status,
                date_last_modified = EXCLUDED.date_last_modified,
                metadata = EXCLUDED.metadata,
                user_sourced_id = EXCLUDED.user_sourced_id,
                class_sourced_id = EXCLUDED.class_sourced_id,
                school_sourced_id = EXCLUDED.school_sourced_id,
                role = EXCLUDED.role,
                is_primary = EXCLUDED.is_primary,
                begin_date = EXCLUDED.begin_date,
                end_date = EXCLUDED.end_date"
        )
        .bind(&enrollment.sourced_id)
        .bind(status_to_str(&enrollment.status))
        .bind(enrollment.date_last_modified)
        .bind(&enrollment.metadata)
        .bind(&enrollment.user)
        .bind(&enrollment.class)
        .bind(&enrollment.school)
        .bind(enrollment_role_to_str(&enrollment.role))
        .bind(enrollment.primary)
        .bind(enrollment.begin_date.as_ref().map(naive_date_to_str))
        .bind(enrollment.end_date.as_ref().map(naive_date_to_str))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_enrollment(&self, sourced_id: &str) -> Result<Option<Enrollment>> {
        let row = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, user_sourced_id, class_sourced_id, school_sourced_id, role, is_primary, begin_date, end_date FROM enrollments WHERE sourced_id = $1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| enrollment_from_row(&r)))
    }

    async fn list_enrollments(&self) -> Result<Vec<Enrollment>> {
        let rows = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, user_sourced_id, class_sourced_id, school_sourced_id, role, is_primary, begin_date, end_date FROM enrollments"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(enrollment_from_row).collect())
    }

    async fn list_enrollments_for_user(&self, user_sourced_id: &str) -> Result<Vec<Enrollment>> {
        let rows = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, user_sourced_id, class_sourced_id, school_sourced_id, role, is_primary, begin_date, end_date FROM enrollments WHERE user_sourced_id = $1"
        )
        .bind(user_sourced_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(enrollment_from_row).collect())
    }

    async fn list_enrollments_for_class(&self, class_sourced_id: &str) -> Result<Vec<Enrollment>> {
        let rows = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, user_sourced_id, class_sourced_id, school_sourced_id, role, is_primary, begin_date, end_date FROM enrollments WHERE class_sourced_id = $1"
        )
        .bind(class_sourced_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(enrollment_from_row).collect())
    }

    async fn delete_enrollment(&self, sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM enrollments WHERE sourced_id = $1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- DemographicsRepository --

#[async_trait]
impl DemographicsRepository for PostgresRepository {
    async fn upsert_demographics(&self, demo: &Demographics) -> Result<()> {
        sqlx::query(
            "INSERT INTO demographics (sourced_id, status, date_last_modified, metadata, birth_date, sex, american_indian_or_alaska_native, asian, black_or_african_american, native_hawaiian_or_other_pacific_islander, white, demographic_race_two_or_more_races, hispanic_or_latino_ethnicity, country_of_birth_code, state_of_birth_abbreviation, city_of_birth, public_school_residence_status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
             ON CONFLICT (sourced_id) DO UPDATE SET
                status = EXCLUDED.status,
                date_last_modified = EXCLUDED.date_last_modified,
                metadata = EXCLUDED.metadata,
                birth_date = EXCLUDED.birth_date,
                sex = EXCLUDED.sex,
                american_indian_or_alaska_native = EXCLUDED.american_indian_or_alaska_native,
                asian = EXCLUDED.asian,
                black_or_african_american = EXCLUDED.black_or_african_american,
                native_hawaiian_or_other_pacific_islander = EXCLUDED.native_hawaiian_or_other_pacific_islander,
                white = EXCLUDED.white,
                demographic_race_two_or_more_races = EXCLUDED.demographic_race_two_or_more_races,
                hispanic_or_latino_ethnicity = EXCLUDED.hispanic_or_latino_ethnicity,
                country_of_birth_code = EXCLUDED.country_of_birth_code,
                state_of_birth_abbreviation = EXCLUDED.state_of_birth_abbreviation,
                city_of_birth = EXCLUDED.city_of_birth,
                public_school_residence_status = EXCLUDED.public_school_residence_status"
        )
        .bind(&demo.sourced_id)
        .bind(status_to_str(&demo.status))
        .bind(demo.date_last_modified)
        .bind(&demo.metadata)
        .bind(demo.birth_date.as_ref().map(naive_date_to_str))
        .bind(demo.sex.as_ref().map(sex_to_str))
        .bind(demo.american_indian_or_alaska_native)
        .bind(demo.asian)
        .bind(demo.black_or_african_american)
        .bind(demo.native_hawaiian_or_other_pacific_islander)
        .bind(demo.white)
        .bind(demo.demographic_race_two_or_more_races)
        .bind(demo.hispanic_or_latino_ethnicity)
        .bind(&demo.country_of_birth_code)
        .bind(&demo.state_of_birth_abbreviation)
        .bind(&demo.city_of_birth)
        .bind(&demo.public_school_residence_status)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_demographics(&self, sourced_id: &str) -> Result<Option<Demographics>> {
        let row = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, birth_date, sex, american_indian_or_alaska_native, asian, black_or_african_american, native_hawaiian_or_other_pacific_islander, white, demographic_race_two_or_more_races, hispanic_or_latino_ethnicity, country_of_birth_code, state_of_birth_abbreviation, city_of_birth, public_school_residence_status FROM demographics WHERE sourced_id = $1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| demo_from_row(&r)))
    }

    async fn list_demographics(&self) -> Result<Vec<Demographics>> {
        let rows = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, birth_date, sex, american_indian_or_alaska_native, asian, black_or_african_american, native_hawaiian_or_other_pacific_islander, white, demographic_race_two_or_more_races, hispanic_or_latino_ethnicity, country_of_birth_code, state_of_birth_abbreviation, city_of_birth, public_school_residence_status FROM demographics"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(demo_from_row).collect())
    }

    async fn delete_demographics(&self, sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM demographics WHERE sourced_id = $1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

fn demo_from_row(r: &sqlx::postgres::PgRow) -> Demographics {
    Demographics {
        sourced_id: r.get("sourced_id"),
        status: parse_status(r.get("status")),
        date_last_modified: r.get("date_last_modified"),
        metadata: r.get("metadata"),
        birth_date: r
            .get::<Option<String>, _>("birth_date")
            .map(|s| parse_naive_date(&s)),
        sex: r.get::<Option<String>, _>("sex").map(|s| parse_sex(&s)),
        american_indian_or_alaska_native: r.get("american_indian_or_alaska_native"),
        asian: r.get("asian"),
        black_or_african_american: r.get("black_or_african_american"),
        native_hawaiian_or_other_pacific_islander: r
            .get("native_hawaiian_or_other_pacific_islander"),
        white: r.get("white"),
        demographic_race_two_or_more_races: r.get("demographic_race_two_or_more_races"),
        hispanic_or_latino_ethnicity: r.get("hispanic_or_latino_ethnicity"),
        country_of_birth_code: r.get("country_of_birth_code"),
        state_of_birth_abbreviation: r.get("state_of_birth_abbreviation"),
        city_of_birth: r.get("city_of_birth"),
        public_school_residence_status: r.get("public_school_residence_status"),
    }
}

// -- SyncRepository --

#[async_trait]
impl SyncRepository for PostgresRepository {
    async fn create_sync_run(&self, provider: &str) -> Result<SyncRun> {
        let now = Utc::now();
        let row = sqlx::query(
            "INSERT INTO sync_runs (provider, status, started_at, users_synced, orgs_synced, courses_synced, classes_synced, enrollments_synced)
             VALUES ($1, $2, $3, 0, 0, 0, 0, 0) RETURNING id"
        )
        .bind(provider)
        .bind(sync_status_to_str(&SyncStatus::Running))
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(SyncRun {
            id: row.get::<i64, _>("id"),
            provider: provider.to_string(),
            status: SyncStatus::Running,
            started_at: now,
            completed_at: None,
            error_message: None,
            users_synced: 0,
            orgs_synced: 0,
            courses_synced: 0,
            classes_synced: 0,
            enrollments_synced: 0,
        })
    }

    async fn update_sync_status(
        &self,
        id: i64,
        status: SyncStatus,
        error_message: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE sync_runs SET status = $1, completed_at = $2, error_message = $3 WHERE id = $4",
        )
        .bind(sync_status_to_str(&status))
        .bind(Utc::now())
        .bind(error_message)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
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
        sqlx::query(
            "UPDATE sync_runs SET users_synced = $1, orgs_synced = $2, courses_synced = $3, classes_synced = $4, enrollments_synced = $5 WHERE id = $6"
        )
        .bind(users)
        .bind(orgs)
        .bind(courses)
        .bind(classes)
        .bind(enrollments)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_sync_run(&self, id: i64) -> Result<Option<SyncRun>> {
        let row = sqlx::query(
            "SELECT id, provider, status, started_at, completed_at, error_message, users_synced, orgs_synced, courses_synced, classes_synced, enrollments_synced FROM sync_runs WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| sync_run_from_row(&r)))
    }

    async fn get_latest_sync_run(&self, provider: &str) -> Result<Option<SyncRun>> {
        let row = sqlx::query(
            "SELECT id, provider, status, started_at, completed_at, error_message, users_synced, orgs_synced, courses_synced, classes_synced, enrollments_synced FROM sync_runs WHERE provider = $1 ORDER BY id DESC LIMIT 1"
        )
        .bind(provider)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| sync_run_from_row(&r)))
    }
}

fn sync_run_from_row(r: &sqlx::postgres::PgRow) -> SyncRun {
    SyncRun {
        id: r.get::<i64, _>("id"),
        provider: r.get("provider"),
        status: parse_sync_status(r.get("status")),
        started_at: r.get("started_at"),
        completed_at: r.get("completed_at"),
        error_message: r.get("error_message"),
        users_synced: r.get::<i32, _>("users_synced") as i64,
        orgs_synced: r.get::<i32, _>("orgs_synced") as i64,
        courses_synced: r.get::<i32, _>("courses_synced") as i64,
        classes_synced: r.get::<i32, _>("classes_synced") as i64,
        enrollments_synced: r.get::<i32, _>("enrollments_synced") as i64,
    }
}

// -- IdpSessionRepository --

#[async_trait]
impl IdpSessionRepository for PostgresRepository {
    async fn create_session(&self, session: &IdpSession) -> Result<()> {
        sqlx::query(
            "INSERT INTO idp_sessions (id, user_sourced_id, auth_method, created_at, expires_at, saml_request_id, relay_state)
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(&session.id)
        .bind(&session.user_sourced_id)
        .bind(auth_method_to_str(&session.auth_method))
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(&session.saml_request_id)
        .bind(&session.relay_state)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_session(&self, id: &str) -> Result<Option<IdpSession>> {
        let row = sqlx::query(
            "SELECT id, user_sourced_id, auth_method, created_at, expires_at, saml_request_id, relay_state FROM idp_sessions WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| IdpSession {
            id: r.get("id"),
            user_sourced_id: r.get("user_sourced_id"),
            auth_method: parse_auth_method(r.get("auth_method")),
            created_at: r.get("created_at"),
            expires_at: r.get("expires_at"),
            saml_request_id: r.get("saml_request_id"),
            relay_state: r.get("relay_state"),
        }))
    }

    async fn delete_session(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM idp_sessions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_sessions(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM idp_sessions WHERE expires_at < $1")
            .bind(Utc::now())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn list_sessions_for_user(&self, user_sourced_id: &str) -> Result<Vec<IdpSession>> {
        let rows = sqlx::query(
            "SELECT id, user_sourced_id, auth_method, created_at, expires_at, saml_request_id, relay_state FROM idp_sessions WHERE user_sourced_id = $1 ORDER BY created_at DESC"
        )
        .bind(user_sourced_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| IdpSession {
                id: r.get("id"),
                user_sourced_id: r.get("user_sourced_id"),
                auth_method: parse_auth_method(r.get("auth_method")),
                created_at: r.get("created_at"),
                expires_at: r.get("expires_at"),
                saml_request_id: r.get("saml_request_id"),
                relay_state: r.get("relay_state"),
            })
            .collect())
    }
}

// -- QrBadgeRepository --

#[async_trait]
impl QrBadgeRepository for PostgresRepository {
    async fn create_badge(&self, badge: &QrBadge) -> Result<i64> {
        let row = sqlx::query(
            "INSERT INTO qr_badges (badge_token, user_sourced_id, is_active, created_at, revoked_at)
             VALUES ($1, $2, $3, $4, $5) RETURNING id"
        )
        .bind(&badge.badge_token)
        .bind(&badge.user_sourced_id)
        .bind(badge.is_active)
        .bind(badge.created_at)
        .bind(badge.revoked_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("id"))
    }

    async fn get_badge_by_token(&self, token: &str) -> Result<Option<QrBadge>> {
        let row = sqlx::query(
            "SELECT id, badge_token, user_sourced_id, is_active, created_at, revoked_at FROM qr_badges WHERE badge_token = $1"
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| QrBadge {
            id: r.get::<i64, _>("id"),
            badge_token: r.get("badge_token"),
            user_sourced_id: r.get("user_sourced_id"),
            is_active: r.get("is_active"),
            created_at: r.get("created_at"),
            revoked_at: r.get("revoked_at"),
        }))
    }

    async fn list_badges_for_user(&self, user_sourced_id: &str) -> Result<Vec<QrBadge>> {
        let rows = sqlx::query(
            "SELECT id, badge_token, user_sourced_id, is_active, created_at, revoked_at FROM qr_badges WHERE user_sourced_id = $1 ORDER BY created_at DESC"
        )
        .bind(user_sourced_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| QrBadge {
                id: r.get::<i64, _>("id"),
                badge_token: r.get("badge_token"),
                user_sourced_id: r.get("user_sourced_id"),
                is_active: r.get("is_active"),
                created_at: r.get("created_at"),
                revoked_at: r.get("revoked_at"),
            })
            .collect())
    }

    async fn revoke_badge(&self, id: i64) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE qr_badges SET is_active = FALSE, revoked_at = $1 WHERE id = $2 AND is_active = TRUE",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- PicturePasswordRepository --

#[async_trait]
impl PicturePasswordRepository for PostgresRepository {
    async fn upsert_picture_password(&self, pp: &PicturePassword) -> Result<()> {
        let sequence_json = serde_json::to_string(&pp.image_sequence)
            .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?;
        sqlx::query(
            "INSERT INTO picture_passwords (user_sourced_id, image_sequence) VALUES ($1, $2)
             ON CONFLICT (user_sourced_id) DO UPDATE SET image_sequence = EXCLUDED.image_sequence",
        )
        .bind(&pp.user_sourced_id)
        .bind(&sequence_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_picture_password(&self, user_sourced_id: &str) -> Result<Option<PicturePassword>> {
        let row = sqlx::query(
            "SELECT user_sourced_id, image_sequence FROM picture_passwords WHERE user_sourced_id = $1"
        )
        .bind(user_sourced_id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => {
                let json_str: String = r.get("image_sequence");
                let image_sequence: Vec<String> = serde_json::from_str(&json_str)
                    .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?;
                Ok(Some(PicturePassword {
                    user_sourced_id: r.get("user_sourced_id"),
                    image_sequence,
                }))
            }
            None => Ok(None),
        }
    }

    async fn delete_picture_password(&self, user_sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM picture_passwords WHERE user_sourced_id = $1")
            .bind(user_sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- IdpAuthLogRepository --

#[async_trait]
impl IdpAuthLogRepository for PostgresRepository {
    async fn log_auth_attempt(&self, entry: &AuthLogEntry) -> Result<i64> {
        let row = sqlx::query(
            "INSERT INTO idp_auth_log (user_sourced_id, username, auth_method, success, ip_address, user_agent, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id"
        )
        .bind(&entry.user_sourced_id)
        .bind(&entry.username)
        .bind(auth_method_to_str(&entry.auth_method))
        .bind(entry.success)
        .bind(&entry.ip_address)
        .bind(&entry.user_agent)
        .bind(entry.created_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("id"))
    }

    async fn list_auth_log(&self, limit: i64) -> Result<Vec<AuthLogEntry>> {
        let rows = sqlx::query(
            "SELECT id, user_sourced_id, username, auth_method, success, ip_address, user_agent, created_at FROM idp_auth_log ORDER BY created_at DESC LIMIT $1"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(auth_log_from_row).collect())
    }

    async fn list_auth_log_for_user(
        &self,
        user_sourced_id: &str,
        limit: i64,
    ) -> Result<Vec<AuthLogEntry>> {
        let rows = sqlx::query(
            "SELECT id, user_sourced_id, username, auth_method, success, ip_address, user_agent, created_at FROM idp_auth_log WHERE user_sourced_id = $1 ORDER BY created_at DESC LIMIT $2"
        )
        .bind(user_sourced_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(auth_log_from_row).collect())
    }
}

fn auth_log_from_row(r: &sqlx::postgres::PgRow) -> AuthLogEntry {
    AuthLogEntry {
        id: r.get::<i64, _>("id"),
        user_sourced_id: r.get("user_sourced_id"),
        username: r.get("username"),
        auth_method: parse_auth_method(r.get("auth_method")),
        success: r.get("success"),
        ip_address: r.get("ip_address"),
        user_agent: r.get("user_agent"),
        created_at: r.get("created_at"),
    }
}

// -- GoogleSyncStateRepository --

#[async_trait]
impl GoogleSyncStateRepository for PostgresRepository {
    async fn upsert_sync_state(&self, state: &GoogleSyncUserState) -> Result<()> {
        sqlx::query(
            "INSERT INTO google_sync_state (user_sourced_id, google_id, google_email, google_ou, field_hash, sync_status, last_synced_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (user_sourced_id) DO UPDATE SET
                google_id = EXCLUDED.google_id,
                google_email = EXCLUDED.google_email,
                google_ou = EXCLUDED.google_ou,
                field_hash = EXCLUDED.field_hash,
                sync_status = EXCLUDED.sync_status,
                last_synced_at = EXCLUDED.last_synced_at,
                updated_at = EXCLUDED.updated_at"
        )
        .bind(&state.user_sourced_id)
        .bind(&state.google_id)
        .bind(&state.google_email)
        .bind(&state.google_ou)
        .bind(&state.field_hash)
        .bind(google_sync_status_to_str(&state.sync_status))
        .bind(state.last_synced_at)
        .bind(state.created_at)
        .bind(state.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_sync_state(&self, user_sourced_id: &str) -> Result<Option<GoogleSyncUserState>> {
        let row = sqlx::query(
            "SELECT user_sourced_id, google_id, google_email, google_ou, field_hash, sync_status, last_synced_at, created_at, updated_at FROM google_sync_state WHERE user_sourced_id = $1"
        )
        .bind(user_sourced_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| google_sync_state_from_row(&r)))
    }

    async fn list_sync_states(&self) -> Result<Vec<GoogleSyncUserState>> {
        let rows = sqlx::query(
            "SELECT user_sourced_id, google_id, google_email, google_ou, field_hash, sync_status, last_synced_at, created_at, updated_at FROM google_sync_state"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(google_sync_state_from_row).collect())
    }

    async fn delete_sync_state(&self, user_sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM google_sync_state WHERE user_sourced_id = $1")
            .bind(user_sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

fn google_sync_state_from_row(r: &sqlx::postgres::PgRow) -> GoogleSyncUserState {
    GoogleSyncUserState {
        user_sourced_id: r.get("user_sourced_id"),
        google_id: r.get("google_id"),
        google_email: r.get("google_email"),
        google_ou: r.get("google_ou"),
        field_hash: r.get("field_hash"),
        sync_status: parse_google_sync_status(r.get("sync_status")),
        last_synced_at: r.get("last_synced_at"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}

// -- GoogleSyncRunRepository --

#[async_trait]
impl GoogleSyncRunRepository for PostgresRepository {
    async fn create_google_sync_run(&self, dry_run: bool) -> Result<GoogleSyncRun> {
        let now = Utc::now();
        let row = sqlx::query(
            "INSERT INTO google_sync_runs (started_at, status, dry_run) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(now)
        .bind(google_sync_run_status_to_str(&GoogleSyncRunStatus::Running))
        .bind(dry_run)
        .fetch_one(&self.pool)
        .await?;

        Ok(GoogleSyncRun {
            id: row.get::<i64, _>("id"),
            started_at: now,
            completed_at: None,
            status: GoogleSyncRunStatus::Running,
            users_created: 0,
            users_updated: 0,
            users_suspended: 0,
            ous_created: 0,
            dry_run,
            error_message: None,
        })
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
        sqlx::query(
            "UPDATE google_sync_runs SET status = $1, completed_at = $2, users_created = $3, users_updated = $4, users_suspended = $5, ous_created = $6, error_message = $7 WHERE id = $8"
        )
        .bind(google_sync_run_status_to_str(&status))
        .bind(Utc::now())
        .bind(users_created as i32)
        .bind(users_updated as i32)
        .bind(users_suspended as i32)
        .bind(ous_created as i32)
        .bind(error_message)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_google_sync_run(&self, id: i64) -> Result<Option<GoogleSyncRun>> {
        let row = sqlx::query(
            "SELECT id, started_at, completed_at, status, users_created, users_updated, users_suspended, ous_created, dry_run, error_message FROM google_sync_runs WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| google_sync_run_from_row(&r)))
    }

    async fn get_latest_google_sync_run(&self) -> Result<Option<GoogleSyncRun>> {
        let row = sqlx::query(
            "SELECT id, started_at, completed_at, status, users_created, users_updated, users_suspended, ous_created, dry_run, error_message FROM google_sync_runs ORDER BY id DESC LIMIT 1"
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| google_sync_run_from_row(&r)))
    }

    async fn list_google_sync_runs(&self, limit: i64) -> Result<Vec<GoogleSyncRun>> {
        let rows = sqlx::query(
            "SELECT id, started_at, completed_at, status, users_created, users_updated, users_suspended, ous_created, dry_run, error_message FROM google_sync_runs ORDER BY id DESC LIMIT $1"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(google_sync_run_from_row).collect())
    }
}

fn google_sync_run_from_row(r: &sqlx::postgres::PgRow) -> GoogleSyncRun {
    GoogleSyncRun {
        id: r.get::<i64, _>("id"),
        started_at: r.get("started_at"),
        completed_at: r.get("completed_at"),
        status: parse_google_sync_run_status(r.get("status")),
        users_created: r.get::<i32, _>("users_created") as i64,
        users_updated: r.get::<i32, _>("users_updated") as i64,
        users_suspended: r.get::<i32, _>("users_suspended") as i64,
        ous_created: r.get::<i32, _>("ous_created") as i64,
        dry_run: r.get("dry_run"),
        error_message: r.get("error_message"),
    }
}

// -- PasswordRepository --

#[async_trait]
impl PasswordRepository for PostgresRepository {
    async fn get_password_hash(&self, user_sourced_id: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT password_hash FROM users WHERE sourced_id = $1")
            .bind(user_sourced_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(r.get("password_hash")),
            None => Ok(None),
        }
    }

    async fn set_password_hash(&self, user_sourced_id: &str, hash: &str) -> Result<()> {
        sqlx::query("UPDATE users SET password_hash = $1 WHERE sourced_id = $2")
            .bind(hash)
            .bind(user_sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// -- AdminSessionRepository --

#[async_trait]
impl AdminSessionRepository for PostgresRepository {
    async fn create_admin_session(&self, session: &AdminSession) -> Result<()> {
        sqlx::query(
            "INSERT INTO admin_sessions (token, created_at, expires_at, ip_address) VALUES ($1, $2, $3, $4)",
        )
        .bind(&session.token)
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(&session.ip_address)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_admin_session(&self, token: &str) -> Result<Option<AdminSession>> {
        let row = sqlx::query(
            "SELECT token, created_at, expires_at, ip_address FROM admin_sessions WHERE token = $1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| AdminSession {
            token: r.get("token"),
            created_at: r.get("created_at"),
            expires_at: r.get("expires_at"),
            ip_address: r.get("ip_address"),
        }))
    }

    async fn delete_admin_session(&self, token: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM admin_sessions WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_admin_sessions(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM admin_sessions WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

// -- AdminAuditRepository --

#[async_trait]
impl AdminAuditRepository for PostgresRepository {
    async fn log_admin_action(
        &self,
        action: &str,
        details: Option<&str>,
        admin_ip: Option<&str>,
    ) -> Result<i64> {
        let row = sqlx::query(
            "INSERT INTO admin_audit_log (action, details, admin_ip) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(action)
        .bind(details)
        .bind(admin_ip)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("id"))
    }

    async fn list_admin_audit_log(&self, limit: i64) -> Result<Vec<AdminAuditEntry>> {
        let rows = sqlx::query(
            "SELECT id, action, details, admin_ip, created_at FROM admin_audit_log ORDER BY id DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        let mut entries = Vec::with_capacity(rows.len());
        for r in &rows {
            entries.push(AdminAuditEntry {
                id: r.get::<i64, _>("id"),
                action: r.get("action"),
                details: r.get("details"),
                admin_ip: r.get("admin_ip"),
                created_at: r.get("created_at"),
            });
        }
        Ok(entries)
    }

    async fn prune_admin_audit_log(
        &self,
        older_than: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64> {
        let result = sqlx::query("DELETE FROM admin_audit_log WHERE created_at < $1")
            .bind(older_than)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

// -- ConfigRepository --

#[async_trait]
impl ConfigRepository for PostgresRepository {
    async fn get_config_override(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM config_overrides WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get("value")))
    }

    async fn set_config_override(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO config_overrides (key, value, updated_at) VALUES ($1, $2, now())
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// -- SsoPartnerRepository --

fn row_to_sso_partner(r: &sqlx::postgres::PgRow) -> SsoPartner {
    let roles_json: serde_json::Value = r.get("roles_json");
    let roles: Vec<String> = serde_json::from_value(roles_json).unwrap_or_default();
    let uris_json: serde_json::Value = r.get("oidc_redirect_uris_json");
    let oidc_redirect_uris: Vec<String> = serde_json::from_value(uris_json).unwrap_or_default();

    SsoPartner {
        id: r.get("id"),
        name: r.get("name"),
        logo_url: r.get("logo_url"),
        protocol: parse_sso_protocol(r.get("protocol")),
        enabled: r.get("enabled"),
        source: parse_sso_source(r.get("source")),
        tenant_id: r.get("tenant_id"),
        roles,
        saml_entity_id: r.get("saml_entity_id"),
        saml_acs_url: r.get("saml_acs_url"),
        oidc_client_id: r.get("oidc_client_id"),
        oidc_client_secret: r.get("oidc_client_secret"),
        oidc_redirect_uris,
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}

#[async_trait]
impl SsoPartnerRepository for PostgresRepository {
    async fn upsert_sso_partner(&self, partner: &SsoPartner) -> Result<()> {
        let roles_json = serde_json::to_value(&partner.roles)
            .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?;
        let uris_json = serde_json::to_value(&partner.oidc_redirect_uris)
            .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO sso_partners (id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
             ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                logo_url = EXCLUDED.logo_url,
                protocol = EXCLUDED.protocol,
                enabled = EXCLUDED.enabled,
                source = EXCLUDED.source,
                tenant_id = EXCLUDED.tenant_id,
                roles_json = EXCLUDED.roles_json,
                saml_entity_id = EXCLUDED.saml_entity_id,
                saml_acs_url = EXCLUDED.saml_acs_url,
                oidc_client_id = EXCLUDED.oidc_client_id,
                oidc_client_secret = EXCLUDED.oidc_client_secret,
                oidc_redirect_uris_json = EXCLUDED.oidc_redirect_uris_json,
                updated_at = EXCLUDED.updated_at"
        )
        .bind(&partner.id)
        .bind(&partner.name)
        .bind(&partner.logo_url)
        .bind(sso_protocol_to_str(&partner.protocol))
        .bind(partner.enabled)
        .bind(sso_source_to_str(&partner.source))
        .bind(&partner.tenant_id)
        .bind(&roles_json)
        .bind(&partner.saml_entity_id)
        .bind(&partner.saml_acs_url)
        .bind(&partner.oidc_client_id)
        .bind(&partner.oidc_client_secret)
        .bind(&uris_json)
        .bind(partner.created_at)
        .bind(partner.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_sso_partner(&self, id: &str) -> Result<Option<SsoPartner>> {
        let row = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_sso_partner))
    }

    async fn get_sso_partner_by_entity_id(&self, entity_id: &str) -> Result<Option<SsoPartner>> {
        let row = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners WHERE saml_entity_id = $1"
        )
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_sso_partner))
    }

    async fn get_sso_partner_by_client_id(&self, client_id: &str) -> Result<Option<SsoPartner>> {
        let row = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners WHERE oidc_client_id = $1"
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_sso_partner))
    }

    async fn list_sso_partners(&self) -> Result<Vec<SsoPartner>> {
        let rows = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners ORDER BY name"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_sso_partner).collect())
    }

    async fn list_sso_partners_for_role(&self, role: &str) -> Result<Vec<SsoPartner>> {
        let rows = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners WHERE enabled = TRUE ORDER BY name"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(row_to_sso_partner)
            .filter(|p| p.is_accessible_by_role(role))
            .collect())
    }

    async fn delete_sso_partner(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM sso_partners WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- OidcCodeRepository --

#[async_trait]
impl OidcCodeRepository for PostgresRepository {
    async fn create_oidc_code(&self, code: &OidcAuthorizationCode) -> Result<()> {
        sqlx::query(
            "INSERT INTO oidc_authorization_codes (code, client_id, user_sourced_id, redirect_uri, scope, nonce, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        )
        .bind(&code.code)
        .bind(&code.client_id)
        .bind(&code.user_sourced_id)
        .bind(&code.redirect_uri)
        .bind(&code.scope)
        .bind(&code.nonce)
        .bind(code.created_at)
        .bind(code.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_oidc_code(&self, code: &str) -> Result<Option<OidcAuthorizationCode>> {
        let row = sqlx::query(
            "SELECT code, client_id, user_sourced_id, redirect_uri, scope, nonce, created_at, expires_at FROM oidc_authorization_codes WHERE code = $1"
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| OidcAuthorizationCode {
            code: r.get("code"),
            client_id: r.get("client_id"),
            user_sourced_id: r.get("user_sourced_id"),
            redirect_uri: r.get("redirect_uri"),
            scope: r.get("scope"),
            nonce: r.get("nonce"),
            created_at: r.get("created_at"),
            expires_at: r.get("expires_at"),
        }))
    }

    async fn delete_oidc_code(&self, code: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM oidc_authorization_codes WHERE code = $1")
            .bind(code)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_oidc_codes(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM oidc_authorization_codes WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

// -- PortalSessionRepository --

#[async_trait]
impl PortalSessionRepository for PostgresRepository {
    async fn create_portal_session(&self, session: &PortalSession) -> Result<()> {
        sqlx::query(
            "INSERT INTO portal_sessions (id, user_sourced_id, created_at, expires_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&session.id)
        .bind(&session.user_sourced_id)
        .bind(session.created_at)
        .bind(session.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_portal_session(&self, id: &str) -> Result<Option<PortalSession>> {
        let row = sqlx::query(
            "SELECT id, user_sourced_id, created_at, expires_at FROM portal_sessions WHERE id = $1 AND expires_at > now()"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| PortalSession {
            id: r.get("id"),
            user_sourced_id: r.get("user_sourced_id"),
            created_at: r.get("created_at"),
            expires_at: r.get("expires_at"),
        }))
    }

    async fn delete_portal_session(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM portal_sessions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_portal_sessions(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM portal_sessions WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

// -- WebhookEndpointRepository / WebhookDeliveryRepository --

fn row_to_webhook_endpoint(row: sqlx::postgres::PgRow) -> WebhookEndpoint {
    let scoping_json: serde_json::Value = row.get("scoping_json");
    let scoping: WebhookScoping = serde_json::from_value(scoping_json).unwrap_or_default();

    WebhookEndpoint {
        id: row.get("id"),
        name: row.get("name"),
        url: row.get("url"),
        secret: row.get("secret"),
        enabled: row.get("enabled"),
        mode: parse_webhook_mode(row.get("mode")),
        security_mode: parse_webhook_security_mode(row.get("security_mode")),
        source: parse_webhook_source(row.get("source")),
        tenant_id: row.get("tenant_id"),
        scoping,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn row_to_webhook_delivery(row: sqlx::postgres::PgRow) -> WebhookDelivery {
    WebhookDelivery {
        id: row.get::<i64, _>("id"),
        webhook_endpoint_id: row.get("webhook_endpoint_id"),
        event_id: row.get("event_id"),
        sync_run_id: row.get::<i64, _>("sync_run_id"),
        status: parse_delivery_status(row.get("status")),
        http_status: row.get("http_status"),
        response_body: row.get("response_body"),
        attempt_count: row.get("attempt_count"),
        next_retry_at: row.get("next_retry_at"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

#[async_trait]
impl WebhookEndpointRepository for PostgresRepository {
    async fn upsert_webhook_endpoint(&self, endpoint: &WebhookEndpoint) -> Result<()> {
        let scoping_json = serde_json::to_value(&endpoint.scoping).unwrap_or(serde_json::json!({}));
        sqlx::query(
            "INSERT INTO webhook_endpoints (id, name, url, secret, enabled, mode, security_mode, source, tenant_id, scoping_json, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
             ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                url = EXCLUDED.url,
                secret = EXCLUDED.secret,
                enabled = EXCLUDED.enabled,
                mode = EXCLUDED.mode,
                security_mode = EXCLUDED.security_mode,
                source = EXCLUDED.source,
                tenant_id = EXCLUDED.tenant_id,
                scoping_json = EXCLUDED.scoping_json,
                updated_at = now()",
        )
        .bind(&endpoint.id)
        .bind(&endpoint.name)
        .bind(&endpoint.url)
        .bind(&endpoint.secret)
        .bind(endpoint.enabled)
        .bind(webhook_mode_to_str(&endpoint.mode))
        .bind(webhook_security_mode_to_str(&endpoint.security_mode))
        .bind(webhook_source_to_str(&endpoint.source))
        .bind(&endpoint.tenant_id)
        .bind(&scoping_json)
        .bind(endpoint.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_webhook_endpoint(&self, id: &str) -> Result<Option<WebhookEndpoint>> {
        let row = sqlx::query("SELECT * FROM webhook_endpoints WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(row_to_webhook_endpoint))
    }

    async fn list_webhook_endpoints(&self) -> Result<Vec<WebhookEndpoint>> {
        let rows = sqlx::query("SELECT * FROM webhook_endpoints ORDER BY created_at")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(row_to_webhook_endpoint).collect())
    }

    async fn list_webhook_endpoints_by_source(&self, source: &str) -> Result<Vec<WebhookEndpoint>> {
        let rows =
            sqlx::query("SELECT * FROM webhook_endpoints WHERE source = $1 ORDER BY created_at")
                .bind(source)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.into_iter().map(row_to_webhook_endpoint).collect())
    }

    async fn delete_webhook_endpoint(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM webhook_endpoints WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl WebhookDeliveryRepository for PostgresRepository {
    async fn create_webhook_delivery(&self, delivery: &WebhookDelivery) -> Result<i64> {
        let row = sqlx::query(
            "INSERT INTO webhook_deliveries (webhook_endpoint_id, event_id, sync_run_id, status, http_status, response_body, attempt_count, next_retry_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
        )
        .bind(&delivery.webhook_endpoint_id)
        .bind(&delivery.event_id)
        .bind(delivery.sync_run_id)
        .bind(delivery_status_to_str(&delivery.status))
        .bind(delivery.http_status)
        .bind(&delivery.response_body)
        .bind(delivery.attempt_count)
        .bind(delivery.next_retry_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("id"))
    }

    async fn update_delivery_status(
        &self,
        id: i64,
        status: DeliveryStatus,
        http_status: Option<i32>,
        response_body: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE webhook_deliveries SET status = $1, http_status = $2, response_body = $3, attempt_count = attempt_count + 1, updated_at = now() WHERE id = $4",
        )
        .bind(delivery_status_to_str(&status))
        .bind(http_status)
        .bind(response_body)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_delivery_next_retry_at(
        &self,
        id: i64,
        next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE webhook_deliveries SET next_retry_at = $1, updated_at = now() WHERE id = $2",
        )
        .bind(next_retry_at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_pending_retries(&self, limit: i64) -> Result<Vec<WebhookDelivery>> {
        let rows = sqlx::query(
            "SELECT * FROM webhook_deliveries WHERE status IN ('pending', 'retrying') AND (next_retry_at IS NULL OR next_retry_at <= now()) ORDER BY created_at LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_webhook_delivery).collect())
    }

    async fn list_deliveries_by_webhook(
        &self,
        webhook_endpoint_id: &str,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>> {
        let rows = sqlx::query(
            "SELECT * FROM webhook_deliveries WHERE webhook_endpoint_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(webhook_endpoint_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_webhook_delivery).collect())
    }

    async fn list_deliveries_by_sync_run(&self, sync_run_id: i64) -> Result<Vec<WebhookDelivery>> {
        let rows = sqlx::query(
            "SELECT * FROM webhook_deliveries WHERE sync_run_id = $1 ORDER BY created_at",
        )
        .bind(sync_run_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_webhook_delivery).collect())
    }
}

// -- AdSyncStateRepository --

fn row_to_ad_sync_state(r: &sqlx::postgres::PgRow) -> AdSyncUserState {
    AdSyncUserState {
        user_sourced_id: r.get("user_sourced_id"),
        ad_dn: r.get("ad_dn"),
        ad_sam_account_name: r.get("ad_sam_account_name"),
        ad_upn: r.get("ad_upn"),
        ad_ou: r.get("ad_ou"),
        field_hash: r.get("field_hash"),
        sync_status: parse_ad_sync_status(r.get("sync_status")),
        initial_password: r.get("initial_password"),
        last_synced_at: r.get("last_synced_at"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}

fn row_to_ad_sync_run(r: &sqlx::postgres::PgRow) -> AdSyncRun {
    AdSyncRun {
        id: r.get("id"),
        started_at: r.get("started_at"),
        completed_at: r.get("completed_at"),
        status: parse_ad_sync_run_status(r.get("status")),
        users_created: r.get::<i32, _>("users_created") as i64,
        users_updated: r.get::<i32, _>("users_updated") as i64,
        users_disabled: r.get::<i32, _>("users_disabled") as i64,
        users_skipped: r.get::<i32, _>("users_skipped") as i64,
        groups_created: r.get::<i32, _>("groups_created") as i64,
        groups_updated: r.get::<i32, _>("groups_updated") as i64,
        errors: r.get::<i32, _>("errors") as i64,
        error_details: r.get("error_details"),
        dry_run: r.get("dry_run"),
    }
}

#[async_trait]
impl AdSyncStateRepository for PostgresRepository {
    async fn upsert_ad_sync_state(&self, state: &AdSyncUserState) -> Result<()> {
        sqlx::query(
            "INSERT INTO ad_sync_state (user_sourced_id, ad_dn, ad_sam_account_name, ad_upn, ad_ou, field_hash, sync_status, initial_password, last_synced_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (user_sourced_id) DO UPDATE SET
                ad_dn = EXCLUDED.ad_dn,
                ad_sam_account_name = EXCLUDED.ad_sam_account_name,
                ad_upn = EXCLUDED.ad_upn,
                ad_ou = EXCLUDED.ad_ou,
                field_hash = EXCLUDED.field_hash,
                sync_status = EXCLUDED.sync_status,
                initial_password = EXCLUDED.initial_password,
                last_synced_at = EXCLUDED.last_synced_at,
                updated_at = EXCLUDED.updated_at"
        )
        .bind(&state.user_sourced_id)
        .bind(&state.ad_dn)
        .bind(&state.ad_sam_account_name)
        .bind(&state.ad_upn)
        .bind(&state.ad_ou)
        .bind(&state.field_hash)
        .bind(ad_sync_status_to_str(&state.sync_status))
        .bind(&state.initial_password)
        .bind(state.last_synced_at)
        .bind(state.created_at)
        .bind(state.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_ad_sync_state(&self, user_sourced_id: &str) -> Result<Option<AdSyncUserState>> {
        let row = sqlx::query("SELECT * FROM ad_sync_state WHERE user_sourced_id = $1")
            .bind(user_sourced_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_ad_sync_state))
    }

    async fn list_ad_sync_states(&self) -> Result<Vec<AdSyncUserState>> {
        let rows = sqlx::query("SELECT * FROM ad_sync_state ORDER BY user_sourced_id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_ad_sync_state).collect())
    }

    async fn delete_ad_sync_state(&self, user_sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM ad_sync_state WHERE user_sourced_id = $1")
            .bind(user_sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl AdSyncRunRepository for PostgresRepository {
    async fn create_ad_sync_run(&self, dry_run: bool) -> Result<AdSyncRun> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO ad_sync_runs (id, started_at, status, dry_run) VALUES ($1, $2, 'running', $3)"
        )
        .bind(&id)
        .bind(now)
        .bind(dry_run)
        .execute(&self.pool)
        .await?;

        Ok(AdSyncRun {
            id,
            started_at: now,
            completed_at: None,
            status: AdSyncRunStatus::Running,
            users_created: 0,
            users_updated: 0,
            users_disabled: 0,
            users_skipped: 0,
            groups_created: 0,
            groups_updated: 0,
            errors: 0,
            error_details: None,
            dry_run,
        })
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
        sqlx::query(
            "UPDATE ad_sync_runs SET status = $2, completed_at = $3, users_created = $4, users_updated = $5, users_disabled = $6, users_skipped = $7, groups_created = $8, groups_updated = $9, errors = $10, error_details = $11 WHERE id = $1"
        )
        .bind(id)
        .bind(ad_sync_run_status_to_str(&status))
        .bind(Utc::now())
        .bind(users_created as i32)
        .bind(users_updated as i32)
        .bind(users_disabled as i32)
        .bind(users_skipped as i32)
        .bind(groups_created as i32)
        .bind(groups_updated as i32)
        .bind(errors as i32)
        .bind(error_details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_ad_sync_run(&self, id: &str) -> Result<Option<AdSyncRun>> {
        let row = sqlx::query("SELECT * FROM ad_sync_runs WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_ad_sync_run))
    }

    async fn get_latest_ad_sync_run(&self) -> Result<Option<AdSyncRun>> {
        let row = sqlx::query("SELECT * FROM ad_sync_runs ORDER BY started_at DESC LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_ad_sync_run))
    }

    async fn list_ad_sync_runs(&self, limit: i64) -> Result<Vec<AdSyncRun>> {
        let rows = sqlx::query("SELECT * FROM ad_sync_runs ORDER BY started_at DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_ad_sync_run).collect())
    }
}

// -- ExternalIdRepository --

#[async_trait]
impl ExternalIdRepository for PostgresRepository {
    async fn get_external_ids(
        &self,
        user_sourced_id: &str,
    ) -> Result<serde_json::Map<String, serde_json::Value>> {
        let row: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT external_ids FROM users WHERE sourced_id = $1")
                .bind(user_sourced_id)
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some((value,)) => {
                if let serde_json::Value::Object(map) = value {
                    Ok(map)
                } else {
                    Ok(serde_json::Map::new())
                }
            }
            None => Ok(serde_json::Map::new()),
        }
    }

    async fn set_external_ids(
        &self,
        user_sourced_id: &str,
        ids: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<()> {
        let value = serde_json::Value::Object(ids.clone());
        sqlx::query("UPDATE users SET external_ids = $2 WHERE sourced_id = $1")
            .bind(user_sourced_id)
            .bind(&value)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn find_user_by_external_id(
        &self,
        provider: &str,
        external_id: &str,
    ) -> Result<Option<User>> {
        // Postgres JSONB extraction: external_ids ->> $1 = $2
        let row = sqlx::query("SELECT * FROM users WHERE external_ids ->> $1 = $2 LIMIT 1")
            .bind(provider)
            .bind(external_id)
            .fetch_optional(&self.pool)
            .await?;
        self.row_to_user(row).await
    }
}

// -- AccessTokenRepository --
//
// AccessToken stores timestamp fields as `String` (RFC 3339) at the model level
// because of `FromRow`. Postgres stores them as TIMESTAMPTZ. We map manually
// here via DateTime<Utc> and stringify on read; we accept either ISO-8601
// inputs by parsing.

fn parse_dt_str(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

#[async_trait]
impl AccessTokenRepository for PostgresRepository {
    async fn create_access_token(&self, token: &AccessToken) -> Result<()> {
        let created_at = parse_dt_str(&token.created_at);
        let expires_at = parse_dt_str(&token.expires_at);
        let revoked_at = token.revoked_at.as_deref().map(parse_dt_str);
        sqlx::query(
            "INSERT INTO access_tokens (token, client_id, user_sourced_id, scopes, created_at, expires_at, revoked_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&token.token)
        .bind(&token.client_id)
        .bind(&token.user_sourced_id)
        .bind(&token.scopes)
        .bind(created_at)
        .bind(expires_at)
        .bind(revoked_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_access_token(&self, token: &str) -> Result<Option<AccessToken>> {
        let row = sqlx::query(
            "SELECT token, client_id, user_sourced_id, scopes, created_at, expires_at, revoked_at FROM access_tokens WHERE token = $1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            let created: DateTime<Utc> = r.get("created_at");
            let expires: DateTime<Utc> = r.get("expires_at");
            let revoked: Option<DateTime<Utc>> = r.get("revoked_at");
            AccessToken {
                token: r.get("token"),
                client_id: r.get("client_id"),
                user_sourced_id: r.get("user_sourced_id"),
                scopes: r.get("scopes"),
                created_at: created.to_rfc3339(),
                expires_at: expires.to_rfc3339(),
                revoked_at: revoked.map(|d| d.to_rfc3339()),
            }
        }))
    }

    async fn revoke_access_token(&self, token: &str) -> Result<()> {
        sqlx::query("UPDATE access_tokens SET revoked_at = $2 WHERE token = $1")
            .bind(token)
            .bind(Utc::now())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_expired_access_tokens(&self) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM access_tokens WHERE expires_at < $1 OR revoked_at IS NOT NULL",
        )
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

// -- ApiTokenRepository --

#[async_trait]
impl ApiTokenRepository for PostgresRepository {
    async fn create_api_token(&self, token: &crate::models::api_token::ApiToken) -> Result<()> {
        let scope_json = token
            .scope
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| crate::error::ChalkError::Serialization(format!("token scope: {e}")))?;
        sqlx::query(
            "INSERT INTO api_tokens \
             (id, name, token_hash, token_prefix, created_at, last_used_at, revoked_at, scope) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&token.id)
        .bind(&token.name)
        .bind(&token.token_hash)
        .bind(&token.token_prefix)
        .bind(token.created_at)
        .bind(token.last_used_at)
        .bind(token.revoked_at)
        .bind(scope_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_api_tokens(&self) -> Result<Vec<crate::models::api_token::ApiToken>> {
        let rows: Vec<(
            String,
            String,
            String,
            String,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<serde_json::Value>,
        )> = sqlx::query_as(
            "SELECT id, name, token_hash, token_prefix, created_at, last_used_at, revoked_at, scope \
             FROM api_tokens \
             ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, name, h, prefix, ca, lu, rv, scope)| crate::models::api_token::ApiToken {
                    id,
                    name,
                    token_hash: h,
                    token_prefix: prefix,
                    created_at: ca,
                    last_used_at: lu,
                    revoked_at: rv,
                    // Display path: tolerate a malformed scope by showing the
                    // token as unscoped rather than failing the whole listing.
                    scope: scope.and_then(|v| serde_json::from_value(v).ok()),
                },
            )
            .collect())
    }

    async fn find_active_api_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<crate::models::api_token::ApiToken>> {
        let row: Option<(
            String,
            String,
            String,
            String,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<serde_json::Value>,
        )> = sqlx::query_as(
            "SELECT id, name, token_hash, token_prefix, created_at, last_used_at, revoked_at, scope \
             FROM api_tokens \
             WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        // Auth path: a stored-but-unparseable scope must NOT silently widen
        // access to unrestricted. Surface it as an error so the request fails
        // closed rather than open.
        row.map(|(id, name, h, prefix, ca, lu, rv, scope)| {
            let scope = scope.map(serde_json::from_value).transpose().map_err(|e| {
                crate::error::ChalkError::Serialization(format!("token scope: {e}"))
            })?;
            Ok(crate::models::api_token::ApiToken {
                id,
                name,
                token_hash: h,
                token_prefix: prefix,
                created_at: ca,
                last_used_at: lu,
                revoked_at: rv,
                scope,
            })
        })
        .transpose()
    }

    async fn touch_api_token(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn revoke_api_token(&self, id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE api_tokens SET revoked_at = NOW() \
             WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// -- PasswordResetTokenRepository --

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

#[async_trait]
impl PasswordResetTokenRepository for PostgresRepository {
    async fn create_reset_token(
        &self,
        user_sourced_id: &str,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO password_reset_tokens (token_hash, user_sourced_id, expires_at) \
             VALUES ($1, $2, $3)",
        )
        .bind(token_hash)
        .bind(user_sourced_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn consume_reset_token(&self, raw_token: &str) -> Result<Option<String>> {
        let token_hash = sha256_hex(raw_token);
        let row = sqlx::query(
            "UPDATE password_reset_tokens \
             SET consumed_at = now() \
             WHERE token_hash = $1 \
               AND consumed_at IS NULL \
               AND expires_at > now() \
             RETURNING user_sourced_id",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<String, _>("user_sourced_id")))
    }

    async fn delete_expired_reset_tokens(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM password_reset_tokens WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

#[async_trait]
impl MagicLoginRepository for PostgresRepository {
    async fn create_magic_login_token(
        &self,
        user_sourced_id: &str,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO magic_login_tokens (token_hash, user_sourced_id, expires_at) \
             VALUES ($1, $2, $3)",
        )
        .bind(token_hash)
        .bind(user_sourced_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn consume_magic_login_token(&self, raw_token: &str) -> Result<Option<String>> {
        let token_hash = sha256_hex(raw_token);
        let row = sqlx::query(
            "UPDATE magic_login_tokens \
             SET consumed_at = now() \
             WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now() \
             RETURNING user_sourced_id",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<String, _>("user_sourced_id")))
    }
}

// -- TenantConfigRepo --
//
// Stores `*_sealed` columns verbatim. The `chalk-hosted` crate wraps this
// repository with a thin facade that applies AES-256-GCM seal/unseal at the
// boundary using `keys::MasterKey`, so this impl never touches the master
// key. Audit logs go to the existing `admin_audit_log` table.

fn audit_details(section: &str, actor: &str) -> String {
    format!("section={section} actor={actor}")
}

#[async_trait]
impl TenantConfigRepo for PostgresRepository {
    async fn get_sis_config(&self) -> Result<Option<SisConfigRecord>> {
        let row = sqlx::query(
            "SELECT enabled, provider, powerschool_base_url, powerschool_token_url, \
             powerschool_client_id, powerschool_client_secret_sealed, infinite_campus_base_url, \
             infinite_campus_client_id, infinite_campus_client_secret_sealed, skyward_base_url, \
             skyward_client_id, skyward_client_secret_sealed, oneroster_csv_dir, sync_schedule, \
             updated_at, updated_by FROM tenant_config_sis WHERE id = TRUE",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| SisConfigRecord {
            enabled: r.get("enabled"),
            provider: r.get("provider"),
            powerschool_base_url: r.get("powerschool_base_url"),
            powerschool_token_url: r.get("powerschool_token_url"),
            powerschool_client_id: r.get("powerschool_client_id"),
            powerschool_client_secret: r.get("powerschool_client_secret_sealed"),
            infinite_campus_base_url: r.get("infinite_campus_base_url"),
            infinite_campus_client_id: r.get("infinite_campus_client_id"),
            infinite_campus_client_secret: r.get("infinite_campus_client_secret_sealed"),
            skyward_base_url: r.get("skyward_base_url"),
            skyward_client_id: r.get("skyward_client_id"),
            skyward_client_secret: r.get("skyward_client_secret_sealed"),
            oneroster_csv_dir: r.get("oneroster_csv_dir"),
            sync_schedule: r.get("sync_schedule"),
            updated_at: Some(r.get("updated_at")),
            updated_by: Some(r.get("updated_by")),
        }))
    }

    async fn put_sis_config(&self, record: SisConfigRecord, actor: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_config_sis (id, enabled, provider, powerschool_base_url, \
             powerschool_token_url, powerschool_client_id, powerschool_client_secret_sealed, \
             infinite_campus_base_url, infinite_campus_client_id, \
             infinite_campus_client_secret_sealed, skyward_base_url, skyward_client_id, \
             skyward_client_secret_sealed, oneroster_csv_dir, sync_schedule, updated_at, \
             updated_by) VALUES (TRUE, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
             $14, now(), $15) \
             ON CONFLICT (id) DO UPDATE SET \
               enabled = EXCLUDED.enabled, \
               provider = EXCLUDED.provider, \
               powerschool_base_url = EXCLUDED.powerschool_base_url, \
               powerschool_token_url = EXCLUDED.powerschool_token_url, \
               powerschool_client_id = EXCLUDED.powerschool_client_id, \
               powerschool_client_secret_sealed = EXCLUDED.powerschool_client_secret_sealed, \
               infinite_campus_base_url = EXCLUDED.infinite_campus_base_url, \
               infinite_campus_client_id = EXCLUDED.infinite_campus_client_id, \
               infinite_campus_client_secret_sealed = EXCLUDED.infinite_campus_client_secret_sealed, \
               skyward_base_url = EXCLUDED.skyward_base_url, \
               skyward_client_id = EXCLUDED.skyward_client_id, \
               skyward_client_secret_sealed = EXCLUDED.skyward_client_secret_sealed, \
               oneroster_csv_dir = EXCLUDED.oneroster_csv_dir, \
               sync_schedule = EXCLUDED.sync_schedule, \
               updated_at = now(), \
               updated_by = EXCLUDED.updated_by",
        )
        .bind(record.enabled)
        .bind(&record.provider)
        .bind(&record.powerschool_base_url)
        .bind(&record.powerschool_token_url)
        .bind(&record.powerschool_client_id)
        .bind(&record.powerschool_client_secret)
        .bind(&record.infinite_campus_base_url)
        .bind(&record.infinite_campus_client_id)
        .bind(&record.infinite_campus_client_secret)
        .bind(&record.skyward_base_url)
        .bind(&record.skyward_client_id)
        .bind(&record.skyward_client_secret)
        .bind(&record.oneroster_csv_dir)
        .bind(&record.sync_schedule)
        .bind(actor)
        .execute(&self.pool)
        .await?;

        self.log_admin_action(
            "tenant_config_sis_updated",
            Some(&audit_details("sis", actor)),
            None,
        )
        .await?;
        Ok(())
    }

    async fn get_google_sync_config(&self) -> Result<Option<GoogleSyncConfigRecord>> {
        let row = sqlx::query(
            "SELECT enabled, workspace_domain, admin_email, service_account_key_sealed, \
             provision_users, manage_ous, suspend_inactive, sync_schedule, updated_at, updated_by \
             FROM tenant_config_google_sync WHERE id = TRUE",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| GoogleSyncConfigRecord {
            enabled: r.get("enabled"),
            workspace_domain: r.get("workspace_domain"),
            admin_email: r.get("admin_email"),
            service_account_key: r.get("service_account_key_sealed"),
            provision_users: r.get("provision_users"),
            manage_ous: r.get("manage_ous"),
            suspend_inactive: r.get("suspend_inactive"),
            sync_schedule: r.get("sync_schedule"),
            updated_at: Some(r.get("updated_at")),
            updated_by: Some(r.get("updated_by")),
        }))
    }

    async fn put_google_sync_config(
        &self,
        record: GoogleSyncConfigRecord,
        actor: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_config_google_sync (id, enabled, workspace_domain, admin_email, \
             service_account_key_sealed, provision_users, manage_ous, suspend_inactive, \
             sync_schedule, updated_at, updated_by) \
             VALUES (TRUE, $1, $2, $3, $4, $5, $6, $7, $8, now(), $9) \
             ON CONFLICT (id) DO UPDATE SET \
               enabled = EXCLUDED.enabled, \
               workspace_domain = EXCLUDED.workspace_domain, \
               admin_email = EXCLUDED.admin_email, \
               service_account_key_sealed = EXCLUDED.service_account_key_sealed, \
               provision_users = EXCLUDED.provision_users, \
               manage_ous = EXCLUDED.manage_ous, \
               suspend_inactive = EXCLUDED.suspend_inactive, \
               sync_schedule = EXCLUDED.sync_schedule, \
               updated_at = now(), \
               updated_by = EXCLUDED.updated_by",
        )
        .bind(record.enabled)
        .bind(&record.workspace_domain)
        .bind(&record.admin_email)
        .bind(&record.service_account_key)
        .bind(record.provision_users)
        .bind(record.manage_ous)
        .bind(record.suspend_inactive)
        .bind(&record.sync_schedule)
        .bind(actor)
        .execute(&self.pool)
        .await?;

        self.log_admin_action(
            "tenant_config_google_sync_updated",
            Some(&audit_details("google_sync", actor)),
            None,
        )
        .await?;
        Ok(())
    }

    async fn get_idp_config(&self) -> Result<Option<IdpConfigRecord>> {
        let row = sqlx::query(
            "SELECT enabled, qr_badge_login, picture_passwords, session_timeout_minutes, \
             default_password_pattern, default_password_roles, saml_cert_sealed, \
             saml_signing_key_sealed, updated_at, updated_by FROM tenant_config_idp \
             WHERE id = TRUE",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| IdpConfigRecord {
            enabled: r.get("enabled"),
            qr_badge_login: r.get("qr_badge_login"),
            picture_passwords: r.get("picture_passwords"),
            session_timeout_minutes: r.get("session_timeout_minutes"),
            default_password_pattern: r.get("default_password_pattern"),
            default_password_roles: r.get("default_password_roles"),
            saml_cert: r.get("saml_cert_sealed"),
            saml_signing_key: r.get("saml_signing_key_sealed"),
            updated_at: Some(r.get("updated_at")),
            updated_by: Some(r.get("updated_by")),
        }))
    }

    async fn put_idp_config(&self, record: IdpConfigRecord, actor: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_config_idp (id, enabled, qr_badge_login, picture_passwords, \
             session_timeout_minutes, default_password_pattern, default_password_roles, \
             saml_cert_sealed, saml_signing_key_sealed, updated_at, updated_by) \
             VALUES (TRUE, $1, $2, $3, $4, $5, $6, $7, $8, now(), $9) \
             ON CONFLICT (id) DO UPDATE SET \
               enabled = EXCLUDED.enabled, \
               qr_badge_login = EXCLUDED.qr_badge_login, \
               picture_passwords = EXCLUDED.picture_passwords, \
               session_timeout_minutes = EXCLUDED.session_timeout_minutes, \
               default_password_pattern = EXCLUDED.default_password_pattern, \
               default_password_roles = EXCLUDED.default_password_roles, \
               saml_cert_sealed = EXCLUDED.saml_cert_sealed, \
               saml_signing_key_sealed = EXCLUDED.saml_signing_key_sealed, \
               updated_at = now(), \
               updated_by = EXCLUDED.updated_by",
        )
        .bind(record.enabled)
        .bind(record.qr_badge_login)
        .bind(record.picture_passwords)
        .bind(record.session_timeout_minutes)
        .bind(&record.default_password_pattern)
        .bind(&record.default_password_roles)
        .bind(&record.saml_cert)
        .bind(&record.saml_signing_key)
        .bind(actor)
        .execute(&self.pool)
        .await?;

        self.log_admin_action(
            "tenant_config_idp_updated",
            Some(&audit_details("idp", actor)),
            None,
        )
        .await?;
        Ok(())
    }

    async fn get_ad_sync_config(&self) -> Result<Option<AdSyncConfigRecord>> {
        let row = sqlx::query(
            "SELECT enabled, host, port, bind_dn, bind_password_sealed, base_dn, user_filter, \
             use_tls, tls_ca_cert_sealed, sync_schedule, ou_mapping, groups, updated_at, \
             updated_by FROM tenant_config_ad_sync WHERE id = TRUE",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| AdSyncConfigRecord {
            enabled: r.get("enabled"),
            host: r.get("host"),
            port: r.get("port"),
            bind_dn: r.get("bind_dn"),
            bind_password: r.get("bind_password_sealed"),
            base_dn: r.get("base_dn"),
            user_filter: r.get("user_filter"),
            use_tls: r.get("use_tls"),
            tls_ca_cert: r.get("tls_ca_cert_sealed"),
            sync_schedule: r.get("sync_schedule"),
            ou_mapping: r.get("ou_mapping"),
            groups: r.get("groups"),
            updated_at: Some(r.get("updated_at")),
            updated_by: Some(r.get("updated_by")),
        }))
    }

    async fn put_ad_sync_config(&self, record: AdSyncConfigRecord, actor: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_config_ad_sync (id, enabled, host, port, bind_dn, \
             bind_password_sealed, base_dn, user_filter, use_tls, tls_ca_cert_sealed, \
             sync_schedule, ou_mapping, groups, updated_at, updated_by) \
             VALUES (TRUE, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now(), $13) \
             ON CONFLICT (id) DO UPDATE SET \
               enabled = EXCLUDED.enabled, \
               host = EXCLUDED.host, \
               port = EXCLUDED.port, \
               bind_dn = EXCLUDED.bind_dn, \
               bind_password_sealed = EXCLUDED.bind_password_sealed, \
               base_dn = EXCLUDED.base_dn, \
               user_filter = EXCLUDED.user_filter, \
               use_tls = EXCLUDED.use_tls, \
               tls_ca_cert_sealed = EXCLUDED.tls_ca_cert_sealed, \
               sync_schedule = EXCLUDED.sync_schedule, \
               ou_mapping = EXCLUDED.ou_mapping, \
               groups = EXCLUDED.groups, \
               updated_at = now(), \
               updated_by = EXCLUDED.updated_by",
        )
        .bind(record.enabled)
        .bind(&record.host)
        .bind(record.port)
        .bind(&record.bind_dn)
        .bind(&record.bind_password)
        .bind(&record.base_dn)
        .bind(&record.user_filter)
        .bind(record.use_tls)
        .bind(&record.tls_ca_cert)
        .bind(&record.sync_schedule)
        .bind(&record.ou_mapping)
        .bind(&record.groups)
        .bind(actor)
        .execute(&self.pool)
        .await?;

        self.log_admin_action(
            "tenant_config_ad_sync_updated",
            Some(&audit_details("ad_sync", actor)),
            None,
        )
        .await?;
        Ok(())
    }
}
