use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use sqlx::{Row, SqlitePool};

use crate::error::{ChalkError, Result};
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

use crate::models::sso::{
    OidcAuthorizationCode, PortalSession, SsoAudience, SsoPartner, SsoPartnerSource, SsoProtocol,
};

use crate::models::access_token::AccessToken;
use crate::models::asset::push_patch;
use crate::models::asset::{
    ActorKind, Asset, AssetEvent, AssetEventFilter, AssetEventType, AssetFilter, AssetGroupCount,
    AssetPatch, AssetRow, AssetSource, AssetStatus, AssetType, MatchState, NewAssetEvent,
    PatchValue,
};
use crate::models::canned_response::CannedResponse;
use crate::models::change_set::{
    ChangeSet, ChangeSetFilter, ChangeSetItem, ChangeSetItemStatus, ChangeSetKind, ChangeSetOp,
    ChangeSetProgress, ChangeSetStatus, CommitClaim, NewChangeSetItem, RemoteTarget,
};
use crate::models::charge::{Charge, ChargeKind, ChargeStatus, NewCharge};
use crate::models::console_user::{ConsoleRole, ConsoleUser, ConsoleUserStatus};
use crate::models::device_sync::{
    DeviceSyncCounters, DeviceSyncCursor, DeviceSyncCursorStatus, DeviceSyncMode,
    DeviceSyncResource, DeviceSyncRun, DeviceSyncRunStatus,
};
use crate::models::job::{Job, JobFilter, JobKind, JobStatus, NewJob};
use crate::models::page::{Page, PageRequest};
use crate::models::saved_view::SavedView;
use crate::models::ticket::{
    NewTicketComment, Ticket, TicketAttachment, TicketComment, TicketFilter, TicketPatch,
    TicketPriority, TicketScope, TicketSource, TicketStatus,
};

use super::repository::{
    AcademicSessionRepository, AccessTokenRepository, AdSyncConfigRecord, AdSyncRunRepository,
    AdSyncStateRepository, AdminAuditRepository, AdminSessionRepository, ApiTokenRepository,
    AssetEventRepository, AssetRepository, CannedResponseRepository, ChalkRepository,
    ChangeSetRepository, ChargeRepository, ClassRepository, ConfigRepository,
    ConsoleUserRepository, CourseRepository, DemographicsRepository, DeviceConfigRecord,
    EnrollmentRepository, ExternalIdRepository, GoogleDeviceSyncRepository, GoogleSyncConfigRecord,
    GoogleSyncRunRepository, GoogleSyncStateRepository, IdpAuthLogRepository, IdpConfigRecord,
    IdpSessionRepository, JobRepository, MagicLoginRepository, OidcCodeRepository, OrgRepository,
    PasswordRepository, PasswordResetTokenRepository, PicturePasswordRepository,
    PortalSessionRepository, QrBadgeRepository, SavedViewRepository, SisConfigRecord,
    SsoPartnerRepository, SyncRepository, TenantConfigRepo, TicketRepository, UserRepository,
    WebhookDeliveryRepository, WebhookEndpointRepository,
};

use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct SqliteRepository {
    pool: SqlitePool,
}

impl SqliteRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    async fn row_to_user(&self, row: Option<sqlx::sqlite::SqliteRow>) -> Result<Option<User>> {
        match row {
            Some(r) => {
                let sid: String = r.get("sourced_id");
                let (orgs, agents, user_ids, grades) =
                    load_user_junction_data(&self.pool, &sid).await?;
                Ok(Some(User {
                    sourced_id: sid,
                    status: parse_status(r.get("status")),
                    date_last_modified: parse_datetime(r.get("date_last_modified")),
                    metadata: parse_metadata(r.get("metadata")),
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

impl ChalkRepository for SqliteRepository {}

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

/// Parse a stored timestamp.
///
/// Every writer in this file binds `datetime_to_str`, so RFC 3339 is the format
/// that actually appears — but **21 tables declare
/// `created_at TEXT NOT NULL DEFAULT (datetime('now'))`**, and SQLite's
/// `datetime()` emits `YYYY-MM-DD HH:MM:SS` with no `T` and no offset. Any
/// insert that omits the column takes that shape instead.
///
/// Without the second branch such a row falls through to `Utc::now()`, so a
/// timestamp that failed to parse renders as *"just now"*. In an audit trail
/// that is not a cosmetic defect: an event from March appears to have happened
/// this second, and nothing about the display says it was a fallback.
///
/// No current caller is broken — `admin_audit_log` is the only table that uses
/// its default, and it has its own matching parser. This is here so the next
/// insert that relies on a default cannot introduce the bug silently.
fn parse_datetime(s: &str) -> DateTime<Utc> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return dt.with_timezone(&Utc);
    }
    // SQLite's own `datetime('now')`, which is always UTC.
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return naive.and_utc();
    }
    Utc::now()
}

fn datetime_to_str(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339()
}

fn parse_naive_date(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .unwrap_or_else(|_| NaiveDate::from_ymd_opt(2000, 1, 1).unwrap())
}

fn naive_date_to_str(d: &NaiveDate) -> String {
    d.format("%Y-%m-%d").to_string()
}

/// Parse a nullable `YYYY-MM-DD` column.
///
/// Unlike [`parse_naive_date`], a malformed value is an error rather than a
/// silent fallback to 2000-01-01. For a nullable column that fallback would
/// invent an AUE date nobody entered, and the device would silently move in or
/// out of the "past AUE" bucket.
fn parse_naive_date_opt(s: Option<String>) -> Result<Option<NaiveDate>> {
    match s {
        None => Ok(None),
        Some(v) => NaiveDate::parse_from_str(&v, "%Y-%m-%d")
            .map(Some)
            .map_err(|e| ChalkError::Serialization(format!("invalid date column {v:?}: {e}"))),
    }
}

/// Parse a TEXT JSON column strictly.
fn parse_json_column(s: &str) -> Result<serde_json::Value> {
    serde_json::from_str(s)
        .map_err(|e| ChalkError::Serialization(format!("invalid JSON column: {e}")))
}

fn parse_metadata(s: Option<String>) -> Option<serde_json::Value> {
    s.and_then(|v| serde_json::from_str(&v).ok())
}

fn metadata_to_str(v: &Option<serde_json::Value>) -> Option<String> {
    v.as_ref().map(|val| val.to_string())
}

// -- OrgRepository --

#[async_trait]
impl OrgRepository for SqliteRepository {
    async fn upsert_org(&self, org: &Org) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO orgs (sourced_id, status, date_last_modified, metadata, name, org_type, identifier, parent_sourced_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
        )
        .bind(&org.sourced_id)
        .bind(status_to_str(&org.status))
        .bind(datetime_to_str(&org.date_last_modified))
        .bind(metadata_to_str(&org.metadata))
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
            "SELECT sourced_id, status, date_last_modified, metadata, name, org_type, identifier, parent_sourced_id FROM orgs WHERE sourced_id = ?1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let sid: String = r.get("sourced_id");
                // Get children
                let children_rows =
                    sqlx::query("SELECT sourced_id FROM orgs WHERE parent_sourced_id = ?1")
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
                    date_last_modified: parse_datetime(r.get("date_last_modified")),
                    metadata: parse_metadata(r.get("metadata")),
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

        let mut orgs = Vec::with_capacity(rows.len());
        for r in &rows {
            let sid: String = r.get("sourced_id");
            let children_rows =
                sqlx::query("SELECT sourced_id FROM orgs WHERE parent_sourced_id = ?1")
                    .bind(&sid)
                    .fetch_all(&self.pool)
                    .await?;
            let children: Vec<String> = children_rows
                .iter()
                .map(|cr| cr.get("sourced_id"))
                .collect();

            orgs.push(Org {
                sourced_id: sid,
                status: parse_status(r.get("status")),
                date_last_modified: parse_datetime(r.get("date_last_modified")),
                metadata: parse_metadata(r.get("metadata")),
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
        let result = sqlx::query("DELETE FROM orgs WHERE sourced_id = ?1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- AcademicSessionRepository --

#[async_trait]
impl AcademicSessionRepository for SqliteRepository {
    async fn upsert_academic_session(&self, session: &AcademicSession) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO academic_sessions (sourced_id, status, date_last_modified, metadata, title, start_date, end_date, session_type, parent_sourced_id, school_year)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        )
        .bind(&session.sourced_id)
        .bind(status_to_str(&session.status))
        .bind(datetime_to_str(&session.date_last_modified))
        .bind(metadata_to_str(&session.metadata))
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
            "SELECT sourced_id, status, date_last_modified, metadata, title, start_date, end_date, session_type, parent_sourced_id, school_year FROM academic_sessions WHERE sourced_id = ?1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let sid: String = r.get("sourced_id");
                let children_rows = sqlx::query(
                    "SELECT sourced_id FROM academic_sessions WHERE parent_sourced_id = ?1",
                )
                .bind(&sid)
                .fetch_all(&self.pool)
                .await?;
                let children: Vec<String> = children_rows
                    .iter()
                    .map(|cr| cr.get("sourced_id"))
                    .collect();

                Ok(Some(AcademicSession {
                    sourced_id: sid,
                    status: parse_status(r.get("status")),
                    date_last_modified: parse_datetime(r.get("date_last_modified")),
                    metadata: parse_metadata(r.get("metadata")),
                    title: r.get("title"),
                    start_date: parse_naive_date(r.get("start_date")),
                    end_date: parse_naive_date(r.get("end_date")),
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

        let mut sessions = Vec::with_capacity(rows.len());
        for r in &rows {
            let sid: String = r.get("sourced_id");
            let children_rows = sqlx::query(
                "SELECT sourced_id FROM academic_sessions WHERE parent_sourced_id = ?1",
            )
            .bind(&sid)
            .fetch_all(&self.pool)
            .await?;
            let children: Vec<String> = children_rows
                .iter()
                .map(|cr| cr.get("sourced_id"))
                .collect();

            sessions.push(AcademicSession {
                sourced_id: sid,
                status: parse_status(r.get("status")),
                date_last_modified: parse_datetime(r.get("date_last_modified")),
                metadata: parse_metadata(r.get("metadata")),
                title: r.get("title"),
                start_date: parse_naive_date(r.get("start_date")),
                end_date: parse_naive_date(r.get("end_date")),
                session_type: parse_session_type(r.get("session_type")),
                parent: r.get("parent_sourced_id"),
                school_year: r.get("school_year"),
                children,
            });
        }
        Ok(sessions)
    }

    async fn delete_academic_session(&self, sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM academic_sessions WHERE sourced_id = ?1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- UserRepository --

async fn load_user_junction_data(
    pool: &SqlitePool,
    user_sourced_id: &str,
) -> Result<(Vec<String>, Vec<String>, Vec<UserIdentifier>, Vec<String>)> {
    let org_rows = sqlx::query("SELECT org_sourced_id FROM user_orgs WHERE user_sourced_id = ?1")
        .bind(user_sourced_id)
        .fetch_all(pool)
        .await?;
    let orgs: Vec<String> = org_rows.iter().map(|r| r.get("org_sourced_id")).collect();

    let agent_rows =
        sqlx::query("SELECT agent_sourced_id FROM user_agents WHERE user_sourced_id = ?1")
            .bind(user_sourced_id)
            .fetch_all(pool)
            .await?;
    let agents: Vec<String> = agent_rows
        .iter()
        .map(|r| r.get("agent_sourced_id"))
        .collect();

    let id_rows =
        sqlx::query("SELECT type, identifier FROM user_identifiers WHERE user_sourced_id = ?1")
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

    let grade_rows = sqlx::query("SELECT grade FROM user_grades WHERE user_sourced_id = ?1")
        .bind(user_sourced_id)
        .fetch_all(pool)
        .await?;
    let grades: Vec<String> = grade_rows.iter().map(|r| r.get("grade")).collect();

    Ok((orgs, agents, user_ids, grades))
}

#[async_trait]
impl UserRepository for SqliteRepository {
    async fn upsert_user(&self, user: &User) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO users (sourced_id, status, date_last_modified, metadata, username, enabled_user, given_name, family_name, middle_name, role, identifier, email, sms, phone)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(sourced_id) DO UPDATE SET
                status = excluded.status,
                date_last_modified = excluded.date_last_modified,
                metadata = excluded.metadata,
                username = excluded.username,
                enabled_user = excluded.enabled_user,
                given_name = excluded.given_name,
                family_name = excluded.family_name,
                middle_name = excluded.middle_name,
                role = excluded.role,
                identifier = excluded.identifier,
                email = excluded.email,
                sms = excluded.sms,
                phone = excluded.phone"
        )
        .bind(&user.sourced_id)
        .bind(status_to_str(&user.status))
        .bind(datetime_to_str(&user.date_last_modified))
        .bind(metadata_to_str(&user.metadata))
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

        // Clear and re-insert junction tables
        sqlx::query("DELETE FROM user_orgs WHERE user_sourced_id = ?1")
            .bind(&user.sourced_id)
            .execute(&mut *tx)
            .await?;
        for org_id in &user.orgs {
            sqlx::query("INSERT INTO user_orgs (user_sourced_id, org_sourced_id) VALUES (?1, ?2)")
                .bind(&user.sourced_id)
                .bind(org_id)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("DELETE FROM user_agents WHERE user_sourced_id = ?1")
            .bind(&user.sourced_id)
            .execute(&mut *tx)
            .await?;
        for agent_id in &user.agents {
            sqlx::query(
                "INSERT INTO user_agents (user_sourced_id, agent_sourced_id) VALUES (?1, ?2)",
            )
            .bind(&user.sourced_id)
            .bind(agent_id)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query("DELETE FROM user_identifiers WHERE user_sourced_id = ?1")
            .bind(&user.sourced_id)
            .execute(&mut *tx)
            .await?;
        for uid in &user.user_ids {
            sqlx::query("INSERT INTO user_identifiers (user_sourced_id, type, identifier) VALUES (?1, ?2, ?3)")
                .bind(&user.sourced_id)
                .bind(&uid.type_)
                .bind(&uid.identifier)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("DELETE FROM user_grades WHERE user_sourced_id = ?1")
            .bind(&user.sourced_id)
            .execute(&mut *tx)
            .await?;
        for grade in &user.grades {
            sqlx::query("INSERT INTO user_grades (user_sourced_id, grade) VALUES (?1, ?2)")
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
            "SELECT sourced_id, status, date_last_modified, metadata, username, enabled_user, given_name, family_name, middle_name, role, identifier, email, sms, phone FROM users WHERE sourced_id = ?1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;

        self.row_to_user(row).await
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, username, enabled_user, given_name, family_name, middle_name, role, identifier, email, sms, phone FROM users WHERE LOWER(username) = LOWER(?1)"
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

        if let Some(ref role) = filter.role {
            sql.push_str(&format!(" AND role = '{}'", role_type_to_str(role)));
        }
        if let Some(ref org_id) = filter.org_sourced_id {
            sql.push_str(" AND sourced_id IN (SELECT user_sourced_id FROM user_orgs WHERE org_sourced_id = ?)");
            binds.push(org_id.clone());
        }
        if let Some(ref grade) = filter.grade {
            sql.push_str(
                " AND sourced_id IN (SELECT user_sourced_id FROM user_grades WHERE grade = ?)",
            );
            binds.push(grade.clone());
        }
        if let Some(ref term) = filter.search {
            // SQLite's LIKE is already case-insensitive for ASCII, which is why
            // only the Postgres half needs ILIKE. The pattern is bound four
            // times rather than interpolated — `escape_like` neutralises the
            // wildcards, the bind neutralises everything else.
            sql.push_str(
                " AND (given_name LIKE ? ESCAPE '\\' OR family_name LIKE ? ESCAPE '\\' \
                 OR email LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\')",
            );
            let pattern = format!("%{}%", escape_like(term));
            for _ in 0..4 {
                binds.push(pattern.clone());
            }
        }
        // Ordered so the cap takes a stable set rather than whatever the
        // planner happens to emit first.
        sql.push_str(" ORDER BY family_name, given_name, sourced_id");
        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT {}", limit.max(0)));
        }

        let mut query = sqlx::query(&sql);
        for b in &binds {
            query = query.bind(b);
        }
        let rows = query.fetch_all(&self.pool).await?;

        let mut users = Vec::with_capacity(rows.len());
        for r in &rows {
            let sid: String = r.get("sourced_id");
            let (orgs, agents, user_ids, grades) =
                load_user_junction_data(&self.pool, &sid).await?;
            users.push(User {
                sourced_id: sid,
                status: parse_status(r.get("status")),
                date_last_modified: parse_datetime(r.get("date_last_modified")),
                metadata: parse_metadata(r.get("metadata")),
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
        let result = sqlx::query("DELETE FROM users WHERE sourced_id = ?1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_user_counts(&self) -> Result<UserCounts> {
        let row = sqlx::query(
            "SELECT
                COUNT(*) as total,
                SUM(CASE WHEN role = 'student' THEN 1 ELSE 0 END) as students,
                SUM(CASE WHEN role = 'teacher' THEN 1 ELSE 0 END) as teachers,
                SUM(CASE WHEN role = 'administrator' THEN 1 ELSE 0 END) as administrators,
                SUM(CASE WHEN role NOT IN ('student', 'teacher', 'administrator') THEN 1 ELSE 0 END) as other
             FROM users"
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(UserCounts {
            total: row.get::<i32, _>("total") as i64,
            students: row.get::<i32, _>("students") as i64,
            teachers: row.get::<i32, _>("teachers") as i64,
            administrators: row.get::<i32, _>("administrators") as i64,
            other: row.get::<i32, _>("other") as i64,
        })
    }
}

// -- CourseRepository --

#[async_trait]
impl CourseRepository for SqliteRepository {
    async fn upsert_course(&self, course: &Course) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT OR REPLACE INTO courses (sourced_id, status, date_last_modified, metadata, title, school_year, course_code, org_sourced_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
        )
        .bind(&course.sourced_id)
        .bind(status_to_str(&course.status))
        .bind(datetime_to_str(&course.date_last_modified))
        .bind(metadata_to_str(&course.metadata))
        .bind(&course.title)
        .bind(&course.school_year)
        .bind(&course.course_code)
        .bind(&course.org)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM course_grades WHERE course_sourced_id = ?1")
            .bind(&course.sourced_id)
            .execute(&mut *tx)
            .await?;
        for grade in &course.grades {
            sqlx::query("INSERT INTO course_grades (course_sourced_id, grade) VALUES (?1, ?2)")
                .bind(&course.sourced_id)
                .bind(grade)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("DELETE FROM course_subjects WHERE course_sourced_id = ?1")
            .bind(&course.sourced_id)
            .execute(&mut *tx)
            .await?;
        for subject in &course.subjects {
            sqlx::query("INSERT INTO course_subjects (course_sourced_id, subject) VALUES (?1, ?2)")
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
            "SELECT sourced_id, status, date_last_modified, metadata, title, school_year, course_code, org_sourced_id FROM courses WHERE sourced_id = ?1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let sid: String = r.get("sourced_id");

                let grade_rows =
                    sqlx::query("SELECT grade FROM course_grades WHERE course_sourced_id = ?1")
                        .bind(&sid)
                        .fetch_all(&self.pool)
                        .await?;
                let grades: Vec<String> = grade_rows.iter().map(|gr| gr.get("grade")).collect();

                let subject_rows =
                    sqlx::query("SELECT subject FROM course_subjects WHERE course_sourced_id = ?1")
                        .bind(&sid)
                        .fetch_all(&self.pool)
                        .await?;
                let subjects: Vec<String> =
                    subject_rows.iter().map(|sr| sr.get("subject")).collect();

                Ok(Some(Course {
                    sourced_id: sid,
                    status: parse_status(r.get("status")),
                    date_last_modified: parse_datetime(r.get("date_last_modified")),
                    metadata: parse_metadata(r.get("metadata")),
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

        let mut courses = Vec::with_capacity(rows.len());
        for r in &rows {
            let sid: String = r.get("sourced_id");

            let grade_rows =
                sqlx::query("SELECT grade FROM course_grades WHERE course_sourced_id = ?1")
                    .bind(&sid)
                    .fetch_all(&self.pool)
                    .await?;
            let grades: Vec<String> = grade_rows.iter().map(|gr| gr.get("grade")).collect();

            let subject_rows =
                sqlx::query("SELECT subject FROM course_subjects WHERE course_sourced_id = ?1")
                    .bind(&sid)
                    .fetch_all(&self.pool)
                    .await?;
            let subjects: Vec<String> = subject_rows.iter().map(|sr| sr.get("subject")).collect();

            courses.push(Course {
                sourced_id: sid,
                status: parse_status(r.get("status")),
                date_last_modified: parse_datetime(r.get("date_last_modified")),
                metadata: parse_metadata(r.get("metadata")),
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
        let result = sqlx::query("DELETE FROM courses WHERE sourced_id = ?1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- ClassRepository --

async fn load_class_junction_data(
    pool: &SqlitePool,
    class_sourced_id: &str,
) -> Result<(Vec<String>, Vec<String>, Vec<String>, Vec<String>)> {
    let term_rows = sqlx::query(
        "SELECT academic_session_sourced_id FROM class_terms WHERE class_sourced_id = ?1",
    )
    .bind(class_sourced_id)
    .fetch_all(pool)
    .await?;
    let terms: Vec<String> = term_rows
        .iter()
        .map(|r| r.get("academic_session_sourced_id"))
        .collect();

    let grade_rows = sqlx::query("SELECT grade FROM class_grades WHERE class_sourced_id = ?1")
        .bind(class_sourced_id)
        .fetch_all(pool)
        .await?;
    let grades: Vec<String> = grade_rows.iter().map(|r| r.get("grade")).collect();

    let subject_rows =
        sqlx::query("SELECT subject FROM class_subjects WHERE class_sourced_id = ?1")
            .bind(class_sourced_id)
            .fetch_all(pool)
            .await?;
    let subjects: Vec<String> = subject_rows.iter().map(|r| r.get("subject")).collect();

    let period_rows = sqlx::query("SELECT period FROM class_periods WHERE class_sourced_id = ?1")
        .bind(class_sourced_id)
        .fetch_all(pool)
        .await?;
    let periods: Vec<String> = period_rows.iter().map(|r| r.get("period")).collect();

    Ok((terms, grades, subjects, periods))
}

#[async_trait]
impl ClassRepository for SqliteRepository {
    async fn upsert_class(&self, class: &Class) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT OR REPLACE INTO classes (sourced_id, status, date_last_modified, metadata, title, class_code, class_type, location, course_sourced_id, school_sourced_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        )
        .bind(&class.sourced_id)
        .bind(status_to_str(&class.status))
        .bind(datetime_to_str(&class.date_last_modified))
        .bind(metadata_to_str(&class.metadata))
        .bind(&class.title)
        .bind(&class.class_code)
        .bind(class_type_to_str(&class.class_type))
        .bind(&class.location)
        .bind(&class.course)
        .bind(&class.school)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM class_terms WHERE class_sourced_id = ?1")
            .bind(&class.sourced_id)
            .execute(&mut *tx)
            .await?;
        for term in &class.terms {
            sqlx::query("INSERT INTO class_terms (class_sourced_id, academic_session_sourced_id) VALUES (?1, ?2)")
                .bind(&class.sourced_id)
                .bind(term)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("DELETE FROM class_grades WHERE class_sourced_id = ?1")
            .bind(&class.sourced_id)
            .execute(&mut *tx)
            .await?;
        for grade in &class.grades {
            sqlx::query("INSERT INTO class_grades (class_sourced_id, grade) VALUES (?1, ?2)")
                .bind(&class.sourced_id)
                .bind(grade)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("DELETE FROM class_subjects WHERE class_sourced_id = ?1")
            .bind(&class.sourced_id)
            .execute(&mut *tx)
            .await?;
        for subject in &class.subjects {
            sqlx::query("INSERT INTO class_subjects (class_sourced_id, subject) VALUES (?1, ?2)")
                .bind(&class.sourced_id)
                .bind(subject)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("DELETE FROM class_periods WHERE class_sourced_id = ?1")
            .bind(&class.sourced_id)
            .execute(&mut *tx)
            .await?;
        for period in &class.periods {
            sqlx::query("INSERT INTO class_periods (class_sourced_id, period) VALUES (?1, ?2)")
                .bind(&class.sourced_id)
                .bind(period)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_class(&self, sourced_id: &str) -> Result<Option<Class>> {
        let row = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, title, class_code, class_type, location, course_sourced_id, school_sourced_id FROM classes WHERE sourced_id = ?1"
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
                    date_last_modified: parse_datetime(r.get("date_last_modified")),
                    metadata: parse_metadata(r.get("metadata")),
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

        let mut classes = Vec::with_capacity(rows.len());
        for r in &rows {
            let sid: String = r.get("sourced_id");
            let (terms, grades, subjects, periods) =
                load_class_junction_data(&self.pool, &sid).await?;

            classes.push(Class {
                sourced_id: sid,
                status: parse_status(r.get("status")),
                date_last_modified: parse_datetime(r.get("date_last_modified")),
                metadata: parse_metadata(r.get("metadata")),
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
        let result = sqlx::query("DELETE FROM classes WHERE sourced_id = ?1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- EnrollmentRepository --

/// Map a SQLite row to an `Enrollment`. All enrollment queries select the same columns,
/// so this avoids duplicating the mapping logic across every method.
fn enrollment_from_row(r: &sqlx::sqlite::SqliteRow) -> Enrollment {
    Enrollment {
        sourced_id: r.get("sourced_id"),
        status: parse_status(r.get("status")),
        date_last_modified: parse_datetime(r.get("date_last_modified")),
        metadata: parse_metadata(r.get("metadata")),
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
impl EnrollmentRepository for SqliteRepository {
    async fn upsert_enrollment(&self, enrollment: &Enrollment) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO enrollments (sourced_id, status, date_last_modified, metadata, user_sourced_id, class_sourced_id, school_sourced_id, role, is_primary, begin_date, end_date)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
        )
        .bind(&enrollment.sourced_id)
        .bind(status_to_str(&enrollment.status))
        .bind(datetime_to_str(&enrollment.date_last_modified))
        .bind(metadata_to_str(&enrollment.metadata))
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
            "SELECT sourced_id, status, date_last_modified, metadata, user_sourced_id, class_sourced_id, school_sourced_id, role, is_primary, begin_date, end_date FROM enrollments WHERE sourced_id = ?1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(enrollment_from_row(&r))),
            None => Ok(None),
        }
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
            "SELECT sourced_id, status, date_last_modified, metadata, user_sourced_id, class_sourced_id, school_sourced_id, role, is_primary, begin_date, end_date FROM enrollments WHERE user_sourced_id = ?1"
        )
        .bind(user_sourced_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(enrollment_from_row).collect())
    }

    async fn list_enrollments_for_class(&self, class_sourced_id: &str) -> Result<Vec<Enrollment>> {
        let rows = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, user_sourced_id, class_sourced_id, school_sourced_id, role, is_primary, begin_date, end_date FROM enrollments WHERE class_sourced_id = ?1"
        )
        .bind(class_sourced_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(enrollment_from_row).collect())
    }

    async fn delete_enrollment(&self, sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM enrollments WHERE sourced_id = ?1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- DemographicsRepository --

#[async_trait]
impl DemographicsRepository for SqliteRepository {
    async fn upsert_demographics(&self, demo: &Demographics) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO demographics (sourced_id, status, date_last_modified, metadata, birth_date, sex, american_indian_or_alaska_native, asian, black_or_african_american, native_hawaiian_or_other_pacific_islander, white, demographic_race_two_or_more_races, hispanic_or_latino_ethnicity, country_of_birth_code, state_of_birth_abbreviation, city_of_birth, public_school_residence_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)"
        )
        .bind(&demo.sourced_id)
        .bind(status_to_str(&demo.status))
        .bind(datetime_to_str(&demo.date_last_modified))
        .bind(metadata_to_str(&demo.metadata))
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
            "SELECT sourced_id, status, date_last_modified, metadata, birth_date, sex, american_indian_or_alaska_native, asian, black_or_african_american, native_hawaiian_or_other_pacific_islander, white, demographic_race_two_or_more_races, hispanic_or_latino_ethnicity, country_of_birth_code, state_of_birth_abbreviation, city_of_birth, public_school_residence_status FROM demographics WHERE sourced_id = ?1"
        )
        .bind(sourced_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(Demographics {
                sourced_id: r.get("sourced_id"),
                status: parse_status(r.get("status")),
                date_last_modified: parse_datetime(r.get("date_last_modified")),
                metadata: parse_metadata(r.get("metadata")),
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
            })),
            None => Ok(None),
        }
    }

    async fn list_demographics(&self) -> Result<Vec<Demographics>> {
        let rows = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, birth_date, sex, american_indian_or_alaska_native, asian, black_or_african_american, native_hawaiian_or_other_pacific_islander, white, demographic_race_two_or_more_races, hispanic_or_latino_ethnicity, country_of_birth_code, state_of_birth_abbreviation, city_of_birth, public_school_residence_status FROM demographics"
        )
        .fetch_all(&self.pool)
        .await?;

        let demos: Vec<Demographics> = rows
            .iter()
            .map(|r| Demographics {
                sourced_id: r.get("sourced_id"),
                status: parse_status(r.get("status")),
                date_last_modified: parse_datetime(r.get("date_last_modified")),
                metadata: parse_metadata(r.get("metadata")),
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
            })
            .collect();

        Ok(demos)
    }

    async fn delete_demographics(&self, sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM demographics WHERE sourced_id = ?1")
            .bind(sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- SyncRepository --

#[async_trait]
impl SyncRepository for SqliteRepository {
    async fn create_sync_run(&self, provider: &str) -> Result<SyncRun> {
        let now = datetime_to_str(&Utc::now());
        let result = sqlx::query(
            "INSERT INTO sync_runs (provider, status, started_at, users_synced, orgs_synced, courses_synced, classes_synced, enrollments_synced)
             VALUES (?1, ?2, ?3, 0, 0, 0, 0, 0)"
        )
        .bind(provider)
        .bind(sync_status_to_str(&SyncStatus::Running))
        .bind(&now)
        .execute(&self.pool)
        .await?;

        let id = result.last_insert_rowid();
        Ok(SyncRun {
            id,
            provider: provider.to_string(),
            status: SyncStatus::Running,
            started_at: parse_datetime(&now),
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
        let now = datetime_to_str(&Utc::now());
        sqlx::query(
            "UPDATE sync_runs SET status = ?1, completed_at = ?2, error_message = ?3 WHERE id = ?4",
        )
        .bind(sync_status_to_str(&status))
        .bind(&now)
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
            "UPDATE sync_runs SET users_synced = ?1, orgs_synced = ?2, courses_synced = ?3, classes_synced = ?4, enrollments_synced = ?5 WHERE id = ?6"
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
            "SELECT id, provider, status, started_at, completed_at, error_message, users_synced, orgs_synced, courses_synced, classes_synced, enrollments_synced FROM sync_runs WHERE id = ?1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(SyncRun {
                id: r.get::<i64, _>("id"),
                provider: r.get("provider"),
                status: parse_sync_status(r.get("status")),
                started_at: parse_datetime(r.get("started_at")),
                completed_at: r
                    .get::<Option<String>, _>("completed_at")
                    .map(|s| parse_datetime(&s)),
                error_message: r.get("error_message"),
                users_synced: r.get::<i64, _>("users_synced"),
                orgs_synced: r.get::<i64, _>("orgs_synced"),
                courses_synced: r.get::<i64, _>("courses_synced"),
                classes_synced: r.get::<i64, _>("classes_synced"),
                enrollments_synced: r.get::<i64, _>("enrollments_synced"),
            })),
            None => Ok(None),
        }
    }

    async fn get_latest_sync_run(&self, provider: &str) -> Result<Option<SyncRun>> {
        let row = sqlx::query(
            "SELECT id, provider, status, started_at, completed_at, error_message, users_synced, orgs_synced, courses_synced, classes_synced, enrollments_synced FROM sync_runs WHERE provider = ?1 ORDER BY id DESC LIMIT 1"
        )
        .bind(provider)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(SyncRun {
                id: r.get::<i64, _>("id"),
                provider: r.get("provider"),
                status: parse_sync_status(r.get("status")),
                started_at: parse_datetime(r.get("started_at")),
                completed_at: r
                    .get::<Option<String>, _>("completed_at")
                    .map(|s| parse_datetime(&s)),
                error_message: r.get("error_message"),
                users_synced: r.get::<i64, _>("users_synced"),
                orgs_synced: r.get::<i64, _>("orgs_synced"),
                courses_synced: r.get::<i64, _>("courses_synced"),
                classes_synced: r.get::<i64, _>("classes_synced"),
                enrollments_synced: r.get::<i64, _>("enrollments_synced"),
            })),
            None => Ok(None),
        }
    }
}

// -- Helper functions for new IDP/Google Sync enums --

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

// -- IdpSessionRepository --

#[async_trait]
impl IdpSessionRepository for SqliteRepository {
    async fn create_session(&self, session: &IdpSession) -> Result<()> {
        sqlx::query(
            "INSERT INTO idp_sessions (id, user_sourced_id, auth_method, created_at, expires_at, saml_request_id, relay_state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        )
        .bind(&session.id)
        .bind(&session.user_sourced_id)
        .bind(auth_method_to_str(&session.auth_method))
        .bind(datetime_to_str(&session.created_at))
        .bind(datetime_to_str(&session.expires_at))
        .bind(&session.saml_request_id)
        .bind(&session.relay_state)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_session(&self, id: &str) -> Result<Option<IdpSession>> {
        let row = sqlx::query(
            "SELECT id, user_sourced_id, auth_method, created_at, expires_at, saml_request_id, relay_state FROM idp_sessions WHERE id = ?1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| IdpSession {
            id: r.get("id"),
            user_sourced_id: r.get("user_sourced_id"),
            auth_method: parse_auth_method(r.get("auth_method")),
            created_at: parse_datetime(r.get("created_at")),
            expires_at: parse_datetime(r.get("expires_at")),
            saml_request_id: r.get("saml_request_id"),
            relay_state: r.get("relay_state"),
        }))
    }

    async fn delete_session(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM idp_sessions WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_sessions(&self) -> Result<u64> {
        let now = datetime_to_str(&Utc::now());
        let result = sqlx::query("DELETE FROM idp_sessions WHERE expires_at < ?1")
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn list_sessions_for_user(&self, user_sourced_id: &str) -> Result<Vec<IdpSession>> {
        let rows = sqlx::query(
            "SELECT id, user_sourced_id, auth_method, created_at, expires_at, saml_request_id, relay_state FROM idp_sessions WHERE user_sourced_id = ?1 ORDER BY created_at DESC"
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
                created_at: parse_datetime(r.get("created_at")),
                expires_at: parse_datetime(r.get("expires_at")),
                saml_request_id: r.get("saml_request_id"),
                relay_state: r.get("relay_state"),
            })
            .collect())
    }
}

// -- QrBadgeRepository --

#[async_trait]
impl QrBadgeRepository for SqliteRepository {
    async fn create_badge(&self, badge: &QrBadge) -> Result<i64> {
        let result = sqlx::query(
            "INSERT INTO qr_badges (badge_token, user_sourced_id, is_active, created_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5)"
        )
        .bind(&badge.badge_token)
        .bind(&badge.user_sourced_id)
        .bind(badge.is_active)
        .bind(datetime_to_str(&badge.created_at))
        .bind(badge.revoked_at.as_ref().map(datetime_to_str))
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    async fn get_badge_by_token(&self, token: &str) -> Result<Option<QrBadge>> {
        let row = sqlx::query(
            "SELECT id, badge_token, user_sourced_id, is_active, created_at, revoked_at FROM qr_badges WHERE badge_token = ?1"
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| QrBadge {
            id: r.get::<i64, _>("id"),
            badge_token: r.get("badge_token"),
            user_sourced_id: r.get("user_sourced_id"),
            is_active: r.get("is_active"),
            created_at: parse_datetime(r.get("created_at")),
            revoked_at: r
                .get::<Option<String>, _>("revoked_at")
                .map(|s| parse_datetime(&s)),
        }))
    }

    async fn list_badges_for_user(&self, user_sourced_id: &str) -> Result<Vec<QrBadge>> {
        let rows = sqlx::query(
            "SELECT id, badge_token, user_sourced_id, is_active, created_at, revoked_at FROM qr_badges WHERE user_sourced_id = ?1 ORDER BY created_at DESC"
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
                created_at: parse_datetime(r.get("created_at")),
                revoked_at: r
                    .get::<Option<String>, _>("revoked_at")
                    .map(|s| parse_datetime(&s)),
            })
            .collect())
    }

    async fn revoke_badge(&self, id: i64) -> Result<bool> {
        let now = datetime_to_str(&Utc::now());
        let result = sqlx::query(
            "UPDATE qr_badges SET is_active = 0, revoked_at = ?1 WHERE id = ?2 AND is_active = 1",
        )
        .bind(&now)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- PicturePasswordRepository --

#[async_trait]
impl PicturePasswordRepository for SqliteRepository {
    async fn upsert_picture_password(&self, pp: &PicturePassword) -> Result<()> {
        let sequence_json = serde_json::to_string(&pp.image_sequence)
            .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?;
        sqlx::query(
            "INSERT OR REPLACE INTO picture_passwords (user_sourced_id, image_sequence) VALUES (?1, ?2)"
        )
        .bind(&pp.user_sourced_id)
        .bind(&sequence_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_picture_password(&self, user_sourced_id: &str) -> Result<Option<PicturePassword>> {
        let row = sqlx::query(
            "SELECT user_sourced_id, image_sequence FROM picture_passwords WHERE user_sourced_id = ?1"
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
        let result = sqlx::query("DELETE FROM picture_passwords WHERE user_sourced_id = ?1")
            .bind(user_sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- IdpAuthLogRepository --

#[async_trait]
impl IdpAuthLogRepository for SqliteRepository {
    async fn log_auth_attempt(&self, entry: &AuthLogEntry) -> Result<i64> {
        let result = sqlx::query(
            "INSERT INTO idp_auth_log (user_sourced_id, username, auth_method, success, ip_address, user_agent, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        )
        .bind(&entry.user_sourced_id)
        .bind(&entry.username)
        .bind(auth_method_to_str(&entry.auth_method))
        .bind(entry.success)
        .bind(&entry.ip_address)
        .bind(&entry.user_agent)
        .bind(datetime_to_str(&entry.created_at))
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    async fn list_auth_log(&self, limit: i64) -> Result<Vec<AuthLogEntry>> {
        let rows = sqlx::query(
            "SELECT id, user_sourced_id, username, auth_method, success, ip_address, user_agent, created_at FROM idp_auth_log ORDER BY created_at DESC LIMIT ?1"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| AuthLogEntry {
                id: r.get::<i64, _>("id"),
                user_sourced_id: r.get("user_sourced_id"),
                username: r.get("username"),
                auth_method: parse_auth_method(r.get("auth_method")),
                success: r.get("success"),
                ip_address: r.get("ip_address"),
                user_agent: r.get("user_agent"),
                created_at: parse_datetime(r.get("created_at")),
            })
            .collect())
    }

    async fn list_auth_log_for_user(
        &self,
        user_sourced_id: &str,
        limit: i64,
    ) -> Result<Vec<AuthLogEntry>> {
        let rows = sqlx::query(
            "SELECT id, user_sourced_id, username, auth_method, success, ip_address, user_agent, created_at FROM idp_auth_log WHERE user_sourced_id = ?1 ORDER BY created_at DESC LIMIT ?2"
        )
        .bind(user_sourced_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| AuthLogEntry {
                id: r.get::<i64, _>("id"),
                user_sourced_id: r.get("user_sourced_id"),
                username: r.get("username"),
                auth_method: parse_auth_method(r.get("auth_method")),
                success: r.get("success"),
                ip_address: r.get("ip_address"),
                user_agent: r.get("user_agent"),
                created_at: parse_datetime(r.get("created_at")),
            })
            .collect())
    }
}

// -- GoogleSyncStateRepository --

#[async_trait]
impl GoogleSyncStateRepository for SqliteRepository {
    async fn upsert_sync_state(&self, state: &GoogleSyncUserState) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO google_sync_state (user_sourced_id, google_id, google_email, google_ou, field_hash, sync_status, last_synced_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
        )
        .bind(&state.user_sourced_id)
        .bind(&state.google_id)
        .bind(&state.google_email)
        .bind(&state.google_ou)
        .bind(&state.field_hash)
        .bind(google_sync_status_to_str(&state.sync_status))
        .bind(state.last_synced_at.as_ref().map(datetime_to_str))
        .bind(datetime_to_str(&state.created_at))
        .bind(datetime_to_str(&state.updated_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_sync_state(&self, user_sourced_id: &str) -> Result<Option<GoogleSyncUserState>> {
        let row = sqlx::query(
            "SELECT user_sourced_id, google_id, google_email, google_ou, field_hash, sync_status, last_synced_at, created_at, updated_at FROM google_sync_state WHERE user_sourced_id = ?1"
        )
        .bind(user_sourced_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| GoogleSyncUserState {
            user_sourced_id: r.get("user_sourced_id"),
            google_id: r.get("google_id"),
            google_email: r.get("google_email"),
            google_ou: r.get("google_ou"),
            field_hash: r.get("field_hash"),
            sync_status: parse_google_sync_status(r.get("sync_status")),
            last_synced_at: r
                .get::<Option<String>, _>("last_synced_at")
                .map(|s| parse_datetime(&s)),
            created_at: parse_datetime(r.get("created_at")),
            updated_at: parse_datetime(r.get("updated_at")),
        }))
    }

    async fn list_sync_states(&self) -> Result<Vec<GoogleSyncUserState>> {
        let rows = sqlx::query(
            "SELECT user_sourced_id, google_id, google_email, google_ou, field_hash, sync_status, last_synced_at, created_at, updated_at FROM google_sync_state"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| GoogleSyncUserState {
                user_sourced_id: r.get("user_sourced_id"),
                google_id: r.get("google_id"),
                google_email: r.get("google_email"),
                google_ou: r.get("google_ou"),
                field_hash: r.get("field_hash"),
                sync_status: parse_google_sync_status(r.get("sync_status")),
                last_synced_at: r
                    .get::<Option<String>, _>("last_synced_at")
                    .map(|s| parse_datetime(&s)),
                created_at: parse_datetime(r.get("created_at")),
                updated_at: parse_datetime(r.get("updated_at")),
            })
            .collect())
    }

    async fn delete_sync_state(&self, user_sourced_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM google_sync_state WHERE user_sourced_id = ?1")
            .bind(user_sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- GoogleSyncRunRepository --

#[async_trait]
impl GoogleSyncRunRepository for SqliteRepository {
    async fn create_google_sync_run(&self, dry_run: bool) -> Result<GoogleSyncRun> {
        let now = datetime_to_str(&Utc::now());
        let result = sqlx::query(
            "INSERT INTO google_sync_runs (started_at, status, dry_run) VALUES (?1, ?2, ?3)",
        )
        .bind(&now)
        .bind(google_sync_run_status_to_str(&GoogleSyncRunStatus::Running))
        .bind(dry_run)
        .execute(&self.pool)
        .await?;

        Ok(GoogleSyncRun {
            id: result.last_insert_rowid(),
            started_at: parse_datetime(&now),
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
        let now = datetime_to_str(&Utc::now());
        sqlx::query(
            "UPDATE google_sync_runs SET status = ?1, completed_at = ?2, users_created = ?3, users_updated = ?4, users_suspended = ?5, ous_created = ?6, error_message = ?7 WHERE id = ?8"
        )
        .bind(google_sync_run_status_to_str(&status))
        .bind(&now)
        .bind(users_created)
        .bind(users_updated)
        .bind(users_suspended)
        .bind(ous_created)
        .bind(error_message)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_google_sync_run(&self, id: i64) -> Result<Option<GoogleSyncRun>> {
        let row = sqlx::query(
            "SELECT id, started_at, completed_at, status, users_created, users_updated, users_suspended, ous_created, dry_run, error_message FROM google_sync_runs WHERE id = ?1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| GoogleSyncRun {
            id: r.get::<i64, _>("id"),
            started_at: parse_datetime(r.get("started_at")),
            completed_at: r
                .get::<Option<String>, _>("completed_at")
                .map(|s| parse_datetime(&s)),
            status: parse_google_sync_run_status(r.get("status")),
            users_created: r.get::<i64, _>("users_created"),
            users_updated: r.get::<i64, _>("users_updated"),
            users_suspended: r.get::<i64, _>("users_suspended"),
            ous_created: r.get::<i64, _>("ous_created"),
            dry_run: r.get("dry_run"),
            error_message: r.get("error_message"),
        }))
    }

    async fn get_latest_google_sync_run(&self) -> Result<Option<GoogleSyncRun>> {
        let row = sqlx::query(
            "SELECT id, started_at, completed_at, status, users_created, users_updated, users_suspended, ous_created, dry_run, error_message FROM google_sync_runs ORDER BY id DESC LIMIT 1"
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| GoogleSyncRun {
            id: r.get::<i64, _>("id"),
            started_at: parse_datetime(r.get("started_at")),
            completed_at: r
                .get::<Option<String>, _>("completed_at")
                .map(|s| parse_datetime(&s)),
            status: parse_google_sync_run_status(r.get("status")),
            users_created: r.get::<i64, _>("users_created"),
            users_updated: r.get::<i64, _>("users_updated"),
            users_suspended: r.get::<i64, _>("users_suspended"),
            ous_created: r.get::<i64, _>("ous_created"),
            dry_run: r.get("dry_run"),
            error_message: r.get("error_message"),
        }))
    }

    async fn list_google_sync_runs(&self, limit: i64) -> Result<Vec<GoogleSyncRun>> {
        let rows = sqlx::query(
            "SELECT id, started_at, completed_at, status, users_created, users_updated, users_suspended, ous_created, dry_run, error_message FROM google_sync_runs ORDER BY id DESC LIMIT ?1"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| GoogleSyncRun {
                id: r.get::<i64, _>("id"),
                started_at: parse_datetime(r.get("started_at")),
                completed_at: r
                    .get::<Option<String>, _>("completed_at")
                    .map(|s| parse_datetime(&s)),
                status: parse_google_sync_run_status(r.get("status")),
                users_created: r.get::<i64, _>("users_created"),
                users_updated: r.get::<i64, _>("users_updated"),
                users_suspended: r.get::<i64, _>("users_suspended"),
                ous_created: r.get::<i64, _>("ous_created"),
                dry_run: r.get("dry_run"),
                error_message: r.get("error_message"),
            })
            .collect())
    }
}

// -- PasswordRepository --

#[async_trait]
impl PasswordRepository for SqliteRepository {
    async fn get_password_hash(&self, user_sourced_id: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT password_hash FROM users WHERE sourced_id = ?1")
            .bind(user_sourced_id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(r.get("password_hash")),
            None => Ok(None),
        }
    }

    async fn set_password_hash(&self, user_sourced_id: &str, hash: &str) -> Result<()> {
        sqlx::query("UPDATE users SET password_hash = ?1 WHERE sourced_id = ?2")
            .bind(hash)
            .bind(user_sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl AdminSessionRepository for SqliteRepository {
    async fn create_admin_session(&self, session: &AdminSession) -> Result<()> {
        sqlx::query(
            "INSERT INTO admin_sessions \
             (token, created_at, expires_at, ip_address, actor_id, actor_label, actor_role) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(&session.token)
        .bind(session.created_at.format("%Y-%m-%d %H:%M:%S").to_string())
        .bind(session.expires_at.format("%Y-%m-%d %H:%M:%S").to_string())
        .bind(&session.ip_address)
        .bind(&session.actor_id)
        .bind(&session.actor_label)
        .bind(&session.actor_role)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_admin_session(&self, token: &str) -> Result<Option<AdminSession>> {
        let row = sqlx::query(
            "SELECT token, created_at, expires_at, ip_address, actor_id, actor_label, actor_role \
             FROM admin_sessions WHERE token = ?1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let created_str: String = r.get("created_at");
                let expires_str: String = r.get("expires_at");
                let created_at =
                    chrono::NaiveDateTime::parse_from_str(&created_str, "%Y-%m-%d %H:%M:%S")
                        .unwrap_or_default()
                        .and_utc();
                let expires_at =
                    chrono::NaiveDateTime::parse_from_str(&expires_str, "%Y-%m-%d %H:%M:%S")
                        .unwrap_or_default()
                        .and_utc();
                Ok(Some(AdminSession {
                    token: r.get("token"),
                    created_at,
                    expires_at,
                    ip_address: r.get("ip_address"),
                    actor_id: r.get("actor_id"),
                    actor_label: r.get("actor_label"),
                    actor_role: r.get("actor_role"),
                }))
            }
            None => Ok(None),
        }
    }

    async fn delete_admin_session(&self, token: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM admin_sessions WHERE token = ?1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_admin_sessions(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM admin_sessions WHERE expires_at < datetime('now')")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

#[async_trait]
impl AdminAuditRepository for SqliteRepository {
    async fn log_admin_action(
        &self,
        action: &str,
        details: Option<&str>,
        admin_ip: Option<&str>,
    ) -> Result<i64> {
        let result = sqlx::query(
            "INSERT INTO admin_audit_log (action, details, admin_ip) VALUES (?1, ?2, ?3)",
        )
        .bind(action)
        .bind(details)
        .bind(admin_ip)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    async fn list_admin_audit_log(&self, limit: i64) -> Result<Vec<AdminAuditEntry>> {
        let rows = sqlx::query(
            "SELECT id, action, details, admin_ip, created_at FROM admin_audit_log ORDER BY id DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut entries = Vec::with_capacity(rows.len());
        for r in &rows {
            let created_str: String = r.get("created_at");
            let created_at =
                chrono::NaiveDateTime::parse_from_str(&created_str, "%Y-%m-%d %H:%M:%S")
                    .unwrap_or_default()
                    .and_utc();
            entries.push(AdminAuditEntry {
                id: r.get("id"),
                action: r.get("action"),
                details: r.get("details"),
                admin_ip: r.get("admin_ip"),
                created_at,
            });
        }
        Ok(entries)
    }

    async fn prune_admin_audit_log(
        &self,
        older_than: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64> {
        // SQLite stores `created_at` as a CURRENT_TIMESTAMP-formatted string
        // (`YYYY-MM-DD HH:MM:SS`). Compare against the same string shape so
        // the comparison sticks to the column's natural order.
        let cutoff = older_than.format("%Y-%m-%d %H:%M:%S").to_string();
        let result = sqlx::query("DELETE FROM admin_audit_log WHERE created_at < ?1")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

#[async_trait]
impl ConfigRepository for SqliteRepository {
    async fn get_config_override(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM config_overrides WHERE key = ?1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get("value")))
    }

    async fn set_config_override(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO config_overrides (key, value, updated_at) VALUES (?1, ?2, datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// -- SsoPartnerRepository --

fn parse_sso_protocol(s: &str) -> SsoProtocol {
    match s {
        "oidc" => SsoProtocol::Oidc,
        "clever_compat" => SsoProtocol::CleverCompat,
        "classlink_compat" => SsoProtocol::ClassLinkCompat,
        "link" => SsoProtocol::Link,
        _ => SsoProtocol::Saml,
    }
}

fn sso_protocol_to_str(p: &SsoProtocol) -> &'static str {
    match p {
        SsoProtocol::Saml => "saml",
        SsoProtocol::Oidc => "oidc",
        SsoProtocol::CleverCompat => "clever_compat",
        SsoProtocol::ClassLinkCompat => "classlink_compat",
        SsoProtocol::Link => "link",
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

fn row_to_sso_partner(r: &sqlx::sqlite::SqliteRow) -> SsoPartner {
    let roles_json: String = r.get("roles_json");
    let roles: Vec<String> = serde_json::from_str(&roles_json).unwrap_or_default();
    let uris_json: String = r.get("oidc_redirect_uris_json");
    let oidc_redirect_uris: Vec<String> = serde_json::from_str(&uris_json).unwrap_or_default();
    let audience: Option<SsoAudience> = r
        .get::<Option<String>, _>("audience_json")
        .and_then(|s| serde_json::from_str(&s).ok());
    let launch_url: Option<String> = r.get("launch_url");

    SsoPartner {
        id: r.get("id"),
        name: r.get("name"),
        logo_url: r.get("logo_url"),
        protocol: parse_sso_protocol(r.get("protocol")),
        enabled: r.get::<bool, _>("enabled"),
        source: parse_sso_source(r.get("source")),
        tenant_id: r.get("tenant_id"),
        roles,
        audience,
        saml_entity_id: r.get("saml_entity_id"),
        saml_acs_url: r.get("saml_acs_url"),
        oidc_client_id: r.get("oidc_client_id"),
        oidc_client_secret: r.get("oidc_client_secret"),
        oidc_redirect_uris,
        launch_url,
        created_at: parse_datetime(r.get("created_at")),
        updated_at: parse_datetime(r.get("updated_at")),
    }
}

#[async_trait]
impl SsoPartnerRepository for SqliteRepository {
    async fn upsert_sso_partner(&self, partner: &SsoPartner) -> Result<()> {
        let roles_json = serde_json::to_string(&partner.roles)
            .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?;
        let audience_json = match &partner.audience {
            Some(a) => Some(
                serde_json::to_string(a)
                    .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?,
            ),
            None => None,
        };
        let uris_json = serde_json::to_string(&partner.oidc_redirect_uris)
            .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO sso_partners (id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, audience_json, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, launch_url, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                logo_url = excluded.logo_url,
                protocol = excluded.protocol,
                enabled = excluded.enabled,
                source = excluded.source,
                tenant_id = excluded.tenant_id,
                roles_json = excluded.roles_json,
                audience_json = excluded.audience_json,
                saml_entity_id = excluded.saml_entity_id,
                saml_acs_url = excluded.saml_acs_url,
                oidc_client_id = excluded.oidc_client_id,
                oidc_client_secret = excluded.oidc_client_secret,
                oidc_redirect_uris_json = excluded.oidc_redirect_uris_json,
                launch_url = excluded.launch_url,
                updated_at = excluded.updated_at"
        )
        .bind(&partner.id)
        .bind(&partner.name)
        .bind(&partner.logo_url)
        .bind(sso_protocol_to_str(&partner.protocol))
        .bind(partner.enabled)
        .bind(sso_source_to_str(&partner.source))
        .bind(&partner.tenant_id)
        .bind(&roles_json)
        .bind(&audience_json)
        .bind(&partner.saml_entity_id)
        .bind(&partner.saml_acs_url)
        .bind(&partner.oidc_client_id)
        .bind(&partner.oidc_client_secret)
        .bind(&uris_json)
        .bind(&partner.launch_url)
        .bind(datetime_to_str(&partner.created_at))
        .bind(datetime_to_str(&partner.updated_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_sso_partner(&self, id: &str) -> Result<Option<SsoPartner>> {
        let row = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, audience_json, launch_url, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners WHERE id = ?1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.as_ref().map(row_to_sso_partner))
    }

    async fn get_sso_partner_by_entity_id(&self, entity_id: &str) -> Result<Option<SsoPartner>> {
        let row = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, audience_json, launch_url, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners WHERE saml_entity_id = ?1"
        )
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.as_ref().map(row_to_sso_partner))
    }

    async fn get_sso_partner_by_client_id(&self, client_id: &str) -> Result<Option<SsoPartner>> {
        let row = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, audience_json, launch_url, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners WHERE oidc_client_id = ?1"
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.as_ref().map(row_to_sso_partner))
    }

    async fn list_sso_partners(&self) -> Result<Vec<SsoPartner>> {
        let rows = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, audience_json, launch_url, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners ORDER BY name"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_sso_partner).collect())
    }

    async fn list_sso_partners_for_role(&self, role: &str) -> Result<Vec<SsoPartner>> {
        // Fetch all enabled partners and filter by role in-memory
        // (JSON role matching in SQL is fragile; list is small)
        let rows = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, audience_json, launch_url, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners WHERE enabled = 1 ORDER BY name"
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
        let result = sqlx::query("DELETE FROM sso_partners WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// -- OidcCodeRepository --

#[async_trait]
impl OidcCodeRepository for SqliteRepository {
    async fn create_oidc_code(&self, code: &OidcAuthorizationCode) -> Result<()> {
        sqlx::query(
            "INSERT INTO oidc_authorization_codes (code, client_id, user_sourced_id, redirect_uri, scope, nonce, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
        )
        .bind(&code.code)
        .bind(&code.client_id)
        .bind(&code.user_sourced_id)
        .bind(&code.redirect_uri)
        .bind(&code.scope)
        .bind(&code.nonce)
        .bind(datetime_to_str(&code.created_at))
        .bind(datetime_to_str(&code.expires_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_oidc_code(&self, code: &str) -> Result<Option<OidcAuthorizationCode>> {
        let row = sqlx::query(
            "SELECT code, client_id, user_sourced_id, redirect_uri, scope, nonce, created_at, expires_at FROM oidc_authorization_codes WHERE code = ?1"
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
            created_at: parse_datetime(r.get("created_at")),
            expires_at: parse_datetime(r.get("expires_at")),
        }))
    }

    async fn delete_oidc_code(&self, code: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM oidc_authorization_codes WHERE code = ?1")
            .bind(code)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_oidc_codes(&self) -> Result<u64> {
        let result =
            sqlx::query("DELETE FROM oidc_authorization_codes WHERE expires_at < datetime('now')")
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected())
    }
}

// -- PortalSessionRepository --

#[async_trait]
impl PortalSessionRepository for SqliteRepository {
    async fn create_portal_session(&self, session: &PortalSession) -> Result<()> {
        sqlx::query(
            "INSERT INTO portal_sessions (id, user_sourced_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&session.id)
        .bind(&session.user_sourced_id)
        .bind(datetime_to_str(&session.created_at))
        .bind(datetime_to_str(&session.expires_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_portal_session(&self, id: &str) -> Result<Option<PortalSession>> {
        let row = sqlx::query(
            "SELECT id, user_sourced_id, created_at, expires_at FROM portal_sessions WHERE id = ?1 AND expires_at > datetime('now')"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| PortalSession {
            id: r.get("id"),
            user_sourced_id: r.get("user_sourced_id"),
            created_at: parse_datetime(r.get("created_at")),
            expires_at: parse_datetime(r.get("expires_at")),
        }))
    }

    async fn delete_portal_session(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM portal_sessions WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_portal_sessions(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM portal_sessions WHERE expires_at < datetime('now')")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

// -- Webhook helper functions --

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

fn row_to_webhook_endpoint(row: sqlx::sqlite::SqliteRow) -> WebhookEndpoint {
    let scoping_json: String = row.get("scoping_json");
    let scoping: WebhookScoping = serde_json::from_str(&scoping_json).unwrap_or_default();

    WebhookEndpoint {
        id: row.get("id"),
        name: row.get("name"),
        url: row.get("url"),
        secret: row.get("secret"),
        enabled: row.get::<i32, _>("enabled") != 0,
        mode: parse_webhook_mode(row.get("mode")),
        security_mode: parse_webhook_security_mode(row.get("security_mode")),
        source: parse_webhook_source(row.get("source")),
        tenant_id: row.get("tenant_id"),
        scoping,
        created_at: parse_datetime(row.get("created_at")),
        updated_at: parse_datetime(row.get("updated_at")),
    }
}

fn row_to_webhook_delivery(row: sqlx::sqlite::SqliteRow) -> WebhookDelivery {
    let next_retry_at: Option<String> = row.get("next_retry_at");
    WebhookDelivery {
        id: row.get::<i64, _>("id"),
        webhook_endpoint_id: row.get("webhook_endpoint_id"),
        event_id: row.get("event_id"),
        sync_run_id: row.get("sync_run_id"),
        status: parse_delivery_status(row.get("status")),
        http_status: row.get("http_status"),
        response_body: row.get("response_body"),
        attempt_count: row.get("attempt_count"),
        next_retry_at: next_retry_at.map(|s| parse_datetime(&s)),
        created_at: parse_datetime(row.get("created_at")),
        updated_at: parse_datetime(row.get("updated_at")),
    }
}

#[async_trait]
impl WebhookEndpointRepository for SqliteRepository {
    async fn upsert_webhook_endpoint(&self, endpoint: &WebhookEndpoint) -> Result<()> {
        let scoping_json =
            serde_json::to_string(&endpoint.scoping).unwrap_or_else(|_| "{}".to_string());
        sqlx::query(
            "INSERT INTO webhook_endpoints (id, name, url, secret, enabled, mode, security_mode, source, tenant_id, scoping_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, datetime('now'))
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                url = excluded.url,
                secret = excluded.secret,
                enabled = excluded.enabled,
                mode = excluded.mode,
                security_mode = excluded.security_mode,
                source = excluded.source,
                tenant_id = excluded.tenant_id,
                scoping_json = excluded.scoping_json,
                updated_at = datetime('now')",
        )
        .bind(&endpoint.id)
        .bind(&endpoint.name)
        .bind(&endpoint.url)
        .bind(&endpoint.secret)
        .bind(endpoint.enabled as i32)
        .bind(webhook_mode_to_str(&endpoint.mode))
        .bind(webhook_security_mode_to_str(&endpoint.security_mode))
        .bind(webhook_source_to_str(&endpoint.source))
        .bind(&endpoint.tenant_id)
        .bind(&scoping_json)
        .bind(endpoint.created_at.format("%Y-%m-%d %H:%M:%S").to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_webhook_endpoint(&self, id: &str) -> Result<Option<WebhookEndpoint>> {
        let row = sqlx::query("SELECT * FROM webhook_endpoints WHERE id = ?1")
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
            sqlx::query("SELECT * FROM webhook_endpoints WHERE source = ?1 ORDER BY created_at")
                .bind(source)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.into_iter().map(row_to_webhook_endpoint).collect())
    }

    async fn delete_webhook_endpoint(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM webhook_endpoints WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl WebhookDeliveryRepository for SqliteRepository {
    async fn create_webhook_delivery(&self, delivery: &WebhookDelivery) -> Result<i64> {
        let next_retry = delivery
            .next_retry_at
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());
        let result = sqlx::query(
            "INSERT INTO webhook_deliveries (webhook_endpoint_id, event_id, sync_run_id, status, http_status, response_body, attempt_count, next_retry_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&delivery.webhook_endpoint_id)
        .bind(&delivery.event_id)
        .bind(delivery.sync_run_id)
        .bind(delivery_status_to_str(&delivery.status))
        .bind(delivery.http_status)
        .bind(&delivery.response_body)
        .bind(delivery.attempt_count)
        .bind(&next_retry)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    async fn update_delivery_status(
        &self,
        id: i64,
        status: DeliveryStatus,
        http_status: Option<i32>,
        response_body: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE webhook_deliveries SET status = ?1, http_status = ?2, response_body = ?3, attempt_count = attempt_count + 1, updated_at = datetime('now') WHERE id = ?4",
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
        // Use the same string format as `create_webhook_delivery` so the
        // string comparison in `list_pending_retries` (against SQLite's
        // `datetime('now')` which uses the same shape) actually works.
        let next_str = next_retry_at.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());
        sqlx::query(
            "UPDATE webhook_deliveries SET next_retry_at = ?1, updated_at = datetime('now') WHERE id = ?2",
        )
        .bind(next_str)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_pending_retries(&self, limit: i64) -> Result<Vec<WebhookDelivery>> {
        let rows = sqlx::query(
            "SELECT * FROM webhook_deliveries WHERE status IN ('pending', 'retrying') AND (next_retry_at IS NULL OR next_retry_at <= datetime('now')) ORDER BY created_at LIMIT ?1",
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
            "SELECT * FROM webhook_deliveries WHERE webhook_endpoint_id = ?1 ORDER BY created_at DESC LIMIT ?2",
        )
        .bind(webhook_endpoint_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_webhook_delivery).collect())
    }

    async fn list_deliveries_by_sync_run(&self, sync_run_id: i64) -> Result<Vec<WebhookDelivery>> {
        let rows = sqlx::query(
            "SELECT * FROM webhook_deliveries WHERE sync_run_id = ?1 ORDER BY created_at",
        )
        .bind(sync_run_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_webhook_delivery).collect())
    }
}

/// Returns the effective schedule by checking DB override first, falling back to config value.
pub async fn effective_schedule<R: ConfigRepository + ?Sized>(
    repo: &R,
    override_key: &str,
    config_value: &str,
) -> String {
    repo.get_config_override(override_key)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| config_value.to_string())
}

// -- AD Sync helper functions --

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

fn row_to_ad_sync_state(r: &sqlx::sqlite::SqliteRow) -> AdSyncUserState {
    let last_synced: Option<String> = r.get("last_synced_at");
    AdSyncUserState {
        user_sourced_id: r.get("user_sourced_id"),
        ad_dn: r.get("ad_dn"),
        ad_sam_account_name: r.get("ad_sam_account_name"),
        ad_upn: r.get("ad_upn"),
        ad_ou: r.get("ad_ou"),
        field_hash: r.get("field_hash"),
        sync_status: parse_ad_sync_status(r.get("sync_status")),
        initial_password: r.get("initial_password"),
        last_synced_at: last_synced.map(|s| parse_datetime(&s)),
        created_at: parse_datetime(r.get("created_at")),
        updated_at: parse_datetime(r.get("updated_at")),
    }
}

fn row_to_ad_sync_run(r: &sqlx::sqlite::SqliteRow) -> AdSyncRun {
    let completed: Option<String> = r.get("completed_at");
    AdSyncRun {
        id: r.get("id"),
        started_at: parse_datetime(r.get("started_at")),
        completed_at: completed.map(|s| parse_datetime(&s)),
        status: parse_ad_sync_run_status(r.get("status")),
        users_created: r.get("users_created"),
        users_updated: r.get("users_updated"),
        users_disabled: r.get("users_disabled"),
        users_skipped: r.get("users_skipped"),
        groups_created: r.get("groups_created"),
        groups_updated: r.get("groups_updated"),
        errors: r.get("errors"),
        error_details: r.get("error_details"),
        dry_run: r.get::<i32, _>("dry_run") != 0,
    }
}

#[async_trait]
impl AdSyncStateRepository for SqliteRepository {
    async fn upsert_ad_sync_state(&self, state: &AdSyncUserState) -> Result<()> {
        sqlx::query(
            "INSERT INTO ad_sync_state (user_sourced_id, ad_dn, ad_sam_account_name, ad_upn, ad_ou, field_hash, sync_status, initial_password, last_synced_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(user_sourced_id) DO UPDATE SET
                ad_dn = excluded.ad_dn,
                ad_sam_account_name = excluded.ad_sam_account_name,
                ad_upn = excluded.ad_upn,
                ad_ou = excluded.ad_ou,
                field_hash = excluded.field_hash,
                sync_status = excluded.sync_status,
                initial_password = excluded.initial_password,
                last_synced_at = excluded.last_synced_at,
                updated_at = excluded.updated_at"
        )
        .bind(&state.user_sourced_id)
        .bind(&state.ad_dn)
        .bind(&state.ad_sam_account_name)
        .bind(&state.ad_upn)
        .bind(&state.ad_ou)
        .bind(&state.field_hash)
        .bind(ad_sync_status_to_str(&state.sync_status))
        .bind(&state.initial_password)
        .bind(state.last_synced_at.as_ref().map(datetime_to_str))
        .bind(datetime_to_str(&state.created_at))
        .bind(datetime_to_str(&state.updated_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_ad_sync_state(&self, user_sourced_id: &str) -> Result<Option<AdSyncUserState>> {
        let row = sqlx::query("SELECT * FROM ad_sync_state WHERE user_sourced_id = ?1")
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
        let result = sqlx::query("DELETE FROM ad_sync_state WHERE user_sourced_id = ?1")
            .bind(user_sourced_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl AdSyncRunRepository for SqliteRepository {
    async fn create_ad_sync_run(&self, dry_run: bool) -> Result<AdSyncRun> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        let now_str = datetime_to_str(&now);

        sqlx::query(
            "INSERT INTO ad_sync_runs (id, started_at, status, dry_run) VALUES (?1, ?2, 'running', ?3)"
        )
        .bind(&id)
        .bind(&now_str)
        .bind(dry_run as i32)
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
        let now_str = datetime_to_str(&Utc::now());
        sqlx::query(
            "UPDATE ad_sync_runs SET status = ?2, completed_at = ?3, users_created = ?4, users_updated = ?5, users_disabled = ?6, users_skipped = ?7, groups_created = ?8, groups_updated = ?9, errors = ?10, error_details = ?11 WHERE id = ?1"
        )
        .bind(id)
        .bind(ad_sync_run_status_to_str(&status))
        .bind(&now_str)
        .bind(users_created)
        .bind(users_updated)
        .bind(users_disabled)
        .bind(users_skipped)
        .bind(groups_created)
        .bind(groups_updated)
        .bind(errors)
        .bind(error_details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_ad_sync_run(&self, id: &str) -> Result<Option<AdSyncRun>> {
        let row = sqlx::query("SELECT * FROM ad_sync_runs WHERE id = ?1")
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
        let rows = sqlx::query("SELECT * FROM ad_sync_runs ORDER BY started_at DESC LIMIT ?1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_ad_sync_run).collect())
    }
}

#[async_trait]
impl ExternalIdRepository for SqliteRepository {
    async fn get_external_ids(
        &self,
        user_sourced_id: &str,
    ) -> Result<serde_json::Map<String, serde_json::Value>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT external_ids FROM users WHERE sourced_id = ?1")
                .bind(user_sourced_id)
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some((json_str,)) => {
                let map: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_str(&json_str).unwrap_or_default();
                Ok(map)
            }
            None => Ok(serde_json::Map::new()),
        }
    }

    async fn set_external_ids(
        &self,
        user_sourced_id: &str,
        ids: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<()> {
        let json_str = serde_json::to_string(ids)
            .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?;
        sqlx::query("UPDATE users SET external_ids = ?2 WHERE sourced_id = ?1")
            .bind(user_sourced_id)
            .bind(&json_str)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn find_user_by_external_id(
        &self,
        provider: &str,
        external_id: &str,
    ) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT * FROM users WHERE json_extract(external_ids, '$.' || ?1) = ?2 LIMIT 1",
        )
        .bind(provider)
        .bind(external_id)
        .fetch_optional(&self.pool)
        .await?;
        self.row_to_user(row).await
    }
}

#[async_trait]
impl AccessTokenRepository for SqliteRepository {
    async fn create_access_token(&self, token: &AccessToken) -> Result<()> {
        sqlx::query(
            "INSERT INTO access_tokens (token, client_id, user_sourced_id, scopes, created_at, expires_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(&token.token)
        .bind(&token.client_id)
        .bind(&token.user_sourced_id)
        .bind(&token.scopes)
        .bind(&token.created_at)
        .bind(&token.expires_at)
        .bind(&token.revoked_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_access_token(&self, token: &str) -> Result<Option<AccessToken>> {
        let row: Option<AccessToken> =
            sqlx::query_as("SELECT * FROM access_tokens WHERE token = ?1")
                .bind(token)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row)
    }

    async fn revoke_access_token(&self, token: &str) -> Result<()> {
        let now = datetime_to_str(&Utc::now());
        sqlx::query("UPDATE access_tokens SET revoked_at = ?2 WHERE token = ?1")
            .bind(token)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_expired_access_tokens(&self) -> Result<u64> {
        let now = datetime_to_str(&Utc::now());
        let result = sqlx::query(
            "DELETE FROM access_tokens WHERE expires_at < ?1 OR revoked_at IS NOT NULL",
        )
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

// -- ApiTokenRepository --

#[async_trait]
impl ApiTokenRepository for SqliteRepository {
    async fn create_api_token(&self, token: &crate::models::api_token::ApiToken) -> Result<()> {
        let scope_json = token
            .scope
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| crate::error::ChalkError::Serialization(format!("token scope: {e}")))?;
        sqlx::query(
            "INSERT INTO api_tokens \
             (id, name, token_hash, token_prefix, created_at, last_used_at, revoked_at, scope) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&token.id)
        .bind(&token.name)
        .bind(&token.token_hash)
        .bind(&token.token_prefix)
        .bind(datetime_to_str(&token.created_at))
        .bind(token.last_used_at.map(|d| datetime_to_str(&d)))
        .bind(token.revoked_at.map(|d| datetime_to_str(&d)))
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
            String,
            Option<String>,
            Option<String>,
            Option<String>,
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
                    created_at: parse_datetime(&ca),
                    last_used_at: lu.as_deref().map(parse_datetime),
                    revoked_at: rv.as_deref().map(parse_datetime),
                    // Display path: tolerate a malformed scope by showing the
                    // token as unscoped rather than failing the whole listing.
                    scope: scope.and_then(|s| serde_json::from_str(&s).ok()),
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
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT id, name, token_hash, token_prefix, created_at, last_used_at, revoked_at, scope \
             FROM api_tokens \
             WHERE token_hash = ?1 AND revoked_at IS NULL",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        // Auth path: a stored-but-unparseable scope must NOT silently widen
        // access to unrestricted. Surface it as an error so the request fails
        // closed rather than open.
        row.map(|(id, name, h, prefix, ca, lu, rv, scope)| {
            let scope = scope
                .map(|s| serde_json::from_str(&s))
                .transpose()
                .map_err(|e| {
                    crate::error::ChalkError::Serialization(format!("token scope: {e}"))
                })?;
            Ok(crate::models::api_token::ApiToken {
                id,
                name,
                token_hash: h,
                token_prefix: prefix,
                created_at: parse_datetime(&ca),
                last_used_at: lu.as_deref().map(parse_datetime),
                revoked_at: rv.as_deref().map(parse_datetime),
                scope,
            })
        })
        .transpose()
    }

    async fn touch_api_token(&self, id: &str) -> Result<()> {
        let now = datetime_to_str(&Utc::now());
        sqlx::query("UPDATE api_tokens SET last_used_at = ?2 WHERE id = ?1")
            .bind(id)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn revoke_api_token(&self, id: &str) -> Result<()> {
        let now = datetime_to_str(&Utc::now());
        sqlx::query(
            "UPDATE api_tokens SET revoked_at = ?2 \
             WHERE id = ?1 AND revoked_at IS NULL",
        )
        .bind(id)
        .bind(&now)
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
impl PasswordResetTokenRepository for SqliteRepository {
    async fn create_reset_token(
        &self,
        user_sourced_id: &str,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO password_reset_tokens (token_hash, user_sourced_id, expires_at) \
             VALUES (?1, ?2, ?3)",
        )
        .bind(token_hash)
        .bind(user_sourced_id)
        .bind(datetime_to_str(&expires_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn consume_reset_token(&self, raw_token: &str) -> Result<Option<String>> {
        let token_hash = sha256_hex(raw_token);
        let now = datetime_to_str(&Utc::now());
        // Atomic: only consume if not already consumed and not expired.
        let row = sqlx::query(
            "UPDATE password_reset_tokens \
             SET consumed_at = ?2 \
             WHERE token_hash = ?1 \
               AND consumed_at IS NULL \
               AND expires_at > ?2 \
             RETURNING user_sourced_id",
        )
        .bind(&token_hash)
        .bind(&now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<String, _>("user_sourced_id")))
    }

    async fn delete_expired_reset_tokens(&self) -> Result<u64> {
        let now = datetime_to_str(&Utc::now());
        let result = sqlx::query("DELETE FROM password_reset_tokens WHERE expires_at < ?1")
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

#[async_trait]
impl MagicLoginRepository for SqliteRepository {
    async fn create_magic_login_token(
        &self,
        user_sourced_id: &str,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO magic_login_tokens (token_hash, user_sourced_id, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(token_hash)
        .bind(user_sourced_id)
        .bind(datetime_to_str(&Utc::now()))
        .bind(datetime_to_str(&expires_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn consume_magic_login_token(&self, raw_token: &str) -> Result<Option<String>> {
        let token_hash = sha256_hex(raw_token);
        let now = datetime_to_str(&Utc::now());
        let row = sqlx::query(
            "UPDATE magic_login_tokens \
             SET consumed_at = ?2 \
             WHERE token_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2 \
             RETURNING user_sourced_id",
        )
        .bind(&token_hash)
        .bind(&now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<String, _>("user_sourced_id")))
    }
}

// -- TenantConfigRepo --
//
// The SQLite backend stores the `*_sealed` columns as raw bytes without any
// crypto. This impl exists primarily for in-memory unit tests; the production
// hosted runtime uses the postgres impl in `db::postgres` wrapped by
// `chalk-hosted` (which applies the AES-256-GCM seal/unseal at the boundary).
//
// Audit rows go into the existing `admin_audit_log` table via the same
// `log_admin_action` call used by webhook/SSO upserts.

fn audit_details_for_section(section: &str, actor: &str) -> String {
    format!("section={section} actor={actor}")
}

#[async_trait]
impl TenantConfigRepo for SqliteRepository {
    async fn get_sis_config(&self) -> Result<Option<SisConfigRecord>> {
        let row = sqlx::query(
            "SELECT enabled, provider, powerschool_base_url, powerschool_token_url, \
             powerschool_client_id, powerschool_client_secret_sealed, infinite_campus_base_url, \
             infinite_campus_token_url, infinite_campus_client_id, \
             infinite_campus_client_secret_sealed, skyward_base_url, skyward_token_url, \
             skyward_client_id, skyward_client_secret_sealed, oneroster_csv_dir, sync_schedule, \
             updated_at, updated_by FROM tenant_config_sis WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            let enabled_int: i64 = r.get("enabled");
            let updated_at_str: String = r.get("updated_at");
            SisConfigRecord {
                enabled: enabled_int != 0,
                provider: r.get("provider"),
                powerschool_base_url: r.get("powerschool_base_url"),
                powerschool_token_url: r.get("powerschool_token_url"),
                powerschool_client_id: r.get("powerschool_client_id"),
                powerschool_client_secret: r.get("powerschool_client_secret_sealed"),
                infinite_campus_base_url: r.get("infinite_campus_base_url"),
                infinite_campus_token_url: r.get("infinite_campus_token_url"),
                infinite_campus_client_id: r.get("infinite_campus_client_id"),
                infinite_campus_client_secret: r.get("infinite_campus_client_secret_sealed"),
                skyward_base_url: r.get("skyward_base_url"),
                skyward_token_url: r.get("skyward_token_url"),
                skyward_client_id: r.get("skyward_client_id"),
                skyward_client_secret: r.get("skyward_client_secret_sealed"),
                oneroster_csv_dir: r.get("oneroster_csv_dir"),
                sync_schedule: r.get("sync_schedule"),
                updated_at: Some(parse_datetime(&updated_at_str)),
                updated_by: Some(r.get::<String, _>("updated_by")),
            }
        }))
    }

    async fn put_sis_config(&self, record: SisConfigRecord, actor: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_config_sis (id, enabled, provider, powerschool_base_url, \
             powerschool_token_url, powerschool_client_id, powerschool_client_secret_sealed, \
             infinite_campus_base_url, infinite_campus_token_url, infinite_campus_client_id, \
             infinite_campus_client_secret_sealed, skyward_base_url, skyward_token_url, \
             skyward_client_id, skyward_client_secret_sealed, oneroster_csv_dir, sync_schedule, \
             updated_at, updated_by) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, \
             datetime('now'), ?17) \
             ON CONFLICT(id) DO UPDATE SET \
               enabled = excluded.enabled, \
               provider = excluded.provider, \
               powerschool_base_url = excluded.powerschool_base_url, \
               powerschool_token_url = excluded.powerschool_token_url, \
               powerschool_client_id = excluded.powerschool_client_id, \
               powerschool_client_secret_sealed = excluded.powerschool_client_secret_sealed, \
               infinite_campus_base_url = excluded.infinite_campus_base_url, \
               infinite_campus_token_url = excluded.infinite_campus_token_url, \
               infinite_campus_client_id = excluded.infinite_campus_client_id, \
               infinite_campus_client_secret_sealed = excluded.infinite_campus_client_secret_sealed, \
               skyward_base_url = excluded.skyward_base_url, \
               skyward_token_url = excluded.skyward_token_url, \
               skyward_client_id = excluded.skyward_client_id, \
               skyward_client_secret_sealed = excluded.skyward_client_secret_sealed, \
               oneroster_csv_dir = excluded.oneroster_csv_dir, \
               sync_schedule = excluded.sync_schedule, \
               updated_at = datetime('now'), \
               updated_by = excluded.updated_by",
        )
        .bind(if record.enabled { 1i64 } else { 0i64 })
        .bind(&record.provider)
        .bind(&record.powerschool_base_url)
        .bind(&record.powerschool_token_url)
        .bind(&record.powerschool_client_id)
        .bind(&record.powerschool_client_secret)
        .bind(&record.infinite_campus_base_url)
        .bind(&record.infinite_campus_token_url)
        .bind(&record.infinite_campus_client_id)
        .bind(&record.infinite_campus_client_secret)
        .bind(&record.skyward_base_url)
        .bind(&record.skyward_token_url)
        .bind(&record.skyward_client_id)
        .bind(&record.skyward_client_secret)
        .bind(&record.oneroster_csv_dir)
        .bind(&record.sync_schedule)
        .bind(actor)
        .execute(&self.pool)
        .await?;

        self.log_admin_action(
            "tenant_config_sis_updated",
            Some(&audit_details_for_section("sis", actor)),
            None,
        )
        .await?;
        Ok(())
    }

    async fn get_google_sync_config(&self) -> Result<Option<GoogleSyncConfigRecord>> {
        let row = sqlx::query(
            "SELECT enabled, workspace_domain, admin_email, service_account_key_sealed, \
             provision_users, manage_ous, suspend_inactive, sync_schedule, updated_at, updated_by \
             FROM tenant_config_google_sync WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            let updated_at_str: String = r.get("updated_at");
            GoogleSyncConfigRecord {
                enabled: r.get::<i64, _>("enabled") != 0,
                workspace_domain: r.get("workspace_domain"),
                admin_email: r.get("admin_email"),
                service_account_key: r.get("service_account_key_sealed"),
                provision_users: r.get::<i64, _>("provision_users") != 0,
                manage_ous: r.get::<i64, _>("manage_ous") != 0,
                suspend_inactive: r.get::<i64, _>("suspend_inactive") != 0,
                sync_schedule: r.get("sync_schedule"),
                updated_at: Some(parse_datetime(&updated_at_str)),
                updated_by: Some(r.get::<String, _>("updated_by")),
            }
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
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'), ?9) \
             ON CONFLICT(id) DO UPDATE SET \
               enabled = excluded.enabled, \
               workspace_domain = excluded.workspace_domain, \
               admin_email = excluded.admin_email, \
               service_account_key_sealed = excluded.service_account_key_sealed, \
               provision_users = excluded.provision_users, \
               manage_ous = excluded.manage_ous, \
               suspend_inactive = excluded.suspend_inactive, \
               sync_schedule = excluded.sync_schedule, \
               updated_at = datetime('now'), \
               updated_by = excluded.updated_by",
        )
        .bind(if record.enabled { 1i64 } else { 0i64 })
        .bind(&record.workspace_domain)
        .bind(&record.admin_email)
        .bind(&record.service_account_key)
        .bind(if record.provision_users { 1i64 } else { 0i64 })
        .bind(if record.manage_ous { 1i64 } else { 0i64 })
        .bind(if record.suspend_inactive { 1i64 } else { 0i64 })
        .bind(&record.sync_schedule)
        .bind(actor)
        .execute(&self.pool)
        .await?;

        self.log_admin_action(
            "tenant_config_google_sync_updated",
            Some(&audit_details_for_section("google_sync", actor)),
            None,
        )
        .await?;
        Ok(())
    }

    async fn get_device_config(&self) -> Result<Option<DeviceConfigRecord>> {
        let row = sqlx::query(
            "SELECT enabled, write_back_enabled, customer_id, admin_email, \
             service_account_key_sealed, page_size, requests_per_minute, sync_schedule, \
             updated_at, updated_by \
             FROM tenant_config_devices WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            let updated_at_str: String = r.get("updated_at");
            DeviceConfigRecord {
                enabled: r.get::<i64, _>("enabled") != 0,
                write_back_enabled: r.get::<i64, _>("write_back_enabled") != 0,
                customer_id: r.get("customer_id"),
                admin_email: r.get("admin_email"),
                service_account_key: r.get("service_account_key_sealed"),
                page_size: r.get("page_size"),
                requests_per_minute: r.get("requests_per_minute"),
                sync_schedule: r.get("sync_schedule"),
                updated_at: Some(parse_datetime(&updated_at_str)),
                updated_by: Some(r.get::<String, _>("updated_by")),
            }
        }))
    }

    async fn put_device_config(&self, record: DeviceConfigRecord, actor: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_config_devices (id, enabled, write_back_enabled, customer_id, \
             admin_email, service_account_key_sealed, page_size, requests_per_minute, \
             sync_schedule, updated_at, updated_by) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'), ?9) \
             ON CONFLICT(id) DO UPDATE SET \
               enabled = excluded.enabled, \
               write_back_enabled = excluded.write_back_enabled, \
               customer_id = excluded.customer_id, \
               admin_email = excluded.admin_email, \
               service_account_key_sealed = excluded.service_account_key_sealed, \
               page_size = excluded.page_size, \
               requests_per_minute = excluded.requests_per_minute, \
               sync_schedule = excluded.sync_schedule, \
               updated_at = datetime('now'), \
               updated_by = excluded.updated_by",
        )
        .bind(if record.enabled { 1i64 } else { 0i64 })
        .bind(if record.write_back_enabled {
            1i64
        } else {
            0i64
        })
        .bind(&record.customer_id)
        .bind(&record.admin_email)
        .bind(&record.service_account_key)
        .bind(record.page_size)
        .bind(record.requests_per_minute)
        .bind(&record.sync_schedule)
        .bind(actor)
        .execute(&self.pool)
        .await?;

        self.log_admin_action(
            "tenant_config_devices_updated",
            Some(&audit_details_for_section("devices", actor)),
            None,
        )
        .await?;
        Ok(())
    }

    async fn get_idp_config(&self) -> Result<Option<IdpConfigRecord>> {
        let row = sqlx::query(
            "SELECT enabled, qr_badge_login, picture_passwords, session_timeout_minutes, \
             default_password_pattern, default_password_roles, saml_cert_sealed, \
             saml_signing_key_sealed, updated_at, updated_by FROM tenant_config_idp WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some(r) => {
                let updated_at_str: String = r.get("updated_at");
                let roles_str: Option<String> = r.get("default_password_roles");
                let default_password_roles = match roles_str {
                    Some(s) if !s.is_empty() => Some(
                        serde_json::from_str(&s)
                            .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?,
                    ),
                    _ => None,
                };
                Ok(Some(IdpConfigRecord {
                    enabled: r.get::<i64, _>("enabled") != 0,
                    qr_badge_login: r.get::<i64, _>("qr_badge_login") != 0,
                    picture_passwords: r.get::<i64, _>("picture_passwords") != 0,
                    session_timeout_minutes: r.get("session_timeout_minutes"),
                    default_password_pattern: r.get("default_password_pattern"),
                    default_password_roles,
                    saml_cert: r.get("saml_cert_sealed"),
                    saml_signing_key: r.get("saml_signing_key_sealed"),
                    updated_at: Some(parse_datetime(&updated_at_str)),
                    updated_by: Some(r.get::<String, _>("updated_by")),
                }))
            }
        }
    }

    async fn put_idp_config(&self, record: IdpConfigRecord, actor: &str) -> Result<()> {
        let roles_str = match &record.default_password_roles {
            Some(v) => Some(
                serde_json::to_string(v)
                    .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?,
            ),
            None => None,
        };
        sqlx::query(
            "INSERT INTO tenant_config_idp (id, enabled, qr_badge_login, picture_passwords, \
             session_timeout_minutes, default_password_pattern, default_password_roles, \
             saml_cert_sealed, saml_signing_key_sealed, updated_at, updated_by) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'), ?9) \
             ON CONFLICT(id) DO UPDATE SET \
               enabled = excluded.enabled, \
               qr_badge_login = excluded.qr_badge_login, \
               picture_passwords = excluded.picture_passwords, \
               session_timeout_minutes = excluded.session_timeout_minutes, \
               default_password_pattern = excluded.default_password_pattern, \
               default_password_roles = excluded.default_password_roles, \
               saml_cert_sealed = excluded.saml_cert_sealed, \
               saml_signing_key_sealed = excluded.saml_signing_key_sealed, \
               updated_at = datetime('now'), \
               updated_by = excluded.updated_by",
        )
        .bind(if record.enabled { 1i64 } else { 0i64 })
        .bind(if record.qr_badge_login { 1i64 } else { 0i64 })
        .bind(if record.picture_passwords { 1i64 } else { 0i64 })
        .bind(record.session_timeout_minutes)
        .bind(&record.default_password_pattern)
        .bind(&roles_str)
        .bind(&record.saml_cert)
        .bind(&record.saml_signing_key)
        .bind(actor)
        .execute(&self.pool)
        .await?;

        self.log_admin_action(
            "tenant_config_idp_updated",
            Some(&audit_details_for_section("idp", actor)),
            None,
        )
        .await?;
        Ok(())
    }

    async fn get_ad_sync_config(&self) -> Result<Option<AdSyncConfigRecord>> {
        let row = sqlx::query(
            "SELECT enabled, host, port, bind_dn, bind_password_sealed, base_dn, user_filter, \
             use_tls, tls_ca_cert_sealed, sync_schedule, ou_mapping, groups, updated_at, \
             updated_by FROM tenant_config_ad_sync WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some(r) => {
                let updated_at_str: String = r.get("updated_at");
                let ou_str: Option<String> = r.get("ou_mapping");
                let groups_str: Option<String> = r.get("groups");
                let parse_json = |s: Option<String>| -> Result<Option<serde_json::Value>> {
                    match s {
                        Some(s) if !s.is_empty() => {
                            Ok(Some(serde_json::from_str(&s).map_err(|e| {
                                crate::error::ChalkError::Serialization(e.to_string())
                            })?))
                        }
                        _ => Ok(None),
                    }
                };
                Ok(Some(AdSyncConfigRecord {
                    enabled: r.get::<i64, _>("enabled") != 0,
                    host: r.get("host"),
                    port: r.get("port"),
                    bind_dn: r.get("bind_dn"),
                    bind_password: r.get("bind_password_sealed"),
                    base_dn: r.get("base_dn"),
                    user_filter: r.get("user_filter"),
                    use_tls: r.get::<i64, _>("use_tls") != 0,
                    tls_ca_cert: r.get("tls_ca_cert_sealed"),
                    sync_schedule: r.get("sync_schedule"),
                    ou_mapping: parse_json(ou_str)?,
                    groups: parse_json(groups_str)?,
                    updated_at: Some(parse_datetime(&updated_at_str)),
                    updated_by: Some(r.get::<String, _>("updated_by")),
                }))
            }
        }
    }

    async fn put_ad_sync_config(&self, record: AdSyncConfigRecord, actor: &str) -> Result<()> {
        let ou_str = match &record.ou_mapping {
            Some(v) => Some(
                serde_json::to_string(v)
                    .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?,
            ),
            None => None,
        };
        let groups_str = match &record.groups {
            Some(v) => Some(
                serde_json::to_string(v)
                    .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?,
            ),
            None => None,
        };
        sqlx::query(
            "INSERT INTO tenant_config_ad_sync (id, enabled, host, port, bind_dn, \
             bind_password_sealed, base_dn, user_filter, use_tls, tls_ca_cert_sealed, \
             sync_schedule, ou_mapping, groups, updated_at, updated_by) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, datetime('now'), ?13) \
             ON CONFLICT(id) DO UPDATE SET \
               enabled = excluded.enabled, \
               host = excluded.host, \
               port = excluded.port, \
               bind_dn = excluded.bind_dn, \
               bind_password_sealed = excluded.bind_password_sealed, \
               base_dn = excluded.base_dn, \
               user_filter = excluded.user_filter, \
               use_tls = excluded.use_tls, \
               tls_ca_cert_sealed = excluded.tls_ca_cert_sealed, \
               sync_schedule = excluded.sync_schedule, \
               ou_mapping = excluded.ou_mapping, \
               groups = excluded.groups, \
               updated_at = datetime('now'), \
               updated_by = excluded.updated_by",
        )
        .bind(if record.enabled { 1i64 } else { 0i64 })
        .bind(&record.host)
        .bind(record.port)
        .bind(&record.bind_dn)
        .bind(&record.bind_password)
        .bind(&record.base_dn)
        .bind(&record.user_filter)
        .bind(if record.use_tls { 1i64 } else { 0i64 })
        .bind(&record.tls_ca_cert)
        .bind(&record.sync_schedule)
        .bind(&ou_str)
        .bind(&groups_str)
        .bind(actor)
        .execute(&self.pool)
        .await?;

        self.log_admin_action(
            "tenant_config_ad_sync_updated",
            Some(&audit_details_for_section("ad_sync", actor)),
            None,
        )
        .await?;
        Ok(())
    }
}

// ===========================================================================
// Device / asset repositories (migrations 019, 021, 022)
//
// Everything below paginates and filters in SQL. Nothing fetches a table and
// narrows it in Rust — see the `AssetRepository` doc comment for why.
// ===========================================================================

/// A `sqlx` query bound to the SQLite driver. Named so the dynamic-SQL helpers
/// below have a readable signature.
type SqliteQuery<'q> = sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>;

/// A `WHERE` clause under construction, plus its binds in placeholder order.
///
/// The count query and the windowed page query are both rendered from one
/// instance of this, so they can never disagree about which rows match.
/// Column names and operators are `&'static str` literals from this file;
/// every caller-supplied value goes through [`FilterSql::binds`].
#[derive(Default)]
struct FilterSql {
    conditions: Vec<String>,
    binds: Vec<String>,
}

impl FilterSql {
    /// The `?n` number the next bind will occupy.
    fn next_placeholder(&self) -> usize {
        self.binds.len() + 1
    }

    /// `col <op> ?n`, binding `value` as text.
    fn text_cmp(&mut self, col: &'static str, op: &'static str, value: impl Into<String>) {
        let n = self.next_placeholder();
        self.binds.push(value.into());
        self.conditions.push(format!("{col} {op} ?{n}"));
    }

    /// `col = ?n`.
    fn text_eq(&mut self, col: &'static str, value: impl Into<String>) {
        self.text_cmp(col, "=", value);
    }

    /// A condition carrying no bind, e.g. `col IS NOT NULL`.
    fn bare(&mut self, condition: &'static str) {
        self.conditions.push(condition.to_string());
    }

    /// Reserve one text bind and let `render` place its `?n` as many times as
    /// the condition needs (a `LIKE` across four columns reuses one bind).
    fn text_custom<F>(&mut self, value: impl Into<String>, render: F)
    where
        F: FnOnce(usize) -> String,
    {
        let n = self.next_placeholder();
        self.binds.push(value.into());
        self.conditions.push(render(n));
    }

    /// `""` when empty, otherwise `" WHERE a AND b"`.
    fn where_sql(&self) -> String {
        if self.conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.conditions.join(" AND "))
        }
    }

    fn bind_all<'q>(&self, mut q: SqliteQuery<'q>) -> SqliteQuery<'q> {
        for b in &self.binds {
            q = q.bind(b.clone());
        }
        q
    }
}

/// Escape the LIKE metacharacters so a user typing `50%` searches for the
/// literal string. Paired with `ESCAPE '\'` at every use site.
fn escape_like(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Run the `COUNT(*)` and the windowed `SELECT` from one [`FilterSql`].
///
/// `columns`, `table` and `order_by` are literals from this file; `filter`
/// holds every caller-supplied value as a bind, and `LIMIT`/`OFFSET` are bound
/// too (their placeholders continue the filter's numbering).
async fn fetch_page<T, F>(
    pool: &SqlitePool,
    columns: &str,
    table: &str,
    filter: &FilterSql,
    order_by: &str,
    page: PageRequest,
    map_row: F,
) -> Result<Page<T>>
where
    F: Fn(&sqlx::sqlite::SqliteRow) -> Result<T>,
{
    let where_sql = filter.where_sql();

    let count_sql = format!("SELECT COUNT(*) FROM {table}{where_sql}");
    let total: i64 = filter
        .bind_all(sqlx::query(&count_sql))
        .fetch_one(pool)
        .await?
        .get(0);

    let limit_n = filter.next_placeholder();
    let offset_n = limit_n + 1;
    let sql = format!(
        "SELECT {columns} FROM {table}{where_sql} {order_by} LIMIT ?{limit_n} OFFSET ?{offset_n}"
    );
    let rows = filter
        .bind_all(sqlx::query(&sql))
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(pool)
        .await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        items.push(map_row(row)?);
    }
    Ok(Page::new(items, total, page))
}

// -- assets --

const ASSET_COLUMNS: &str = "id, asset_tag, serial_number, asset_type, make, model, status, \
     school_org_sourced_id, assigned_user_sourced_id, org_unit_path, source, match_state, \
     google_device_id, annotated_user, annotated_asset_id, aue_date, os_version, last_sync_at, \
     last_known_ip, purchase_date, purchase_cost_cents, funding_source, warranty_expires, \
     location, notes, created_at, updated_at";

fn asset_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<Asset> {
    Ok(Asset {
        id: r.get("id"),
        asset_tag: r.get("asset_tag"),
        serial_number: r.get("serial_number"),
        asset_type: AssetType::parse(r.get::<String, _>("asset_type").as_str())?,
        make: r.get("make"),
        model: r.get("model"),
        status: AssetStatus::parse(r.get::<String, _>("status").as_str())?,
        school_org_sourced_id: r.get("school_org_sourced_id"),
        assigned_user_sourced_id: r.get("assigned_user_sourced_id"),
        org_unit_path: r.get("org_unit_path"),
        source: AssetSource::parse(r.get::<String, _>("source").as_str())?,
        match_state: MatchState::parse(r.get::<String, _>("match_state").as_str())?,
        google_device_id: r.get("google_device_id"),
        annotated_user: r.get("annotated_user"),
        annotated_asset_id: r.get("annotated_asset_id"),
        aue_date: parse_naive_date_opt(r.get("aue_date"))?,
        os_version: r.get("os_version"),
        last_sync_at: r
            .get::<Option<String>, _>("last_sync_at")
            .map(|s| parse_datetime(&s)),
        last_known_ip: r.get("last_known_ip"),
        purchase_date: parse_naive_date_opt(r.get("purchase_date"))?,
        purchase_cost_cents: r.get("purchase_cost_cents"),
        funding_source: r.get("funding_source"),
        warranty_expires: parse_naive_date_opt(r.get("warranty_expires"))?,
        location: r.get("location"),
        notes: r.get("notes"),
        created_at: parse_datetime(&r.get::<String, _>("created_at")),
        updated_at: parse_datetime(&r.get::<String, _>("updated_at")),
    })
}

/// Bind all 27 asset columns, in `ASSET_COLUMNS` order, onto `?1..?27`.
fn bind_asset<'q>(q: SqliteQuery<'q>, a: &Asset) -> SqliteQuery<'q> {
    q.bind(a.id.clone())
        .bind(a.asset_tag.clone())
        .bind(a.serial_number.clone())
        .bind(a.asset_type.as_str())
        .bind(a.make.clone())
        .bind(a.model.clone())
        .bind(a.status.as_str())
        .bind(a.school_org_sourced_id.clone())
        .bind(a.assigned_user_sourced_id.clone())
        .bind(a.org_unit_path.clone())
        .bind(a.source.as_str())
        .bind(a.match_state.as_str())
        .bind(a.google_device_id.clone())
        .bind(a.annotated_user.clone())
        .bind(a.annotated_asset_id.clone())
        .bind(a.aue_date.as_ref().map(naive_date_to_str))
        .bind(a.os_version.clone())
        .bind(a.last_sync_at.as_ref().map(datetime_to_str))
        .bind(a.last_known_ip.clone())
        .bind(a.purchase_date.as_ref().map(naive_date_to_str))
        .bind(a.purchase_cost_cents)
        .bind(a.funding_source.clone())
        .bind(a.warranty_expires.as_ref().map(naive_date_to_str))
        .bind(a.location.clone())
        .bind(a.notes.clone())
        .bind(datetime_to_str(&a.created_at))
        .bind(datetime_to_str(&a.updated_at))
}

const ASSET_INSERT_PLACEHOLDERS: &str = "?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, \
     ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27";

/// The `SET` list for an [`AssetPatch`], starting at `?1`, always ending with
/// `updated_at = ?{n+1}`.
///
/// Shared by `update_asset` and the transactional `mark_item_applied` so the
/// two cannot drift on which columns a patch writes or how they are numbered.
fn asset_patch_set_sql(changes: &[(&'static str, PatchValue)]) -> String {
    let mut parts: Vec<String> = changes
        .iter()
        .enumerate()
        .map(|(i, (col, _))| format!("{col} = ?{}", i + 1))
        .collect();
    parts.push(format!("updated_at = ?{}", changes.len() + 1));
    parts.join(", ")
}

/// Bind one generated `SET` value. `Null` binds a typed `None` so SQLite
/// writes a real SQL NULL rather than the string `"null"`.
fn bind_patch_value<'q>(q: SqliteQuery<'q>, value: &PatchValue) -> SqliteQuery<'q> {
    match value {
        PatchValue::Null => q.bind(Option::<String>::None),
        PatchValue::Text(s) => q.bind(s.clone()),
        PatchValue::Int(i) => q.bind(*i),
        PatchValue::Date(d) => q.bind(naive_date_to_str(d)),
        PatchValue::Timestamp(t) => q.bind(datetime_to_str(t)),
    }
}

/// Every [`AssetFilter`] field pushed into SQL.
fn asset_filter_sql(filter: &AssetFilter) -> FilterSql {
    let mut f = FilterSql::default();

    if let Some(v) = filter.status {
        f.text_eq("status", v.as_str());
    }
    if let Some(v) = filter.asset_type {
        f.text_eq("asset_type", v.as_str());
    }
    if let Some(v) = filter.source {
        f.text_eq("source", v.as_str());
    }
    if let Some(v) = filter.match_state {
        f.text_eq("match_state", v.as_str());
    }
    if let Some(v) = &filter.school_org_sourced_id {
        f.text_eq("school_org_sourced_id", v.clone());
    }
    if !filter.school_org_sourced_ids.is_empty() {
        // An IN list rather than a second equality, and ANDed with the single
        // filter above so an operator's choice narrows *within* the token's
        // boundary and can never widen past it.
        let placeholders: Vec<String> = filter
            .school_org_sourced_ids
            .iter()
            .map(|v| {
                let n = f.next_placeholder();
                f.binds.push(v.clone());
                format!("?{n}")
            })
            .collect();
        f.conditions.push(format!(
            "school_org_sourced_id IN ({})",
            placeholders.join(", ")
        ));
    }
    if let Some(v) = &filter.assigned_user_sourced_id {
        f.text_eq("assigned_user_sourced_id", v.clone());
    }
    if let Some(prefix) = &filter.org_unit_path_prefix {
        // The OU itself plus everything strictly below it. A bare
        // `LIKE '/Students%'` would also swallow `/StudentsArchive`.
        let exact_n = f.next_placeholder();
        f.binds.push(prefix.clone());
        let like_n = f.next_placeholder();
        f.binds.push(format!("{}/%", escape_like(prefix)));
        f.conditions.push(format!(
            "(org_unit_path = ?{exact_n} OR org_unit_path LIKE ?{like_n} ESCAPE '\\')"
        ));
    }
    match filter.assigned {
        Some(true) => f.bare("assigned_user_sourced_id IS NOT NULL"),
        Some(false) => f.bare("assigned_user_sourced_id IS NULL"),
        None => {}
    }
    if let Some(d) = filter.aue_before {
        f.text_cmp("aue_date", "<", naive_date_to_str(&d));
    }
    if let Some(term) = &filter.search {
        // SQLite's LIKE is already case-insensitive for ASCII.
        f.text_custom(format!("%{}%", escape_like(term)), |n| {
            format!(
                "(asset_tag LIKE ?{n} ESCAPE '\\' \
                 OR serial_number LIKE ?{n} ESCAPE '\\' \
                 OR annotated_user LIKE ?{n} ESCAPE '\\' \
                 OR annotated_asset_id LIKE ?{n} ESCAPE '\\')"
            )
        });
    }

    f
}

#[async_trait]
impl AssetRepository for SqliteRepository {
    async fn create_asset(&self, asset: &Asset) -> Result<()> {
        let sql =
            format!("INSERT INTO assets ({ASSET_COLUMNS}) VALUES ({ASSET_INSERT_PLACEHOLDERS})");
        bind_asset(sqlx::query(&sql), asset)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn upsert_asset(&self, asset: &Asset) -> Result<()> {
        let sql = format!(
            "INSERT OR REPLACE INTO assets ({ASSET_COLUMNS}) VALUES ({ASSET_INSERT_PLACEHOLDERS})"
        );
        bind_asset(sqlx::query(&sql), asset)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_asset(&self, id: &str) -> Result<Option<Asset>> {
        let sql = format!("SELECT {ASSET_COLUMNS} FROM assets WHERE id = ?1");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(asset_from_row).transpose()
    }

    async fn get_asset_by_google_device_id(&self, google_device_id: &str) -> Result<Option<Asset>> {
        let sql = format!("SELECT {ASSET_COLUMNS} FROM assets WHERE google_device_id = ?1");
        let row = sqlx::query(&sql)
            .bind(google_device_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(asset_from_row).transpose()
    }

    async fn get_asset_by_serial(&self, serial_number: &str) -> Result<Option<Asset>> {
        let sql = format!("SELECT {ASSET_COLUMNS} FROM assets WHERE serial_number = ?1");
        let row = sqlx::query(&sql)
            .bind(serial_number)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(asset_from_row).transpose()
    }

    async fn find_assets_by_asset_tag(&self, asset_tag: &str) -> Result<Vec<Asset>> {
        let sql = format!("SELECT {ASSET_COLUMNS} FROM assets WHERE asset_tag = ?1");
        let rows = sqlx::query(&sql)
            .bind(asset_tag)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(asset_from_row).collect()
    }

    async fn list_assets(&self, filter: &AssetFilter, page: PageRequest) -> Result<Page<Asset>> {
        // The only interpolated caller-influenced values in the whole file:
        // both are closed enums, so `ORDER BY` can never carry free text.
        let order_by = filter.order_by_sql("");
        fetch_page(
            &self.pool,
            ASSET_COLUMNS,
            "assets",
            &asset_filter_sql(filter),
            &order_by,
            page,
            asset_from_row,
        )
        .await
    }

    async fn list_assets_with_roster(
        &self,
        filter: &AssetFilter,
        page: PageRequest,
    ) -> Result<Page<AssetRow>> {
        let f = asset_filter_sql(filter);
        let where_sql = f.where_sql();

        let count_sql = format!("SELECT COUNT(*) FROM assets{where_sql}");
        let total: i64 = f
            .bind_all(sqlx::query(&count_sql))
            .fetch_one(&self.pool)
            .await?
            .get(0);

        // The window is computed first and the joins wrap it, so `users` and
        // `orgs` are probed at most `limit` times each rather than scanned
        // alongside a 20k-row `assets` filter. It also keeps
        // `asset_filter_sql`'s column names unqualified and unambiguous —
        // `users` and `orgs` both have a `status` column, so filtering across
        // the join directly would silently need every predicate re-prefixed.
        let limit_n = f.next_placeholder();
        let offset_n = limit_n + 1;
        //
        // The outer `ORDER BY` is not redundant: a join over a subquery has no
        // guaranteed row order, so the same closed-enum sort is re-applied to
        // the joined result. Both clauses come from `AssetFilter::order_by_sql`
        // so they cannot disagree, including on NULL placement.
        let sql = format!(
            "SELECT a.*, u.given_name AS assigned_given_name, \
             u.family_name AS assigned_family_name, u.email AS assigned_email, \
             o.name AS school_name \
             FROM (SELECT {ASSET_COLUMNS} FROM assets{where_sql} {} \
             LIMIT ?{limit_n} OFFSET ?{offset_n}) a \
             LEFT JOIN users u ON u.sourced_id = a.assigned_user_sourced_id \
             LEFT JOIN orgs o ON o.sourced_id = a.school_org_sourced_id {}",
            filter.order_by_sql(""),
            filter.order_by_sql("a.")
        );
        let rows = f
            .bind_all(sqlx::query(&sql))
            .bind(page.limit())
            .bind(page.offset())
            .fetch_all(&self.pool)
            .await?;

        let mut items = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(AssetRow {
                asset: asset_from_row(row)?,
                assigned_given_name: row.get("assigned_given_name"),
                assigned_family_name: row.get("assigned_family_name"),
                assigned_email: row.get("assigned_email"),
                school_name: row.get("school_name"),
            });
        }
        Ok(Page::new(items, total, page))
    }

    async fn count_assets(&self, filter: &AssetFilter) -> Result<i64> {
        let f = asset_filter_sql(filter);
        let sql = format!("SELECT COUNT(*) FROM assets{}", f.where_sql());
        let total: i64 = f
            .bind_all(sqlx::query(&sql))
            .fetch_one(&self.pool)
            .await?
            .get(0);
        Ok(total)
    }

    async fn count_assets_by_school_and_status(
        &self,
        filter: &AssetFilter,
    ) -> Result<Vec<AssetGroupCount>> {
        let f = asset_filter_sql(filter);
        // Ordered so the two backends return the same sequence — a report that
        // reshuffled between SQLite and Postgres would be a parity failure
        // nobody could reproduce. NULL schools sort first on both.
        let sql = format!(
            "SELECT school_org_sourced_id, status, COUNT(*) AS n FROM assets{} \
             GROUP BY school_org_sourced_id, status \
             ORDER BY school_org_sourced_id IS NOT NULL, school_org_sourced_id, status",
            f.where_sql()
        );
        let rows = f.bind_all(sqlx::query(&sql)).fetch_all(&self.pool).await?;
        rows.iter()
            .map(|r| {
                Ok(AssetGroupCount {
                    school_org_sourced_id: r.get("school_org_sourced_id"),
                    status: AssetStatus::parse(&r.get::<String, _>("status"))?,
                    count: r.get("n"),
                })
            })
            .collect()
    }

    async fn update_asset(&self, id: &str, patch: &AssetPatch) -> Result<bool> {
        update_asset_on(&self.pool, id, patch).await
    }

    async fn apply_patch_with_event(
        &self,
        id: &str,
        patch: &AssetPatch,
        event: &NewAssetEvent,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let updated = update_asset_on(&mut *tx, id, patch).await?;
        // A missing asset rolls back rather than logging an event against an id
        // that does not exist. `asset_events.asset_id` is a RESTRICT foreign
        // key, so the insert would fail anyway — returning false is the honest
        // answer, and it keeps the two backends behaving identically.
        if !updated {
            tx.rollback().await?;
            return Ok(false);
        }
        append_event_on(&mut *tx, event).await?;
        tx.commit().await?;
        Ok(true)
    }
}

/// The `UPDATE assets` statement, over any executor, so the plain and the
/// transactional callers cannot drift on set-clause, `updated_at` stamping or
/// the empty-patch case.
async fn update_asset_on<'e, E>(exec: E, id: &str, patch: &AssetPatch) -> Result<bool>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let changes = patch.changes();
    if changes.is_empty() {
        let exists = sqlx::query("SELECT 1 FROM assets WHERE id = ?1")
            .bind(id)
            .fetch_optional(exec)
            .await?;
        return Ok(exists.is_some());
    }

    let set_sql = asset_patch_set_sql(&changes);
    let id_n = changes.len() + 2;
    let sql = format!("UPDATE assets SET {set_sql} WHERE id = ?{id_n}");

    let mut q = sqlx::query(&sql);
    for (_, value) in &changes {
        q = bind_patch_value(q, value);
    }
    let result = q
        .bind(datetime_to_str(&Utc::now()))
        .bind(id)
        .execute(exec)
        .await?;
    Ok(result.rows_affected() == 1)
}

// -- asset_events --

const ASSET_EVENT_COLUMNS: &str =
    "id, asset_id, actor, actor_kind, event_type, payload, created_at";

fn asset_event_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<AssetEvent> {
    Ok(AssetEvent {
        id: r.get("id"),
        asset_id: r.get("asset_id"),
        actor: r.get("actor"),
        actor_kind: ActorKind::parse(r.get::<String, _>("actor_kind").as_str())?,
        event_type: AssetEventType::parse(r.get::<String, _>("event_type").as_str())?,
        payload: r
            .get::<Option<String>, _>("payload")
            .map(|s| parse_json_column(&s))
            .transpose()?,
        created_at: parse_datetime(&r.get::<String, _>("created_at")),
    })
}

/// The `INSERT INTO asset_events` statement, over any executor, so an event
/// appended inside a transaction is byte-for-byte the same row as one appended
/// on its own.
async fn append_event_on<'e, E>(exec: E, event: &NewAssetEvent) -> Result<i64>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let result = sqlx::query(
        "INSERT INTO asset_events (asset_id, actor, actor_kind, event_type, payload, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&event.asset_id)
    .bind(&event.actor)
    .bind(event.actor_kind.as_str())
    .bind(event.event_type.as_str())
    .bind(event.payload.as_ref().map(|p| p.to_string()))
    .bind(datetime_to_str(&Utc::now()))
    .execute(exec)
    .await?;
    Ok(result.last_insert_rowid())
}

// -- jobs (migration 023) --

const JOB_COLUMNS: &str = "id, kind, status, payload, run_after, attempt, max_attempts, \
     started_at, finished_at, last_error, created_at, updated_at";

fn job_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<Job> {
    Ok(Job {
        id: r.get("id"),
        kind: JobKind::parse(r.get::<String, _>("kind").as_str())?,
        status: JobStatus::parse(r.get::<String, _>("status").as_str())?,
        payload: parse_json_column(&r.get::<String, _>("payload"))?,
        run_after: r
            .get::<Option<String>, _>("run_after")
            .map(|s| parse_datetime(&s)),
        attempt: r.get("attempt"),
        max_attempts: r.get("max_attempts"),
        started_at: r
            .get::<Option<String>, _>("started_at")
            .map(|s| parse_datetime(&s)),
        finished_at: r
            .get::<Option<String>, _>("finished_at")
            .map(|s| parse_datetime(&s)),
        last_error: r.get("last_error"),
        created_at: parse_datetime(&r.get::<String, _>("created_at")),
        updated_at: parse_datetime(&r.get::<String, _>("updated_at")),
    })
}

#[async_trait]
impl JobRepository for SqliteRepository {
    async fn enqueue(&self, job: &NewJob) -> Result<Job> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = datetime_to_str(&Utc::now());
        sqlx::query(
            "INSERT INTO jobs (id, kind, status, payload, run_after, attempt, max_attempts, \
             created_at, updated_at) VALUES (?1, ?2, 'queued', ?3, ?4, 0, ?5, ?6, ?6)",
        )
        .bind(&id)
        .bind(job.kind.as_str())
        .bind(job.payload.to_string())
        .bind(job.run_after.map(|t| datetime_to_str(&t)))
        .bind(job.resolved_max_attempts())
        .bind(&now)
        .execute(&self.pool)
        .await?;

        self.get_job(&id)
            .await?
            .ok_or_else(|| ChalkError::Sync(format!("job {id} vanished after insert")))
    }

    async fn get_job(&self, id: &str) -> Result<Option<Job>> {
        let sql = format!("SELECT {JOB_COLUMNS} FROM jobs WHERE id = ?1");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(job_from_row).transpose()
    }

    async fn next_claimable(&self, now: DateTime<Utc>) -> Result<Option<Job>> {
        // Oldest first, so a queue that briefly outruns the worker drains in
        // the order work was asked for rather than newest-wins.
        let sql = format!(
            "SELECT {JOB_COLUMNS} FROM jobs WHERE status = 'queued' \
             AND (run_after IS NULL OR run_after <= ?1) \
             ORDER BY created_at ASC, id ASC LIMIT 1"
        );
        let row = sqlx::query(&sql)
            .bind(datetime_to_str(&now))
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(job_from_row).transpose()
    }

    async fn claim(&self, id: &str, now: DateTime<Utc>) -> Result<bool> {
        let ts = datetime_to_str(&now);
        let result = sqlx::query(
            "UPDATE jobs SET status = 'running', started_at = ?1, attempt = attempt + 1, \
             updated_at = ?1 WHERE id = ?2 AND status = 'queued'",
        )
        .bind(&ts)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn finish(&self, id: &str, status: JobStatus, error: Option<&str>) -> Result<bool> {
        let ts = datetime_to_str(&Utc::now());
        let result = sqlx::query(
            "UPDATE jobs SET status = ?1, finished_at = ?2, last_error = ?3, updated_at = ?2 \
             WHERE id = ?4 AND status = 'running'",
        )
        .bind(status.as_str())
        .bind(&ts)
        .bind(error)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn requeue(
        &self,
        id: &str,
        run_after: Option<DateTime<Utc>>,
        error: &str,
    ) -> Result<bool> {
        let ts = datetime_to_str(&Utc::now());
        // `attempt` is deliberately not reset: the budget is spent by claiming,
        // so a job that keeps failing runs out rather than looping forever.
        let result = sqlx::query(
            "UPDATE jobs SET status = 'queued', run_after = ?1, last_error = ?2, \
             started_at = NULL, updated_at = ?3 WHERE id = ?4 AND status = 'running'",
        )
        .bind(run_after.map(|t| datetime_to_str(&t)))
        .bind(error)
        .bind(&ts)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn fail_abandoned(&self, cutoff: DateTime<Utc>) -> Result<u64> {
        let ts = datetime_to_str(&Utc::now());
        let result = sqlx::query(
            "UPDATE jobs SET status = 'failed', finished_at = ?1, updated_at = ?1, \
             last_error = 'abandoned (process restart)' \
             WHERE status = 'running' AND started_at IS NOT NULL AND started_at < ?2",
        )
        .bind(&ts)
        .bind(datetime_to_str(&cutoff))
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn list_jobs(&self, filter: &JobFilter, page: PageRequest) -> Result<Page<Job>> {
        let mut f = FilterSql::default();
        if let Some(v) = filter.kind {
            f.text_eq("kind", v.as_str());
        }
        if let Some(v) = filter.status {
            f.text_eq("status", v.as_str());
        }
        fetch_page(
            &self.pool,
            JOB_COLUMNS,
            "jobs",
            &f,
            "ORDER BY created_at DESC, id DESC",
            page,
            job_from_row,
        )
        .await
    }
}

#[async_trait]
impl AssetEventRepository for SqliteRepository {
    async fn append_event(&self, event: &NewAssetEvent) -> Result<i64> {
        append_event_on(&self.pool, event).await
    }

    async fn list_events(
        &self,
        filter: &AssetEventFilter,
        page: PageRequest,
    ) -> Result<Page<AssetEvent>> {
        let mut f = FilterSql::default();
        if let Some(v) = &filter.asset_id {
            f.text_eq("asset_id", v.clone());
        }
        if let Some(v) = filter.event_type {
            f.text_eq("event_type", v.as_str());
        }
        if let Some(v) = &filter.actor {
            f.text_eq("actor", v.clone());
        }
        if let Some(v) = &filter.school_org_sourced_id {
            // A subquery rather than a join: `fetch_page` counts and windows
            // one table, and widening it to a join for one optional filter
            // would change the shape of every other query it serves.
            f.text_custom(v.clone(), |n| {
                format!("asset_id IN (SELECT id FROM assets WHERE school_org_sourced_id = ?{n})")
            });
        }
        if let Some(v) = filter.since {
            f.text_cmp("created_at", ">=", datetime_to_str(&v));
        }
        if let Some(v) = filter.until {
            f.text_cmp("created_at", "<=", datetime_to_str(&v));
        }

        fetch_page(
            &self.pool,
            ASSET_EVENT_COLUMNS,
            "asset_events",
            &f,
            "ORDER BY created_at DESC, id DESC",
            page,
            asset_event_from_row,
        )
        .await
    }
}

// -- console users (migration 027) --

/// Build a [`ConsoleUser`] from a row. Enum columns fall back to the type
/// default on an unrecognised value rather than failing the whole read — a
/// corrupt `role` should not lock everyone out of the account list.
fn console_user_from_row(r: &sqlx::sqlite::SqliteRow) -> ConsoleUser {
    let parse_ts = |s: String| {
        chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S")
            .unwrap_or_default()
            .and_utc()
    };
    ConsoleUser {
        id: r.get("id"),
        email: r.get("email"),
        display_name: r.get("display_name"),
        password_hash: r.get("password_hash"),
        role: r
            .get::<String, _>("role")
            .parse()
            .unwrap_or(ConsoleRole::Technician),
        status: r
            .get::<String, _>("status")
            .parse()
            .unwrap_or(ConsoleUserStatus::Active),
        created_at: parse_ts(r.get("created_at")),
        updated_at: parse_ts(r.get("updated_at")),
    }
}

const CONSOLE_USER_COLUMNS: &str =
    "id, email, display_name, password_hash, role, status, created_at, updated_at";

#[async_trait]
impl ConsoleUserRepository for SqliteRepository {
    async fn create_console_user(&self, user: &ConsoleUser) -> Result<()> {
        sqlx::query(
            "INSERT INTO console_users \
             (id, email, display_name, password_hash, role, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&user.id)
        .bind(&user.email)
        .bind(&user.display_name)
        .bind(&user.password_hash)
        .bind(user.role.as_str())
        .bind(user.status.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_console_user_by_email(&self, email: &str) -> Result<Option<ConsoleUser>> {
        let row = sqlx::query(&format!(
            "SELECT {CONSOLE_USER_COLUMNS} FROM console_users WHERE email = ?1"
        ))
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| console_user_from_row(&r)))
    }

    async fn get_console_user(&self, id: &str) -> Result<Option<ConsoleUser>> {
        let row = sqlx::query(&format!(
            "SELECT {CONSOLE_USER_COLUMNS} FROM console_users WHERE id = ?1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| console_user_from_row(&r)))
    }

    async fn list_console_users(&self) -> Result<Vec<ConsoleUser>> {
        let rows = sqlx::query(&format!(
            "SELECT {CONSOLE_USER_COLUMNS} FROM console_users ORDER BY created_at DESC, email ASC"
        ))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(console_user_from_row).collect())
    }

    async fn update_console_user(&self, user: &ConsoleUser) -> Result<()> {
        sqlx::query(
            "UPDATE console_users SET display_name = ?1, password_hash = ?2, role = ?3, \
             status = ?4, updated_at = datetime('now') WHERE id = ?5",
        )
        .bind(&user.display_name)
        .bind(&user.password_hash)
        .bind(user.role.as_str())
        .bind(user.status.as_str())
        .bind(&user.id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn count_console_users(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM console_users")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get("n"))
    }
}

// -- charges (migration 028) --

const CHARGE_COLUMNS: &str = "id, asset_id, user_sourced_id, ticket_id, kind, amount_cents, \
     status, insurance_applied, reason, actor, created_at, updated_at";

fn charge_from_row(r: &sqlx::sqlite::SqliteRow) -> Charge {
    let parse_ts = |s: String| {
        chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S")
            .unwrap_or_default()
            .and_utc()
    };
    Charge {
        id: r.get("id"),
        asset_id: r.get("asset_id"),
        user_sourced_id: r.get("user_sourced_id"),
        ticket_id: r.get("ticket_id"),
        kind: r
            .get::<String, _>("kind")
            .parse()
            .unwrap_or(ChargeKind::Other),
        amount_cents: r.get("amount_cents"),
        status: r
            .get::<String, _>("status")
            .parse()
            .unwrap_or(ChargeStatus::Assessed),
        insurance_applied: r.get::<i64, _>("insurance_applied") != 0,
        reason: r.get("reason"),
        actor: r.get("actor"),
        created_at: parse_ts(r.get("created_at")),
        updated_at: parse_ts(r.get("updated_at")),
    }
}

fn canned_response_from_row(r: &sqlx::sqlite::SqliteRow) -> CannedResponse {
    CannedResponse {
        id: r.get("id"),
        title: r.get("title"),
        body: r.get("body"),
        created_at: parse_datetime(&r.get::<String, _>("created_at")),
        updated_at: parse_datetime(&r.get::<String, _>("updated_at")),
    }
}

#[async_trait]
impl CannedResponseRepository for SqliteRepository {
    async fn create_canned_response(&self, response: &CannedResponse) -> Result<()> {
        sqlx::query(
            "INSERT INTO canned_responses (id, title, body, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&response.id)
        .bind(&response.title)
        .bind(&response.body)
        .bind(datetime_to_str(&response.created_at))
        .bind(datetime_to_str(&response.updated_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_canned_responses(&self) -> Result<Vec<CannedResponse>> {
        let rows = sqlx::query(
            "SELECT id, title, body, created_at, updated_at FROM canned_responses \
             ORDER BY created_at DESC, id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(canned_response_from_row).collect())
    }

    async fn get_canned_response(&self, id: &str) -> Result<Option<CannedResponse>> {
        let row = sqlx::query(
            "SELECT id, title, body, created_at, updated_at FROM canned_responses WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| canned_response_from_row(&r)))
    }

    async fn delete_canned_response(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM canned_responses WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl SavedViewRepository for SqliteRepository {
    async fn create_saved_view(&self, view: &SavedView) -> Result<()> {
        sqlx::query(
            "INSERT INTO saved_views (id, name, query_string, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&view.id)
        .bind(&view.name)
        .bind(&view.query_string)
        .bind(datetime_to_str(&view.created_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_saved_views(&self) -> Result<Vec<SavedView>> {
        let rows = sqlx::query(
            "SELECT id, name, query_string, created_at FROM saved_views \
             ORDER BY created_at DESC, id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| SavedView {
                id: r.get("id"),
                name: r.get("name"),
                query_string: r.get("query_string"),
                created_at: parse_datetime(&r.get::<String, _>("created_at")),
            })
            .collect())
    }

    async fn delete_saved_view(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM saved_views WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ChargeRepository for SqliteRepository {
    async fn create_charge(&self, charge: &NewCharge) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO charges \
             (id, asset_id, user_sourced_id, ticket_id, kind, amount_cents, status, \
              insurance_applied, reason, actor) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(&id)
        .bind(&charge.asset_id)
        .bind(&charge.user_sourced_id)
        .bind(&charge.ticket_id)
        .bind(charge.kind.as_str())
        .bind(charge.amount_cents)
        .bind(charge.status.as_str())
        .bind(charge.insurance_applied as i64)
        .bind(&charge.reason)
        .bind(&charge.actor)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    async fn get_charge(&self, id: &str) -> Result<Option<Charge>> {
        let row = sqlx::query(&format!(
            "SELECT {CHARGE_COLUMNS} FROM charges WHERE id = ?1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| charge_from_row(&r)))
    }

    async fn list_charges_for_user(&self, user_sourced_id: &str) -> Result<Vec<Charge>> {
        let rows = sqlx::query(&format!(
            "SELECT {CHARGE_COLUMNS} FROM charges WHERE user_sourced_id = ?1 \
             ORDER BY created_at DESC, id ASC"
        ))
        .bind(user_sourced_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(charge_from_row).collect())
    }

    async fn list_charges_for_asset(&self, asset_id: &str) -> Result<Vec<Charge>> {
        let rows = sqlx::query(&format!(
            "SELECT {CHARGE_COLUMNS} FROM charges WHERE asset_id = ?1 \
             ORDER BY created_at DESC, id ASC"
        ))
        .bind(asset_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(charge_from_row).collect())
    }

    async fn update_charge_status(
        &self,
        id: &str,
        status: ChargeStatus,
        insurance_applied: bool,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE charges SET status = ?1, insurance_applied = ?2, \
             updated_at = datetime('now') WHERE id = ?3",
        )
        .bind(status.as_str())
        .bind(insurance_applied as i64)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// -- google device sync (migration 021) --

const DEVICE_SYNC_RUN_COLUMNS: &str = "id, started_at, completed_at, status, mode, devices_seen, \
     devices_created, devices_updated, devices_matched, devices_unmatched, api_calls, \
     throttle_events, dry_run, error_message";

fn device_sync_run_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<DeviceSyncRun> {
    Ok(DeviceSyncRun {
        id: r.get("id"),
        started_at: parse_datetime(&r.get::<String, _>("started_at")),
        completed_at: r
            .get::<Option<String>, _>("completed_at")
            .map(|s| parse_datetime(&s)),
        status: DeviceSyncRunStatus::parse(r.get::<String, _>("status").as_str())?,
        mode: DeviceSyncMode::parse(r.get::<String, _>("mode").as_str())?,
        counters: DeviceSyncCounters {
            devices_seen: r.get("devices_seen"),
            devices_created: r.get("devices_created"),
            devices_updated: r.get("devices_updated"),
            devices_matched: r.get("devices_matched"),
            devices_unmatched: r.get("devices_unmatched"),
            api_calls: r.get("api_calls"),
            throttle_events: r.get("throttle_events"),
        },
        dry_run: r.get::<i64, _>("dry_run") != 0,
        error_message: r.get("error_message"),
    })
}

#[async_trait]
impl GoogleDeviceSyncRepository for SqliteRepository {
    async fn get_cursor(&self, resource: DeviceSyncResource) -> Result<Option<DeviceSyncCursor>> {
        let row = sqlx::query(
            "SELECT resource_type, page_token, last_full_sync_at, last_delta_at, status, \
             error_message, updated_at FROM google_device_sync_cursors WHERE resource_type = ?1",
        )
        .bind(resource.as_str())
        .fetch_optional(&self.pool)
        .await?;

        let Some(r) = row else { return Ok(None) };
        Ok(Some(DeviceSyncCursor {
            resource: DeviceSyncResource::parse(r.get::<String, _>("resource_type").as_str())?,
            page_token: r.get("page_token"),
            last_full_sync_at: r
                .get::<Option<String>, _>("last_full_sync_at")
                .map(|s| parse_datetime(&s)),
            last_delta_at: r
                .get::<Option<String>, _>("last_delta_at")
                .map(|s| parse_datetime(&s)),
            status: DeviceSyncCursorStatus::parse(r.get::<String, _>("status").as_str())?,
            error_message: r.get("error_message"),
            updated_at: parse_datetime(&r.get::<String, _>("updated_at")),
        }))
    }

    async fn upsert_cursor(&self, cursor: &DeviceSyncCursor) -> Result<()> {
        sqlx::query(
            "INSERT INTO google_device_sync_cursors \
             (resource_type, page_token, last_full_sync_at, last_delta_at, status, error_message, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT(resource_type) DO UPDATE SET \
               page_token = excluded.page_token, \
               last_full_sync_at = excluded.last_full_sync_at, \
               last_delta_at = excluded.last_delta_at, \
               status = excluded.status, \
               error_message = excluded.error_message, \
               updated_at = excluded.updated_at",
        )
        .bind(cursor.resource.as_str())
        .bind(cursor.page_token.clone())
        .bind(cursor.last_full_sync_at.as_ref().map(datetime_to_str))
        .bind(cursor.last_delta_at.as_ref().map(datetime_to_str))
        .bind(cursor.status.as_str())
        .bind(cursor.error_message.clone())
        .bind(datetime_to_str(&cursor.updated_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn start_run(&self, mode: DeviceSyncMode, dry_run: bool) -> Result<DeviceSyncRun> {
        let started_at = Utc::now();
        let result = sqlx::query(
            "INSERT INTO google_device_sync_runs (started_at, status, mode, dry_run) \
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(datetime_to_str(&started_at))
        .bind(DeviceSyncRunStatus::Running.as_str())
        .bind(mode.as_str())
        .bind(i64::from(dry_run))
        .execute(&self.pool)
        .await?;

        Ok(DeviceSyncRun {
            id: result.last_insert_rowid(),
            started_at,
            completed_at: None,
            status: DeviceSyncRunStatus::Running,
            mode,
            counters: DeviceSyncCounters::default(),
            dry_run,
            error_message: None,
        })
    }

    async fn update_run_counters(&self, id: i64, counters: &DeviceSyncCounters) -> Result<()> {
        // Every counter binds as i64. `as i32` here would silently truncate a
        // district past 2^31 API calls into a negative number.
        sqlx::query(
            "UPDATE google_device_sync_runs SET devices_seen = ?1, devices_created = ?2, \
             devices_updated = ?3, devices_matched = ?4, devices_unmatched = ?5, api_calls = ?6, \
             throttle_events = ?7 WHERE id = ?8",
        )
        .bind(counters.devices_seen)
        .bind(counters.devices_created)
        .bind(counters.devices_updated)
        .bind(counters.devices_matched)
        .bind(counters.devices_unmatched)
        .bind(counters.api_calls)
        .bind(counters.throttle_events)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn finish_run(
        &self,
        id: i64,
        status: DeviceSyncRunStatus,
        counters: &DeviceSyncCounters,
        error_message: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE google_device_sync_runs SET status = ?1, completed_at = ?2, \
             devices_seen = ?3, devices_created = ?4, devices_updated = ?5, devices_matched = ?6, \
             devices_unmatched = ?7, api_calls = ?8, throttle_events = ?9, error_message = ?10 \
             WHERE id = ?11",
        )
        .bind(status.as_str())
        .bind(datetime_to_str(&Utc::now()))
        .bind(counters.devices_seen)
        .bind(counters.devices_created)
        .bind(counters.devices_updated)
        .bind(counters.devices_matched)
        .bind(counters.devices_unmatched)
        .bind(counters.api_calls)
        .bind(counters.throttle_events)
        .bind(error_message)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_run(&self, id: i64) -> Result<Option<DeviceSyncRun>> {
        let sql =
            format!("SELECT {DEVICE_SYNC_RUN_COLUMNS} FROM google_device_sync_runs WHERE id = ?1");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(device_sync_run_from_row).transpose()
    }

    async fn latest_run(&self) -> Result<Option<DeviceSyncRun>> {
        let sql = format!(
            "SELECT {DEVICE_SYNC_RUN_COLUMNS} FROM google_device_sync_runs ORDER BY id DESC LIMIT 1"
        );
        let row = sqlx::query(&sql).fetch_optional(&self.pool).await?;
        row.as_ref().map(device_sync_run_from_row).transpose()
    }

    async fn list_runs(&self, page: PageRequest) -> Result<Page<DeviceSyncRun>> {
        fetch_page(
            &self.pool,
            DEVICE_SYNC_RUN_COLUMNS,
            "google_device_sync_runs",
            &FilterSql::default(),
            "ORDER BY id DESC",
            page,
            device_sync_run_from_row,
        )
        .await
    }
}

// -- change sets (migration 022) --

const CHANGE_SET_COLUMNS: &str = "id, kind, status, created_by, plan_hash, expected_item_count, \
     summary, created_at, committed_at";

const CHANGE_SET_ITEM_COLUMNS: &str = "id, change_set_id, asset_id, target_ref, google_device_id, \
     op, field, old_value, new_value, remote_target, status, error, applied_at";

fn change_set_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<ChangeSet> {
    Ok(ChangeSet {
        id: r.get("id"),
        kind: ChangeSetKind::parse(r.get::<String, _>("kind").as_str())?,
        status: ChangeSetStatus::parse(r.get::<String, _>("status").as_str())?,
        created_by: r.get("created_by"),
        plan_hash: r.get("plan_hash"),
        expected_item_count: r.get("expected_item_count"),
        summary: parse_json_column(&r.get::<String, _>("summary"))?,
        created_at: parse_datetime(&r.get::<String, _>("created_at")),
        committed_at: r
            .get::<Option<String>, _>("committed_at")
            .map(|s| parse_datetime(&s)),
    })
}

fn change_set_item_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<ChangeSetItem> {
    Ok(ChangeSetItem {
        id: r.get("id"),
        change_set_id: r.get("change_set_id"),
        asset_id: r.get("asset_id"),
        target_ref: r.get("target_ref"),
        google_device_id: r.get("google_device_id"),
        op: ChangeSetOp::parse(r.get::<String, _>("op").as_str())?,
        field: r.get("field"),
        old_value: r.get("old_value"),
        new_value: r.get("new_value"),
        remote_target: RemoteTarget::parse(r.get::<String, _>("remote_target").as_str())?,
        status: ChangeSetItemStatus::parse(r.get::<String, _>("status").as_str())?,
        error: r.get("error"),
        applied_at: r
            .get::<Option<String>, _>("applied_at")
            .map(|s| parse_datetime(&s)),
    })
}

#[async_trait]
impl ChangeSetRepository for SqliteRepository {
    async fn create_change_set(&self, set: &ChangeSet, items: &[NewChangeSetItem]) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        let sql = format!(
            "INSERT INTO change_sets ({CHANGE_SET_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
        );
        sqlx::query(&sql)
            .bind(&set.id)
            .bind(set.kind.as_str())
            .bind(set.status.as_str())
            .bind(&set.created_by)
            .bind(&set.plan_hash)
            .bind(set.expected_item_count)
            .bind(set.summary.to_string())
            .bind(datetime_to_str(&set.created_at))
            .bind(set.committed_at.as_ref().map(datetime_to_str))
            .execute(&mut *tx)
            .await?;

        for item in items {
            sqlx::query(
                "INSERT INTO change_set_items (change_set_id, asset_id, target_ref, \
                 google_device_id, op, field, old_value, new_value, remote_target, status) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )
            .bind(&set.id)
            .bind(&item.asset_id)
            .bind(&item.target_ref)
            .bind(&item.google_device_id)
            .bind(item.op.as_str())
            .bind(&item.field)
            .bind(&item.old_value)
            .bind(&item.new_value)
            .bind(item.remote_target.as_str())
            .bind(ChangeSetItemStatus::Pending.as_str())
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_change_set(&self, id: &str) -> Result<Option<ChangeSet>> {
        let sql = format!("SELECT {CHANGE_SET_COLUMNS} FROM change_sets WHERE id = ?1");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(change_set_from_row).transpose()
    }

    async fn list_change_sets(
        &self,
        filter: &ChangeSetFilter,
        page: PageRequest,
    ) -> Result<Page<ChangeSet>> {
        let mut f = FilterSql::default();
        if let Some(v) = filter.kind {
            f.text_eq("kind", v.as_str());
        }
        if let Some(v) = filter.status {
            f.text_eq("status", v.as_str());
        }
        if let Some(v) = &filter.created_by {
            f.text_eq("created_by", v.clone());
        }

        fetch_page(
            &self.pool,
            CHANGE_SET_COLUMNS,
            "change_sets",
            &f,
            "ORDER BY created_at DESC, id DESC",
            page,
            change_set_from_row,
        )
        .await
    }

    async fn list_items(
        &self,
        change_set_id: &str,
        status: Option<ChangeSetItemStatus>,
        page: PageRequest,
    ) -> Result<Page<ChangeSetItem>> {
        let mut f = FilterSql::default();
        f.text_eq("change_set_id", change_set_id);
        if let Some(s) = status {
            f.text_eq("status", s.as_str());
        }

        fetch_page(
            &self.pool,
            CHANGE_SET_ITEM_COLUMNS,
            "change_set_items",
            &f,
            "ORDER BY id ASC",
            page,
            change_set_item_from_row,
        )
        .await
    }

    async fn item_status_counts(&self, change_set_id: &str) -> Result<ChangeSetProgress> {
        let rows = sqlx::query(
            "SELECT status, COUNT(*) AS n FROM change_set_items WHERE change_set_id = ?1 \
             GROUP BY status",
        )
        .bind(change_set_id)
        .fetch_all(&self.pool)
        .await?;

        let mut progress = ChangeSetProgress::default();
        for r in &rows {
            let status = ChangeSetItemStatus::parse(r.get::<String, _>("status").as_str())?;
            let n: i64 = r.get("n");
            match status {
                ChangeSetItemStatus::Pending => progress.pending += n,
                ChangeSetItemStatus::Applied => progress.applied += n,
                ChangeSetItemStatus::Failed => progress.failed += n,
                ChangeSetItemStatus::Indeterminate => progress.indeterminate += n,
                ChangeSetItemStatus::Skipped => progress.skipped += n,
            }
        }
        Ok(progress)
    }

    async fn claim_for_commit(
        &self,
        id: &str,
        plan_hash: &str,
        expected_item_count: i64,
    ) -> Result<CommitClaim> {
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query(
            "SELECT status, plan_hash, expected_item_count FROM change_sets WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            return Ok(CommitClaim::NotFound);
        };

        let status = ChangeSetStatus::parse(row.get::<String, _>("status").as_str())?;
        if status != ChangeSetStatus::Planned {
            return Ok(CommitClaim::NotPlanned { status });
        }

        let stored_hash: String = row.get("plan_hash");
        let stored_count: i64 = row.get("expected_item_count");
        let live_count: i64 =
            sqlx::query("SELECT COUNT(*) FROM change_set_items WHERE change_set_id = ?1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?
                .get(0);

        if plan_hash != stored_hash
            || expected_item_count != stored_count
            || expected_item_count != live_count
        {
            return Ok(CommitClaim::Stale {
                expected_plan_hash: plan_hash.to_string(),
                actual_plan_hash: stored_hash,
                expected_item_count,
                actual_item_count: live_count,
            });
        }

        let result = sqlx::query(
            "UPDATE change_sets SET status = 'committing' WHERE id = ?1 AND status = 'planned'",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() != 1 {
            // A concurrent claimer won the conditional UPDATE.
            return Ok(CommitClaim::NotPlanned {
                status: ChangeSetStatus::Committing,
            });
        }

        tx.commit().await?;
        Ok(CommitClaim::Claimed)
    }

    async fn mark_item_applied(
        &self,
        item_id: i64,
        asset_patch: Option<&AssetPatch>,
        event: &NewAssetEvent,
    ) -> Result<()> {
        // One transaction, three writes. If any statement below fails the
        // transaction is dropped without a commit and SQLite rolls the whole
        // thing back — there is no state where the asset moved but its history
        // and item status disagree. Deliberately does not call the other trait
        // methods: those run on `self.pool` and would each be their own atom.
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query("SELECT asset_id FROM change_set_items WHERE id = ?1")
            .bind(item_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            return Err(ChalkError::Sync(format!(
                "change set item {item_id} not found"
            )));
        };
        let asset_id: Option<String> = row.get("asset_id");

        if let (Some(patch), Some(asset_id)) = (asset_patch, asset_id.as_ref()) {
            let changes = patch.changes();
            if !changes.is_empty() {
                let set_sql = asset_patch_set_sql(&changes);
                let id_n = changes.len() + 2;
                let sql = format!("UPDATE assets SET {set_sql} WHERE id = ?{id_n}");
                let mut q = sqlx::query(&sql);
                for (_, value) in &changes {
                    q = bind_patch_value(q, value);
                }
                q.bind(datetime_to_str(&Utc::now()))
                    .bind(asset_id)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        sqlx::query(
            "INSERT INTO asset_events (asset_id, actor, actor_kind, event_type, payload, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&event.asset_id)
        .bind(&event.actor)
        .bind(event.actor_kind.as_str())
        .bind(event.event_type.as_str())
        .bind(event.payload.as_ref().map(|p| p.to_string()))
        .bind(datetime_to_str(&Utc::now()))
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE change_set_items SET status = 'applied', applied_at = ?1, error = NULL \
             WHERE id = ?2",
        )
        .bind(datetime_to_str(&Utc::now()))
        .bind(item_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn mark_item_created(
        &self,
        item_id: i64,
        asset: &Asset,
        event: &NewAssetEvent,
    ) -> Result<()> {
        // Same atom as `mark_item_applied`, with an INSERT where the UPDATE is
        // and one extra write: the item is pointed at the asset it just made,
        // so the audit trail names a real device rather than a NULL.
        let mut tx = self.pool.begin().await?;

        let sql =
            format!("INSERT INTO assets ({ASSET_COLUMNS}) VALUES ({ASSET_INSERT_PLACEHOLDERS})");
        bind_asset(sqlx::query(&sql), asset)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "INSERT INTO asset_events (asset_id, actor, actor_kind, event_type, payload, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&event.asset_id)
        .bind(&event.actor)
        .bind(event.actor_kind.as_str())
        .bind(event.event_type.as_str())
        .bind(event.payload.as_ref().map(|p| p.to_string()))
        .bind(datetime_to_str(&Utc::now()))
        .execute(&mut *tx)
        .await?;

        let updated = sqlx::query(
            "UPDATE change_set_items SET status = 'applied', applied_at = ?1, error = NULL, \
             asset_id = ?2 WHERE id = ?3",
        )
        .bind(datetime_to_str(&Utc::now()))
        .bind(&asset.id)
        .bind(item_id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            return Err(ChalkError::Sync(format!(
                "change set item {item_id} not found"
            )));
        }

        tx.commit().await?;
        Ok(())
    }

    async fn mark_item_outcome(
        &self,
        item_id: i64,
        status: ChangeSetItemStatus,
        error: Option<&str>,
    ) -> Result<()> {
        if status == ChangeSetItemStatus::Applied {
            return Err(ChalkError::Sync(
                "mark_item_outcome cannot set 'applied' — use mark_item_applied so the asset \
                 write and the audit event cannot be skipped"
                    .to_string(),
            ));
        }

        sqlx::query(
            "UPDATE change_set_items SET status = ?1, error = ?2, applied_at = NULL WHERE id = ?3",
        )
        .bind(status.as_str())
        .bind(error)
        .bind(item_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn finish_commit(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE change_sets SET status = ?1, committed_at = ?2 WHERE id = ?3")
            .bind(ChangeSetStatus::Committed.as_str())
            .bind(datetime_to_str(&Utc::now()))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn discard_change_set(&self, id: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE change_sets SET status = 'discarded' WHERE id = ?1 AND status = 'planned'",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn rearm_failed_items(&self, change_set_id: &str) -> Result<i64> {
        let mut tx = self.pool.begin().await?;

        let result = sqlx::query(
            "UPDATE change_set_items SET status = 'pending', error = NULL, applied_at = NULL \
             WHERE change_set_id = ?1 AND status IN ('pending', 'failed', 'indeterminate')",
        )
        .bind(change_set_id)
        .execute(&mut *tx)
        .await?;
        let rearmed = result.rows_affected() as i64;

        sqlx::query("UPDATE change_sets SET status = 'planned' WHERE id = ?1")
            .bind(change_set_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(rearmed)
    }
}

const TICKET_COLUMNS: &str = "id, number, requester_user_sourced_id, requester_email, asset_id, \
     school_org_sourced_id, assignee_user_sourced_id, status, priority, category, subject, body, \
     source, email_message_id, sla_due_at, first_response_at, resolved_at, closed_at, created_at, \
     updated_at, assignee_console_user_id, resolution_due_at";

fn ticket_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<Ticket> {
    Ok(Ticket {
        id: r.get("id"),
        number: r.get("number"),
        requester_user_sourced_id: r.get("requester_user_sourced_id"),
        requester_email: r.get("requester_email"),
        asset_id: r.get("asset_id"),
        school_org_sourced_id: r.get("school_org_sourced_id"),
        assignee_user_sourced_id: r.get("assignee_user_sourced_id"),
        assignee_console_user_id: r.get("assignee_console_user_id"),
        resolution_due_at: opt_datetime(r, "resolution_due_at"),
        status: TicketStatus::parse(&r.get::<String, _>("status"))?,
        priority: TicketPriority::parse(&r.get::<String, _>("priority"))?,
        category: r.get("category"),
        subject: r.get("subject"),
        body: r.get("body"),
        source: TicketSource::parse(&r.get::<String, _>("source"))?,
        email_message_id: r.get("email_message_id"),
        sla_due_at: opt_datetime(r, "sla_due_at"),
        first_response_at: opt_datetime(r, "first_response_at"),
        resolved_at: opt_datetime(r, "resolved_at"),
        closed_at: opt_datetime(r, "closed_at"),
        created_at: parse_datetime(&r.get::<String, _>("created_at")),
        updated_at: parse_datetime(&r.get::<String, _>("updated_at")),
    })
}

fn opt_datetime(r: &sqlx::sqlite::SqliteRow, col: &str) -> Option<DateTime<Utc>> {
    r.get::<Option<String>, _>(col)
        .as_deref()
        .map(parse_datetime)
}

fn comment_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<TicketComment> {
    Ok(TicketComment {
        id: r.get("id"),
        ticket_id: r.get("ticket_id"),
        author_user_sourced_id: r.get("author_user_sourced_id"),
        author_email: r.get("author_email"),
        body: r.get("body"),
        is_internal: r.get::<i64, _>("is_internal") != 0,
        source: TicketSource::parse(&r.get::<String, _>("source"))?,
        email_message_id: r.get("email_message_id"),
        created_at: parse_datetime(&r.get::<String, _>("created_at")),
    })
}

/// Every [`TicketFilter`] field pushed into SQL.
fn ticket_filter_sql(filter: &TicketFilter, scope: &TicketScope) -> FilterSql {
    let mut f = FilterSql::default();

    if let Some(v) = filter.status {
        f.text_eq("status", v.as_str());
    }
    if let Some(v) = filter.priority {
        f.text_eq("priority", v.as_str());
    }
    if let Some(v) = &filter.assignee_user_sourced_id {
        f.text_eq("assignee_user_sourced_id", v.clone());
    }
    if let Some(v) = &filter.assignee_console_user_id {
        f.text_eq("assignee_console_user_id", v.clone());
    }
    if let Some(v) = &filter.requester_user_sourced_id {
        f.text_eq("requester_user_sourced_id", v.clone());
    }
    if let Some(v) = &filter.school_org_sourced_id {
        f.text_eq("school_org_sourced_id", v.clone());
    }
    if let Some(schools) = scope.schools() {
        // ANDed with the single-school filter above, so a caller's own choice
        // narrows within the boundary and can never widen past it.
        if schools.is_empty() {
            // A grant that named no schools granted nothing. Without this the
            // IN list would be empty and the clause would vanish, turning the
            // narrowest possible scope into the widest.
            f.bare("1 = 0");
        } else {
            let placeholders: Vec<String> = schools
                .iter()
                .map(|v| {
                    let n = f.next_placeholder();
                    f.binds.push(v.clone());
                    format!("?{n}")
                })
                .collect();
            f.conditions.push(format!(
                "school_org_sourced_id IN ({})",
                placeholders.join(", ")
            ));
        }
    }
    if let Some(v) = &filter.asset_id {
        f.text_eq("asset_id", v.clone());
    }
    if let Some(tag) = &filter.tag {
        let n = f.next_placeholder();
        f.binds.push(tag.trim().to_lowercase());
        // Naming the outer table rather than a bare `id`: ticket_tags happens
        // to have no `id` column today, but this must not break the day it
        // grows one.
        f.conditions.push(format!(
            "EXISTS (SELECT 1 FROM ticket_tags tt WHERE tt.ticket_id = tickets.id AND tt.tag = ?{n})"
        ));
    }
    // "Unassigned" means no technician has claimed it. A ticket is owned by a
    // console_user (F1), not a roster user, so this reads the console column.
    match filter.unassigned {
        Some(true) => f.bare("assignee_console_user_id IS NULL"),
        Some(false) => f.bare("assignee_console_user_id IS NOT NULL"),
        None => {}
    }
    if filter.breached_only {
        // Overdue *and* still actionable. A resolved ticket that was late is a
        // reporting fact, not something a queue should be shouting about.
        let n = f.next_placeholder();
        f.binds.push(datetime_to_str(&Utc::now()));
        f.conditions.push(format!(
            "(sla_due_at IS NOT NULL AND sla_due_at < ?{n} AND {})",
            TicketStatus::clock_running_sql_in()
        ));
    }
    if let Some(q) = &filter.search {
        let like = format!("%{}%", escape_like(&q.to_lowercase()));
        let a = f.next_placeholder();
        f.binds.push(like.clone());
        let b = f.next_placeholder();
        f.binds.push(like);
        f.conditions.push(format!(
            "(LOWER(subject) LIKE ?{a} ESCAPE '\\' OR LOWER(body) LIKE ?{b} ESCAPE '\\')"
        ));
    }
    f
}

#[async_trait]
impl TicketRepository for SqliteRepository {
    async fn create_ticket(&self, ticket: &Ticket) -> Result<Ticket> {
        // The number is allocated inside this transaction. SQLite serializes
        // writers, so the read-modify-write of the counter cannot interleave —
        // and doing it here rather than in the caller is what stops two
        // submissions sharing a number.
        let mut tx = self.pool.begin().await?;

        sqlx::query("UPDATE ticket_counters SET next_number = next_number + 1 WHERE id = 1")
            .execute(&mut *tx)
            .await?;
        let number: i64 = sqlx::query("SELECT next_number - 1 FROM ticket_counters WHERE id = 1")
            .fetch_one(&mut *tx)
            .await?
            .get(0);

        let sql = format!(
            "INSERT INTO tickets ({TICKET_COLUMNS}) VALUES \
             (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, \
             ?19, ?20, ?21, ?22)"
        );
        sqlx::query(&sql)
            .bind(&ticket.id)
            .bind(number)
            .bind(&ticket.requester_user_sourced_id)
            .bind(&ticket.requester_email)
            .bind(&ticket.asset_id)
            .bind(&ticket.school_org_sourced_id)
            .bind(&ticket.assignee_user_sourced_id)
            .bind(ticket.status.as_str())
            .bind(ticket.priority.as_str())
            .bind(&ticket.category)
            .bind(&ticket.subject)
            .bind(&ticket.body)
            .bind(ticket.source.as_str())
            .bind(&ticket.email_message_id)
            .bind(ticket.sla_due_at.as_ref().map(datetime_to_str))
            .bind(ticket.first_response_at.as_ref().map(datetime_to_str))
            .bind(ticket.resolved_at.as_ref().map(datetime_to_str))
            .bind(ticket.closed_at.as_ref().map(datetime_to_str))
            .bind(datetime_to_str(&ticket.created_at))
            .bind(datetime_to_str(&ticket.updated_at))
            .bind(&ticket.assignee_console_user_id)
            .bind(ticket.resolution_due_at.as_ref().map(datetime_to_str))
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(Ticket {
            number,
            ..ticket.clone()
        })
    }

    async fn get_ticket(&self, id: &str) -> Result<Option<Ticket>> {
        let sql = format!("SELECT {TICKET_COLUMNS} FROM tickets WHERE id = ?1");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(ticket_from_row).transpose()
    }

    async fn get_ticket_by_number(&self, number: i64) -> Result<Option<Ticket>> {
        let sql = format!("SELECT {TICKET_COLUMNS} FROM tickets WHERE number = ?1");
        let row = sqlx::query(&sql)
            .bind(number)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(ticket_from_row).transpose()
    }

    async fn get_ticket_by_message_id(&self, message_id: &str) -> Result<Option<Ticket>> {
        let sql = format!("SELECT {TICKET_COLUMNS} FROM tickets WHERE email_message_id = ?1");
        let row = sqlx::query(&sql)
            .bind(message_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(ticket_from_row).transpose()
    }

    async fn list_tickets(
        &self,
        filter: &TicketFilter,
        scope: &TicketScope,
        page: PageRequest,
    ) -> Result<Page<Ticket>> {
        let order_by = filter.order_by_sql("");
        fetch_page(
            &self.pool,
            TICKET_COLUMNS,
            "tickets",
            &ticket_filter_sql(filter, scope),
            &order_by,
            page,
            ticket_from_row,
        )
        .await
    }

    async fn count_tickets(&self, filter: &TicketFilter, scope: &TicketScope) -> Result<i64> {
        let f = ticket_filter_sql(filter, scope);
        let sql = format!("SELECT COUNT(*) FROM tickets{}", f.where_sql());
        let total: i64 = f
            .bind_all(sqlx::query(&sql))
            .fetch_one(&self.pool)
            .await?
            .get(0);
        Ok(total)
    }

    async fn update_ticket(&self, id: &str, patch: &TicketPatch) -> Result<bool> {
        let changes = ticket_patch_changes(patch);
        if changes.is_empty() {
            let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM tickets WHERE id = ?1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            return Ok(exists.is_some());
        }
        let set_sql = asset_patch_set_sql(&changes);
        let id_n = changes.len() + 2;
        let sql = format!("UPDATE tickets SET {set_sql} WHERE id = ?{id_n}");
        let mut q = sqlx::query(&sql);
        for (_, value) in &changes {
            q = bind_patch_value(q, value);
        }
        let res = q
            .bind(datetime_to_str(&Utc::now()))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn append_comment(&self, comment: &NewTicketComment) -> Result<TicketComment> {
        // One transaction: the comment and, when it is the first visible reply
        // from somebody other than the requester, the first-response stamp.
        // First-response time is the number a district is measured on, and
        // computing it from a second write leaves a window where the comment
        // exists and the clock says nobody has answered.
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        let res = sqlx::query(
            "INSERT INTO ticket_comments \
             (ticket_id, author_user_sourced_id, author_email, body, is_internal, source, \
             email_message_id, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&comment.ticket_id)
        .bind(&comment.author_user_sourced_id)
        .bind(&comment.author_email)
        .bind(&comment.body)
        .bind(if comment.is_internal { 1i64 } else { 0i64 })
        .bind(comment.source.as_str())
        .bind(&comment.email_message_id)
        .bind(datetime_to_str(&now))
        .execute(&mut *tx)
        .await?;
        let id = res.last_insert_rowid();

        if !comment.is_internal {
            // Only a reply the requester can see counts, and only from someone
            // else: a requester adding "any update?" is not a first response.
            sqlx::query(
                "UPDATE tickets SET first_response_at = ?1, updated_at = ?1 \
                 WHERE id = ?2 AND first_response_at IS NULL \
                 AND (requester_user_sourced_id IS NULL OR requester_user_sourced_id IS NOT ?3)",
            )
            .bind(datetime_to_str(&now))
            .bind(&comment.ticket_id)
            .bind(&comment.author_user_sourced_id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query("UPDATE tickets SET updated_at = ?1 WHERE id = ?2")
                .bind(datetime_to_str(&now))
                .bind(&comment.ticket_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(TicketComment {
            id,
            ticket_id: comment.ticket_id.clone(),
            author_user_sourced_id: comment.author_user_sourced_id.clone(),
            author_email: comment.author_email.clone(),
            body: comment.body.clone(),
            is_internal: comment.is_internal,
            source: comment.source,
            email_message_id: comment.email_message_id.clone(),
            created_at: now,
        })
    }

    async fn list_comments(
        &self,
        ticket_id: &str,
        include_internal: bool,
    ) -> Result<Vec<TicketComment>> {
        // Filtered in SQL, not after the fetch: an internal note must never
        // travel to a caller who is not allowed to see it, and "we filter it
        // out in the template" is one refactor away from a leak.
        let visibility = if include_internal {
            ""
        } else {
            " AND is_internal = 0"
        };
        let sql = format!(
            "SELECT id, ticket_id, author_user_sourced_id, author_email, body, is_internal, \
             source, email_message_id, created_at FROM ticket_comments \
             WHERE ticket_id = ?1{visibility} ORDER BY created_at, id"
        );
        let rows = sqlx::query(&sql)
            .bind(ticket_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(comment_from_row).collect()
    }

    async fn ticket_id_for_comment_message_id(&self, message_id: &str) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT ticket_id FROM ticket_comments WHERE email_message_id = ?1 LIMIT 1",
        )
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<String, _>("ticket_id")))
    }

    async fn add_attachment(&self, a: &TicketAttachment) -> Result<()> {
        sqlx::query(
            "INSERT INTO ticket_attachments \
             (id, ticket_id, comment_id, filename, content_type, size_bytes, sha256, \
             storage_key, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&a.id)
        .bind(&a.ticket_id)
        .bind(a.comment_id)
        .bind(&a.filename)
        .bind(&a.content_type)
        .bind(a.size_bytes)
        .bind(&a.sha256)
        .bind(&a.storage_key)
        .bind(datetime_to_str(&a.created_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_attachment(&self, id: &str) -> Result<Option<TicketAttachment>> {
        let row = sqlx::query(
            "SELECT id, ticket_id, comment_id, filename, content_type, size_bytes, sha256, \
             storage_key, created_at FROM ticket_attachments WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| TicketAttachment {
            id: r.get("id"),
            ticket_id: r.get("ticket_id"),
            comment_id: r.get("comment_id"),
            filename: r.get("filename"),
            content_type: r.get("content_type"),
            size_bytes: r.get("size_bytes"),
            sha256: r.get("sha256"),
            storage_key: r.get("storage_key"),
            created_at: parse_datetime(&r.get::<String, _>("created_at")),
        }))
    }

    async fn list_attachments(&self, ticket_id: &str) -> Result<Vec<TicketAttachment>> {
        let rows = sqlx::query(
            "SELECT id, ticket_id, comment_id, filename, content_type, size_bytes, sha256, \
             storage_key, created_at FROM ticket_attachments WHERE ticket_id = ?1 \
             ORDER BY created_at, id",
        )
        .bind(ticket_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| TicketAttachment {
                id: r.get("id"),
                ticket_id: r.get("ticket_id"),
                comment_id: r.get("comment_id"),
                filename: r.get("filename"),
                content_type: r.get("content_type"),
                size_bytes: r.get("size_bytes"),
                sha256: r.get("sha256"),
                storage_key: r.get("storage_key"),
                created_at: parse_datetime(&r.get::<String, _>("created_at")),
            })
            .collect())
    }

    async fn set_ticket_tags(&self, ticket_id: &str, tags: &[String]) -> Result<()> {
        // Replace-all inside one transaction, so a concurrent read never sees
        // the half-empty middle state.
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM ticket_tags WHERE ticket_id = ?1")
            .bind(ticket_id)
            .execute(&mut *tx)
            .await?;
        for tag in normalized_tags(tags) {
            sqlx::query("INSERT OR IGNORE INTO ticket_tags (ticket_id, tag) VALUES (?1, ?2)")
                .bind(ticket_id)
                .bind(tag)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn get_ticket_tags(&self, ticket_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT tag FROM ticket_tags WHERE ticket_id = ?1 ORDER BY tag")
            .bind(ticket_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|r| r.get("tag")).collect())
    }

    async fn get_tags_for_tickets(&self, ticket_ids: &[String]) -> Result<Vec<(String, String)>> {
        if ticket_ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders: Vec<String> = (1..=ticket_ids.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "SELECT ticket_id, tag FROM ticket_tags WHERE ticket_id IN ({}) ORDER BY tag",
            placeholders.join(", ")
        );
        let mut q = sqlx::query(&sql);
        for id in ticket_ids {
            q = q.bind(id);
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows
            .iter()
            .map(|r| (r.get("ticket_id"), r.get("tag")))
            .collect())
    }

    async fn list_all_tags(&self) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT DISTINCT tag FROM ticket_tags ORDER BY tag")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|r| r.get("tag")).collect())
    }
}

/// Tags as stored: trimmed, lowercased, de-duplicated, empties dropped. Shared
/// by both drivers so "Wifi" and "wifi " cannot become two tags on one backend
/// and one on the other.
pub(crate) fn normalized_tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = tags
        .iter()
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The columns a ticket patch writes, reusing the asset patch machinery so the
/// two cannot drift on how a `Patch::Clear` is bound.
///
/// `pub(crate)` so the Postgres driver uses the same list — two hand-kept
/// column sets is two places for a backend to quietly stop writing a field.
pub(crate) fn ticket_patch_changes(patch: &TicketPatch) -> Vec<(&'static str, PatchValue)> {
    let mut out: Vec<(&'static str, PatchValue)> = Vec::new();
    if let Some(v) = patch.status {
        out.push(("status", PatchValue::Text(v.as_str().to_string())));
    }
    if let Some(v) = patch.priority {
        out.push(("priority", PatchValue::Text(v.as_str().to_string())));
    }
    if let Some(v) = &patch.subject {
        out.push(("subject", PatchValue::Text(v.clone())));
    }
    push_patch(
        &mut out,
        "assignee_user_sourced_id",
        &patch.assignee_user_sourced_id,
        |v| PatchValue::Text(v.clone()),
    );
    push_patch(
        &mut out,
        "assignee_console_user_id",
        &patch.assignee_console_user_id,
        |v| PatchValue::Text(v.clone()),
    );
    push_patch(
        &mut out,
        "school_org_sourced_id",
        &patch.school_org_sourced_id,
        |v| PatchValue::Text(v.clone()),
    );
    push_patch(&mut out, "asset_id", &patch.asset_id, |v| {
        PatchValue::Text(v.clone())
    });
    push_patch(&mut out, "category", &patch.category, |v| {
        PatchValue::Text(v.clone())
    });
    push_patch(&mut out, "sla_due_at", &patch.sla_due_at, |v| {
        PatchValue::Timestamp(*v)
    });
    push_patch(
        &mut out,
        "resolution_due_at",
        &patch.resolution_due_at,
        |v| PatchValue::Timestamp(*v),
    );
    push_patch(
        &mut out,
        "first_response_at",
        &patch.first_response_at,
        |v| PatchValue::Timestamp(*v),
    );
    push_patch(&mut out, "resolved_at", &patch.resolved_at, |v| {
        PatchValue::Timestamp(*v)
    });
    push_patch(&mut out, "closed_at", &patch.closed_at, |v| {
        PatchValue::Timestamp(*v)
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repository::{
        AccessTokenRepository, AdminAuditRepository, AdminSessionRepository, AssetEventRepository,
        AssetRepository, CannedResponseRepository, ChangeSetRepository, ChargeRepository,
        ConfigRepository, ConsoleUserRepository, DeviceConfigRecord, GoogleDeviceSyncRepository,
        GoogleSyncRunRepository, GoogleSyncStateRepository, IdpAuthLogRepository,
        IdpSessionRepository, PasswordRepository, PicturePasswordRepository, QrBadgeRepository,
        TenantConfigRepo, UserRepository, WebhookDeliveryRepository, WebhookEndpointRepository,
    };
    use crate::db::DatabasePool;
    use crate::models::charge::{outstanding_balance_cents, ChargeKind, ChargeStatus, NewCharge};
    use crate::models::common::{
        ClassType, EnrollmentRole, OrgType, RoleType, SessionType, Sex, Status,
    };
    use chrono::Duration;
    use chrono::TimeZone;

    async fn setup() -> SqliteRepository {
        let pool = DatabasePool::new_sqlite_memory().await.unwrap();
        match pool {
            DatabasePool::Sqlite(p) => SqliteRepository::new(p),

            DatabasePool::Postgres(_) => unreachable!("test setup uses sqlite memory"),
        }
    }

    #[tokio::test]
    async fn canned_responses_round_trip_and_delete() {
        use crate::models::canned_response::CannedResponse;
        let repo = setup().await;

        repo.create_canned_response(&CannedResponse::new(
            "cr-1",
            "Hard reset",
            "Hold the power button for ten seconds, then try again.",
        ))
        .await
        .unwrap();

        let all = repo.list_canned_responses().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].title, "Hard reset");

        let got = repo.get_canned_response("cr-1").await.unwrap().unwrap();
        assert!(got.body.contains("ten seconds"));

        repo.delete_canned_response("cr-1").await.unwrap();
        assert!(repo.get_canned_response("cr-1").await.unwrap().is_none());
    }

    fn console_user(
        id: &str,
        email: &str,
        role: crate::models::console_user::ConsoleRole,
    ) -> ConsoleUser {
        ConsoleUser {
            id: id.into(),
            email: email.into(),
            display_name: "Test Tech".into(),
            password_hash: Some("$argon2id$hash".into()),
            role,
            status: ConsoleUserStatus::Active,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn console_user_round_trips_and_updates() {
        use crate::models::console_user::ConsoleRole;
        let repo = setup().await;

        assert_eq!(repo.count_console_users().await.unwrap(), 0);
        repo.create_console_user(&console_user("u-1", "ravi@d.org", ConsoleRole::Technician))
            .await
            .unwrap();
        assert_eq!(repo.count_console_users().await.unwrap(), 1);

        // Read back by email (the login path) and by id (the edit path).
        let by_email = repo.get_console_user_by_email("ravi@d.org").await.unwrap();
        assert!(by_email.is_some());
        let fetched = repo.get_console_user("u-1").await.unwrap().unwrap();
        assert_eq!(fetched.role, ConsoleRole::Technician);
        assert_eq!(fetched.password_hash.as_deref(), Some("$argon2id$hash"));

        // Promote to admin and disable; email and id are immutable, the rest updates.
        let mut updated = fetched;
        updated.role = ConsoleRole::Admin;
        updated.status = ConsoleUserStatus::Disabled;
        updated.display_name = "Ravi P".into();
        repo.update_console_user(&updated).await.unwrap();
        let after = repo.get_console_user("u-1").await.unwrap().unwrap();
        assert_eq!(after.role, ConsoleRole::Admin);
        assert!(!after.is_active());
        assert_eq!(after.display_name, "Ravi P");
    }

    #[tokio::test]
    async fn console_user_email_is_unique() {
        use crate::models::console_user::ConsoleRole;
        let repo = setup().await;
        repo.create_console_user(&console_user("u-1", "dup@d.org", ConsoleRole::Technician))
            .await
            .unwrap();
        // Same email, different id — the unique index must reject it, so two
        // people can never claim one login.
        let clash = repo
            .create_console_user(&console_user("u-2", "dup@d.org", ConsoleRole::Admin))
            .await;
        assert!(clash.is_err(), "duplicate console email must be rejected");
    }

    #[tokio::test]
    async fn a_missing_console_user_is_none_not_an_error() {
        let repo = setup().await;
        assert!(repo.get_console_user("nope").await.unwrap().is_none());
        assert!(repo
            .get_console_user_by_email("nobody@d.org")
            .await
            .unwrap()
            .is_none());
    }

    /// The charge ledger through the repository: a family's outstanding balance
    /// is the sum of their assessed charges, and waiving one drops it — proven
    /// against the same independent arithmetic the model test uses, but now
    /// round-tripped through SQLite so the row encoding is exercised too.
    #[tokio::test]
    async fn charges_persist_and_the_balance_reflects_waivers() {
        let repo = setup().await;
        // The charge's user_sourced_id FKs the roster, so the student must exist.
        let mut student = sample_user();
        student.sourced_id = "u-1".to_string();
        student.orgs = vec![];
        student.grades = vec![];
        repo.upsert_user(&student).await.unwrap();

        let new = |amount: i64, status: ChargeStatus| NewCharge {
            asset_id: None,
            user_sourced_id: Some("u-1".into()),
            ticket_id: None,
            kind: ChargeKind::RepairFee,
            amount_cents: amount,
            status,
            insurance_applied: false,
            reason: Some("cracked screen".into()),
            actor: "Ravi Patel".into(),
        };

        repo.create_charge(&new(5000, ChargeStatus::Assessed))
            .await
            .unwrap();
        let waivable = repo
            .create_charge(&new(3000, ChargeStatus::Assessed))
            .await
            .unwrap();

        let charges = repo.list_charges_for_user("u-1").await.unwrap();
        assert_eq!(charges.len(), 2);
        assert_eq!(outstanding_balance_cents(&charges), 8000);

        // Waive the $30 fine under a protection plan; the balance drops to $50.
        repo.update_charge_status(&waivable, ChargeStatus::Waived, true)
            .await
            .unwrap();
        let after = repo.list_charges_for_user("u-1").await.unwrap();
        assert_eq!(outstanding_balance_cents(&after), 5000);
        // The waiver recorded that insurance was applied.
        let waived = after.iter().find(|c| c.id == waivable).unwrap();
        assert!(waived.insurance_applied);
        assert_eq!(waived.actor, "Ravi Patel");
    }

    fn sample_org() -> Org {
        Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Springfield District".to_string(),
            org_type: OrgType::District,
            identifier: Some("SSD001".to_string()),
            parent: None,
            children: vec![],
        }
    }

    fn sample_school() -> Org {
        Org {
            sourced_id: "org-002".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Springfield High".to_string(),
            org_type: OrgType::School,
            identifier: None,
            parent: Some("org-001".to_string()),
            children: vec![],
        }
    }

    fn sample_academic_session() -> AcademicSession {
        AcademicSession {
            sourced_id: "term-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "Fall 2025".to_string(),
            start_date: NaiveDate::from_ymd_opt(2025, 8, 15).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2025, 12, 20).unwrap(),
            session_type: SessionType::Term,
            parent: None,
            school_year: "2025".to_string(),
            children: vec![],
        }
    }

    fn sample_user() -> User {
        User {
            sourced_id: "user-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "jdoe".to_string(),
            user_ids: vec![UserIdentifier {
                type_: "LDAP".to_string(),
                identifier: "jdoe@example.com".to_string(),
            }],
            enabled_user: true,
            given_name: "John".to_string(),
            family_name: "Doe".to_string(),
            middle_name: Some("M".to_string()),
            role: RoleType::Student,
            identifier: Some("STU001".to_string()),
            email: Some("jdoe@example.com".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-001".to_string()],
            grades: vec!["09".to_string()],
        }
    }

    fn sample_teacher() -> User {
        User {
            sourced_id: "user-002".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "asmith".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "Alice".to_string(),
            family_name: "Smith".to_string(),
            middle_name: None,
            role: RoleType::Teacher,
            identifier: None,
            email: Some("asmith@example.com".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-001".to_string()],
            grades: vec![],
        }
    }

    fn sample_course() -> Course {
        Course {
            sourced_id: "course-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "Algebra I".to_string(),
            school_year: Some("2025".to_string()),
            course_code: Some("ALG1".to_string()),
            grades: vec!["09".to_string()],
            subjects: vec!["Mathematics".to_string()],
            org: "org-001".to_string(),
        }
    }

    fn sample_class() -> Class {
        Class {
            sourced_id: "class-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "Algebra I - Period 1".to_string(),
            class_code: Some("ALG1-P1".to_string()),
            class_type: ClassType::Scheduled,
            location: Some("Room 101".to_string()),
            grades: vec!["09".to_string()],
            subjects: vec!["Mathematics".to_string()],
            course: "course-001".to_string(),
            school: "org-002".to_string(),
            terms: vec!["term-001".to_string()],
            periods: vec!["1".to_string()],
        }
    }

    fn sample_enrollment() -> Enrollment {
        Enrollment {
            sourced_id: "enr-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            user: "user-001".to_string(),
            class: "class-001".to_string(),
            school: "org-002".to_string(),
            role: EnrollmentRole::Student,
            primary: None,
            begin_date: Some(NaiveDate::from_ymd_opt(2025, 8, 15).unwrap()),
            end_date: Some(NaiveDate::from_ymd_opt(2026, 6, 1).unwrap()),
        }
    }

    fn sample_demographics() -> Demographics {
        Demographics {
            sourced_id: "user-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            birth_date: Some(NaiveDate::from_ymd_opt(2009, 3, 15).unwrap()),
            sex: Some(Sex::Male),
            american_indian_or_alaska_native: Some(false),
            asian: Some(false),
            black_or_african_american: Some(false),
            native_hawaiian_or_other_pacific_islander: Some(false),
            white: Some(true),
            demographic_race_two_or_more_races: Some(false),
            hispanic_or_latino_ethnicity: Some(false),
            country_of_birth_code: Some("US".to_string()),
            state_of_birth_abbreviation: Some("IL".to_string()),
            city_of_birth: Some("Springfield".to_string()),
            public_school_residence_status: None,
        }
    }

    // -- Migration test --

    #[tokio::test]
    async fn migration_runs_successfully() {
        let _repo = setup().await;
        // If setup() succeeds, the migration ran successfully
    }

    // -- Config overrides tests --

    #[tokio::test]
    async fn config_override_get_missing_returns_none() {
        let repo = setup().await;
        let result = repo.get_config_override("nonexistent.key").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn config_override_set_and_get() {
        let repo = setup().await;
        repo.set_config_override("sis.sync_schedule", "0 4 * * *")
            .await
            .unwrap();
        let value = repo.get_config_override("sis.sync_schedule").await.unwrap();
        assert_eq!(value, Some("0 4 * * *".to_string()));
    }

    #[tokio::test]
    async fn config_override_upsert_updates_value() {
        let repo = setup().await;
        repo.set_config_override("sis.sync_schedule", "0 2 * * *")
            .await
            .unwrap();
        repo.set_config_override("sis.sync_schedule", "30 3 * * *")
            .await
            .unwrap();
        let value = repo.get_config_override("sis.sync_schedule").await.unwrap();
        assert_eq!(value, Some("30 3 * * *".to_string()));
    }

    #[tokio::test]
    async fn config_override_multiple_keys() {
        let repo = setup().await;
        repo.set_config_override("sis.sync_schedule", "0 2 * * *")
            .await
            .unwrap();
        repo.set_config_override("google_sync.sync_schedule", "0 3 * * *")
            .await
            .unwrap();
        assert_eq!(
            repo.get_config_override("sis.sync_schedule").await.unwrap(),
            Some("0 2 * * *".to_string())
        );
        assert_eq!(
            repo.get_config_override("google_sync.sync_schedule")
                .await
                .unwrap(),
            Some("0 3 * * *".to_string())
        );
    }

    #[tokio::test]
    async fn effective_schedule_uses_override() {
        let repo = setup().await;
        repo.set_config_override("sis.sync_schedule", "0 6 * * *")
            .await
            .unwrap();
        let result = effective_schedule(&repo, "sis.sync_schedule", "0 2 * * *").await;
        assert_eq!(result, "0 6 * * *");
    }

    #[tokio::test]
    async fn effective_schedule_falls_back_to_config() {
        let repo = setup().await;
        let result = effective_schedule(&repo, "sis.sync_schedule", "0 2 * * *").await;
        assert_eq!(result, "0 2 * * *");
    }

    // -- Org CRUD tests --

    #[tokio::test]
    async fn org_crud_round_trip() {
        let repo = setup().await;
        let org = sample_org();

        repo.upsert_org(&org).await.unwrap();
        let fetched = repo.get_org("org-001").await.unwrap().unwrap();
        assert_eq!(fetched.sourced_id, org.sourced_id);
        assert_eq!(fetched.name, org.name);
        assert_eq!(fetched.org_type, org.org_type);
        assert_eq!(fetched.identifier, org.identifier);
    }

    #[tokio::test]
    async fn org_upsert_updates_fields() {
        let repo = setup().await;
        let mut org = sample_org();
        repo.upsert_org(&org).await.unwrap();

        org.name = "Updated District".to_string();
        repo.upsert_org(&org).await.unwrap();

        let fetched = repo.get_org("org-001").await.unwrap().unwrap();
        assert_eq!(fetched.name, "Updated District");
    }

    #[tokio::test]
    async fn org_children_populated() {
        let repo = setup().await;
        let parent = sample_org();
        let child = sample_school();

        repo.upsert_org(&parent).await.unwrap();
        repo.upsert_org(&child).await.unwrap();

        let fetched = repo.get_org("org-001").await.unwrap().unwrap();
        assert_eq!(fetched.children, vec!["org-002"]);
    }

    #[tokio::test]
    async fn org_list() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_org(&sample_school()).await.unwrap();

        let orgs = repo.list_orgs().await.unwrap();
        assert_eq!(orgs.len(), 2);
    }

    #[tokio::test]
    async fn org_delete() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();

        let deleted = repo.delete_org("org-001").await.unwrap();
        assert!(deleted);

        let fetched = repo.get_org("org-001").await.unwrap();
        assert!(fetched.is_none());

        let not_deleted = repo.delete_org("nonexistent").await.unwrap();
        assert!(!not_deleted);
    }

    #[tokio::test]
    async fn org_get_nonexistent() {
        let repo = setup().await;
        let fetched = repo.get_org("nonexistent").await.unwrap();
        assert!(fetched.is_none());
    }

    // -- AcademicSession CRUD tests --

    #[tokio::test]
    async fn academic_session_crud_round_trip() {
        let repo = setup().await;
        let session = sample_academic_session();

        repo.upsert_academic_session(&session).await.unwrap();
        let fetched = repo
            .get_academic_session("term-001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.sourced_id, session.sourced_id);
        assert_eq!(fetched.title, session.title);
        assert_eq!(fetched.start_date, session.start_date);
        assert_eq!(fetched.end_date, session.end_date);
        assert_eq!(fetched.session_type, session.session_type);
        assert_eq!(fetched.school_year, session.school_year);
    }

    #[tokio::test]
    async fn academic_session_upsert_updates() {
        let repo = setup().await;
        let mut session = sample_academic_session();
        repo.upsert_academic_session(&session).await.unwrap();

        session.title = "Updated Fall 2025".to_string();
        repo.upsert_academic_session(&session).await.unwrap();

        let fetched = repo
            .get_academic_session("term-001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.title, "Updated Fall 2025");
    }

    #[tokio::test]
    async fn academic_session_children() {
        let repo = setup().await;
        let parent = sample_academic_session();
        let child = AcademicSession {
            sourced_id: "gp-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "Grading Period 1".to_string(),
            start_date: NaiveDate::from_ymd_opt(2025, 8, 15).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2025, 10, 15).unwrap(),
            session_type: SessionType::GradingPeriod,
            parent: Some("term-001".to_string()),
            school_year: "2025".to_string(),
            children: vec![],
        };

        repo.upsert_academic_session(&parent).await.unwrap();
        repo.upsert_academic_session(&child).await.unwrap();

        let fetched = repo
            .get_academic_session("term-001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.children, vec!["gp-001"]);
    }

    #[tokio::test]
    async fn academic_session_list() {
        let repo = setup().await;
        repo.upsert_academic_session(&sample_academic_session())
            .await
            .unwrap();
        let sessions = repo.list_academic_sessions().await.unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn academic_session_delete() {
        let repo = setup().await;
        repo.upsert_academic_session(&sample_academic_session())
            .await
            .unwrap();

        let deleted = repo.delete_academic_session("term-001").await.unwrap();
        assert!(deleted);

        let fetched = repo.get_academic_session("term-001").await.unwrap();
        assert!(fetched.is_none());
    }

    // -- User CRUD tests --

    #[tokio::test]
    async fn user_crud_round_trip() {
        let repo = setup().await;
        // Insert org first (for FK in user_orgs)
        repo.upsert_org(&sample_org()).await.unwrap();

        let user = sample_user();
        repo.upsert_user(&user).await.unwrap();

        let fetched = repo.get_user("user-001").await.unwrap().unwrap();
        assert_eq!(fetched.sourced_id, user.sourced_id);
        assert_eq!(fetched.username, user.username);
        assert_eq!(fetched.given_name, user.given_name);
        assert_eq!(fetched.family_name, user.family_name);
        assert_eq!(fetched.middle_name, user.middle_name);
        assert_eq!(fetched.role, user.role);
        assert_eq!(fetched.email, user.email);
        assert_eq!(fetched.enabled_user, user.enabled_user);
    }

    #[tokio::test]
    async fn user_junction_tables_populated() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();

        let user = sample_user();
        repo.upsert_user(&user).await.unwrap();

        let fetched = repo.get_user("user-001").await.unwrap().unwrap();
        assert_eq!(fetched.orgs, vec!["org-001"]);
        assert_eq!(fetched.grades, vec!["09"]);
        assert_eq!(fetched.user_ids.len(), 1);
        assert_eq!(fetched.user_ids[0].type_, "LDAP");
        assert_eq!(fetched.user_ids[0].identifier, "jdoe@example.com");
    }

    #[tokio::test]
    async fn user_upsert_updates_fields() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();

        let mut user = sample_user();
        repo.upsert_user(&user).await.unwrap();

        user.given_name = "Jane".to_string();
        user.grades = vec!["10".to_string()];
        repo.upsert_user(&user).await.unwrap();

        let fetched = repo.get_user("user-001").await.unwrap().unwrap();
        assert_eq!(fetched.given_name, "Jane");
        assert_eq!(fetched.grades, vec!["10"]);
    }

    #[tokio::test]
    async fn user_list_filter_by_role() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();

        repo.upsert_user(&sample_user()).await.unwrap();
        repo.upsert_user(&sample_teacher()).await.unwrap();

        let filter = UserFilter {
            role: Some(RoleType::Student),
            ..Default::default()
        };
        let students = repo.list_users(&filter).await.unwrap();
        assert_eq!(students.len(), 1);
        assert_eq!(students[0].sourced_id, "user-001");

        let all_filter = UserFilter::default();
        let all = repo.list_users(&all_filter).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn user_delete() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let deleted = repo.delete_user("user-001").await.unwrap();
        assert!(deleted);

        let fetched = repo.get_user("user-001").await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn user_counts() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();
        repo.upsert_user(&sample_teacher()).await.unwrap();

        let admin = User {
            sourced_id: "user-003".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "admin1".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "Bob".to_string(),
            family_name: "Admin".to_string(),
            middle_name: None,
            role: RoleType::Administrator,
            identifier: None,
            email: None,
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec![],
            grades: vec![],
        };
        repo.upsert_user(&admin).await.unwrap();

        let counts = repo.get_user_counts().await.unwrap();
        assert_eq!(counts.total, 3);
        assert_eq!(counts.students, 1);
        assert_eq!(counts.teachers, 1);
        assert_eq!(counts.administrators, 1);
        assert_eq!(counts.other, 0);
    }

    // -- Course CRUD tests --

    #[tokio::test]
    async fn course_crud_round_trip() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();

        let course = sample_course();
        repo.upsert_course(&course).await.unwrap();

        let fetched = repo.get_course("course-001").await.unwrap().unwrap();
        assert_eq!(fetched.sourced_id, course.sourced_id);
        assert_eq!(fetched.title, course.title);
        assert_eq!(fetched.school_year, course.school_year);
        assert_eq!(fetched.course_code, course.course_code);
        assert_eq!(fetched.grades, course.grades);
        assert_eq!(fetched.subjects, course.subjects);
        assert_eq!(fetched.org, course.org);
    }

    #[tokio::test]
    async fn course_upsert_updates() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();

        let mut course = sample_course();
        repo.upsert_course(&course).await.unwrap();

        course.title = "Algebra II".to_string();
        course.grades = vec!["10".to_string(), "11".to_string()];
        repo.upsert_course(&course).await.unwrap();

        let fetched = repo.get_course("course-001").await.unwrap().unwrap();
        assert_eq!(fetched.title, "Algebra II");
        assert_eq!(fetched.grades.len(), 2);
    }

    #[tokio::test]
    async fn course_list() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_course(&sample_course()).await.unwrap();

        let courses = repo.list_courses().await.unwrap();
        assert_eq!(courses.len(), 1);
    }

    #[tokio::test]
    async fn course_delete() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_course(&sample_course()).await.unwrap();

        let deleted = repo.delete_course("course-001").await.unwrap();
        assert!(deleted);

        let fetched = repo.get_course("course-001").await.unwrap();
        assert!(fetched.is_none());
    }

    // -- Class CRUD tests --

    #[tokio::test]
    async fn class_crud_round_trip() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_org(&sample_school()).await.unwrap();
        repo.upsert_academic_session(&sample_academic_session())
            .await
            .unwrap();
        repo.upsert_course(&sample_course()).await.unwrap();

        let class = sample_class();
        repo.upsert_class(&class).await.unwrap();

        let fetched = repo.get_class("class-001").await.unwrap().unwrap();
        assert_eq!(fetched.sourced_id, class.sourced_id);
        assert_eq!(fetched.title, class.title);
        assert_eq!(fetched.class_type, class.class_type);
        assert_eq!(fetched.course, class.course);
        assert_eq!(fetched.school, class.school);
        assert_eq!(fetched.terms, class.terms);
        assert_eq!(fetched.grades, class.grades);
        assert_eq!(fetched.subjects, class.subjects);
        assert_eq!(fetched.periods, class.periods);
    }

    #[tokio::test]
    async fn class_upsert_updates() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_org(&sample_school()).await.unwrap();
        repo.upsert_academic_session(&sample_academic_session())
            .await
            .unwrap();
        repo.upsert_course(&sample_course()).await.unwrap();

        let mut class = sample_class();
        repo.upsert_class(&class).await.unwrap();

        class.title = "Updated Class".to_string();
        class.periods = vec!["2".to_string(), "3".to_string()];
        repo.upsert_class(&class).await.unwrap();

        let fetched = repo.get_class("class-001").await.unwrap().unwrap();
        assert_eq!(fetched.title, "Updated Class");
        assert_eq!(fetched.periods.len(), 2);
    }

    #[tokio::test]
    async fn class_list() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_org(&sample_school()).await.unwrap();
        repo.upsert_academic_session(&sample_academic_session())
            .await
            .unwrap();
        repo.upsert_course(&sample_course()).await.unwrap();
        repo.upsert_class(&sample_class()).await.unwrap();

        let classes = repo.list_classes().await.unwrap();
        assert_eq!(classes.len(), 1);
    }

    #[tokio::test]
    async fn class_delete() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_org(&sample_school()).await.unwrap();
        repo.upsert_academic_session(&sample_academic_session())
            .await
            .unwrap();
        repo.upsert_course(&sample_course()).await.unwrap();
        repo.upsert_class(&sample_class()).await.unwrap();

        let deleted = repo.delete_class("class-001").await.unwrap();
        assert!(deleted);

        let fetched = repo.get_class("class-001").await.unwrap();
        assert!(fetched.is_none());
    }

    // -- Enrollment CRUD tests --

    #[tokio::test]
    async fn enrollment_crud_round_trip() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_org(&sample_school()).await.unwrap();
        repo.upsert_academic_session(&sample_academic_session())
            .await
            .unwrap();
        repo.upsert_course(&sample_course()).await.unwrap();
        repo.upsert_class(&sample_class()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let enrollment = sample_enrollment();
        repo.upsert_enrollment(&enrollment).await.unwrap();

        let fetched = repo.get_enrollment("enr-001").await.unwrap().unwrap();
        assert_eq!(fetched.sourced_id, enrollment.sourced_id);
        assert_eq!(fetched.user, enrollment.user);
        assert_eq!(fetched.class, enrollment.class);
        assert_eq!(fetched.role, enrollment.role);
        assert_eq!(fetched.begin_date, enrollment.begin_date);
        assert_eq!(fetched.end_date, enrollment.end_date);
    }

    #[tokio::test]
    async fn enrollment_upsert_updates() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_org(&sample_school()).await.unwrap();
        repo.upsert_academic_session(&sample_academic_session())
            .await
            .unwrap();
        repo.upsert_course(&sample_course()).await.unwrap();
        repo.upsert_class(&sample_class()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let mut enrollment = sample_enrollment();
        repo.upsert_enrollment(&enrollment).await.unwrap();

        enrollment.primary = Some(true);
        repo.upsert_enrollment(&enrollment).await.unwrap();

        let fetched = repo.get_enrollment("enr-001").await.unwrap().unwrap();
        assert_eq!(fetched.primary, Some(true));
    }

    #[tokio::test]
    async fn enrollment_list() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_org(&sample_school()).await.unwrap();
        repo.upsert_academic_session(&sample_academic_session())
            .await
            .unwrap();
        repo.upsert_course(&sample_course()).await.unwrap();
        repo.upsert_class(&sample_class()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();
        repo.upsert_enrollment(&sample_enrollment()).await.unwrap();

        let enrollments = repo.list_enrollments().await.unwrap();
        assert_eq!(enrollments.len(), 1);
    }

    #[tokio::test]
    async fn enrollment_delete() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_org(&sample_school()).await.unwrap();
        repo.upsert_academic_session(&sample_academic_session())
            .await
            .unwrap();
        repo.upsert_course(&sample_course()).await.unwrap();
        repo.upsert_class(&sample_class()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();
        repo.upsert_enrollment(&sample_enrollment()).await.unwrap();

        let deleted = repo.delete_enrollment("enr-001").await.unwrap();
        assert!(deleted);

        let fetched = repo.get_enrollment("enr-001").await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn list_enrollments_for_user_returns_matching() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_org(&sample_school()).await.unwrap();
        repo.upsert_academic_session(&sample_academic_session())
            .await
            .unwrap();
        repo.upsert_course(&sample_course()).await.unwrap();
        repo.upsert_class(&sample_class()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        // Two enrollments for user-001
        repo.upsert_enrollment(&Enrollment {
            sourced_id: "enr-u1a".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            user: "user-001".to_string(),
            class: "class-001".to_string(),
            school: "org-002".to_string(),
            role: EnrollmentRole::Student,
            primary: Some(true),
            begin_date: None,
            end_date: None,
        })
        .await
        .unwrap();
        repo.upsert_enrollment(&Enrollment {
            sourced_id: "enr-u1b".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            user: "user-001".to_string(),
            class: "class-001".to_string(),
            school: "org-002".to_string(),
            role: EnrollmentRole::Student,
            primary: None,
            begin_date: None,
            end_date: None,
        })
        .await
        .unwrap();

        // Create a second user and one enrollment for user-002
        let mut user2 = sample_user();
        user2.sourced_id = "user-002".to_string();
        user2.username = "jsmith".to_string();
        repo.upsert_user(&user2).await.unwrap();

        repo.upsert_enrollment(&Enrollment {
            sourced_id: "enr-u2".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            user: "user-002".to_string(),
            class: "class-001".to_string(),
            school: "org-002".to_string(),
            role: EnrollmentRole::Teacher,
            primary: Some(true),
            begin_date: None,
            end_date: None,
        })
        .await
        .unwrap();

        let result = repo.list_enrollments_for_user("user-001").await.unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|e| e.user == "user-001"));
    }

    #[tokio::test]
    async fn list_enrollments_for_class_returns_matching() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_org(&sample_school()).await.unwrap();
        repo.upsert_academic_session(&sample_academic_session())
            .await
            .unwrap();
        repo.upsert_course(&sample_course()).await.unwrap();
        repo.upsert_class(&sample_class()).await.unwrap();

        // Add a second class
        let mut class2 = sample_class();
        class2.sourced_id = "class-002".to_string();
        class2.title = "Algebra I - Period 2".to_string();
        repo.upsert_class(&class2).await.unwrap();

        repo.upsert_user(&sample_user()).await.unwrap();

        // Two enrollments in class-001
        repo.upsert_enrollment(&Enrollment {
            sourced_id: "enr-c1a".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            user: "user-001".to_string(),
            class: "class-001".to_string(),
            school: "org-002".to_string(),
            role: EnrollmentRole::Student,
            primary: None,
            begin_date: None,
            end_date: None,
        })
        .await
        .unwrap();
        repo.upsert_enrollment(&Enrollment {
            sourced_id: "enr-c1b".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            user: "user-001".to_string(),
            class: "class-001".to_string(),
            school: "org-002".to_string(),
            role: EnrollmentRole::Teacher,
            primary: Some(true),
            begin_date: None,
            end_date: None,
        })
        .await
        .unwrap();

        // One enrollment in class-002
        repo.upsert_enrollment(&Enrollment {
            sourced_id: "enr-c2".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            user: "user-001".to_string(),
            class: "class-002".to_string(),
            school: "org-002".to_string(),
            role: EnrollmentRole::Student,
            primary: None,
            begin_date: None,
            end_date: None,
        })
        .await
        .unwrap();

        let result = repo.list_enrollments_for_class("class-001").await.unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|e| e.class == "class-001"));
    }

    #[tokio::test]
    async fn list_enrollments_for_user_returns_empty() {
        let repo = setup().await;
        let result = repo
            .list_enrollments_for_user("nonexistent-user")
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn list_enrollments_for_class_returns_empty() {
        let repo = setup().await;
        let result = repo
            .list_enrollments_for_class("nonexistent-class")
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    // -- Demographics CRUD tests --

    #[tokio::test]
    async fn demographics_crud_round_trip() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let demo = sample_demographics();
        repo.upsert_demographics(&demo).await.unwrap();

        let fetched = repo.get_demographics("user-001").await.unwrap().unwrap();
        assert_eq!(fetched.sourced_id, demo.sourced_id);
        assert_eq!(fetched.birth_date, demo.birth_date);
        assert_eq!(fetched.sex, demo.sex);
        assert_eq!(fetched.white, demo.white);
        assert_eq!(fetched.country_of_birth_code, demo.country_of_birth_code);
    }

    #[tokio::test]
    async fn demographics_upsert_updates() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let mut demo = sample_demographics();
        repo.upsert_demographics(&demo).await.unwrap();

        demo.city_of_birth = Some("Chicago".to_string());
        repo.upsert_demographics(&demo).await.unwrap();

        let fetched = repo.get_demographics("user-001").await.unwrap().unwrap();
        assert_eq!(fetched.city_of_birth, Some("Chicago".to_string()));
    }

    #[tokio::test]
    async fn demographics_list() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();
        repo.upsert_demographics(&sample_demographics())
            .await
            .unwrap();

        let demos = repo.list_demographics().await.unwrap();
        assert_eq!(demos.len(), 1);
    }

    #[tokio::test]
    async fn demographics_delete() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();
        repo.upsert_demographics(&sample_demographics())
            .await
            .unwrap();

        let deleted = repo.delete_demographics("user-001").await.unwrap();
        assert!(deleted);

        let fetched = repo.get_demographics("user-001").await.unwrap();
        assert!(fetched.is_none());
    }

    // -- Sync CRUD tests --

    #[tokio::test]
    async fn sync_run_create_and_get() {
        let repo = setup().await;
        let run = repo.create_sync_run("clever").await.unwrap();
        assert_eq!(run.provider, "clever");
        assert_eq!(run.status, SyncStatus::Running);
        assert_eq!(run.users_synced, 0);

        let fetched = repo.get_sync_run(run.id).await.unwrap().unwrap();
        assert_eq!(fetched.provider, "clever");
    }

    #[tokio::test]
    async fn sync_run_update_status() {
        let repo = setup().await;
        let run = repo.create_sync_run("clever").await.unwrap();

        repo.update_sync_status(run.id, SyncStatus::Completed, None)
            .await
            .unwrap();

        let fetched = repo.get_sync_run(run.id).await.unwrap().unwrap();
        assert_eq!(fetched.status, SyncStatus::Completed);
        assert!(fetched.completed_at.is_some());
        assert!(fetched.error_message.is_none());
    }

    #[tokio::test]
    async fn sync_run_update_status_with_error() {
        let repo = setup().await;
        let run = repo.create_sync_run("classlink").await.unwrap();

        repo.update_sync_status(run.id, SyncStatus::Failed, Some("Connection timeout"))
            .await
            .unwrap();

        let fetched = repo.get_sync_run(run.id).await.unwrap().unwrap();
        assert_eq!(fetched.status, SyncStatus::Failed);
        assert_eq!(
            fetched.error_message,
            Some("Connection timeout".to_string())
        );
    }

    #[tokio::test]
    async fn sync_run_update_counts() {
        let repo = setup().await;
        let run = repo.create_sync_run("clever").await.unwrap();

        repo.update_sync_counts(run.id, 100, 5, 20, 30, 400)
            .await
            .unwrap();

        let fetched = repo.get_sync_run(run.id).await.unwrap().unwrap();
        assert_eq!(fetched.users_synced, 100);
        assert_eq!(fetched.orgs_synced, 5);
        assert_eq!(fetched.courses_synced, 20);
        assert_eq!(fetched.classes_synced, 30);
        assert_eq!(fetched.enrollments_synced, 400);
    }

    #[tokio::test]
    async fn sync_run_get_latest() {
        let repo = setup().await;
        let _run1 = repo.create_sync_run("clever").await.unwrap();
        let run2 = repo.create_sync_run("clever").await.unwrap();
        let _run3 = repo.create_sync_run("classlink").await.unwrap();

        let latest = repo.get_latest_sync_run("clever").await.unwrap().unwrap();
        assert_eq!(latest.id, run2.id);

        let latest_cl = repo
            .get_latest_sync_run("classlink")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest_cl.id, _run3.id);

        let none = repo.get_latest_sync_run("nonexistent").await.unwrap();
        assert!(none.is_none());
    }

    // -- IDP Session CRUD tests --

    #[tokio::test]
    async fn idp_session_create_and_get() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let session = IdpSession {
            id: "sess-001".to_string(),
            user_sourced_id: "user-001".to_string(),
            auth_method: AuthMethod::Password,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(8),
            saml_request_id: None,
            relay_state: None,
        };
        repo.create_session(&session).await.unwrap();

        let fetched = repo.get_session("sess-001").await.unwrap().unwrap();
        assert_eq!(fetched.id, "sess-001");
        assert_eq!(fetched.user_sourced_id, "user-001");
        assert_eq!(fetched.auth_method, AuthMethod::Password);
    }

    #[tokio::test]
    async fn idp_session_with_saml_fields() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let session = IdpSession {
            id: "sess-saml".to_string(),
            user_sourced_id: "user-001".to_string(),
            auth_method: AuthMethod::Saml,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(8),
            saml_request_id: Some("req-123".to_string()),
            relay_state: Some("https://google.com".to_string()),
        };
        repo.create_session(&session).await.unwrap();

        let fetched = repo.get_session("sess-saml").await.unwrap().unwrap();
        assert_eq!(fetched.saml_request_id, Some("req-123".to_string()));
        assert_eq!(fetched.relay_state, Some("https://google.com".to_string()));
    }

    #[tokio::test]
    async fn idp_session_delete() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let session = IdpSession {
            id: "sess-del".to_string(),
            user_sourced_id: "user-001".to_string(),
            auth_method: AuthMethod::Password,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(8),
            saml_request_id: None,
            relay_state: None,
        };
        repo.create_session(&session).await.unwrap();

        let deleted = repo.delete_session("sess-del").await.unwrap();
        assert!(deleted);

        let fetched = repo.get_session("sess-del").await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn idp_session_list_for_user() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        for i in 0..3 {
            let session = IdpSession {
                id: format!("sess-{i}"),
                user_sourced_id: "user-001".to_string(),
                auth_method: AuthMethod::Password,
                created_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::hours(8),
                saml_request_id: None,
                relay_state: None,
            };
            repo.create_session(&session).await.unwrap();
        }

        let sessions = repo.list_sessions_for_user("user-001").await.unwrap();
        assert_eq!(sessions.len(), 3);
    }

    #[tokio::test]
    async fn idp_session_get_nonexistent() {
        let repo = setup().await;
        let fetched = repo.get_session("nonexistent").await.unwrap();
        assert!(fetched.is_none());
    }

    // -- QR Badge CRUD tests --

    #[tokio::test]
    async fn qr_badge_create_and_get() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let badge = QrBadge {
            id: 0,
            badge_token: "token-abc-123".to_string(),
            user_sourced_id: "user-001".to_string(),
            is_active: true,
            created_at: Utc::now(),
            revoked_at: None,
        };
        let id = repo.create_badge(&badge).await.unwrap();
        assert!(id > 0);

        let fetched = repo
            .get_badge_by_token("token-abc-123")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.badge_token, "token-abc-123");
        assert_eq!(fetched.user_sourced_id, "user-001");
        assert!(fetched.is_active);
        assert!(fetched.revoked_at.is_none());
    }

    #[tokio::test]
    async fn qr_badge_revoke() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let badge = QrBadge {
            id: 0,
            badge_token: "token-revoke".to_string(),
            user_sourced_id: "user-001".to_string(),
            is_active: true,
            created_at: Utc::now(),
            revoked_at: None,
        };
        let id = repo.create_badge(&badge).await.unwrap();

        let revoked = repo.revoke_badge(id).await.unwrap();
        assert!(revoked);

        let fetched = repo
            .get_badge_by_token("token-revoke")
            .await
            .unwrap()
            .unwrap();
        assert!(!fetched.is_active);
        assert!(fetched.revoked_at.is_some());

        // Revoking again should return false
        let revoked_again = repo.revoke_badge(id).await.unwrap();
        assert!(!revoked_again);
    }

    #[tokio::test]
    async fn qr_badge_list_for_user() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        for i in 0..2 {
            let badge = QrBadge {
                id: 0,
                badge_token: format!("token-list-{i}"),
                user_sourced_id: "user-001".to_string(),
                is_active: true,
                created_at: Utc::now(),
                revoked_at: None,
            };
            repo.create_badge(&badge).await.unwrap();
        }

        let badges = repo.list_badges_for_user("user-001").await.unwrap();
        assert_eq!(badges.len(), 2);
    }

    #[tokio::test]
    async fn qr_badge_get_nonexistent() {
        let repo = setup().await;
        let fetched = repo.get_badge_by_token("nonexistent").await.unwrap();
        assert!(fetched.is_none());
    }

    // -- Picture Password CRUD tests --

    #[tokio::test]
    async fn picture_password_upsert_and_get() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let pp = PicturePassword {
            user_sourced_id: "user-001".to_string(),
            image_sequence: vec!["cat".to_string(), "dog".to_string(), "fish".to_string()],
        };
        repo.upsert_picture_password(&pp).await.unwrap();

        let fetched = repo
            .get_picture_password("user-001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.user_sourced_id, "user-001");
        assert_eq!(fetched.image_sequence, vec!["cat", "dog", "fish"]);
    }

    #[tokio::test]
    async fn picture_password_upsert_updates() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let pp = PicturePassword {
            user_sourced_id: "user-001".to_string(),
            image_sequence: vec!["cat".to_string(), "dog".to_string()],
        };
        repo.upsert_picture_password(&pp).await.unwrap();

        let pp2 = PicturePassword {
            user_sourced_id: "user-001".to_string(),
            image_sequence: vec!["bird".to_string(), "tree".to_string(), "sun".to_string()],
        };
        repo.upsert_picture_password(&pp2).await.unwrap();

        let fetched = repo
            .get_picture_password("user-001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.image_sequence, vec!["bird", "tree", "sun"]);
    }

    #[tokio::test]
    async fn picture_password_delete() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let pp = PicturePassword {
            user_sourced_id: "user-001".to_string(),
            image_sequence: vec!["cat".to_string()],
        };
        repo.upsert_picture_password(&pp).await.unwrap();

        let deleted = repo.delete_picture_password("user-001").await.unwrap();
        assert!(deleted);

        let fetched = repo.get_picture_password("user-001").await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn picture_password_get_nonexistent() {
        let repo = setup().await;
        let fetched = repo.get_picture_password("nonexistent").await.unwrap();
        assert!(fetched.is_none());
    }

    // -- Auth Log tests --

    #[tokio::test]
    async fn auth_log_create_and_list() {
        let repo = setup().await;

        let entry = AuthLogEntry {
            id: 0,
            user_sourced_id: Some("user-001".to_string()),
            username: Some("jdoe".to_string()),
            auth_method: AuthMethod::Password,
            success: true,
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Chrome/120".to_string()),
            created_at: Utc::now(),
        };
        let id = repo.log_auth_attempt(&entry).await.unwrap();
        assert!(id > 0);

        let logs = repo.list_auth_log(10).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].auth_method, AuthMethod::Password);
        assert!(logs[0].success);
    }

    #[tokio::test]
    async fn auth_log_list_for_user() {
        let repo = setup().await;

        for success in [true, false] {
            let entry = AuthLogEntry {
                id: 0,
                user_sourced_id: Some("user-001".to_string()),
                username: Some("jdoe".to_string()),
                auth_method: AuthMethod::QrBadge,
                success,
                ip_address: None,
                user_agent: None,
                created_at: Utc::now(),
            };
            repo.log_auth_attempt(&entry).await.unwrap();
        }

        // Add one for a different user
        let entry = AuthLogEntry {
            id: 0,
            user_sourced_id: Some("user-002".to_string()),
            username: Some("asmith".to_string()),
            auth_method: AuthMethod::Password,
            success: true,
            ip_address: None,
            user_agent: None,
            created_at: Utc::now(),
        };
        repo.log_auth_attempt(&entry).await.unwrap();

        let logs = repo.list_auth_log_for_user("user-001", 10).await.unwrap();
        assert_eq!(logs.len(), 2);

        let all_logs = repo.list_auth_log(10).await.unwrap();
        assert_eq!(all_logs.len(), 3);
    }

    #[tokio::test]
    async fn auth_log_limit() {
        let repo = setup().await;

        for i in 0..5 {
            let entry = AuthLogEntry {
                id: 0,
                user_sourced_id: Some(format!("user-{i}")),
                username: None,
                auth_method: AuthMethod::Password,
                success: true,
                ip_address: None,
                user_agent: None,
                created_at: Utc::now(),
            };
            repo.log_auth_attempt(&entry).await.unwrap();
        }

        let logs = repo.list_auth_log(3).await.unwrap();
        assert_eq!(logs.len(), 3);
    }

    // -- Google Sync State CRUD tests --

    #[tokio::test]
    async fn google_sync_state_upsert_and_get() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let state = GoogleSyncUserState {
            user_sourced_id: "user-001".to_string(),
            google_id: Some("112233".to_string()),
            google_email: Some("jdoe@school.edu".to_string()),
            google_ou: Some("/Students/HS/09".to_string()),
            field_hash: "abc123".to_string(),
            sync_status: GoogleSyncStatus::Synced,
            last_synced_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        repo.upsert_sync_state(&state).await.unwrap();

        let fetched = repo.get_sync_state("user-001").await.unwrap().unwrap();
        assert_eq!(fetched.user_sourced_id, "user-001");
        assert_eq!(fetched.google_id, Some("112233".to_string()));
        assert_eq!(fetched.field_hash, "abc123");
        assert_eq!(fetched.sync_status, GoogleSyncStatus::Synced);
    }

    #[tokio::test]
    async fn google_sync_state_upsert_updates() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let state = GoogleSyncUserState {
            user_sourced_id: "user-001".to_string(),
            google_id: None,
            google_email: None,
            google_ou: None,
            field_hash: "hash1".to_string(),
            sync_status: GoogleSyncStatus::Pending,
            last_synced_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        repo.upsert_sync_state(&state).await.unwrap();

        let updated = GoogleSyncUserState {
            field_hash: "hash2".to_string(),
            sync_status: GoogleSyncStatus::Synced,
            google_email: Some("jdoe@school.edu".to_string()),
            ..state
        };
        repo.upsert_sync_state(&updated).await.unwrap();

        let fetched = repo.get_sync_state("user-001").await.unwrap().unwrap();
        assert_eq!(fetched.field_hash, "hash2");
        assert_eq!(fetched.sync_status, GoogleSyncStatus::Synced);
        assert_eq!(fetched.google_email, Some("jdoe@school.edu".to_string()));
    }

    #[tokio::test]
    async fn google_sync_state_list() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();
        repo.upsert_user(&sample_teacher()).await.unwrap();

        for uid in ["user-001", "user-002"] {
            let state = GoogleSyncUserState {
                user_sourced_id: uid.to_string(),
                google_id: None,
                google_email: None,
                google_ou: None,
                field_hash: "hash".to_string(),
                sync_status: GoogleSyncStatus::Pending,
                last_synced_at: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            repo.upsert_sync_state(&state).await.unwrap();
        }

        let states = repo.list_sync_states().await.unwrap();
        assert_eq!(states.len(), 2);
    }

    #[tokio::test]
    async fn google_sync_state_delete() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let state = GoogleSyncUserState {
            user_sourced_id: "user-001".to_string(),
            google_id: None,
            google_email: None,
            google_ou: None,
            field_hash: "hash".to_string(),
            sync_status: GoogleSyncStatus::Pending,
            last_synced_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        repo.upsert_sync_state(&state).await.unwrap();

        let deleted = repo.delete_sync_state("user-001").await.unwrap();
        assert!(deleted);

        let fetched = repo.get_sync_state("user-001").await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn google_sync_state_get_nonexistent() {
        let repo = setup().await;
        let fetched = repo.get_sync_state("nonexistent").await.unwrap();
        assert!(fetched.is_none());
    }

    // -- Google Sync Run CRUD tests --

    #[tokio::test]
    async fn google_sync_run_create_and_get() {
        let repo = setup().await;
        let run = repo.create_google_sync_run(false).await.unwrap();
        assert_eq!(run.status, GoogleSyncRunStatus::Running);
        assert!(!run.dry_run);
        assert_eq!(run.users_created, 0);

        let fetched = repo.get_google_sync_run(run.id).await.unwrap().unwrap();
        assert_eq!(fetched.id, run.id);
    }

    #[tokio::test]
    async fn google_sync_run_create_dry_run() {
        let repo = setup().await;
        let run = repo.create_google_sync_run(true).await.unwrap();
        assert!(run.dry_run);
    }

    #[tokio::test]
    async fn google_sync_run_update() {
        let repo = setup().await;
        let run = repo.create_google_sync_run(false).await.unwrap();

        repo.update_google_sync_run(run.id, GoogleSyncRunStatus::Completed, 50, 10, 3, 5, None)
            .await
            .unwrap();

        let fetched = repo.get_google_sync_run(run.id).await.unwrap().unwrap();
        assert_eq!(fetched.status, GoogleSyncRunStatus::Completed);
        assert_eq!(fetched.users_created, 50);
        assert_eq!(fetched.users_updated, 10);
        assert_eq!(fetched.users_suspended, 3);
        assert_eq!(fetched.ous_created, 5);
        assert!(fetched.completed_at.is_some());
        assert!(fetched.error_message.is_none());
    }

    #[tokio::test]
    async fn google_sync_run_update_with_error() {
        let repo = setup().await;
        let run = repo.create_google_sync_run(false).await.unwrap();

        repo.update_google_sync_run(
            run.id,
            GoogleSyncRunStatus::Failed,
            0,
            0,
            0,
            0,
            Some("API rate limit exceeded"),
        )
        .await
        .unwrap();

        let fetched = repo.get_google_sync_run(run.id).await.unwrap().unwrap();
        assert_eq!(fetched.status, GoogleSyncRunStatus::Failed);
        assert_eq!(
            fetched.error_message,
            Some("API rate limit exceeded".to_string())
        );
    }

    #[tokio::test]
    async fn google_sync_run_get_latest() {
        let repo = setup().await;
        let _run1 = repo.create_google_sync_run(false).await.unwrap();
        let run2 = repo.create_google_sync_run(false).await.unwrap();

        let latest = repo.get_latest_google_sync_run().await.unwrap().unwrap();
        assert_eq!(latest.id, run2.id);
    }

    #[tokio::test]
    async fn google_sync_run_list() {
        let repo = setup().await;
        for _ in 0..5 {
            repo.create_google_sync_run(false).await.unwrap();
        }

        let runs = repo.list_google_sync_runs(3).await.unwrap();
        assert_eq!(runs.len(), 3);

        let all_runs = repo.list_google_sync_runs(10).await.unwrap();
        assert_eq!(all_runs.len(), 5);
    }

    #[tokio::test]
    async fn google_sync_run_get_nonexistent() {
        let repo = setup().await;
        let fetched = repo.get_google_sync_run(99999).await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn google_sync_run_get_latest_empty() {
        let repo = setup().await;
        let latest = repo.get_latest_google_sync_run().await.unwrap();
        assert!(latest.is_none());
    }

    // -- PasswordRepository tests --

    #[tokio::test]
    async fn password_hash_set_and_get() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        let user = sample_user();
        repo.upsert_user(&user).await.unwrap();

        // Initially no password hash
        let hash = repo.get_password_hash(&user.sourced_id).await.unwrap();
        assert!(hash.is_none());

        // Set password hash
        repo.set_password_hash(&user.sourced_id, "$argon2id$v=19$m=65536,t=2,p=1$salt$hash")
            .await
            .unwrap();

        // Retrieve it
        let hash = repo.get_password_hash(&user.sourced_id).await.unwrap();
        assert_eq!(
            hash.as_deref(),
            Some("$argon2id$v=19$m=65536,t=2,p=1$salt$hash")
        );
    }

    #[tokio::test]
    async fn password_hash_nonexistent_user() {
        let repo = setup().await;
        let hash = repo.get_password_hash("nonexistent").await.unwrap();
        assert!(hash.is_none());
    }

    // -- PasswordResetTokenRepository tests --

    #[tokio::test]
    async fn reset_token_consume_returns_user_then_consumed() {
        use crate::db::repository::PasswordResetTokenRepository;
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        let user = sample_user();
        repo.upsert_user(&user).await.unwrap();

        let raw = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let hash = sha256_hex(raw);
        let expires = Utc::now() + chrono::Duration::hours(24);
        repo.create_reset_token(&user.sourced_id, &hash, expires)
            .await
            .unwrap();

        // First consume succeeds and returns the user id.
        let got = repo.consume_reset_token(raw).await.unwrap();
        assert_eq!(got.as_deref(), Some(user.sourced_id.as_str()));

        // Second consume returns None (single-use enforcement).
        let again = repo.consume_reset_token(raw).await.unwrap();
        assert!(again.is_none());
    }

    #[tokio::test]
    async fn reset_token_consume_unknown_returns_none() {
        use crate::db::repository::PasswordResetTokenRepository;
        let repo = setup().await;
        let got = repo.consume_reset_token("not-a-real-token").await.unwrap();
        assert!(got.is_none());
    }

    // -- MagicLoginRepository tests --

    #[tokio::test]
    async fn magic_login_token_single_use_and_expiry() {
        use crate::db::repository::MagicLoginRepository;
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        let user = sample_user();
        repo.upsert_user(&user).await.unwrap();

        let raw = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";
        let hash = sha256_hex(raw);
        repo.create_magic_login_token(
            &user.sourced_id,
            &hash,
            Utc::now() + chrono::Duration::minutes(15),
        )
        .await
        .unwrap();

        // First redeem returns the user; second is rejected (single-use).
        assert_eq!(
            repo.consume_magic_login_token(raw)
                .await
                .unwrap()
                .as_deref(),
            Some(user.sourced_id.as_str())
        );
        assert!(repo.consume_magic_login_token(raw).await.unwrap().is_none());

        // Unknown + expired tokens are rejected.
        assert!(repo
            .consume_magic_login_token("nope")
            .await
            .unwrap()
            .is_none());
        let expired_raw = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";
        repo.create_magic_login_token(
            &user.sourced_id,
            &sha256_hex(expired_raw),
            Utc::now() - chrono::Duration::minutes(1),
        )
        .await
        .unwrap();
        assert!(repo
            .consume_magic_login_token(expired_raw)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn reset_token_expired_not_consumable() {
        use crate::db::repository::PasswordResetTokenRepository;
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        let user = sample_user();
        repo.upsert_user(&user).await.unwrap();

        let raw = "expiredtoken-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hash = sha256_hex(raw);
        let expired = Utc::now() - chrono::Duration::hours(1);
        repo.create_reset_token(&user.sourced_id, &hash, expired)
            .await
            .unwrap();

        let got = repo.consume_reset_token(raw).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn reset_token_delete_expired_removes_only_expired() {
        use crate::db::repository::PasswordResetTokenRepository;
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        let user = sample_user();
        repo.upsert_user(&user).await.unwrap();

        let valid_hash = sha256_hex("valid-token-x");
        let expired_hash = sha256_hex("expired-token-x");
        repo.create_reset_token(
            &user.sourced_id,
            &valid_hash,
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
        repo.create_reset_token(
            &user.sourced_id,
            &expired_hash,
            Utc::now() - chrono::Duration::hours(1),
        )
        .await
        .unwrap();

        let removed = repo.delete_expired_reset_tokens().await.unwrap();
        assert_eq!(removed, 1);

        // Valid token still consumable.
        let got = repo.consume_reset_token("valid-token-x").await.unwrap();
        assert_eq!(got.as_deref(), Some(user.sourced_id.as_str()));
    }

    // -- get_user_by_username tests --

    #[tokio::test]
    async fn get_user_by_username_found() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        let user = sample_user();
        repo.upsert_user(&user).await.unwrap();

        let found = repo.get_user_by_username("jdoe").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().sourced_id, "user-001");
    }

    #[tokio::test]
    async fn get_user_by_username_not_found() {
        let repo = setup().await;
        let found = repo.get_user_by_username("nonexistent").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn get_user_by_username_case_insensitive() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        let mut user = sample_user();
        user.username = "JDoe".to_string();
        repo.upsert_user(&user).await.unwrap();

        // Should find with exact case
        let found = repo.get_user_by_username("JDoe").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().sourced_id, "user-001");

        // Should find with all lowercase
        let found = repo.get_user_by_username("jdoe").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().sourced_id, "user-001");

        // Should find with all uppercase
        let found = repo.get_user_by_username("JDOE").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().sourced_id, "user-001");

        // Should find with mixed case
        let found = repo.get_user_by_username("jDoE").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().sourced_id, "user-001");
    }

    // -- Admin Session tests --

    #[tokio::test]
    async fn create_and_get_admin_session() {
        use crate::models::audit::AdminSession;
        let repo = setup().await;
        let session = AdminSession {
            token: "test-session-token".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            ip_address: Some("127.0.0.1".to_string()),
            actor_id: None,
            actor_label: None,
            actor_role: None,
        };
        repo.create_admin_session(&session).await.unwrap();

        let found = repo.get_admin_session("test-session-token").await.unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.token, "test-session-token");
        assert_eq!(found.ip_address.as_deref(), Some("127.0.0.1"));
    }

    #[tokio::test]
    async fn get_admin_session_not_found() {
        let repo = setup().await;
        let found = repo.get_admin_session("nonexistent").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn delete_admin_session() {
        use crate::models::audit::AdminSession;
        let repo = setup().await;
        let session = AdminSession {
            token: "del-token".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            ip_address: None,
            actor_id: None,
            actor_label: None,
            actor_role: None,
        };
        repo.create_admin_session(&session).await.unwrap();

        let deleted = repo.delete_admin_session("del-token").await.unwrap();
        assert!(deleted);

        let found = repo.get_admin_session("del-token").await.unwrap();
        assert!(found.is_none());

        // Delete again should return false
        let deleted = repo.delete_admin_session("del-token").await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn delete_expired_admin_sessions() {
        use crate::models::audit::AdminSession;
        let repo = setup().await;

        // Create an already-expired session
        let expired = AdminSession {
            token: "expired-token".to_string(),
            created_at: Utc::now() - chrono::Duration::hours(48),
            expires_at: Utc::now() - chrono::Duration::hours(24),
            ip_address: None,
            actor_id: None,
            actor_label: None,
            actor_role: None,
        };
        repo.create_admin_session(&expired).await.unwrap();

        // Create a valid session
        let valid = AdminSession {
            token: "valid-token".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            ip_address: None,
            actor_id: None,
            actor_label: None,
            actor_role: None,
        };
        repo.create_admin_session(&valid).await.unwrap();

        let count = repo.delete_expired_admin_sessions().await.unwrap();
        assert_eq!(count, 1);

        // Valid session should still exist
        assert!(repo
            .get_admin_session("valid-token")
            .await
            .unwrap()
            .is_some());
        // Expired should be gone
        assert!(repo
            .get_admin_session("expired-token")
            .await
            .unwrap()
            .is_none());
    }

    // -- Admin Audit tests --

    #[tokio::test]
    async fn log_and_list_admin_audit() {
        let repo = setup().await;

        let id1 = repo
            .log_admin_action("login", Some("Admin logged in"), Some("192.168.1.1"))
            .await
            .unwrap();
        assert!(id1 > 0);

        let id2 = repo
            .log_admin_action("logout", None, Some("192.168.1.1"))
            .await
            .unwrap();
        assert!(id2 > id1);

        let entries = repo.list_admin_audit_log(10).await.unwrap();
        assert_eq!(entries.len(), 2);
        // Most recent first
        assert_eq!(entries[0].action, "logout");
        assert_eq!(entries[1].action, "login");
        assert_eq!(entries[1].details.as_deref(), Some("Admin logged in"));
    }

    #[tokio::test]
    async fn list_admin_audit_respects_limit() {
        let repo = setup().await;

        for i in 0..5 {
            repo.log_admin_action(&format!("action_{}", i), None, None)
                .await
                .unwrap();
        }

        let entries = repo.list_admin_audit_log(3).await.unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn list_admin_audit_empty() {
        let repo = setup().await;
        let entries = repo.list_admin_audit_log(10).await.unwrap();
        assert!(entries.is_empty());
    }

    // -- Webhook Endpoint Tests --

    fn sample_webhook_endpoint() -> WebhookEndpoint {
        WebhookEndpoint {
            id: "wh-001".to_string(),
            name: "Test Webhook".to_string(),
            url: "https://example.com/webhook".to_string(),
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

    #[tokio::test]
    async fn webhook_endpoint_upsert_and_get() {
        let repo = setup().await;
        let endpoint = sample_webhook_endpoint();
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        let fetched = repo.get_webhook_endpoint("wh-001").await.unwrap().unwrap();
        assert_eq!(fetched.id, "wh-001");
        assert_eq!(fetched.name, "Test Webhook");
        assert_eq!(fetched.url, "https://example.com/webhook");
        assert!(fetched.enabled);
        assert_eq!(fetched.mode, WebhookMode::Batched);
        assert_eq!(fetched.security_mode, WebhookSecurityMode::SignOnly);
        assert_eq!(fetched.source, WebhookSource::Database);
    }

    #[tokio::test]
    async fn webhook_endpoint_get_nonexistent() {
        let repo = setup().await;
        let result = repo.get_webhook_endpoint("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn webhook_endpoint_upsert_updates() {
        let repo = setup().await;
        let mut endpoint = sample_webhook_endpoint();
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        endpoint.name = "Updated Name".to_string();
        endpoint.enabled = false;
        endpoint.mode = WebhookMode::PerEntity;
        endpoint.security_mode = WebhookSecurityMode::Encrypted;
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        let fetched = repo.get_webhook_endpoint("wh-001").await.unwrap().unwrap();
        assert_eq!(fetched.name, "Updated Name");
        assert!(!fetched.enabled);
        assert_eq!(fetched.mode, WebhookMode::PerEntity);
        assert_eq!(fetched.security_mode, WebhookSecurityMode::Encrypted);
    }

    #[tokio::test]
    async fn webhook_endpoint_list() {
        let repo = setup().await;
        let mut ep1 = sample_webhook_endpoint();
        ep1.id = "wh-001".to_string();
        ep1.source = WebhookSource::Database;
        repo.upsert_webhook_endpoint(&ep1).await.unwrap();

        let mut ep2 = sample_webhook_endpoint();
        ep2.id = "wh-002".to_string();
        ep2.source = WebhookSource::Toml;
        repo.upsert_webhook_endpoint(&ep2).await.unwrap();

        let all = repo.list_webhook_endpoints().await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn webhook_endpoint_list_by_source() {
        let repo = setup().await;
        let mut ep1 = sample_webhook_endpoint();
        ep1.id = "wh-001".to_string();
        ep1.source = WebhookSource::Database;
        repo.upsert_webhook_endpoint(&ep1).await.unwrap();

        let mut ep2 = sample_webhook_endpoint();
        ep2.id = "wh-002".to_string();
        ep2.source = WebhookSource::Toml;
        repo.upsert_webhook_endpoint(&ep2).await.unwrap();

        let db_only = repo
            .list_webhook_endpoints_by_source("database")
            .await
            .unwrap();
        assert_eq!(db_only.len(), 1);
        assert_eq!(db_only[0].id, "wh-001");

        let toml_only = repo.list_webhook_endpoints_by_source("toml").await.unwrap();
        assert_eq!(toml_only.len(), 1);
        assert_eq!(toml_only[0].id, "wh-002");
    }

    #[tokio::test]
    async fn webhook_endpoint_delete() {
        let repo = setup().await;
        repo.upsert_webhook_endpoint(&sample_webhook_endpoint())
            .await
            .unwrap();

        let deleted = repo.delete_webhook_endpoint("wh-001").await.unwrap();
        assert!(deleted);

        let result = repo.get_webhook_endpoint("wh-001").await.unwrap();
        assert!(result.is_none());

        let not_deleted = repo.delete_webhook_endpoint("wh-001").await.unwrap();
        assert!(!not_deleted);
    }

    #[tokio::test]
    async fn webhook_endpoint_scoping_roundtrip() {
        let repo = setup().await;
        let mut endpoint = sample_webhook_endpoint();
        endpoint.scoping = WebhookScoping {
            entity_types: vec![
                crate::webhooks::models::EntityType::User,
                crate::webhooks::models::EntityType::Enrollment,
            ],
            org_sourced_ids: vec!["org-1".to_string()],
            roles: vec!["student".to_string()],
            excluded_fields: vec!["demographics.birthDate".to_string()],
        };
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        let fetched = repo.get_webhook_endpoint("wh-001").await.unwrap().unwrap();
        assert_eq!(fetched.scoping.entity_types.len(), 2);
        assert_eq!(fetched.scoping.org_sourced_ids, vec!["org-1"]);
        assert_eq!(fetched.scoping.roles, vec!["student"]);
        assert_eq!(
            fetched.scoping.excluded_fields,
            vec!["demographics.birthDate"]
        );
    }

    #[tokio::test]
    async fn webhook_endpoint_with_tenant_id() {
        let repo = setup().await;
        let mut endpoint = sample_webhook_endpoint();
        endpoint.tenant_id = Some("tenant-abc".to_string());
        repo.upsert_webhook_endpoint(&endpoint).await.unwrap();

        let fetched = repo.get_webhook_endpoint("wh-001").await.unwrap().unwrap();
        assert_eq!(fetched.tenant_id.as_deref(), Some("tenant-abc"));
    }

    // -- Webhook Delivery Tests --

    fn sample_webhook_delivery(webhook_endpoint_id: &str) -> WebhookDelivery {
        WebhookDelivery {
            id: 0, // auto-increment
            webhook_endpoint_id: webhook_endpoint_id.to_string(),
            event_id: "evt-001".to_string(),
            sync_run_id: 1,
            status: DeliveryStatus::Pending,
            http_status: None,
            response_body: None,
            attempt_count: 0,
            next_retry_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn webhook_delivery_create_and_list() {
        let repo = setup().await;
        repo.upsert_webhook_endpoint(&sample_webhook_endpoint())
            .await
            .unwrap();

        let delivery = sample_webhook_delivery("wh-001");
        let id = repo.create_webhook_delivery(&delivery).await.unwrap();
        assert!(id > 0);

        let deliveries = repo.list_deliveries_by_webhook("wh-001", 10).await.unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].webhook_endpoint_id, "wh-001");
        assert_eq!(deliveries[0].event_id, "evt-001");
        assert_eq!(deliveries[0].status, DeliveryStatus::Pending);
    }

    #[tokio::test]
    async fn webhook_delivery_update_status() {
        let repo = setup().await;
        repo.upsert_webhook_endpoint(&sample_webhook_endpoint())
            .await
            .unwrap();

        let delivery = sample_webhook_delivery("wh-001");
        let id = repo.create_webhook_delivery(&delivery).await.unwrap();

        repo.update_delivery_status(id, DeliveryStatus::Delivered, Some(200), Some("OK"))
            .await
            .unwrap();

        let deliveries = repo.list_deliveries_by_webhook("wh-001", 10).await.unwrap();
        assert_eq!(deliveries[0].status, DeliveryStatus::Delivered);
        assert_eq!(deliveries[0].http_status, Some(200));
        assert_eq!(deliveries[0].response_body.as_deref(), Some("OK"));
        assert_eq!(deliveries[0].attempt_count, 1);
    }

    #[tokio::test]
    async fn webhook_delivery_list_pending_retries() {
        let repo = setup().await;
        repo.upsert_webhook_endpoint(&sample_webhook_endpoint())
            .await
            .unwrap();

        // Create a pending delivery
        let d1 = sample_webhook_delivery("wh-001");
        repo.create_webhook_delivery(&d1).await.unwrap();

        // Create a delivered delivery
        let d2 = sample_webhook_delivery("wh-001");
        let id2 = repo.create_webhook_delivery(&d2).await.unwrap();
        repo.update_delivery_status(id2, DeliveryStatus::Delivered, Some(200), None)
            .await
            .unwrap();

        let pending = repo.list_pending_retries(10).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].status, DeliveryStatus::Pending);
    }

    #[tokio::test]
    async fn webhook_delivery_list_by_sync_run() {
        let repo = setup().await;
        repo.upsert_webhook_endpoint(&sample_webhook_endpoint())
            .await
            .unwrap();

        let mut d1 = sample_webhook_delivery("wh-001");
        d1.sync_run_id = 10;
        repo.create_webhook_delivery(&d1).await.unwrap();

        let mut d2 = sample_webhook_delivery("wh-001");
        d2.sync_run_id = 20;
        d2.event_id = "evt-002".to_string();
        repo.create_webhook_delivery(&d2).await.unwrap();

        let run10 = repo.list_deliveries_by_sync_run(10).await.unwrap();
        assert_eq!(run10.len(), 1);
        assert_eq!(run10[0].sync_run_id, 10);

        let run20 = repo.list_deliveries_by_sync_run(20).await.unwrap();
        assert_eq!(run20.len(), 1);
        assert_eq!(run20[0].sync_run_id, 20);
    }

    #[tokio::test]
    async fn webhook_delivery_multiple_retries() {
        let repo = setup().await;
        repo.upsert_webhook_endpoint(&sample_webhook_endpoint())
            .await
            .unwrap();

        let delivery = sample_webhook_delivery("wh-001");
        let id = repo.create_webhook_delivery(&delivery).await.unwrap();

        // First retry fails
        repo.update_delivery_status(
            id,
            DeliveryStatus::Retrying,
            Some(500),
            Some("Server Error"),
        )
        .await
        .unwrap();

        // Second retry fails
        repo.update_delivery_status(id, DeliveryStatus::Retrying, Some(502), Some("Bad Gateway"))
            .await
            .unwrap();

        // Third retry succeeds
        repo.update_delivery_status(id, DeliveryStatus::Delivered, Some(200), Some("OK"))
            .await
            .unwrap();

        let deliveries = repo.list_deliveries_by_webhook("wh-001", 10).await.unwrap();
        assert_eq!(deliveries[0].attempt_count, 3);
        assert_eq!(deliveries[0].status, DeliveryStatus::Delivered);
    }

    // -- find_user_by_external_id tests --

    #[tokio::test]
    async fn find_user_by_external_id_returns_matching_user() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        // Set external IDs for the user
        let mut ids = serde_json::Map::new();
        ids.insert(
            "clever".to_string(),
            serde_json::Value::String("clever-abc123".to_string()),
        );
        repo.set_external_ids("user-001", &ids).await.unwrap();

        let found = repo
            .find_user_by_external_id("clever", "clever-abc123")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().sourced_id, "user-001");
    }

    #[tokio::test]
    async fn find_user_by_external_id_returns_none_for_wrong_provider() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let mut ids = serde_json::Map::new();
        ids.insert(
            "clever".to_string(),
            serde_json::Value::String("clever-abc123".to_string()),
        );
        repo.set_external_ids("user-001", &ids).await.unwrap();

        let found = repo
            .find_user_by_external_id("classlink", "clever-abc123")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn find_user_by_external_id_returns_none_for_wrong_id() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let mut ids = serde_json::Map::new();
        ids.insert(
            "clever".to_string(),
            serde_json::Value::String("clever-abc123".to_string()),
        );
        repo.set_external_ids("user-001", &ids).await.unwrap();

        let found = repo
            .find_user_by_external_id("clever", "clever-wrong")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn find_user_by_external_id_returns_none_when_no_external_ids() {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();

        let found = repo
            .find_user_by_external_id("clever", "anything")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    // -- AccessToken repository tests --

    fn sample_access_token() -> crate::models::access_token::AccessToken {
        crate::models::access_token::AccessToken {
            token: "tok-abc123".to_string(),
            client_id: "client-001".to_string(),
            user_sourced_id: "user-001".to_string(),
            scopes: "openid profile".to_string(),
            created_at: "2025-06-01T12:00:00Z".to_string(),
            expires_at: "2099-06-01T13:00:00Z".to_string(),
            revoked_at: None,
        }
    }

    #[tokio::test]
    async fn access_token_create_and_get() {
        let repo = setup().await;
        let token = sample_access_token();
        repo.create_access_token(&token).await.unwrap();

        let found = repo.get_access_token("tok-abc123").await.unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.token, "tok-abc123");
        assert_eq!(found.client_id, "client-001");
        assert_eq!(found.user_sourced_id, "user-001");
        assert_eq!(found.scopes, "openid profile");
        assert!(found.revoked_at.is_none());
    }

    #[tokio::test]
    async fn access_token_get_nonexistent() {
        let repo = setup().await;
        let found = repo.get_access_token("nonexistent").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn access_token_revoke() {
        let repo = setup().await;
        let token = sample_access_token();
        repo.create_access_token(&token).await.unwrap();

        repo.revoke_access_token("tok-abc123").await.unwrap();

        let found = repo.get_access_token("tok-abc123").await.unwrap().unwrap();
        assert!(found.revoked_at.is_some());
    }

    #[tokio::test]
    async fn access_token_delete_expired() {
        let repo = setup().await;

        // Create an expired token
        let mut expired_token = sample_access_token();
        expired_token.token = "tok-expired".to_string();
        expired_token.expires_at = "2020-01-01T00:00:00Z".to_string();
        repo.create_access_token(&expired_token).await.unwrap();

        // Create a valid token
        let valid_token = sample_access_token();
        repo.create_access_token(&valid_token).await.unwrap();

        let deleted = repo.delete_expired_access_tokens().await.unwrap();
        assert_eq!(deleted, 1);

        // Valid token should still exist
        assert!(repo.get_access_token("tok-abc123").await.unwrap().is_some());
        // Expired token should be gone
        assert!(repo
            .get_access_token("tok-expired")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn access_token_delete_revoked() {
        let repo = setup().await;
        let token = sample_access_token();
        repo.create_access_token(&token).await.unwrap();

        repo.revoke_access_token("tok-abc123").await.unwrap();

        let deleted = repo.delete_expired_access_tokens().await.unwrap();
        assert_eq!(deleted, 1);

        assert!(repo.get_access_token("tok-abc123").await.unwrap().is_none());
    }

    // -- TenantConfigRepo round-trip tests --

    fn sample_sis() -> crate::db::repository::SisConfigRecord {
        crate::db::repository::SisConfigRecord {
            enabled: true,
            provider: Some("powerschool".into()),
            powerschool_base_url: Some("https://ps.example.com".into()),
            powerschool_token_url: Some("https://ps.example.com/oauth/access_token".into()),
            powerschool_client_id: Some("client-abc".into()),
            powerschool_client_secret: Some(b"sealed-bytes-1".to_vec()),
            infinite_campus_base_url: None,
            infinite_campus_token_url: None,
            infinite_campus_client_id: None,
            infinite_campus_client_secret: None,
            skyward_base_url: None,
            skyward_token_url: None,
            skyward_client_id: None,
            skyward_client_secret: None,
            oneroster_csv_dir: None,
            sync_schedule: Some("0 */6 * * *".into()),
            updated_at: None,
            updated_by: None,
        }
    }

    fn sample_google() -> crate::db::repository::GoogleSyncConfigRecord {
        crate::db::repository::GoogleSyncConfigRecord {
            enabled: true,
            workspace_domain: Some("example.edu".into()),
            admin_email: Some("admin@example.edu".into()),
            service_account_key: Some(b"{\"type\":\"service_account\"}".to_vec()),
            provision_users: true,
            manage_ous: false,
            suspend_inactive: true,
            sync_schedule: Some("hourly".into()),
            updated_at: None,
            updated_by: None,
        }
    }

    fn sample_idp() -> crate::db::repository::IdpConfigRecord {
        crate::db::repository::IdpConfigRecord {
            enabled: true,
            qr_badge_login: true,
            picture_passwords: false,
            session_timeout_minutes: Some(60),
            default_password_pattern: Some("dictionary".into()),
            default_password_roles: Some(serde_json::json!(["student", "teacher"])),
            saml_cert: Some(b"-----BEGIN CERTIFICATE-----".to_vec()),
            saml_signing_key: Some(b"-----BEGIN PRIVATE KEY-----".to_vec()),
            updated_at: None,
            updated_by: None,
        }
    }

    fn sample_ad() -> crate::db::repository::AdSyncConfigRecord {
        crate::db::repository::AdSyncConfigRecord {
            enabled: true,
            host: Some("ldap.example.com".into()),
            port: Some(636),
            bind_dn: Some("cn=svc,ou=svc,dc=ex,dc=com".into()),
            bind_password: Some(b"sealed-pw".to_vec()),
            base_dn: Some("dc=ex,dc=com".into()),
            user_filter: Some("(objectClass=user)".into()),
            use_tls: true,
            tls_ca_cert: Some(b"-----BEGIN CERTIFICATE-----".to_vec()),
            sync_schedule: Some("0 2 * * *".into()),
            ou_mapping: Some(serde_json::json!({"student": "ou=Students"})),
            groups: Some(serde_json::json!(["g1", "g2"])),
            updated_at: None,
            updated_by: None,
        }
    }

    async fn count_audit(repo: &SqliteRepository, action: &str) -> i64 {
        let entries = repo.list_admin_audit_log(100).await.unwrap();
        entries.iter().filter(|e| e.action == action).count() as i64
    }

    #[tokio::test]
    async fn tenant_config_sis_round_trip() {
        let repo = setup().await;
        assert!(repo.get_sis_config().await.unwrap().is_none());

        let record = sample_sis();
        repo.put_sis_config(record.clone(), "ops@example.com")
            .await
            .unwrap();

        let got = repo.get_sis_config().await.unwrap().expect("row exists");
        assert_eq!(got.enabled, record.enabled);
        assert_eq!(got.provider, record.provider);
        assert_eq!(got.powerschool_base_url, record.powerschool_base_url);
        assert_eq!(
            got.powerschool_client_secret,
            record.powerschool_client_secret
        );
        assert_eq!(got.sync_schedule, record.sync_schedule);
        assert_eq!(got.updated_by.as_deref(), Some("ops@example.com"));

        // Idempotent upsert (no duplicate rows).
        let mut updated = record;
        updated.provider = Some("skyward".into());
        repo.put_sis_config(updated.clone(), "ops2@example.com")
            .await
            .unwrap();
        let got2 = repo.get_sis_config().await.unwrap().unwrap();
        assert_eq!(got2.provider.as_deref(), Some("skyward"));
        assert_eq!(got2.updated_by.as_deref(), Some("ops2@example.com"));

        // Audit row for every put.
        assert_eq!(count_audit(&repo, "tenant_config_sis_updated").await, 2);
    }

    /// The bug this guards: `tenant_config_sis` used to store only
    /// `powerschool_token_url`, so a Skyward or Infinite Campus tenant had
    /// nowhere to put the OAuth token endpoint and `SkywardConnector::new` /
    /// `InfiniteCampusConnector::new` failed forever with
    /// "token_url is required". This walks the whole chain: persist the
    /// per-provider column, read it back, materialize it into `SisConfig` the
    /// way the hosted loader does, and construct the connector.
    #[tokio::test]
    async fn per_provider_token_urls_round_trip_and_build_connectors() {
        use crate::config::SisConfig;
        use crate::connectors::infinite_campus::InfiniteCampusConnector;
        use crate::connectors::skyward::SkywardConnector;

        let repo = setup().await;
        let record = crate::db::repository::SisConfigRecord {
            enabled: true,
            provider: Some("skyward".into()),
            skyward_base_url: Some("https://skyward.example.org/API/v1".into()),
            skyward_token_url: Some("https://skyward.example.org/API/oauth/token".into()),
            skyward_client_id: Some("sky-client".into()),
            skyward_client_secret: Some(b"sky-secret".to_vec()),
            infinite_campus_base_url: Some("https://campus.example.org/campus/api".into()),
            infinite_campus_token_url: Some(
                "https://campus.example.org/campus/oauth2/token".into(),
            ),
            infinite_campus_client_id: Some("ic-client".into()),
            infinite_campus_client_secret: Some(b"ic-secret".to_vec()),
            ..Default::default()
        };
        repo.put_sis_config(record.clone(), "ops@example.com")
            .await
            .unwrap();

        let got = repo.get_sis_config().await.unwrap().expect("row exists");
        assert_eq!(got.skyward_token_url, record.skyward_token_url);
        assert_eq!(
            got.infinite_campus_token_url,
            record.infinite_campus_token_url
        );

        let skyward_cfg = SisConfig {
            enabled: true,
            base_url: got.skyward_base_url.clone().unwrap(),
            token_url: got.skyward_token_url.clone(),
            client_id: got.skyward_client_id.clone().unwrap(),
            client_secret: String::from_utf8(got.skyward_client_secret.clone().unwrap()).unwrap(),
            ..Default::default()
        };
        assert!(SkywardConnector::new(&skyward_cfg).is_ok());

        let ic_cfg = SisConfig {
            enabled: true,
            base_url: got.infinite_campus_base_url.clone().unwrap(),
            token_url: got.infinite_campus_token_url.clone(),
            client_id: got.infinite_campus_client_id.clone().unwrap(),
            client_secret: String::from_utf8(got.infinite_campus_client_secret.clone().unwrap())
                .unwrap(),
            ..Default::default()
        };
        assert!(InfiniteCampusConnector::new(&ic_cfg).is_ok());

        // Without the column there is nothing to carry, which is exactly the
        // failure a hosted tenant hit on every sync tick.
        let no_token = SisConfig {
            token_url: None,
            ..skyward_cfg
        };
        assert!(SkywardConnector::new(&no_token).is_err());
    }

    #[tokio::test]
    async fn tenant_config_google_round_trip() {
        let repo = setup().await;
        assert!(repo.get_google_sync_config().await.unwrap().is_none());

        let record = sample_google();
        repo.put_google_sync_config(record.clone(), "actor")
            .await
            .unwrap();
        let got = repo.get_google_sync_config().await.unwrap().unwrap();
        assert_eq!(got.workspace_domain, record.workspace_domain);
        assert_eq!(got.service_account_key, record.service_account_key);
        assert_eq!(got.provision_users, record.provision_users);
        assert_eq!(got.suspend_inactive, record.suspend_inactive);

        repo.put_google_sync_config(record.clone(), "actor2")
            .await
            .unwrap();
        assert_eq!(
            count_audit(&repo, "tenant_config_google_sync_updated").await,
            2
        );
    }

    #[tokio::test]
    async fn tenant_config_idp_round_trip() {
        let repo = setup().await;
        assert!(repo.get_idp_config().await.unwrap().is_none());

        let record = sample_idp();
        repo.put_idp_config(record.clone(), "actor").await.unwrap();
        let got = repo.get_idp_config().await.unwrap().unwrap();
        assert_eq!(got.qr_badge_login, record.qr_badge_login);
        assert_eq!(got.session_timeout_minutes, record.session_timeout_minutes);
        assert_eq!(got.default_password_roles, record.default_password_roles);
        assert_eq!(got.saml_cert, record.saml_cert);
        assert_eq!(got.saml_signing_key, record.saml_signing_key);

        repo.put_idp_config(record, "actor2").await.unwrap();
        assert_eq!(count_audit(&repo, "tenant_config_idp_updated").await, 2);
    }

    #[tokio::test]
    async fn tenant_config_ad_sync_round_trip() {
        let repo = setup().await;
        assert!(repo.get_ad_sync_config().await.unwrap().is_none());

        let record = sample_ad();
        repo.put_ad_sync_config(record.clone(), "actor")
            .await
            .unwrap();
        let got = repo.get_ad_sync_config().await.unwrap().unwrap();
        assert_eq!(got.host, record.host);
        assert_eq!(got.port, record.port);
        assert_eq!(got.bind_password, record.bind_password);
        assert_eq!(got.use_tls, record.use_tls);
        assert_eq!(got.tls_ca_cert, record.tls_ca_cert);
        assert_eq!(got.ou_mapping, record.ou_mapping);
        assert_eq!(got.groups, record.groups);

        repo.put_ad_sync_config(record, "actor2").await.unwrap();
        assert_eq!(count_audit(&repo, "tenant_config_ad_sync_updated").await, 2);
    }

    // =======================================================================
    // Assets / events / device sync / change sets (migrations 019, 021, 022)
    // =======================================================================

    use crate::models::asset::{AssetSort, Patch};
    use crate::models::page::SortDirection;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    fn ts(y: i32, m: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, day, 8, 30, 0).unwrap()
    }

    /// A repo with `org-001`, `org-002` and `user-001` present, so assets may
    /// reference them without tripping the FKs (which are ON).
    async fn asset_setup() -> SqliteRepository {
        let repo = setup().await;
        repo.upsert_org(&sample_org()).await.unwrap();
        repo.upsert_org(&sample_school()).await.unwrap();
        repo.upsert_user(&sample_user()).await.unwrap();
        repo
    }

    fn full_asset(id: &str) -> Asset {
        Asset {
            id: id.to_string(),
            asset_tag: Some("TAG-001".into()),
            serial_number: Some("SN-ABC123".into()),
            asset_type: AssetType::Laptop,
            make: Some("Dell".into()),
            model: Some("Latitude".into()),
            status: AssetStatus::Repair,
            school_org_sourced_id: Some("org-002".into()),
            assigned_user_sourced_id: Some("user-001".into()),
            org_unit_path: Some("/Students/Grade5".into()),
            source: AssetSource::Google,
            match_state: MatchState::Matched,
            google_device_id: Some("gdev-1".into()),
            annotated_user: Some("jdoe@example.com".into()),
            annotated_asset_id: Some("A-42".into()),
            aue_date: Some(d(2029, 6, 30)),
            os_version: Some("120.0".into()),
            last_sync_at: Some(ts(2026, 3, 4)),
            last_known_ip: Some("10.0.0.7".into()),
            purchase_date: Some(d(2023, 8, 1)),
            purchase_cost_cents: Some(24_999),
            funding_source: Some("Title I".into()),
            warranty_expires: Some(d(2027, 8, 1)),
            location: Some("Room 12".into()),
            notes: Some("cracked screen".into()),
            created_at: ts(2026, 1, 1),
            updated_at: ts(2026, 1, 2),
        }
    }

    #[tokio::test]
    async fn asset_round_trips_every_field_type() {
        let repo = asset_setup().await;
        let asset = full_asset("asset-1");
        repo.create_asset(&asset).await.unwrap();

        let got = repo.get_asset("asset-1").await.unwrap().unwrap();
        assert_eq!(got, asset, "every column must survive the round trip");
        // Spot-check the types that go through a string encoding.
        assert_eq!(got.aue_date, Some(d(2029, 6, 30)));
        assert_eq!(got.last_sync_at, Some(ts(2026, 3, 4)));
        assert_eq!(got.purchase_cost_cents, Some(24_999));
        assert_eq!(got.asset_type, AssetType::Laptop);
        assert_eq!(got.status, AssetStatus::Repair);
        assert_eq!(got.source, AssetSource::Google);
        assert_eq!(got.match_state, MatchState::Matched);
    }

    #[tokio::test]
    async fn asset_with_all_nulls_round_trips() {
        let repo = asset_setup().await;
        let asset = Asset::new("asset-empty");
        repo.create_asset(&asset).await.unwrap();
        let got = repo.get_asset("asset-empty").await.unwrap().unwrap();
        assert_eq!(got.aue_date, None);
        assert_eq!(got.purchase_date, None);
        assert_eq!(got.warranty_expires, None);
        assert_eq!(got.last_sync_at, None);
        assert_eq!(got.purchase_cost_cents, None);
    }

    #[tokio::test]
    async fn get_asset_returns_none_for_unknown_id() {
        let repo = asset_setup().await;
        assert!(repo.get_asset("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn update_asset_applies_set_clear_and_leaves_unchanged_alone() {
        let repo = asset_setup().await;
        repo.create_asset(&full_asset("asset-1")).await.unwrap();

        let patch = AssetPatch {
            status: Some(AssetStatus::Storage),
            // Clear must write a real NULL, not the string "null".
            assigned_user_sourced_id: Patch::Clear,
            aue_date: Patch::Clear,
            purchase_cost_cents: Patch::Set(50_000),
            last_sync_at: Patch::Set(ts(2026, 5, 5)),
            notes: Patch::Set("fixed".into()),
            // Everything else is Unchanged.
            ..Default::default()
        };
        assert!(repo.update_asset("asset-1", &patch).await.unwrap());

        let got = repo.get_asset("asset-1").await.unwrap().unwrap();
        assert_eq!(got.status, AssetStatus::Storage);
        assert_eq!(got.assigned_user_sourced_id, None);
        assert_eq!(got.aue_date, None);
        assert_eq!(got.purchase_cost_cents, Some(50_000));
        assert_eq!(got.last_sync_at, Some(ts(2026, 5, 5)));
        assert_eq!(got.notes.as_deref(), Some("fixed"));
        // Untouched columns survive verbatim.
        assert_eq!(got.asset_tag.as_deref(), Some("TAG-001"));
        assert_eq!(got.serial_number.as_deref(), Some("SN-ABC123"));
        assert_eq!(got.google_device_id.as_deref(), Some("gdev-1"));
        assert_eq!(got.purchase_date, Some(d(2023, 8, 1)));
        assert!(got.updated_at > got.created_at, "updated_at is restamped");

        // A NULL aue_date really is NULL, not a parseable placeholder.
        let raw: Option<String> = sqlx::query("SELECT aue_date FROM assets WHERE id = ?1")
            .bind("asset-1")
            .fetch_one(repo.pool())
            .await
            .unwrap()
            .get(0);
        assert_eq!(raw, None);
    }

    #[tokio::test]
    async fn update_asset_with_empty_patch_reports_existence_without_writing() {
        let repo = asset_setup().await;
        repo.create_asset(&full_asset("asset-1")).await.unwrap();
        let before = repo.get_asset("asset-1").await.unwrap().unwrap();

        assert!(repo
            .update_asset("asset-1", &AssetPatch::default())
            .await
            .unwrap());
        assert!(!repo
            .update_asset("missing", &AssetPatch::default())
            .await
            .unwrap());

        let after = repo.get_asset("asset-1").await.unwrap().unwrap();
        assert_eq!(before, after, "an empty patch must not restamp updated_at");
    }

    #[tokio::test]
    async fn update_asset_returns_false_for_unknown_id() {
        let repo = asset_setup().await;
        let patch = AssetPatch {
            status: Some(AssetStatus::Lost),
            ..Default::default()
        };
        assert!(!repo.update_asset("missing", &patch).await.unwrap());
    }

    #[tokio::test]
    async fn upsert_asset_replaces_the_whole_row() {
        let repo = asset_setup().await;
        repo.create_asset(&full_asset("asset-1")).await.unwrap();

        let mut replacement = Asset::new("asset-1");
        replacement.serial_number = Some("SN-NEW".into());
        repo.upsert_asset(&replacement).await.unwrap();

        let got = repo.get_asset("asset-1").await.unwrap().unwrap();
        assert_eq!(got.serial_number.as_deref(), Some("SN-NEW"));
        assert_eq!(got.notes, None, "upsert owns the whole row");
    }

    #[tokio::test]
    async fn lookup_by_google_device_id_and_serial() {
        let repo = asset_setup().await;
        repo.create_asset(&full_asset("asset-1")).await.unwrap();

        let by_dev = repo
            .get_asset_by_google_device_id("gdev-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_dev.id, "asset-1");
        let by_serial = repo
            .get_asset_by_serial("SN-ABC123")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_serial.id, "asset-1");

        assert!(repo
            .get_asset_by_google_device_id("gdev-none")
            .await
            .unwrap()
            .is_none());
        assert!(repo.get_asset_by_serial("SN-none").await.unwrap().is_none());
    }

    /// Seven assets tagged `A-1`..`A-7`, alternating status/type/assignment.
    async fn seed_seven(repo: &SqliteRepository) {
        for i in 1..=7 {
            let mut a = Asset::new(format!("asset-{i}"));
            a.asset_tag = Some(format!("A-{i}"));
            a.serial_number = Some(format!("SN-{i}"));
            a.status = if i % 2 == 0 {
                AssetStatus::Repair
            } else {
                AssetStatus::Active
            };
            a.asset_type = if i <= 3 {
                AssetType::Chromebook
            } else {
                AssetType::Tablet
            };
            a.match_state = if i == 7 {
                MatchState::Unmatched
            } else {
                MatchState::Matched
            };
            a.school_org_sourced_id = if i <= 4 { Some("org-002".into()) } else { None };
            a.assigned_user_sourced_id = if i <= 2 {
                Some("user-001".into())
            } else {
                None
            };
            a.org_unit_path = Some(match i {
                1 | 2 => "/Students".to_string(),
                3 => "/Students/Grade5".to_string(),
                4 => "/StudentsArchive".to_string(),
                _ => "/Staff".to_string(),
            });
            a.aue_date = Some(d(2027 + i, 1, 1));
            a.annotated_user = Some(format!("user{i}@example.com"));
            repo.create_asset(&a).await.unwrap();
        }
    }

    fn by_tag_asc() -> AssetFilter {
        AssetFilter {
            sort: AssetSort::AssetTag,
            direction: SortDirection::Asc,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn list_assets_windows_in_sql_with_a_full_total() {
        let repo = asset_setup().await;
        seed_seven(&repo).await;
        let filter = by_tag_asc();

        let p1 = repo
            .list_assets(&filter, PageRequest::new(3, 0))
            .await
            .unwrap();
        assert_eq!(p1.items.len(), 3);
        assert_eq!(p1.total, 7, "total is the filtered count, not the page len");
        assert!(p1.has_more());
        assert_eq!(p1.next_offset(), Some(3));
        let tags: Vec<_> = p1.items.iter().map(|a| a.asset_tag.clone()).collect();
        assert_eq!(
            tags,
            vec![Some("A-1".into()), Some("A-2".into()), Some("A-3".into())]
        );

        let p2 = repo
            .list_assets(&filter, PageRequest::new(3, 3))
            .await
            .unwrap();
        assert_eq!(
            p2.items
                .iter()
                .map(|a| a.asset_tag.clone().unwrap())
                .collect::<Vec<_>>(),
            vec!["A-4", "A-5", "A-6"]
        );
        assert!(p2.has_more());

        let p3 = repo
            .list_assets(&filter, PageRequest::new(3, 6))
            .await
            .unwrap();
        assert_eq!(p3.items.len(), 1);
        assert_eq!(p3.items[0].asset_tag.as_deref(), Some("A-7"));
        assert!(!p3.has_more());
        assert_eq!(p3.next_offset(), None);

        // Pages tile the result set exactly once — stable ordering.
        let mut all: Vec<String> = Vec::new();
        for p in [&p1, &p2, &p3] {
            all.extend(p.items.iter().map(|a| a.id.clone()));
        }
        let mut sorted = all.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(all.len(), 7);
        assert_eq!(sorted.len(), 7);

        let past_end = repo
            .list_assets(&filter, PageRequest::new(3, 99))
            .await
            .unwrap();
        assert!(past_end.items.is_empty());
        assert_eq!(past_end.total, 7);
    }

    /// The product wedge, at the repository seam: student and school arrive
    /// beside the device from one query, not from a per-row lookup.
    #[tokio::test]
    async fn list_assets_with_roster_joins_student_and_school() {
        let repo = asset_setup().await;
        seed_seven(&repo).await;

        let page = repo
            .list_assets_with_roster(&by_tag_asc(), PageRequest::new(100, 0))
            .await
            .unwrap();
        assert_eq!(page.total, 7);
        let by_tag = |tag: &str| {
            page.items
                .iter()
                .find(|r| r.asset.asset_tag.as_deref() == Some(tag))
                .unwrap_or_else(|| panic!("{tag} missing"))
                .clone()
        };

        // Assigned + schooled (i <= 2).
        let a1 = by_tag("A-1");
        assert_eq!(a1.assigned_display_name().as_deref(), Some("Doe, John"));
        assert_eq!(a1.assigned_email.as_deref(), Some("jdoe@example.com"));
        assert_eq!(a1.school_name.as_deref(), Some("Springfield High"));

        // Schooled but unassigned (i == 3, 4): school resolves, student does not.
        let a3 = by_tag("A-3");
        assert_eq!(a3.assigned_display_name(), None);
        assert_eq!(a3.assigned_email, None);
        assert_eq!(a3.school_name.as_deref(), Some("Springfield High"));

        // Neither (i >= 5). A LEFT JOIN must keep the row, not drop it.
        let a5 = by_tag("A-5");
        assert_eq!(a5.assigned_display_name(), None);
        assert_eq!(a5.school_name, None);
    }

    /// The join must not change which rows come back or in what order — it is
    /// a decoration on `list_assets`, not a second query with its own opinion.
    #[tokio::test]
    async fn list_assets_with_roster_windows_and_orders_identically() {
        let repo = asset_setup().await;
        seed_seven(&repo).await;

        for filter in [
            by_tag_asc(),
            AssetFilter {
                sort: AssetSort::Status,
                direction: SortDirection::Desc,
                ..Default::default()
            },
            AssetFilter {
                assigned: Some(false),
                sort: AssetSort::SerialNumber,
                direction: SortDirection::Desc,
                ..Default::default()
            },
        ] {
            for offset in [0, 3, 6, 99] {
                let req = PageRequest::new(3, offset);
                let bare = repo.list_assets(&filter, req).await.unwrap();
                let joined = repo.list_assets_with_roster(&filter, req).await.unwrap();
                assert_eq!(bare.total, joined.total, "{filter:?} @ {offset}");
                assert_eq!(
                    bare.items,
                    joined
                        .items
                        .iter()
                        .map(|r| r.asset.clone())
                        .collect::<Vec<_>>(),
                    "{filter:?} @ {offset}"
                );
            }
        }
    }

    /// `LIMIT`/`OFFSET` reach SQL. If the join were applied before the window,
    /// a page would cost the whole filtered set — this asserts the page is the
    /// page, including past the end.
    #[tokio::test]
    async fn list_assets_with_roster_pages_in_sql() {
        let repo = asset_setup().await;
        seed_seven(&repo).await;
        let filter = by_tag_asc();

        let p2 = repo
            .list_assets_with_roster(&filter, PageRequest::new(3, 3))
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 3);
        assert_eq!(p2.total, 7);
        assert_eq!(
            p2.items
                .iter()
                .map(|r| r.asset.asset_tag.clone().unwrap())
                .collect::<Vec<_>>(),
            vec!["A-4", "A-5", "A-6"]
        );

        let past_end = repo
            .list_assets_with_roster(&filter, PageRequest::new(3, 99))
            .await
            .unwrap();
        assert!(past_end.items.is_empty());
        assert_eq!(past_end.total, 7);
    }

    /// Every filter narrows the joined listing exactly as it narrows the bare
    /// one. The join adds two tables that both have a `status` column, so a
    /// mis-scoped predicate would silently filter on the wrong one.
    #[tokio::test]
    async fn list_assets_with_roster_applies_every_filter() {
        let repo = asset_setup().await;
        seed_seven(&repo).await;
        let page = PageRequest::new(100, 0);

        for filter in [
            AssetFilter {
                status: Some(AssetStatus::Repair),
                ..Default::default()
            },
            AssetFilter {
                school_org_sourced_id: Some("org-002".into()),
                ..Default::default()
            },
            AssetFilter {
                assigned: Some(true),
                ..Default::default()
            },
            AssetFilter {
                org_unit_path_prefix: Some("/Students".into()),
                ..Default::default()
            },
            AssetFilter {
                aue_before: Some(d(2030, 1, 1)),
                ..Default::default()
            },
            AssetFilter {
                search: Some("SN-2".into()),
                ..Default::default()
            },
        ] {
            let expected = repo.count_assets(&filter).await.unwrap();
            let joined = repo.list_assets_with_roster(&filter, page).await.unwrap();
            assert_eq!(joined.total, expected, "{filter:?}");
            assert_eq!(joined.items.len() as i64, expected, "{filter:?}");
        }
    }

    /// A device pointing at a roster row that has since been deleted. The FK is
    /// `ON DELETE SET NULL`, so this is really a check that the LEFT JOIN keeps
    /// the device visible rather than hiding fleet from a technician.
    #[tokio::test]
    async fn list_assets_with_roster_keeps_devices_whose_user_is_gone() {
        let repo = asset_setup().await;
        let mut a = Asset::new("asset-orphan");
        a.asset_tag = Some("A-1".into());
        a.assigned_user_sourced_id = Some("user-001".into());
        repo.create_asset(&a).await.unwrap();

        repo.delete_user("user-001").await.unwrap();

        let page = repo
            .list_assets_with_roster(&by_tag_asc(), PageRequest::new(10, 0))
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1, "the device must not vanish");
        assert_eq!(page.items[0].assigned_display_name(), None);
    }

    #[tokio::test]
    async fn list_assets_sorts_descending_with_a_stable_tiebreaker() {
        let repo = asset_setup().await;
        seed_seven(&repo).await;
        // `status` ties across many rows; `id` breaks it deterministically.
        let filter = AssetFilter {
            sort: AssetSort::Status,
            direction: SortDirection::Desc,
            ..Default::default()
        };
        let first = repo
            .list_assets(&filter, PageRequest::new(7, 0))
            .await
            .unwrap();
        let again = repo
            .list_assets(&filter, PageRequest::new(7, 0))
            .await
            .unwrap();
        assert_eq!(first.items, again.items);
        assert_eq!(first.items[0].status, AssetStatus::Repair);
    }

    #[tokio::test]
    async fn every_asset_filter_field_narrows_in_sql() {
        let repo = asset_setup().await;
        seed_seven(&repo).await;
        let page = PageRequest::new(100, 0);

        let cases: Vec<(AssetFilter, i64, &str)> = vec![
            (
                AssetFilter {
                    status: Some(AssetStatus::Repair),
                    ..Default::default()
                },
                3,
                "status",
            ),
            (
                AssetFilter {
                    asset_type: Some(AssetType::Chromebook),
                    ..Default::default()
                },
                3,
                "asset_type",
            ),
            (
                AssetFilter {
                    source: Some(AssetSource::Manual),
                    ..Default::default()
                },
                7,
                "source",
            ),
            (
                AssetFilter {
                    match_state: Some(MatchState::Unmatched),
                    ..Default::default()
                },
                1,
                "match_state",
            ),
            (
                AssetFilter {
                    school_org_sourced_id: Some("org-002".into()),
                    ..Default::default()
                },
                4,
                "school",
            ),
            (
                AssetFilter {
                    assigned_user_sourced_id: Some("user-001".into()),
                    ..Default::default()
                },
                2,
                "assigned_user",
            ),
            (
                AssetFilter {
                    assigned: Some(true),
                    ..Default::default()
                },
                2,
                "assigned = true",
            ),
            (
                AssetFilter {
                    assigned: Some(false),
                    ..Default::default()
                },
                5,
                "assigned = false",
            ),
            (
                AssetFilter {
                    org_unit_path_prefix: Some("/Students".into()),
                    ..Default::default()
                },
                3,
                "ou prefix excludes /StudentsArchive",
            ),
            (
                AssetFilter {
                    org_unit_path_prefix: Some("/Students/Grade5".into()),
                    ..Default::default()
                },
                1,
                "exact ou",
            ),
            (
                AssetFilter {
                    aue_before: Some(d(2030, 1, 1)),
                    ..Default::default()
                },
                2,
                "aue_before",
            ),
            (
                AssetFilter {
                    search: Some("SN-3".into()),
                    ..Default::default()
                },
                1,
                "search serial",
            ),
            (
                AssetFilter {
                    search: Some("a-4".into()),
                    ..Default::default()
                },
                1,
                "search is case-insensitive over asset_tag",
            ),
            (
                AssetFilter {
                    search: Some("user7@example.com".into()),
                    ..Default::default()
                },
                1,
                "search annotated_user",
            ),
            (
                AssetFilter {
                    status: Some(AssetStatus::Repair),
                    asset_type: Some(AssetType::Tablet),
                    ..Default::default()
                },
                2,
                "combined filters AND together",
            ),
        ];

        for (filter, expected, label) in cases {
            let listed = repo.list_assets(&filter, page).await.unwrap();
            assert_eq!(listed.total, expected, "list total for {label}");
            assert_eq!(listed.items.len() as i64, expected, "list rows for {label}");
            assert_eq!(
                repo.count_assets(&filter).await.unwrap(),
                expected,
                "count_assets must agree with list_assets().total for {label}"
            );
        }
    }

    #[tokio::test]
    async fn search_treats_like_metacharacters_literally() {
        let repo = asset_setup().await;
        let mut hit = Asset::new("asset-pct");
        hit.asset_tag = Some("50%OFF".into());
        repo.create_asset(&hit).await.unwrap();
        let mut miss = Asset::new("asset-other");
        miss.asset_tag = Some("50ZOFF".into());
        repo.create_asset(&miss).await.unwrap();
        let mut underscore = Asset::new("asset-us");
        underscore.asset_tag = Some("AXB".into());
        repo.create_asset(&underscore).await.unwrap();

        let page = PageRequest::new(50, 0);

        let pct = repo
            .list_assets(
                &AssetFilter {
                    search: Some("50%".into()),
                    ..Default::default()
                },
                page,
            )
            .await
            .unwrap();
        assert_eq!(pct.total, 1, "'%' must not act as a wildcard");
        assert_eq!(pct.items[0].id, "asset-pct");

        let underscore_hits = repo
            .list_assets(
                &AssetFilter {
                    search: Some("A_B".into()),
                    ..Default::default()
                },
                page,
            )
            .await
            .unwrap();
        assert_eq!(underscore_hits.total, 0, "'_' must not match any character");
    }

    /// The compound op's reason for existing: the patch and its audit event
    /// land together or not at all. `update_asset` and `append_event` sit on
    /// two different traits, so a caller doing them in sequence can leave an
    /// asset changed with no record of who changed it — and for the queue that
    /// assigns devices to students, an unexplained assignment is worse than
    /// none.
    /// The resolve picker's lookup. Case-insensitive across all four columns,
    /// because a technician types "smith" and the roster holds "Smith".
    #[tokio::test]
    async fn user_search_is_case_insensitive_across_name_email_and_username() {
        let repo = setup().await;
        for (sid, given, family, username, email) in [
            ("u-1", "John", "Doe", "jdoe", "jdoe@example.com"),
            ("u-2", "Jane", "Smith", "jsmith", "jsmith@example.com"),
            ("u-3", "Carlos", "Ruiz", "cruiz", "carlos.ruiz@example.com"),
        ] {
            let mut u = sample_user();
            u.sourced_id = sid.into();
            u.given_name = given.into();
            u.family_name = family.into();
            u.username = username.into();
            u.email = Some(email.into());
            // Bare `setup()` creates no orgs, and the junction rows are FKs.
            u.user_ids = vec![];
            u.orgs = vec![];
            u.grades = vec![];
            repo.upsert_user(&u).await.unwrap();
        }

        let ids =
            |users: Vec<User>| -> Vec<String> { users.into_iter().map(|u| u.sourced_id).collect() };

        // family name, wrong case
        assert_eq!(
            ids(repo
                .list_users(&UserFilter::search("smith", 10))
                .await
                .unwrap()),
            vec!["u-2"]
        );
        // given name
        assert_eq!(
            ids(repo
                .list_users(&UserFilter::search("CARLOS", 10))
                .await
                .unwrap()),
            vec!["u-3"]
        );
        // username
        assert_eq!(
            ids(repo
                .list_users(&UserFilter::search("jdoe", 10))
                .await
                .unwrap()),
            vec!["u-1"]
        );
        // email domain matches every seeded user, and the order is the
        // documented family-name sort rather than insertion order
        assert_eq!(
            ids(repo
                .list_users(&UserFilter::search("@example.com", 10))
                .await
                .unwrap()),
            vec!["u-1", "u-3", "u-2"]
        );
    }

    /// A wildcard typed into the search box is a literal, not a pattern.
    /// Without `escape_like` a lone `%` would match the entire roster — the
    /// exact opposite of a search — and `_` would silently match any character.
    #[tokio::test]
    async fn user_search_treats_like_wildcards_as_literal_text() {
        let repo = setup().await;
        for (sid, family) in [("u-1", "Doe"), ("u-2", "100% Cotton"), ("u-3", "Ruiz")] {
            let mut u = sample_user();
            u.sourced_id = sid.into();
            u.family_name = family.into();
            u.username = sid.into();
            u.email = None;
            u.user_ids = vec![];
            u.orgs = vec![];
            u.grades = vec![];
            repo.upsert_user(&u).await.unwrap();
        }

        let hits = repo.list_users(&UserFilter::search("%", 10)).await.unwrap();
        assert_eq!(
            hits.len(),
            1,
            "a bare % matched the whole roster instead of the one literal %"
        );
        assert_eq!(hits[0].sourced_id, "u-2");
    }

    /// The cap is what keeps a type-ahead from becoming an N+1 over a 20,000
    /// row district — `list_users` loads junction data per returned user.
    #[tokio::test]
    async fn user_search_limit_caps_the_result_set() {
        let repo = setup().await;
        for i in 0..10 {
            let mut u = sample_user();
            u.sourced_id = format!("u-{i:02}");
            u.family_name = format!("Tester{i:02}");
            u.username = format!("t{i:02}");
            u.email = None;
            u.user_ids = vec![];
            u.orgs = vec![];
            u.grades = vec![];
            repo.upsert_user(&u).await.unwrap();
        }

        assert_eq!(
            repo.list_users(&UserFilter::search("tester", 3))
                .await
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            repo.list_users(&UserFilter::search("tester", 100))
                .await
                .unwrap()
                .len(),
            10
        );
        assert_eq!(
            repo.list_users(&UserFilter::default()).await.unwrap().len(),
            10,
            "no limit means no cap"
        );
    }

    /// "Everything that happened to my school's devices". `asset_events` holds
    /// no school, so this resolves through a subquery against `assets` — which
    /// means it follows a device's *present* school, and a device moved between
    /// buildings takes its whole history with it. That is the intended
    /// behaviour and this test pins it, because the alternative reading (events
    /// frozen to the school they happened at) would need a denormalised column
    /// and is a different feature.
    /// Both stored shapes parse. The second exists because 21 tables default
    /// `created_at` to SQLite's `datetime('now')`, and without it such a row
    /// renders as "just now" — an event from March appearing to have happened
    /// this second, with nothing marking it as a fallback.
    #[test]
    fn stored_timestamps_parse_in_both_shapes_sqlite_can_produce() {
        let expected = Utc.with_ymd_and_hms(2026, 3, 14, 9, 30, 0).unwrap();

        // What every writer in this file binds.
        assert_eq!(parse_datetime("2026-03-14T09:30:00+00:00"), expected);
        // What `DEFAULT (datetime('now'))` writes.
        assert_eq!(parse_datetime("2026-03-14 09:30:00"), expected);

        // Genuinely unparseable still falls back rather than panicking, but the
        // fallback is now only reachable for input neither writer produces.
        let fallback = parse_datetime("not a timestamp");
        assert!((Utc::now() - fallback).num_seconds().abs() < 5);
    }

    // -- tenant_config_devices (migration 024) --

    /// Sealed key material must survive as **bytes**. AES-256-GCM output is not
    /// valid UTF-8, so a column or binding that coerced it to text would
    /// corrupt it — and the corruption would only surface later, as a
    /// decryption failure that looks like a wrong master key rather than a
    /// storage bug.
    #[tokio::test]
    async fn device_config_round_trips_sealed_bytes_intact() {
        let repo = setup().await;

        // Bytes that are deliberately not valid UTF-8, including an interior
        // NUL — the two things a text round-trip would destroy.
        let sealed: Vec<u8> = vec![0x00, 0xff, 0xfe, 0x01, 0x80, 0x00, 0x7f, 0xc3, 0x28];
        let record = DeviceConfigRecord {
            enabled: true,
            customer_id: Some("my_customer".into()),
            admin_email: Some("admin@example.edu".into()),
            service_account_key: Some(sealed.clone()),
            page_size: Some(200),
            requests_per_minute: Some(500),
            sync_schedule: Some("0 4 * * *".into()),
            ..Default::default()
        };
        repo.put_device_config(record, "admin-1").await.unwrap();

        let back = repo.get_device_config().await.unwrap().unwrap();
        assert_eq!(
            back.service_account_key.as_deref(),
            Some(sealed.as_slice()),
            "sealed bytes must survive byte-for-byte"
        );
        assert!(back.enabled);
        assert_eq!(back.customer_id.as_deref(), Some("my_customer"));
        assert_eq!(back.admin_email.as_deref(), Some("admin@example.edu"));
        assert_eq!(back.page_size, Some(200));
        assert_eq!(back.requests_per_minute, Some(500));
        assert_eq!(back.sync_schedule.as_deref(), Some("0 4 * * *"));
        assert_eq!(back.updated_by.as_deref(), Some("admin-1"));
    }

    /// The table is a singleton, so a second write updates rather than
    /// inserting. Two rows would mean a device sync could read either one.
    #[tokio::test]
    async fn device_config_is_a_singleton_that_updates_in_place() {
        let repo = setup().await;

        repo.put_device_config(
            DeviceConfigRecord {
                enabled: false,
                admin_email: Some("first@example.edu".into()),
                service_account_key: Some(vec![1, 2, 3]),
                ..Default::default()
            },
            "admin-1",
        )
        .await
        .unwrap();
        repo.put_device_config(
            DeviceConfigRecord {
                enabled: true,
                admin_email: Some("second@example.edu".into()),
                service_account_key: Some(vec![4, 5, 6]),
                ..Default::default()
            },
            "admin-2",
        )
        .await
        .unwrap();

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_config_devices")
            .fetch_one(&repo.pool)
            .await
            .unwrap();
        assert_eq!(rows, 1, "one tenant, one row");

        let back = repo.get_device_config().await.unwrap().unwrap();
        assert!(back.enabled);
        assert_eq!(back.admin_email.as_deref(), Some("second@example.edu"));
        assert_eq!(back.service_account_key.as_deref(), Some(&[4u8, 5, 6][..]));
        assert_eq!(back.updated_by.as_deref(), Some("admin-2"));
    }

    /// Nothing configured is `None`, not a default-filled record. The console
    /// has to tell "never set up" apart from "set up and then disabled".
    #[tokio::test]
    async fn an_unconfigured_device_module_reads_as_none() {
        let repo = setup().await;
        assert!(repo.get_device_config().await.unwrap().is_none());
    }

    /// Clearing the key must write a real NULL rather than an empty blob: the
    /// console reads `is_some()` to decide whether a key is on file, and a
    /// zero-length blob would claim one is.
    #[tokio::test]
    async fn a_cleared_key_is_null_not_an_empty_blob() {
        let repo = setup().await;
        repo.put_device_config(
            DeviceConfigRecord {
                service_account_key: Some(vec![9, 9, 9]),
                ..Default::default()
            },
            "admin-1",
        )
        .await
        .unwrap();
        repo.put_device_config(
            DeviceConfigRecord {
                service_account_key: None,
                ..Default::default()
            },
            "admin-1",
        )
        .await
        .unwrap();

        assert_eq!(
            repo.get_device_config()
                .await
                .unwrap()
                .unwrap()
                .service_account_key,
            None
        );
    }

    /// Every config write is audited. A credential changing hands with no
    /// record is the kind of thing a district's security review asks about.
    #[tokio::test]
    async fn writing_device_config_is_audited() {
        let repo = setup().await;
        repo.put_device_config(
            DeviceConfigRecord {
                enabled: true,
                ..Default::default()
            },
            "admin-1",
        )
        .await
        .unwrap();

        let log = repo.list_admin_audit_log(10).await.unwrap();
        assert!(
            log.iter()
                .any(|e| e.action == "tenant_config_devices_updated"),
            "the write must appear in the admin audit log"
        );
    }

    // -- jobs (migration 023) --

    /// A claim is a conditional UPDATE, and **exactly one** caller may win it.
    /// This is the property the whole runner rests on: SQLite has no
    /// `SKIP LOCKED`, so correctness comes from `WHERE status = 'queued'` plus
    /// checking `rows_affected`, not from a lock.
    #[tokio::test]
    async fn only_one_claimer_can_win_a_job() {
        let repo = setup().await;
        let job = repo
            .enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
            .await
            .unwrap();
        assert_eq!(job.status, JobStatus::Queued);
        assert_eq!(job.attempt, 0);

        let now = Utc::now();
        assert!(repo.claim(&job.id, now).await.unwrap(), "first claim wins");
        assert!(
            !repo.claim(&job.id, now).await.unwrap(),
            "a second claimer must lose rather than run the same job twice"
        );

        let claimed = repo.get_job(&job.id).await.unwrap().unwrap();
        assert_eq!(claimed.status, JobStatus::Running);
        assert_eq!(
            claimed.attempt, 1,
            "the retry budget is spent by claiming, so a process that dies \
             mid-run has still used an attempt"
        );
        assert!(claimed.started_at.is_some());
    }

    /// `run_after` is a floor, not a hint. A job scheduled for later must be
    /// invisible to the worker until then, or a backoff delay does nothing.
    #[tokio::test]
    async fn a_delayed_job_is_not_claimable_until_its_time() {
        let repo = setup().await;
        let now = Utc::now();
        let later = repo
            .enqueue(&NewJob::now(JobKind::GoogleDeviceSync).run_after(now + Duration::hours(1)))
            .await
            .unwrap();

        assert!(
            repo.next_claimable(now).await.unwrap().is_none(),
            "not due yet"
        );
        let due = repo
            .next_claimable(now + Duration::hours(2))
            .await
            .unwrap()
            .expect("due now");
        assert_eq!(due.id, later.id);
    }

    /// Oldest first, so a queue that briefly outruns the worker drains in the
    /// order work was asked for rather than newest-wins.
    #[tokio::test]
    async fn the_queue_drains_oldest_first() {
        let repo = setup().await;
        let mut ids = Vec::new();
        for _ in 0..3 {
            ids.push(
                repo.enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
                    .await
                    .unwrap()
                    .id,
            );
            // SQLite stores second-resolution timestamps for some columns, so
            // without a gap the created_at values tie and the ordering falls to
            // the id tiebreaker rather than to time.
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        }

        let first = repo.next_claimable(Utc::now()).await.unwrap().unwrap();
        assert_eq!(first.id, ids[0]);
        repo.claim(&first.id, Utc::now()).await.unwrap();

        let second = repo.next_claimable(Utc::now()).await.unwrap().unwrap();
        assert_eq!(second.id, ids[1], "claiming the first advances the queue");
    }

    /// Recovery exists because a `running` row can only mean a worker claimed
    /// it and the process died. It must be marked failed, never silently
    /// re-queued — a job that writes to Google may have applied part of its
    /// work, and re-running it is the fleet-wide double-apply that
    /// `max_attempts = 1` exists to prevent.
    #[tokio::test]
    async fn abandoned_jobs_are_failed_not_requeued() {
        let repo = setup().await;
        let job = repo
            .enqueue(&NewJob::now(JobKind::ChangeSetCommit))
            .await
            .unwrap();
        let claimed_at = Utc::now() - Duration::hours(2);
        assert!(repo.claim(&job.id, claimed_at).await.unwrap());

        // A fresh job that nobody has claimed must survive recovery untouched.
        let queued = repo
            .enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
            .await
            .unwrap();

        let swept = repo
            .fail_abandoned(Utc::now() - Duration::minutes(30))
            .await
            .unwrap();
        assert_eq!(swept, 1);

        let recovered = repo.get_job(&job.id).await.unwrap().unwrap();
        assert_eq!(recovered.status, JobStatus::Failed);
        assert!(recovered
            .last_error
            .as_deref()
            .unwrap()
            .contains("abandoned"));
        assert!(
            !recovered.may_retry(),
            "a Google-writing job gets one attempt, and it was spent"
        );

        assert_eq!(
            repo.get_job(&queued.id).await.unwrap().unwrap().status,
            JobStatus::Queued,
            "recovery must not touch jobs nobody claimed"
        );
    }

    /// A worker still inside the liveness window is alive, not abandoned.
    /// Sweeping it would fail a job that is about to succeed.
    #[tokio::test]
    async fn a_running_job_inside_the_window_survives_recovery() {
        let repo = setup().await;
        let job = repo
            .enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
            .await
            .unwrap();
        assert!(repo.claim(&job.id, Utc::now()).await.unwrap());

        assert_eq!(
            repo.fail_abandoned(Utc::now() - Duration::minutes(30))
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            repo.get_job(&job.id).await.unwrap().unwrap().status,
            JobStatus::Running
        );
    }

    /// Finishing and requeueing both act only on a job this worker holds.
    /// Without the `status = 'running'` guard, a stale worker returning after a
    /// recovery sweep could overwrite the outcome of a job that has since been
    /// failed and re-armed.
    #[tokio::test]
    async fn terminal_transitions_only_apply_to_a_running_job() {
        let repo = setup().await;
        let job = repo
            .enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
            .await
            .unwrap();

        assert!(
            !repo
                .finish(&job.id, JobStatus::Succeeded, None)
                .await
                .unwrap(),
            "a queued job was never claimed, so it cannot succeed"
        );
        assert!(!repo.requeue(&job.id, None, "nope").await.unwrap());

        assert!(repo.claim(&job.id, Utc::now()).await.unwrap());
        assert!(repo
            .finish(&job.id, JobStatus::Succeeded, None)
            .await
            .unwrap());
        assert!(
            !repo
                .finish(&job.id, JobStatus::Failed, Some("late"))
                .await
                .unwrap(),
            "a finished job cannot be finished twice"
        );

        let done = repo.get_job(&job.id).await.unwrap().unwrap();
        assert_eq!(done.status, JobStatus::Succeeded);
        assert!(done.finished_at.is_some());
        assert_eq!(done.last_error, None);
    }

    /// Requeue returns a job to the queue **without** refunding the attempt, so
    /// a job that keeps failing runs out of budget rather than looping forever.
    #[tokio::test]
    async fn requeue_keeps_the_attempt_already_spent() {
        let repo = setup().await;
        let job = repo
            .enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
            .await
            .unwrap();
        repo.claim(&job.id, Utc::now()).await.unwrap();
        assert!(repo.requeue(&job.id, None, "transient").await.unwrap());

        let back = repo.get_job(&job.id).await.unwrap().unwrap();
        assert_eq!(back.status, JobStatus::Queued);
        assert_eq!(back.attempt, 1, "the failed attempt is not refunded");
        assert_eq!(back.last_error.as_deref(), Some("transient"));
        assert!(back.started_at.is_none(), "it is not running any more");
        assert!(back.may_retry());
    }

    #[tokio::test]
    async fn payload_and_max_attempts_survive_a_round_trip() {
        let repo = setup().await;
        let job = repo
            .enqueue(
                &NewJob::now(JobKind::ChangeSetCommit)
                    .with_payload(serde_json::json!({"changeSetId": "cs-1", "items": 42})),
            )
            .await
            .unwrap();

        let back = repo.get_job(&job.id).await.unwrap().unwrap();
        assert_eq!(back.payload["changeSetId"], "cs-1");
        assert_eq!(back.payload["items"], 42);
        assert_eq!(
            back.max_attempts, 1,
            "a Google-writing kind defaults to at-most-once"
        );
    }

    #[tokio::test]
    async fn jobs_list_filters_by_kind_and_status() {
        let repo = setup().await;
        let sync = repo
            .enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
            .await
            .unwrap();
        repo.enqueue(&NewJob::now(JobKind::ChangeSetCommit))
            .await
            .unwrap();
        repo.claim(&sync.id, Utc::now()).await.unwrap();

        let all = repo
            .list_jobs(&JobFilter::default(), PageRequest::new(50, 0))
            .await
            .unwrap();
        assert_eq!(all.total, 2);

        let running = repo
            .list_jobs(
                &JobFilter {
                    status: Some(JobStatus::Running),
                    ..Default::default()
                },
                PageRequest::new(50, 0),
            )
            .await
            .unwrap();
        assert_eq!(running.total, 1);
        assert_eq!(running.items[0].id, sync.id);

        let commits = repo
            .list_jobs(
                &JobFilter {
                    kind: Some(JobKind::ChangeSetCommit),
                    ..Default::default()
                },
                PageRequest::new(50, 0),
            )
            .await
            .unwrap();
        assert_eq!(commits.total, 1);
    }

    #[tokio::test]
    async fn events_can_be_filtered_to_one_schools_devices() {
        let repo = asset_setup().await;

        let mut at_school = Asset::new("asset-hs");
        at_school.school_org_sourced_id = Some("org-002".into());
        repo.create_asset(&at_school).await.unwrap();
        // Same district, no school set: must not be swept in.
        repo.create_asset(&Asset::new("asset-none")).await.unwrap();

        for id in ["asset-hs", "asset-none"] {
            repo.append_event(&NewAssetEvent::simple(
                id,
                "system:google-sync",
                ActorKind::System,
                AssetEventType::Imported,
            ))
            .await
            .unwrap();
        }

        let page = repo
            .list_events(
                &AssetEventFilter {
                    school_org_sourced_id: Some("org-002".into()),
                    ..Default::default()
                },
                PageRequest::new(50, 0),
            )
            .await
            .unwrap();
        assert_eq!(page.total, 1, "only the school's device");
        assert_eq!(page.items[0].asset_id, "asset-hs");

        // The device moves. Its history moves with it.
        assert!(repo
            .update_asset(
                "asset-hs",
                &AssetPatch {
                    school_org_sourced_id: Patch::Clear,
                    ..Default::default()
                }
            )
            .await
            .unwrap());
        let after = repo
            .list_events(
                &AssetEventFilter {
                    school_org_sourced_id: Some("org-002".into()),
                    ..Default::default()
                },
                PageRequest::new(50, 0),
            )
            .await
            .unwrap();
        assert_eq!(
            after.total, 0,
            "the filter follows the device's current school, by design"
        );
    }

    /// "Everything this administrator did" — the audit question the actor
    /// column exists to answer.
    #[tokio::test]
    async fn events_can_be_filtered_to_one_actor() {
        let repo = asset_setup().await;
        repo.create_asset(&Asset::new("asset-1")).await.unwrap();

        for actor in ["console:admin", "system:google-sync", "console:admin"] {
            let kind = if actor.starts_with("system:") {
                ActorKind::System
            } else {
                ActorKind::Admin
            };
            repo.append_event(&NewAssetEvent::simple(
                "asset-1",
                actor,
                kind,
                AssetEventType::Imported,
            ))
            .await
            .unwrap();
        }

        let page = repo
            .list_events(
                &AssetEventFilter {
                    actor: Some("console:admin".into()),
                    ..Default::default()
                },
                PageRequest::new(50, 0),
            )
            .await
            .unwrap();
        assert_eq!(page.total, 2);
        assert!(page.items.iter().all(|e| e.actor == "console:admin"));

        // Combining filters narrows rather than replacing.
        let combined = repo
            .list_events(
                &AssetEventFilter {
                    actor: Some("console:admin".into()),
                    event_type: Some(AssetEventType::Assigned),
                    ..Default::default()
                },
                PageRequest::new(50, 0),
            )
            .await
            .unwrap();
        assert_eq!(combined.total, 0, "no admin-assigned events were written");
    }

    #[tokio::test]
    async fn apply_patch_with_event_writes_both() {
        let repo = asset_setup().await;
        repo.create_asset(&Asset::new("asset-1")).await.unwrap();

        let ok = repo
            .apply_patch_with_event(
                "asset-1",
                &AssetPatch {
                    assigned_user_sourced_id: Patch::Set("user-001".into()),
                    match_state: Some(MatchState::Manual),
                    ..Default::default()
                },
                &NewAssetEvent::simple(
                    "asset-1",
                    "admin-1",
                    ActorKind::Admin,
                    AssetEventType::Assigned,
                ),
            )
            .await
            .unwrap();
        assert!(ok);

        let asset = repo.get_asset("asset-1").await.unwrap().unwrap();
        assert_eq!(asset.assigned_user_sourced_id.as_deref(), Some("user-001"));
        assert_eq!(asset.match_state, MatchState::Manual);

        let events = repo
            .list_events(
                &AssetEventFilter::for_asset("asset-1"),
                PageRequest::new(10, 0),
            )
            .await
            .unwrap();
        assert_eq!(events.total, 1, "the event committed with the patch");
        assert_eq!(events.items[0].event_type, AssetEventType::Assigned);
    }

    /// A patch against an id that does not exist must write nothing at all.
    /// Without the rollback the event would be attempted against a missing
    /// asset — `asset_events.asset_id` is RESTRICT, so it would error rather
    /// than return the honest `false`.
    #[tokio::test]
    async fn apply_patch_with_event_writes_nothing_for_a_missing_asset() {
        let repo = asset_setup().await;

        let ok = repo
            .apply_patch_with_event(
                "no-such-asset",
                &AssetPatch {
                    status: Some(AssetStatus::Repair),
                    ..Default::default()
                },
                &NewAssetEvent::simple(
                    "no-such-asset",
                    "admin-1",
                    ActorKind::Admin,
                    AssetEventType::StatusChanged,
                ),
            )
            .await
            .unwrap();
        assert!(!ok, "no row to patch");

        let events = repo
            .list_events(&AssetEventFilter::default(), PageRequest::new(10, 0))
            .await
            .unwrap();
        assert_eq!(events.total, 0, "no orphan event was written");
    }

    #[tokio::test]
    async fn append_event_returns_the_new_id_and_lists_newest_first() {
        let repo = asset_setup().await;
        repo.create_asset(&Asset::new("asset-1")).await.unwrap();
        repo.create_asset(&Asset::new("asset-2")).await.unwrap();

        let id1 = repo
            .append_event(&NewAssetEvent::field_changed(
                "asset-1",
                "user-001",
                ActorKind::Admin,
                "status",
                Some("active"),
                Some("repair"),
            ))
            .await
            .unwrap();
        let id2 = repo
            .append_event(&NewAssetEvent::simple(
                "asset-1",
                "system:google-sync",
                ActorKind::System,
                AssetEventType::MovedOu,
            ))
            .await
            .unwrap();
        let id3 = repo
            .append_event(&NewAssetEvent::simple(
                "asset-2",
                "user-001",
                ActorKind::Admin,
                AssetEventType::Imported,
            ))
            .await
            .unwrap();
        assert!(id1 < id2 && id2 < id3);

        let page = PageRequest::new(50, 0);
        let all = repo
            .list_events(&AssetEventFilter::default(), page)
            .await
            .unwrap();
        assert_eq!(all.total, 3);
        assert_eq!(
            all.items.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![id3, id2, id1],
            "newest first"
        );

        let for_asset = repo
            .list_events(&AssetEventFilter::for_asset("asset-1"), page)
            .await
            .unwrap();
        assert_eq!(for_asset.total, 2);

        let by_type = repo
            .list_events(
                &AssetEventFilter {
                    event_type: Some(AssetEventType::MovedOu),
                    ..Default::default()
                },
                page,
            )
            .await
            .unwrap();
        assert_eq!(by_type.total, 1);
        assert_eq!(by_type.items[0].id, id2);

        let by_actor = repo
            .list_events(
                &AssetEventFilter {
                    actor: Some("system:google-sync".into()),
                    ..Default::default()
                },
                page,
            )
            .await
            .unwrap();
        assert_eq!(by_actor.total, 1);

        // The JSON payload survives the TEXT column.
        let payload = for_asset
            .items
            .iter()
            .find(|e| e.id == id1)
            .unwrap()
            .payload
            .clone()
            .unwrap();
        assert_eq!(payload["field"], "status");
        assert_eq!(payload["new"], "repair");

        let none_in_window = repo
            .list_events(
                &AssetEventFilter {
                    since: Some(ts(2099, 1, 1)),
                    ..Default::default()
                },
                page,
            )
            .await
            .unwrap();
        assert_eq!(none_in_window.total, 0);
    }

    #[tokio::test]
    async fn list_events_paginates() {
        let repo = asset_setup().await;
        repo.create_asset(&Asset::new("asset-1")).await.unwrap();
        for _ in 0..5 {
            repo.append_event(&NewAssetEvent::simple(
                "asset-1",
                "a",
                ActorKind::System,
                AssetEventType::Imported,
            ))
            .await
            .unwrap();
        }
        let p = repo
            .list_events(&AssetEventFilter::default(), PageRequest::new(2, 2))
            .await
            .unwrap();
        assert_eq!(p.total, 5);
        assert_eq!(p.items.len(), 2);
        assert!(p.has_more());
    }

    #[tokio::test]
    async fn device_sync_cursor_inserts_then_updates() {
        let repo = setup().await;
        assert!(repo
            .get_cursor(DeviceSyncResource::ChromeOsDevices)
            .await
            .unwrap()
            .is_none());

        let mut cursor = DeviceSyncCursor::idle(DeviceSyncResource::ChromeOsDevices);
        cursor.updated_at = ts(2026, 2, 1);
        repo.upsert_cursor(&cursor).await.unwrap();
        let got = repo
            .get_cursor(DeviceSyncResource::ChromeOsDevices)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, cursor);
        assert!(!got.is_resumable());

        cursor.page_token = Some("tok-2".into());
        cursor.status = DeviceSyncCursorStatus::Running;
        cursor.last_full_sync_at = Some(ts(2026, 2, 2));
        cursor.last_delta_at = Some(ts(2026, 2, 3));
        cursor.error_message = Some("rate limited".into());
        cursor.updated_at = ts(2026, 2, 4);
        repo.upsert_cursor(&cursor).await.unwrap();

        let got = repo
            .get_cursor(DeviceSyncResource::ChromeOsDevices)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, cursor);
        assert!(got.is_resumable());

        // The upsert updated in place rather than inserting a second row.
        let n: i64 = sqlx::query("SELECT COUNT(*) FROM google_device_sync_cursors")
            .fetch_one(repo.pool())
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 1);

        // Other resources are independent.
        assert!(repo
            .get_cursor(DeviceSyncResource::OrgUnits)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn device_sync_run_lifecycle() {
        let repo = setup().await;
        let run = repo.start_run(DeviceSyncMode::Delta, true).await.unwrap();
        assert!(run.is_running());
        assert!(run.dry_run);
        assert_eq!(run.mode, DeviceSyncMode::Delta);
        assert_eq!(run.counters, DeviceSyncCounters::default());

        let mid = DeviceSyncCounters {
            devices_seen: 10,
            api_calls: 3,
            ..Default::default()
        };
        repo.update_run_counters(run.id, &mid).await.unwrap();
        let fetched = repo.get_run(run.id).await.unwrap().unwrap();
        assert_eq!(fetched.counters, mid);
        assert!(fetched.is_running());
        assert!(fetched.dry_run);
        assert_eq!(fetched.started_at, run.started_at);

        let final_counters = DeviceSyncCounters {
            devices_seen: 20,
            devices_created: 4,
            devices_updated: 5,
            devices_matched: 6,
            devices_unmatched: 7,
            api_calls: 8,
            throttle_events: 9,
        };
        repo.finish_run(
            run.id,
            DeviceSyncRunStatus::Failed,
            &final_counters,
            Some("boom"),
        )
        .await
        .unwrap();

        let done = repo.get_run(run.id).await.unwrap().unwrap();
        assert_eq!(done.status, DeviceSyncRunStatus::Failed);
        assert_eq!(done.counters, final_counters);
        assert_eq!(done.error_message.as_deref(), Some("boom"));
        assert!(done.completed_at.is_some());
        assert!(!done.is_running());

        assert!(repo.get_run(999).await.unwrap().is_none());
    }

    /// Regression guard: SQLite INTEGER is 64-bit and every counter binds as
    /// `i64`. An `as i32` anywhere in the chain turns this into a negative
    /// number.
    #[tokio::test]
    async fn device_sync_counters_survive_above_i32_max() {
        let repo = setup().await;
        let run = repo.start_run(DeviceSyncMode::Full, false).await.unwrap();
        let big = i64::from(i32::MAX) + 1_000;
        let counters = DeviceSyncCounters {
            devices_seen: big,
            devices_created: big + 1,
            devices_updated: big + 2,
            devices_matched: big + 3,
            devices_unmatched: big + 4,
            api_calls: i64::MAX,
            throttle_events: big + 5,
        };
        repo.update_run_counters(run.id, &counters).await.unwrap();
        assert_eq!(
            repo.get_run(run.id).await.unwrap().unwrap().counters,
            counters
        );

        repo.finish_run(run.id, DeviceSyncRunStatus::Succeeded, &counters, None)
            .await
            .unwrap();
        assert_eq!(repo.latest_run().await.unwrap().unwrap().counters, counters);
    }

    #[tokio::test]
    async fn latest_run_and_list_runs_are_newest_first() {
        let repo = setup().await;
        assert!(repo.latest_run().await.unwrap().is_none());

        let mut ids = Vec::new();
        for _ in 0..5 {
            ids.push(
                repo.start_run(DeviceSyncMode::Full, false)
                    .await
                    .unwrap()
                    .id,
            );
        }
        assert_eq!(repo.latest_run().await.unwrap().unwrap().id, ids[4]);

        let p1 = repo.list_runs(PageRequest::new(2, 0)).await.unwrap();
        assert_eq!(p1.total, 5);
        assert_eq!(
            p1.items.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![ids[4], ids[3]]
        );
        assert!(p1.has_more());

        let p3 = repo.list_runs(PageRequest::new(2, 4)).await.unwrap();
        assert_eq!(
            p3.items.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![ids[0]]
        );
        assert!(!p3.has_more());
    }

    fn planned_set(id: &str, items: i64) -> ChangeSet {
        ChangeSet::planned(id, ChangeSetKind::BulkEdit, "user-001", "hash-1", items)
    }

    async fn item_ids(repo: &SqliteRepository, set_id: &str) -> Vec<i64> {
        repo.list_items(set_id, None, PageRequest::new(500, 0))
            .await
            .unwrap()
            .items
            .iter()
            .map(|i| i.id)
            .collect()
    }

    /// Two assets and a 3-item change set targeting `asset-1`.
    async fn change_set_fixture(repo: &SqliteRepository) -> Vec<i64> {
        repo.create_asset(&full_asset("asset-1")).await.unwrap();
        let mut other = Asset::new("asset-2");
        other.google_device_id = Some("gdev-taken".into());
        repo.create_asset(&other).await.unwrap();

        let items = vec![
            NewChangeSetItem::update_field("asset-1", "notes", None, Some("new".into())),
            NewChangeSetItem::move_ou("asset-1", "gdev-1", Some("/a".into()), "/b"),
            NewChangeSetItem::update_field("asset-2", "location", None, Some("Room 3".into())),
        ];
        repo.create_change_set(&planned_set("cs-1", 3), &items)
            .await
            .unwrap();
        item_ids(repo, "cs-1").await
    }

    #[tokio::test]
    async fn create_change_set_writes_the_set_and_its_items_together() {
        let repo = asset_setup().await;
        let ids = change_set_fixture(&repo).await;
        assert_eq!(ids.len(), 3);

        let set = repo.get_change_set("cs-1").await.unwrap().unwrap();
        assert_eq!(set.status, ChangeSetStatus::Planned);
        assert_eq!(set.kind, ChangeSetKind::BulkEdit);
        assert_eq!(set.plan_hash, "hash-1");
        assert_eq!(set.expected_item_count, 3);
        assert_eq!(set.summary, serde_json::json!({}));
        assert!(set.committed_at.is_none());

        let items = repo
            .list_items("cs-1", None, PageRequest::new(50, 0))
            .await
            .unwrap();
        assert_eq!(items.total, 3);
        assert_eq!(items.items[1].op, ChangeSetOp::MoveOu);
        assert_eq!(items.items[1].remote_target, RemoteTarget::Google);
        assert_eq!(items.items[1].google_device_id.as_deref(), Some("gdev-1"));
        assert!(items
            .items
            .iter()
            .all(|i| i.status == ChangeSetItemStatus::Pending));

        assert!(repo.get_change_set("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn create_change_set_rolls_back_when_an_item_is_invalid() {
        let repo = asset_setup().await;
        let items = vec![
            NewChangeSetItem::update_field("asset-1", "notes", None, None),
            // No such asset — the FK rejects this item.
            NewChangeSetItem::update_field("ghost", "notes", None, None),
        ];
        repo.create_asset(&Asset::new("asset-1")).await.unwrap();
        assert!(repo
            .create_change_set(&planned_set("cs-bad", 2), &items)
            .await
            .is_err());
        assert!(
            repo.get_change_set("cs-bad").await.unwrap().is_none(),
            "a partial item list would silently under-apply"
        );
    }

    #[tokio::test]
    async fn item_status_counts_and_filtered_list_items() {
        let repo = asset_setup().await;
        let ids = change_set_fixture(&repo).await;

        repo.mark_item_outcome(ids[1], ChangeSetItemStatus::Failed, Some("429"))
            .await
            .unwrap();
        repo.mark_item_outcome(ids[2], ChangeSetItemStatus::Skipped, None)
            .await
            .unwrap();

        let counts = repo.item_status_counts("cs-1").await.unwrap();
        assert_eq!(counts.pending, 1);
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.skipped, 1);
        assert_eq!(counts.total(), 3);
        assert_eq!(counts.retryable(), 2);

        let failed = repo
            .list_items(
                "cs-1",
                Some(ChangeSetItemStatus::Failed),
                PageRequest::new(50, 0),
            )
            .await
            .unwrap();
        assert_eq!(failed.total, 1);
        assert_eq!(failed.items[0].id, ids[1]);
        assert_eq!(failed.items[0].error.as_deref(), Some("429"));

        let pending = repo
            .list_items(
                "cs-1",
                Some(ChangeSetItemStatus::Pending),
                PageRequest::new(50, 0),
            )
            .await
            .unwrap();
        assert_eq!(pending.total, 1);

        // Items of another set never leak in.
        repo.create_change_set(&planned_set("cs-2", 0), &[])
            .await
            .unwrap();
        assert_eq!(
            repo.list_items("cs-2", None, PageRequest::new(50, 0))
                .await
                .unwrap()
                .total,
            0
        );

        let paged = repo
            .list_items("cs-1", None, PageRequest::new(2, 1))
            .await
            .unwrap();
        assert_eq!(paged.total, 3);
        assert_eq!(paged.items.len(), 2);
    }

    #[tokio::test]
    async fn list_change_sets_filters_and_paginates() {
        let repo = asset_setup().await;
        for i in 0..4 {
            let mut set = ChangeSet::planned(
                format!("cs-{i}"),
                if i % 2 == 0 {
                    ChangeSetKind::BulkEdit
                } else {
                    ChangeSetKind::CsvImport
                },
                if i < 2 { "user-001" } else { "user-002" },
                "h",
                0,
            );
            set.created_at = ts(2026, 1, 1) + chrono::Duration::minutes(i);
            repo.create_change_set(&set, &[]).await.unwrap();
        }
        repo.discard_change_set("cs-0").await.unwrap();

        let page = PageRequest::new(50, 0);
        let all = repo
            .list_change_sets(&ChangeSetFilter::default(), page)
            .await
            .unwrap();
        assert_eq!(all.total, 4);
        assert_eq!(all.items[0].id, "cs-3", "newest first");

        let by_kind = repo
            .list_change_sets(
                &ChangeSetFilter {
                    kind: Some(ChangeSetKind::CsvImport),
                    ..Default::default()
                },
                page,
            )
            .await
            .unwrap();
        assert_eq!(by_kind.total, 2);

        let by_status = repo
            .list_change_sets(
                &ChangeSetFilter {
                    status: Some(ChangeSetStatus::Discarded),
                    ..Default::default()
                },
                page,
            )
            .await
            .unwrap();
        assert_eq!(by_status.total, 1);
        assert_eq!(by_status.items[0].id, "cs-0");

        let by_creator = repo
            .list_change_sets(
                &ChangeSetFilter {
                    created_by: Some("user-002".into()),
                    ..Default::default()
                },
                page,
            )
            .await
            .unwrap();
        assert_eq!(by_creator.total, 2);

        let windowed = repo
            .list_change_sets(&ChangeSetFilter::default(), PageRequest::new(2, 2))
            .await
            .unwrap();
        assert_eq!(windowed.total, 4);
        assert_eq!(windowed.items.len(), 2);
        assert!(!windowed.has_more());
    }

    #[tokio::test]
    async fn claim_for_commit_is_won_exactly_once() {
        let repo = asset_setup().await;
        change_set_fixture(&repo).await;

        assert_eq!(
            repo.claim_for_commit("cs-1", "hash-1", 3).await.unwrap(),
            CommitClaim::Claimed
        );
        assert_eq!(
            repo.get_change_set("cs-1").await.unwrap().unwrap().status,
            ChangeSetStatus::Committing
        );

        // A second claimer sees the status the winner left behind.
        assert_eq!(
            repo.claim_for_commit("cs-1", "hash-1", 3).await.unwrap(),
            CommitClaim::NotPlanned {
                status: ChangeSetStatus::Committing
            }
        );
    }

    #[tokio::test]
    async fn claim_for_commit_rejects_stale_and_unknown_plans() {
        let repo = asset_setup().await;
        change_set_fixture(&repo).await;

        assert_eq!(
            repo.claim_for_commit("nope", "hash-1", 3).await.unwrap(),
            CommitClaim::NotFound
        );

        assert_eq!(
            repo.claim_for_commit("cs-1", "hash-OTHER", 3)
                .await
                .unwrap(),
            CommitClaim::Stale {
                expected_plan_hash: "hash-OTHER".into(),
                actual_plan_hash: "hash-1".into(),
                expected_item_count: 3,
                actual_item_count: 3,
            }
        );

        assert_eq!(
            repo.claim_for_commit("cs-1", "hash-1", 2).await.unwrap(),
            CommitClaim::Stale {
                expected_plan_hash: "hash-1".into(),
                actual_plan_hash: "hash-1".into(),
                expected_item_count: 2,
                actual_item_count: 3,
            }
        );

        // A refused claim leaves the set claimable.
        assert_eq!(
            repo.get_change_set("cs-1").await.unwrap().unwrap().status,
            ChangeSetStatus::Planned
        );
        assert!(repo
            .claim_for_commit("cs-1", "hash-1", 3)
            .await
            .unwrap()
            .is_claimed());
    }

    /// The plan drifted: an item was added since the preview the operator
    /// approved, so the live count no longer matches.
    #[tokio::test]
    async fn claim_for_commit_compares_against_the_live_item_count() {
        let repo = asset_setup().await;
        change_set_fixture(&repo).await;
        repo.create_change_set(&planned_set("cs-drift", 1), &[])
            .await
            .unwrap();

        assert_eq!(
            repo.claim_for_commit("cs-drift", "hash-1", 1)
                .await
                .unwrap(),
            CommitClaim::Stale {
                expected_plan_hash: "hash-1".into(),
                actual_plan_hash: "hash-1".into(),
                expected_item_count: 1,
                actual_item_count: 0,
            }
        );
    }

    #[tokio::test]
    async fn mark_item_applied_is_one_atom() {
        let repo = asset_setup().await;
        let ids = change_set_fixture(&repo).await;

        let patch = AssetPatch {
            status: Some(AssetStatus::Storage),
            notes: Patch::Set("applied".into()),
            assigned_user_sourced_id: Patch::Clear,
            ..Default::default()
        };
        let event = NewAssetEvent::field_changed(
            "asset-1",
            "user-001",
            ActorKind::Admin,
            "status",
            Some("repair"),
            Some("storage"),
        );
        repo.mark_item_applied(ids[0], Some(&patch), &event)
            .await
            .unwrap();

        let asset = repo.get_asset("asset-1").await.unwrap().unwrap();
        assert_eq!(asset.status, AssetStatus::Storage);
        assert_eq!(asset.notes.as_deref(), Some("applied"));
        assert_eq!(asset.assigned_user_sourced_id, None);

        let events = repo
            .list_events(&AssetEventFilter::default(), PageRequest::new(50, 0))
            .await
            .unwrap();
        assert_eq!(events.total, 1, "exactly one event row");
        assert_eq!(events.items[0].event_type, AssetEventType::FieldChanged);

        let item = repo
            .list_items("cs-1", None, PageRequest::new(50, 0))
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|i| i.id == ids[0])
            .unwrap();
        assert_eq!(item.status, ChangeSetItemStatus::Applied);
        assert!(item.applied_at.is_some());
        assert!(item.error.is_none());
    }

    #[tokio::test]
    async fn mark_item_applied_accepts_a_purely_remote_item() {
        let repo = asset_setup().await;
        let ids = change_set_fixture(&repo).await;
        let before = repo.get_asset("asset-1").await.unwrap().unwrap();

        repo.mark_item_applied(
            ids[1],
            None,
            &NewAssetEvent::simple(
                "asset-1",
                "system:google-sync",
                ActorKind::System,
                AssetEventType::MovedOu,
            ),
        )
        .await
        .unwrap();

        assert_eq!(repo.get_asset("asset-1").await.unwrap().unwrap(), before);
        assert_eq!(repo.item_status_counts("cs-1").await.unwrap().applied, 1);
    }

    /// **The rollback test.** The event insert violates
    /// `asset_events.asset_id REFERENCES assets(id)`, which fires *after* the
    /// asset UPDATE has already run inside the transaction. Either all three
    /// writes land or none do.
    #[tokio::test]
    async fn mark_item_applied_rolls_back_everything_on_failure() {
        let repo = asset_setup().await;
        let ids = change_set_fixture(&repo).await;
        let before = repo.get_asset("asset-1").await.unwrap().unwrap();

        let patch = AssetPatch {
            status: Some(AssetStatus::Lost),
            notes: Patch::Set("should not persist".into()),
            ..Default::default()
        };
        let bad_event = NewAssetEvent::simple(
            "no-such-asset",
            "user-001",
            ActorKind::Admin,
            AssetEventType::StatusChanged,
        );

        let err = repo
            .mark_item_applied(ids[0], Some(&patch), &bad_event)
            .await;
        assert!(err.is_err(), "the FK violation must surface as an error");

        // (a) the asset is untouched, including updated_at
        assert_eq!(
            repo.get_asset("asset-1").await.unwrap().unwrap(),
            before,
            "the asset UPDATE must be rolled back with the rest"
        );
        // (b) no event row exists at all
        let events = repo
            .list_events(&AssetEventFilter::default(), PageRequest::new(50, 0))
            .await
            .unwrap();
        assert_eq!(events.total, 0);
        // (c) the item is still pending
        let counts = repo.item_status_counts("cs-1").await.unwrap();
        assert_eq!(counts.pending, 3);
        assert_eq!(counts.applied, 0);
    }

    /// The same atomicity, failing on the asset UPDATE instead: the patch
    /// collides with the unique `google_device_id` index.
    #[tokio::test]
    async fn mark_item_applied_rolls_back_on_a_unique_index_violation() {
        let repo = asset_setup().await;
        let ids = change_set_fixture(&repo).await;
        let before = repo.get_asset("asset-1").await.unwrap().unwrap();

        let patch = AssetPatch {
            // Already owned by asset-2.
            google_device_id: Patch::Set("gdev-taken".into()),
            notes: Patch::Set("should not persist".into()),
            ..Default::default()
        };
        assert!(repo
            .mark_item_applied(
                ids[0],
                Some(&patch),
                &NewAssetEvent::simple(
                    "asset-1",
                    "user-001",
                    ActorKind::Admin,
                    AssetEventType::FieldChanged,
                ),
            )
            .await
            .is_err());

        assert_eq!(repo.get_asset("asset-1").await.unwrap().unwrap(), before);
        assert_eq!(
            repo.list_events(&AssetEventFilter::default(), PageRequest::new(50, 0))
                .await
                .unwrap()
                .total,
            0
        );
        assert_eq!(repo.item_status_counts("cs-1").await.unwrap().pending, 3);
    }

    #[tokio::test]
    async fn mark_item_applied_rejects_an_unknown_item() {
        let repo = asset_setup().await;
        change_set_fixture(&repo).await;
        assert!(repo
            .mark_item_applied(
                9_999,
                None,
                &NewAssetEvent::simple("asset-1", "a", ActorKind::System, AssetEventType::Imported),
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn mark_item_outcome_rejects_applied_and_accepts_the_rest() {
        let repo = asset_setup().await;
        let ids = change_set_fixture(&repo).await;

        let err = repo
            .mark_item_outcome(ids[0], ChangeSetItemStatus::Applied, None)
            .await
            .expect_err("applied must go through mark_item_applied");
        assert!(err.to_string().contains("mark_item_applied"));
        assert_eq!(repo.item_status_counts("cs-1").await.unwrap().pending, 3);

        for (id, status) in [
            (ids[0], ChangeSetItemStatus::Failed),
            (ids[1], ChangeSetItemStatus::Indeterminate),
            (ids[2], ChangeSetItemStatus::Skipped),
        ] {
            repo.mark_item_outcome(id, status, Some("detail"))
                .await
                .unwrap();
        }

        let counts = repo.item_status_counts("cs-1").await.unwrap();
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.indeterminate, 1);
        assert_eq!(counts.skipped, 1);
        assert_eq!(counts.pending, 0);
    }

    #[tokio::test]
    async fn rearm_moves_retryable_items_and_the_set_back() {
        let repo = asset_setup().await;
        let ids = change_set_fixture(&repo).await;
        // A fourth and fifth item so every status is represented.
        repo.create_change_set(
            &planned_set("cs-other", 0),
            &[NewChangeSetItem::update_field(
                "asset-2", "notes", None, None,
            )],
        )
        .await
        .unwrap();

        repo.claim_for_commit("cs-1", "hash-1", 3).await.unwrap();
        // applied, skipped, and one left pending.
        repo.mark_item_applied(
            ids[0],
            None,
            &NewAssetEvent::simple(
                "asset-1",
                "a",
                ActorKind::System,
                AssetEventType::FieldChanged,
            ),
        )
        .await
        .unwrap();
        repo.mark_item_outcome(ids[1], ChangeSetItemStatus::Skipped, None)
            .await
            .unwrap();
        repo.finish_commit("cs-1").await.unwrap();

        let committed = repo.get_change_set("cs-1").await.unwrap().unwrap();
        assert_eq!(committed.status, ChangeSetStatus::Committed);
        assert!(committed.committed_at.is_some());

        // ids[2] is still pending -> the only re-armable one here.
        assert_eq!(repo.rearm_failed_items("cs-1").await.unwrap(), 1);

        let counts = repo.item_status_counts("cs-1").await.unwrap();
        assert_eq!(counts.applied, 1, "applied items are never re-armed");
        assert_eq!(counts.skipped, 1, "a human said no — leave it");
        assert_eq!(counts.pending, 1);
        assert_eq!(
            repo.get_change_set("cs-1").await.unwrap().unwrap().status,
            ChangeSetStatus::Planned
        );

        // Another set's items are untouched.
        assert_eq!(
            repo.item_status_counts("cs-other").await.unwrap().pending,
            1
        );
    }

    #[tokio::test]
    async fn rearm_clears_error_and_applied_at_on_failed_items() {
        let repo = asset_setup().await;
        let ids = change_set_fixture(&repo).await;
        repo.mark_item_outcome(ids[0], ChangeSetItemStatus::Failed, Some("429"))
            .await
            .unwrap();
        repo.mark_item_outcome(ids[1], ChangeSetItemStatus::Indeterminate, Some("timeout"))
            .await
            .unwrap();

        assert_eq!(repo.rearm_failed_items("cs-1").await.unwrap(), 3);
        let items = repo
            .list_items("cs-1", None, PageRequest::new(50, 0))
            .await
            .unwrap();
        assert!(items
            .items
            .iter()
            .all(|i| i.status == ChangeSetItemStatus::Pending
                && i.error.is_none()
                && i.applied_at.is_none()));
    }

    #[tokio::test]
    async fn discard_only_succeeds_from_planned() {
        let repo = asset_setup().await;
        change_set_fixture(&repo).await;

        assert!(repo
            .claim_for_commit("cs-1", "hash-1", 3)
            .await
            .unwrap()
            .is_claimed());
        assert!(
            !repo.discard_change_set("cs-1").await.unwrap(),
            "a committing set is never discardable"
        );
        assert_eq!(
            repo.get_change_set("cs-1").await.unwrap().unwrap().status,
            ChangeSetStatus::Committing
        );

        repo.create_change_set(&planned_set("cs-2", 0), &[])
            .await
            .unwrap();
        assert!(repo.discard_change_set("cs-2").await.unwrap());
        assert_eq!(
            repo.get_change_set("cs-2").await.unwrap().unwrap().status,
            ChangeSetStatus::Discarded
        );
        // Idempotent second call reports "nothing to do".
        assert!(!repo.discard_change_set("cs-2").await.unwrap());
        assert!(!repo.discard_change_set("nope").await.unwrap());
    }

    #[tokio::test]
    async fn parse_naive_date_opt_errors_rather_than_inventing_a_date() {
        assert_eq!(parse_naive_date_opt(None).unwrap(), None);
        assert_eq!(
            parse_naive_date_opt(Some("2029-06-30".into())).unwrap(),
            Some(d(2029, 6, 30))
        );
        assert!(parse_naive_date_opt(Some("not-a-date".into())).is_err());
        assert!(parse_naive_date_opt(Some(String::new())).is_err());
    }

    #[tokio::test]
    async fn escape_like_neutralises_metacharacters() {
        assert_eq!(escape_like("50%"), "50\\%");
        assert_eq!(escape_like("a_b"), "a\\_b");
        assert_eq!(escape_like("c\\d"), "c\\\\d");
        assert_eq!(escape_like("plain"), "plain");
    }

    // -----------------------------------------------------------------------
    // Tickets (WS-4)
    // -----------------------------------------------------------------------

    async fn ticket_fixture() -> std::sync::Arc<SqliteRepository> {
        let repo = match DatabasePool::new_sqlite_memory().await.unwrap() {
            DatabasePool::Sqlite(p) => std::sync::Arc::new(SqliteRepository::new(p)),
            DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
        };
        repo.upsert_org(&crate::models::org::Org {
            sourced_id: "org-hs".into(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            name: "Springfield High".into(),
            org_type: OrgType::School,
            identifier: None,
            parent: None,
            children: vec![],
        })
        .await
        .unwrap();
        for sid in ["teacher-1", "tech-1"] {
            repo.upsert_user(&crate::models::user::User {
                sourced_id: sid.into(),
                status: Status::Active,
                date_last_modified: Utc::now(),
                metadata: None,
                username: sid.into(),
                user_ids: vec![],
                enabled_user: true,
                given_name: "Given".into(),
                family_name: "Family".into(),
                middle_name: None,
                role: RoleType::Teacher,
                identifier: None,
                email: Some(format!("{sid}@example.edu")),
                sms: None,
                phone: None,
                agents: vec![],
                orgs: vec![],
                grades: vec![],
            })
            .await
            .unwrap();
        }
        // Technicians a ticket can be assigned to (F1 console_users, the target
        // of the assignee FK — distinct from the roster users above).
        for (id, name) in [("tech-ana", "Ana Tech"), ("tech-1", "First Responder")] {
            let now = Utc::now();
            repo.create_console_user(&crate::models::console_user::ConsoleUser {
                id: id.into(),
                email: format!("{id}@district.test"),
                display_name: name.into(),
                password_hash: None,
                role: crate::models::console_user::ConsoleRole::Technician,
                status: crate::models::console_user::ConsoleUserStatus::Active,
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();
        }
        repo
    }

    fn new_ticket(id: &str, subject: &str) -> Ticket {
        let mut t = Ticket::new(id, subject);
        t.requester_user_sourced_id = Some("teacher-1".into());
        t.school_org_sourced_id = Some("org-hs".into());
        t
    }

    /// Numbers are allocated by the repository, monotonically, never repeating.
    /// This is what lets a district say "ticket 412" and mean one thing.
    #[tokio::test]
    async fn ticket_numbers_are_allocated_monotonically_and_never_repeat() {
        let repo = ticket_fixture().await;
        let mut seen = Vec::new();
        for i in 0..5 {
            seen.push(
                repo.create_ticket(&new_ticket(&format!("t-{i}"), "Cracked screen"))
                    .await
                    .unwrap()
                    .number,
            );
        }
        assert_eq!(seen, vec![1, 2, 3, 4, 5]);

        // The caller cannot choose one.
        let mut greedy = new_ticket("t-greedy", "Nope");
        greedy.number = 999;
        assert_eq!(
            repo.create_ticket(&greedy).await.unwrap().number,
            6,
            "the counter decides, not the caller"
        );
        assert_eq!(
            repo.get_ticket("t-greedy").await.unwrap().unwrap().number,
            6
        );
    }

    /// Concurrent submissions never share a number. Two teachers filing at once
    /// is a Monday morning, and MAX(number)+1 would collide.
    #[tokio::test]
    async fn simultaneous_tickets_never_share_a_number() {
        let repo = ticket_fixture().await;
        let mut handles = Vec::new();
        for i in 0..12 {
            let r = repo.clone();
            handles.push(tokio::spawn(async move {
                r.create_ticket(&new_ticket(&format!("c-{i}"), "Race"))
                    .await
                    .unwrap()
                    .number
            }));
        }
        let mut numbers = Vec::new();
        for h in handles {
            numbers.push(h.await.unwrap());
        }
        numbers.sort_unstable();
        numbers.dedup();
        assert_eq!(numbers.len(), 12, "every ticket got its own number");
    }

    /// The first visible reply from somebody other than the requester stamps
    /// first-response time, in the same transaction as the comment.
    #[tokio::test]
    async fn the_first_visible_reply_from_staff_stamps_first_response() {
        let repo = ticket_fixture().await;
        repo.create_ticket(&new_ticket("t-1", "Cracked screen"))
            .await
            .unwrap();
        assert!(repo
            .get_ticket("t-1")
            .await
            .unwrap()
            .unwrap()
            .first_response_at
            .is_none());

        repo.append_comment(&NewTicketComment::reply("t-1", "tech-1", "On our way"))
            .await
            .unwrap();
        let first = repo
            .get_ticket("t-1")
            .await
            .unwrap()
            .unwrap()
            .first_response_at;
        assert!(first.is_some(), "a staff reply is a first response");

        repo.append_comment(&NewTicketComment::reply("t-1", "tech-1", "Fixed"))
            .await
            .unwrap();
        assert_eq!(
            repo.get_ticket("t-1")
                .await
                .unwrap()
                .unwrap()
                .first_response_at,
            first,
            "first response is stamped once"
        );
    }

    /// An internal note is not an answer. Stamping it would let a district
    /// report a response time for a conversation nobody outside IT saw.
    #[tokio::test]
    async fn an_internal_note_is_not_a_first_response() {
        let repo = ticket_fixture().await;
        repo.create_ticket(&new_ticket("t-1", "Cracked screen"))
            .await
            .unwrap();
        repo.append_comment(&NewTicketComment::internal_note(
            "t-1",
            "tech-1",
            "ordered a part",
        ))
        .await
        .unwrap();
        assert!(
            repo.get_ticket("t-1")
                .await
                .unwrap()
                .unwrap()
                .first_response_at
                .is_none(),
            "nobody has answered the requester yet"
        );
    }

    /// The requester chasing their own ticket is not a response to it.
    #[tokio::test]
    async fn the_requester_commenting_is_not_a_first_response() {
        let repo = ticket_fixture().await;
        repo.create_ticket(&new_ticket("t-1", "Cracked screen"))
            .await
            .unwrap();
        repo.append_comment(&NewTicketComment::reply("t-1", "teacher-1", "any update?"))
            .await
            .unwrap();
        assert!(
            repo.get_ticket("t-1")
                .await
                .unwrap()
                .unwrap()
                .first_response_at
                .is_none(),
            "the requester cannot answer themselves"
        );
    }

    /// Internal notes are filtered in SQL, so one never travels to a caller who
    /// must not see it. "The template hides it" is one refactor from a leak.
    #[tokio::test]
    async fn internal_notes_are_withheld_from_the_requester_view() {
        let repo = ticket_fixture().await;
        repo.create_ticket(&new_ticket("t-1", "Cracked screen"))
            .await
            .unwrap();
        repo.append_comment(&NewTicketComment::reply("t-1", "tech-1", "On our way"))
            .await
            .unwrap();
        repo.append_comment(&NewTicketComment::internal_note(
            "t-1",
            "tech-1",
            "third time this month",
        ))
        .await
        .unwrap();

        assert_eq!(repo.list_comments("t-1", true).await.unwrap().len(), 2);
        let requester = repo.list_comments("t-1", false).await.unwrap();
        assert_eq!(requester.len(), 1);
        assert_eq!(requester[0].body, "On our way");
        assert!(!requester.iter().any(|c| c.is_internal));
    }

    /// Email dedup is an insert conflict, not a check-then-insert. A mail loop
    /// delivering twice in one second beats a read-first guard every time.
    #[tokio::test]
    async fn the_same_message_id_cannot_create_two_tickets() {
        let repo = ticket_fixture().await;
        let mut first = new_ticket("t-1", "Printer jam");
        first.email_message_id = Some("<abc@school.edu>".into());
        repo.create_ticket(&first).await.unwrap();

        let mut duplicate = new_ticket("t-2", "Printer jam");
        duplicate.email_message_id = Some("<abc@school.edu>".into());
        assert!(
            repo.create_ticket(&duplicate).await.is_err(),
            "the unique index is the dedup"
        );

        assert_eq!(
            repo.get_ticket_by_message_id("<abc@school.edu>")
                .await
                .unwrap()
                .unwrap()
                .id,
            "t-1",
            "and the ingestor can thread onto the original"
        );
    }

    /// Tickets with no Message-ID do not collide. The index is partial for
    /// exactly this reason — most tickets come from the portal.
    #[tokio::test]
    async fn tickets_without_a_message_id_do_not_collide() {
        let repo = ticket_fixture().await;
        for i in 0..3 {
            repo.create_ticket(&new_ticket(&format!("t-{i}"), "Portal"))
                .await
                .unwrap();
        }
        assert_eq!(
            repo.count_tickets(&TicketFilter::default(), &TicketScope::Unrestricted)
                .await
                .unwrap(),
            3
        );
    }

    /// Breached means overdue *and still actionable*. A resolved ticket that
    /// was late is a reporting fact, not a queue item.
    #[tokio::test]
    async fn the_breached_filter_excludes_settled_tickets() {
        let repo = ticket_fixture().await;
        let past = Utc::now() - chrono::Duration::days(2);
        for (id, status) in [
            ("t-open", TicketStatus::Open),
            ("t-resolved", TicketStatus::Resolved),
        ] {
            let mut t = new_ticket(id, "Late");
            t.sla_due_at = Some(past);
            t.status = status;
            repo.create_ticket(&t).await.unwrap();
        }
        let mut future = new_ticket("t-future", "Fine");
        future.sla_due_at = Some(Utc::now() + chrono::Duration::days(2));
        repo.create_ticket(&future).await.unwrap();

        let breached = repo
            .list_tickets(
                &TicketFilter {
                    breached_only: true,
                    ..Default::default()
                },
                &TicketScope::Unrestricted,
                PageRequest::new(50, 0),
            )
            .await
            .unwrap();
        assert_eq!(
            breached
                .items
                .iter()
                .map(|t| t.id.as_str())
                .collect::<Vec<_>>(),
            vec!["t-open"]
        );
    }

    /// Filters and paging reach the database, and the total matches.
    #[tokio::test]
    async fn ticket_filters_and_paging_reach_the_database() {
        let repo = ticket_fixture().await;
        for i in 0..7 {
            let mut t = new_ticket(&format!("t-{i}"), "Screen");
            if i % 2 == 0 {
                t.status = TicketStatus::Resolved;
            }
            if i == 3 {
                // Claimed by a technician (console_user), so it is the one
                // ticket the "unassigned" filter must exclude.
                t.assignee_console_user_id = Some("tech-1".into());
            }
            repo.create_ticket(&t).await.unwrap();
        }

        let open = repo
            .list_tickets(
                &TicketFilter {
                    status: Some(TicketStatus::Open),
                    ..Default::default()
                },
                &TicketScope::Unrestricted,
                PageRequest::new(2, 0),
            )
            .await
            .unwrap();
        assert_eq!(open.items.len(), 2, "one page");
        assert_eq!(open.total, 3, "of three matching");

        assert_eq!(
            repo.count_tickets(
                &TicketFilter {
                    unassigned: Some(true),
                    ..Default::default()
                },
                &TicketScope::Unrestricted,
            )
            .await
            .unwrap(),
            6
        );
    }

    /// Search covers subject and body, case-insensitively.
    #[tokio::test]
    async fn ticket_search_covers_subject_and_body() {
        let repo = ticket_fixture().await;
        let mut a = new_ticket("t-1", "Cracked SCREEN");
        a.body = "dropped in the hallway".into();
        repo.create_ticket(&a).await.unwrap();
        let mut b = new_ticket("t-2", "Wifi");
        b.body = "cannot reach the Screen share".into();
        repo.create_ticket(&b).await.unwrap();
        repo.create_ticket(&new_ticket("t-3", "Printer"))
            .await
            .unwrap();

        assert_eq!(
            repo.count_tickets(
                &TicketFilter {
                    search: Some("screen".into()),
                    ..Default::default()
                },
                &TicketScope::Unrestricted,
            )
            .await
            .unwrap(),
            2,
            "subject and body, either case"
        );
    }

    /// A scoped filter narrows within the boundary and never past it.
    #[tokio::test]
    async fn the_school_set_filter_intersects_rather_than_replaces() {
        let repo = ticket_fixture().await;
        repo.upsert_org(&crate::models::org::Org {
            sourced_id: "org-ms".into(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            name: "Shelbyville Middle".into(),
            org_type: OrgType::School,
            identifier: None,
            parent: None,
            children: vec![],
        })
        .await
        .unwrap();
        repo.create_ticket(&new_ticket("t-hs", "High school"))
            .await
            .unwrap();
        let mut ms = new_ticket("t-ms", "Middle school");
        ms.school_org_sourced_id = Some("org-ms".into());
        repo.create_ticket(&ms).await.unwrap();

        let out = repo
            .list_tickets(
                &TicketFilter {
                    school_org_sourced_id: Some("org-ms".into()),
                    ..Default::default()
                },
                &TicketScope::Schools(vec!["org-hs".into()]),
                PageRequest::new(50, 0),
            )
            .await
            .unwrap();
        assert!(out.items.is_empty(), "the filter must not widen the scope");

        // And within the boundary the caller's filter still works.
        let inside = repo
            .list_tickets(
                &TicketFilter::default(),
                &TicketScope::Schools(vec!["org-hs".into()]),
                PageRequest::new(50, 0),
            )
            .await
            .unwrap();
        assert_eq!(
            inside
                .items
                .iter()
                .map(|t| t.id.as_str())
                .collect::<Vec<_>>(),
            vec!["t-hs"]
        );

        // A grant that named no schools grants nothing — not everything.
        let none = repo
            .list_tickets(
                &TicketFilter::default(),
                &TicketScope::Schools(Vec::new()),
                PageRequest::new(50, 0),
            )
            .await
            .unwrap();
        assert!(none.items.is_empty(), "an empty grant sees nothing");
        assert_eq!(none.total, 0, "and the total must agree");
    }

    /// A patch clears deliberately and leaves unmentioned columns alone.
    #[tokio::test]
    async fn a_ticket_patch_distinguishes_clearing_from_leaving_alone() {
        let repo = ticket_fixture().await;
        let mut t = new_ticket("t-1", "Cracked screen");
        t.assignee_user_sourced_id = Some("tech-1".into());
        t.category = Some("hardware".into());
        repo.create_ticket(&t).await.unwrap();

        assert!(repo
            .update_ticket(
                "t-1",
                &TicketPatch {
                    status: Some(TicketStatus::InProgress),
                    assignee_user_sourced_id: Patch::Clear,
                    ..Default::default()
                },
            )
            .await
            .unwrap());

        let after = repo.get_ticket("t-1").await.unwrap().unwrap();
        assert_eq!(after.status, TicketStatus::InProgress);
        assert_eq!(
            after.assignee_user_sourced_id, None,
            "explicitly unassigned"
        );
        assert_eq!(
            after.category.as_deref(),
            Some("hardware"),
            "never mentioned, so untouched"
        );
        assert!(
            !repo
                .update_ticket("nope", &TicketPatch::default())
                .await
                .unwrap(),
            "a missing ticket reports false"
        );
    }

    /// A technician claims a ticket, it leaves the unassigned queue and joins
    /// their own, and unassigning reverses both.
    #[tokio::test]
    async fn a_ticket_is_claimed_and_released_by_a_technician() {
        let repo = ticket_fixture().await;
        repo.create_ticket(&new_ticket("t-1", "Cracked screen"))
            .await
            .unwrap();

        // Born unassigned.
        assert_eq!(
            repo.count_tickets(
                &TicketFilter {
                    unassigned: Some(true),
                    ..Default::default()
                },
                &TicketScope::Unrestricted,
            )
            .await
            .unwrap(),
            1
        );

        assert!(repo
            .update_ticket(
                "t-1",
                &TicketPatch {
                    assignee_console_user_id: Patch::Set("tech-ana".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap());

        let after = repo.get_ticket("t-1").await.unwrap().unwrap();
        assert_eq!(after.assignee_console_user_id.as_deref(), Some("tech-ana"));

        // Off the unassigned queue, on to Ana's.
        assert_eq!(
            repo.count_tickets(
                &TicketFilter {
                    unassigned: Some(true),
                    ..Default::default()
                },
                &TicketScope::Unrestricted,
            )
            .await
            .unwrap(),
            0,
            "claimed, so no longer unassigned"
        );
        assert_eq!(
            repo.count_tickets(
                &TicketFilter {
                    assignee_console_user_id: Some("tech-ana".into()),
                    ..Default::default()
                },
                &TicketScope::Unrestricted,
            )
            .await
            .unwrap(),
            1,
            "in Ana's queue"
        );

        // Release it.
        assert!(repo
            .update_ticket(
                "t-1",
                &TicketPatch {
                    assignee_console_user_id: Patch::Clear,
                    ..Default::default()
                },
            )
            .await
            .unwrap());
        let after = repo.get_ticket("t-1").await.unwrap().unwrap();
        assert_eq!(after.assignee_console_user_id, None, "released");
    }

    /// Tags round-trip normalized, replace wholesale, and drive the filter.
    #[tokio::test]
    async fn ticket_tags_are_normalized_replaced_and_filterable() {
        let repo = ticket_fixture().await;
        repo.create_ticket(&new_ticket("t-1", "Wifi drops"))
            .await
            .unwrap();
        repo.create_ticket(&new_ticket("t-2", "Printer jam"))
            .await
            .unwrap();

        // " WiFi " and "wifi" are one tag, and the empty entry is dropped.
        repo.set_ticket_tags(
            "t-1",
            &[" WiFi ".into(), "wifi".into(), "cart".into(), " ".into()],
        )
        .await
        .unwrap();
        assert_eq!(
            repo.get_ticket_tags("t-1").await.unwrap(),
            vec!["cart", "wifi"]
        );

        // The filter matches by normalized tag, in SQL.
        let hit = repo
            .count_tickets(
                &TicketFilter {
                    tag: Some("WIFI".into()),
                    ..Default::default()
                },
                &TicketScope::Unrestricted,
            )
            .await
            .unwrap();
        assert_eq!(hit, 1, "only the tagged ticket matches");

        // Replace-all: the new set is the whole truth.
        repo.set_ticket_tags("t-1", &["printer".into()])
            .await
            .unwrap();
        assert_eq!(
            repo.get_ticket_tags("t-1").await.unwrap(),
            vec!["printer"],
            "old tags are gone"
        );

        // The distinct list serves the dropdown; batch fetch serves the queue.
        repo.set_ticket_tags("t-2", &["printer".into(), "urgent-parent".into()])
            .await
            .unwrap();
        assert_eq!(
            repo.list_all_tags().await.unwrap(),
            vec!["printer", "urgent-parent"]
        );
        let batch = repo
            .get_tags_for_tickets(&["t-1".into(), "t-2".into()])
            .await
            .unwrap();
        assert_eq!(batch.len(), 3, "two tickets, three tag rows");
    }

    /// Saved views store the queue's own query string and round-trip.
    #[tokio::test]
    async fn saved_views_round_trip_and_delete() {
        use crate::models::saved_view::SavedView;
        let repo = ticket_fixture().await;

        repo.create_saved_view(&SavedView::new(
            "v-1",
            "Unassigned urgent",
            "assigned=unassigned&priority=urgent",
        ))
        .await
        .unwrap();

        let all = repo.list_saved_views().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "Unassigned urgent");
        assert_eq!(all[0].query_string, "assigned=unassigned&priority=urgent");

        repo.delete_saved_view("v-1").await.unwrap();
        assert!(repo.list_saved_views().await.unwrap().is_empty());
    }
}
