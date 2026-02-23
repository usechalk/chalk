use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use sqlx::{Row, SqlitePool};

use crate::error::Result;
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
    OidcAuthorizationCode, PortalSession, SsoPartner, SsoPartnerSource, SsoProtocol,
};

use super::repository::{
    AcademicSessionRepository, AdSyncRunRepository, AdSyncStateRepository, AdminAuditRepository,
    AdminSessionRepository, ChalkRepository, ClassRepository, ConfigRepository, CourseRepository,
    DemographicsRepository, EnrollmentRepository, ExternalIdRepository, GoogleSyncRunRepository,
    GoogleSyncStateRepository, IdpAuthLogRepository, IdpSessionRepository, OidcCodeRepository,
    OrgRepository, PasswordRepository, PicturePasswordRepository, PortalSessionRepository,
    QrBadgeRepository, SsoPartnerRepository, SyncRepository, UserRepository,
    WebhookDeliveryRepository, WebhookEndpointRepository,
};

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

fn parse_datetime(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
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
            Some(r) => Ok(Some(Enrollment {
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
            })),
            None => Ok(None),
        }
    }

    async fn list_enrollments(&self) -> Result<Vec<Enrollment>> {
        let rows = sqlx::query(
            "SELECT sourced_id, status, date_last_modified, metadata, user_sourced_id, class_sourced_id, school_sourced_id, role, is_primary, begin_date, end_date FROM enrollments"
        )
        .fetch_all(&self.pool)
        .await?;

        let enrollments: Vec<Enrollment> = rows
            .iter()
            .map(|r| Enrollment {
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
            })
            .collect();

        Ok(enrollments)
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
            "INSERT INTO admin_sessions (token, created_at, expires_at, ip_address) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&session.token)
        .bind(session.created_at.format("%Y-%m-%d %H:%M:%S").to_string())
        .bind(session.expires_at.format("%Y-%m-%d %H:%M:%S").to_string())
        .bind(&session.ip_address)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_admin_session(&self, token: &str) -> Result<Option<AdminSession>> {
        let row = sqlx::query(
            "SELECT token, created_at, expires_at, ip_address FROM admin_sessions WHERE token = ?1",
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

fn row_to_sso_partner(r: &sqlx::sqlite::SqliteRow) -> SsoPartner {
    let roles_json: String = r.get("roles_json");
    let roles: Vec<String> = serde_json::from_str(&roles_json).unwrap_or_default();
    let uris_json: String = r.get("oidc_redirect_uris_json");
    let oidc_redirect_uris: Vec<String> = serde_json::from_str(&uris_json).unwrap_or_default();

    SsoPartner {
        id: r.get("id"),
        name: r.get("name"),
        logo_url: r.get("logo_url"),
        protocol: parse_sso_protocol(r.get("protocol")),
        enabled: r.get::<bool, _>("enabled"),
        source: parse_sso_source(r.get("source")),
        tenant_id: r.get("tenant_id"),
        roles,
        saml_entity_id: r.get("saml_entity_id"),
        saml_acs_url: r.get("saml_acs_url"),
        oidc_client_id: r.get("oidc_client_id"),
        oidc_client_secret: r.get("oidc_client_secret"),
        oidc_redirect_uris,
        created_at: parse_datetime(r.get("created_at")),
        updated_at: parse_datetime(r.get("updated_at")),
    }
}

#[async_trait]
impl SsoPartnerRepository for SqliteRepository {
    async fn upsert_sso_partner(&self, partner: &SsoPartner) -> Result<()> {
        let roles_json = serde_json::to_string(&partner.roles)
            .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?;
        let uris_json = serde_json::to_string(&partner.oidc_redirect_uris)
            .map_err(|e| crate::error::ChalkError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO sso_partners (id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                logo_url = excluded.logo_url,
                protocol = excluded.protocol,
                enabled = excluded.enabled,
                source = excluded.source,
                tenant_id = excluded.tenant_id,
                roles_json = excluded.roles_json,
                saml_entity_id = excluded.saml_entity_id,
                saml_acs_url = excluded.saml_acs_url,
                oidc_client_id = excluded.oidc_client_id,
                oidc_client_secret = excluded.oidc_client_secret,
                oidc_redirect_uris_json = excluded.oidc_redirect_uris_json,
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
        .bind(&partner.saml_entity_id)
        .bind(&partner.saml_acs_url)
        .bind(&partner.oidc_client_id)
        .bind(&partner.oidc_client_secret)
        .bind(&uris_json)
        .bind(datetime_to_str(&partner.created_at))
        .bind(datetime_to_str(&partner.updated_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_sso_partner(&self, id: &str) -> Result<Option<SsoPartner>> {
        let row = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners WHERE id = ?1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.as_ref().map(row_to_sso_partner))
    }

    async fn get_sso_partner_by_entity_id(&self, entity_id: &str) -> Result<Option<SsoPartner>> {
        let row = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners WHERE saml_entity_id = ?1"
        )
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.as_ref().map(row_to_sso_partner))
    }

    async fn get_sso_partner_by_client_id(&self, client_id: &str) -> Result<Option<SsoPartner>> {
        let row = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners WHERE oidc_client_id = ?1"
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
        // Fetch all enabled partners and filter by role in-memory
        // (JSON role matching in SQL is fragile; list is small)
        let rows = sqlx::query(
            "SELECT id, name, logo_url, protocol, enabled, source, tenant_id, roles_json, saml_entity_id, saml_acs_url, oidc_client_id, oidc_client_secret, oidc_redirect_uris_json, created_at, updated_at FROM sso_partners WHERE enabled = 1 ORDER BY name"
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
pub async fn effective_schedule(
    repo: &impl ConfigRepository,
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
        errors: i64,
        error_details: Option<&str>,
    ) -> Result<()> {
        let now_str = datetime_to_str(&Utc::now());
        sqlx::query(
            "UPDATE ad_sync_runs SET status = ?2, completed_at = ?3, users_created = ?4, users_updated = ?5, users_disabled = ?6, users_skipped = ?7, errors = ?8, error_details = ?9 WHERE id = ?1"
        )
        .bind(id)
        .bind(ad_sync_run_status_to_str(&status))
        .bind(&now_str)
        .bind(users_created)
        .bind(users_updated)
        .bind(users_disabled)
        .bind(users_skipped)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repository::{
        AdminAuditRepository, AdminSessionRepository, ConfigRepository, GoogleSyncRunRepository,
        GoogleSyncStateRepository, IdpAuthLogRepository, IdpSessionRepository, PasswordRepository,
        PicturePasswordRepository, QrBadgeRepository, WebhookDeliveryRepository,
        WebhookEndpointRepository,
    };
    use crate::db::DatabasePool;
    use crate::models::common::{
        ClassType, EnrollmentRole, OrgType, RoleType, SessionType, Sex, Status,
    };
    use chrono::TimeZone;

    async fn setup() -> SqliteRepository {
        let pool = DatabasePool::new_sqlite_memory().await.unwrap();
        match pool {
            DatabasePool::Sqlite(p) => SqliteRepository::new(p),
        }
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
        };
        repo.create_admin_session(&expired).await.unwrap();

        // Create a valid session
        let valid = AdminSession {
            token: "valid-token".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            ip_address: None,
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
}
