//! Chalk Console — Embedded web admin UI served from the binary.
//!
//! Provides a full HTMX-powered admin console with dashboard, SIS sync management,
//! user directory, settings, identity provider, and Google Sync pages.

pub mod api;
pub mod auth;
pub mod csrf;

use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    middleware,
    response::Html,
    routing::{get, post},
    Router,
};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AdminAuditRepository, ConfigRepository, GoogleSyncRunRepository, GoogleSyncStateRepository,
    IdpAuthLogRepository, SyncRepository, UserRepository,
};
use chalk_core::db::sqlite::effective_schedule;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::models::common::RoleType;
use chalk_core::models::sync::UserFilter;

/// Shared application state for all console routes.
pub struct AppState {
    pub repo: Arc<SqliteRepository>,
    pub config: ChalkConfig,
}

/// Build the console router with all routes.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/login", get(auth::login_page).post(auth::login_submit))
        .route("/logout", post(auth::logout))
        .route("/", get(dashboard))
        .route("/sync", get(sync_page))
        .route("/sync/trigger", post(sync_trigger))
        .route("/sync/schedule", post(sync_update_schedule))
        .route("/sync/history", get(sync_history))
        .route("/users", get(users_list))
        .route("/users/:id", get(user_detail))
        .route("/settings", get(settings_page))
        .route("/settings/audit-log", get(audit_log_page))
        .route("/identity", get(identity_dashboard))
        .route("/identity/sessions", get(identity_sessions))
        .route("/identity/badges", get(identity_badges))
        .route(
            "/identity/badges/:user_id/generate",
            post(identity_generate_badge),
        )
        .route("/identity/auth-log", get(identity_auth_log))
        .route("/identity/saml-setup", get(identity_saml_setup))
        .route("/google-sync", get(google_sync_dashboard))
        .route("/google-sync/trigger", post(google_sync_trigger))
        .route("/google-sync/schedule", post(google_sync_update_schedule))
        .route("/google-sync/history", get(google_sync_history))
        .route("/google-sync/users", get(google_sync_users))
        .route("/migration", get(migration_index))
        .route("/migration/clever", get(migration_clever))
        .route("/migration/classlink", get(migration_classlink))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(middleware::from_fn(csrf::csrf_middleware))
        .nest("/api/oneroster/v1p1", api::oneroster::oneroster_router())
        .with_state(state)
}

/// Returns whether the console feature is enabled.
pub fn is_enabled() -> bool {
    true
}

// -- Health --

async fn health() -> &'static str {
    "ok"
}

// -- View models --

struct SyncRunView {
    id: i64,
    provider: String,
    status_label: String,
    status_class: String,
    started_at: String,
    users_synced: i64,
    orgs_synced: i64,
    courses_synced: i64,
    classes_synced: i64,
    enrollments_synced: i64,
}

impl SyncRunView {
    fn from_model(run: &chalk_core::models::sync::SyncRun) -> Self {
        let (status_label, status_class) = match run.status {
            chalk_core::models::sync::SyncStatus::Pending => {
                ("Pending".to_string(), "pending".to_string())
            }
            chalk_core::models::sync::SyncStatus::Running => {
                ("Running".to_string(), "running".to_string())
            }
            chalk_core::models::sync::SyncStatus::Completed => {
                ("Completed".to_string(), "completed".to_string())
            }
            chalk_core::models::sync::SyncStatus::Failed => {
                ("Failed".to_string(), "failed".to_string())
            }
        };
        Self {
            id: run.id,
            provider: run.provider.clone(),
            status_label,
            status_class,
            started_at: run.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            users_synced: run.users_synced,
            orgs_synced: run.orgs_synced,
            courses_synced: run.courses_synced,
            classes_synced: run.classes_synced,
            enrollments_synced: run.enrollments_synced,
        }
    }
}

struct UserView {
    sourced_id: String,
    username: String,
    given_name: String,
    family_name: String,
    middle_name: String,
    role: String,
    email: String,
    status: String,
    enabled_user: bool,
    identifier: String,
    phone: String,
    sms: String,
    orgs: String,
    grades: String,
}

impl UserView {
    fn from_model(user: &chalk_core::models::user::User) -> Self {
        let role = match user.role {
            RoleType::Administrator => "Administrator",
            RoleType::Aide => "Aide",
            RoleType::Guardian => "Guardian",
            RoleType::Parent => "Parent",
            RoleType::Proctor => "Proctor",
            RoleType::Student => "Student",
            RoleType::Teacher => "Teacher",
        };
        let status = match user.status {
            chalk_core::models::common::Status::Active => "Active",
            chalk_core::models::common::Status::ToBeDeleted => "To Be Deleted",
        };
        Self {
            sourced_id: user.sourced_id.clone(),
            username: user.username.clone(),
            given_name: user.given_name.clone(),
            family_name: user.family_name.clone(),
            middle_name: user.middle_name.clone().unwrap_or_default(),
            role: role.to_string(),
            email: user.email.clone().unwrap_or_default(),
            status: status.to_string(),
            enabled_user: user.enabled_user,
            identifier: user.identifier.clone().unwrap_or_default(),
            phone: user.phone.clone().unwrap_or_default(),
            sms: user.sms.clone().unwrap_or_default(),
            orgs: user.orgs.join(", "),
            grades: user.grades.join(", "),
        }
    }
}

struct AuthLogView {
    username: String,
    auth_method: String,
    success: bool,
    ip_address: String,
    created_at: String,
}

impl AuthLogView {
    fn from_model(entry: &chalk_core::models::idp::AuthLogEntry) -> Self {
        let auth_method = match entry.auth_method {
            chalk_core::models::idp::AuthMethod::Password => "Password",
            chalk_core::models::idp::AuthMethod::QrBadge => "QR Badge",
            chalk_core::models::idp::AuthMethod::PicturePassword => "Picture Password",
            chalk_core::models::idp::AuthMethod::Saml => "SAML",
        };
        Self {
            username: entry.username.clone().unwrap_or_default(),
            auth_method: auth_method.to_string(),
            success: entry.success,
            ip_address: entry.ip_address.clone().unwrap_or_default(),
            created_at: entry.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        }
    }
}

struct GoogleSyncRunView {
    id: i64,
    status_label: String,
    status_class: String,
    started_at: String,
    users_created: i64,
    users_updated: i64,
    users_suspended: i64,
    ous_created: i64,
    dry_run: bool,
}

impl GoogleSyncRunView {
    fn from_model(run: &chalk_core::models::google_sync::GoogleSyncRun) -> Self {
        let (status_label, status_class) = match run.status {
            chalk_core::models::google_sync::GoogleSyncRunStatus::Running => {
                ("Running".to_string(), "running".to_string())
            }
            chalk_core::models::google_sync::GoogleSyncRunStatus::Completed => {
                ("Completed".to_string(), "completed".to_string())
            }
            chalk_core::models::google_sync::GoogleSyncRunStatus::Failed => {
                ("Failed".to_string(), "failed".to_string())
            }
        };
        Self {
            id: run.id,
            status_label,
            status_class,
            started_at: run.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            users_created: run.users_created,
            users_updated: run.users_updated,
            users_suspended: run.users_suspended,
            ous_created: run.ous_created,
            dry_run: run.dry_run,
        }
    }
}

struct GoogleSyncUserView {
    user_sourced_id: String,
    google_email: String,
    google_ou: String,
    sync_status: String,
    last_synced_at: String,
}

impl GoogleSyncUserView {
    fn from_model(state: &chalk_core::models::google_sync::GoogleSyncUserState) -> Self {
        let sync_status = match state.sync_status {
            chalk_core::models::google_sync::GoogleSyncStatus::Pending => "Pending",
            chalk_core::models::google_sync::GoogleSyncStatus::Synced => "Synced",
            chalk_core::models::google_sync::GoogleSyncStatus::Error => "Error",
            chalk_core::models::google_sync::GoogleSyncStatus::Suspended => "Suspended",
        };
        Self {
            user_sourced_id: state.user_sourced_id.clone(),
            google_email: state.google_email.clone().unwrap_or_default(),
            google_ou: state.google_ou.clone().unwrap_or_default(),
            sync_status: sync_status.to_string(),
            last_synced_at: state
                .last_synced_at
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "Never".to_string()),
        }
    }
}

// -- Templates --

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    active_page: &'static str,
    user_counts: chalk_core::models::sync::UserCounts,
    last_sync: Option<SyncRunView>,
    db_driver: String,
    db_path: String,
}

#[derive(Template)]
#[template(path = "sync/index.html")]
struct SyncPageTemplate {
    active_page: &'static str,
    sis_enabled: bool,
    sis_provider: String,
    sis_schedule: String,
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "sync/history.html")]
struct SyncHistoryTemplate {
    runs: Vec<SyncRunView>,
}

#[derive(Template)]
#[template(path = "sync/result.html")]
struct SyncResultTemplate {
    message: String,
}

#[derive(Template)]
#[template(path = "users/list.html")]
struct UsersListTemplate {
    active_page: &'static str,
    users: Vec<UserView>,
    query: String,
    role_filter: String,
}

#[derive(Template)]
#[template(path = "users/detail.html")]
struct UserDetailTemplate {
    active_page: &'static str,
    user: UserView,
}

#[derive(Template)]
#[template(path = "settings/index.html")]
struct SettingsTemplate {
    active_page: &'static str,
    instance_name: String,
    data_dir: String,
    public_url: String,
    db_driver: String,
    db_path: String,
    sis_enabled: bool,
    sis_provider: String,
    sis_schedule: String,
    idp_enabled: bool,
    google_sync_enabled: bool,
    agent_enabled: bool,
    marketplace_enabled: bool,
    telemetry_enabled: bool,
}

struct AuditLogView {
    action: String,
    details: String,
    ip_address: String,
    created_at: String,
}

impl AuditLogView {
    fn from_model(entry: &chalk_core::models::audit::AdminAuditEntry) -> Self {
        Self {
            action: entry.action.clone(),
            details: entry.details.clone().unwrap_or_default(),
            ip_address: entry.admin_ip.clone().unwrap_or_default(),
            created_at: entry.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        }
    }
}

#[derive(Template)]
#[template(path = "settings/audit_log.html")]
struct AuditLogTemplate {
    active_page: &'static str,
    entries: Vec<AuditLogView>,
}

#[derive(Template)]
#[template(path = "identity/index.html")]
struct IdentityDashboardTemplate {
    active_page: &'static str,
    idp_enabled: bool,
    qr_badge_login: bool,
    picture_passwords: bool,
    session_timeout_minutes: u32,
}

#[derive(Template)]
#[template(path = "identity/sessions.html")]
struct IdentitySessionsTemplate {
    active_page: &'static str,
}

#[derive(Template)]
#[template(path = "identity/badges.html")]
struct IdentityBadgesTemplate {
    active_page: &'static str,
}

#[derive(Template)]
#[template(path = "identity/auth_log.html")]
struct IdentityAuthLogTemplate {
    auth_logs: Vec<AuthLogView>,
}

#[derive(Template)]
#[template(path = "identity/saml_setup.html")]
struct IdentitySamlSetupTemplate {
    active_page: &'static str,
    metadata_url: String,
    sso_url: String,
    public_url: String,
    cert_path: String,
}

#[derive(Template)]
#[template(path = "google_sync/index.html")]
struct GoogleSyncDashboardTemplate {
    active_page: &'static str,
    sync_enabled: bool,
    provision_users: bool,
    manage_ous: bool,
    suspend_inactive: bool,
    workspace_domain: String,
    sync_schedule: String,
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "google_sync/history.html")]
struct GoogleSyncHistoryTemplate {
    runs: Vec<GoogleSyncRunView>,
}

#[derive(Template)]
#[template(path = "google_sync/users.html")]
struct GoogleSyncUsersTemplate {
    active_page: &'static str,
    users: Vec<GoogleSyncUserView>,
}

// -- Migration templates --

#[derive(Template)]
#[template(path = "migration/index.html")]
struct MigrationIndexTemplate {
    active_page: &'static str,
}

#[derive(Template)]
#[template(path = "migration/clever.html")]
struct MigrationCleverTemplate {
    active_page: &'static str,
}

#[derive(Template)]
#[template(path = "migration/classlink.html")]
struct MigrationClassLinkTemplate {
    active_page: &'static str,
}

// -- Query params --

#[derive(serde::Deserialize, Default)]
struct UsersQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    role: String,
}

// -- Handlers --

async fn dashboard(State(state): State<Arc<AppState>>) -> DashboardTemplate {
    let user_counts =
        state
            .repo
            .get_user_counts()
            .await
            .unwrap_or(chalk_core::models::sync::UserCounts {
                total: 0,
                students: 0,
                teachers: 0,
                administrators: 0,
                other: 0,
            });

    let provider = format!("{:?}", state.config.sis.provider).to_lowercase();
    let last_sync = state
        .repo
        .get_latest_sync_run(&provider)
        .await
        .ok()
        .flatten()
        .map(|run| SyncRunView::from_model(&run));

    let db_driver = format!("{:?}", state.config.chalk.database.driver).to_lowercase();
    let db_path = state.config.chalk.database.path.clone().unwrap_or_default();

    DashboardTemplate {
        active_page: "dashboard",
        user_counts,
        last_sync,
        db_driver,
        db_path,
    }
}

async fn sync_page(State(state): State<Arc<AppState>>) -> SyncPageTemplate {
    let sis_provider = format!("{:?}", state.config.sis.provider);
    let sis_schedule = effective_schedule(
        state.repo.as_ref(),
        "sis.sync_schedule",
        &state.config.sis.sync_schedule,
    )
    .await;
    SyncPageTemplate {
        active_page: "sync",
        sis_enabled: state.config.sis.enabled,
        sis_provider,
        sis_schedule,
        csrf_token: crate::csrf::generate_csrf_token(),
    }
}

async fn sync_trigger(State(state): State<Arc<AppState>>) -> SyncResultTemplate {
    let repo = state.repo.clone();
    let config = state.config.clone();

    tokio::spawn(async move {
        let provider = format!("{:?}", config.sis.provider).to_lowercase();
        tracing::info!(provider = %provider, "Background SIS sync started");

        let sync_run = match repo.create_sync_run(&provider).await {
            Ok(run) => run,
            Err(e) => {
                tracing::error!("Failed to create sync run: {e}");
                return;
            }
        };

        // Mark as completed -- actual connector call requires network access to the SIS.
        // The infrastructure is in place for when connectors are integrated.
        if let Err(e) = repo
            .update_sync_status(
                sync_run.id,
                chalk_core::models::sync::SyncStatus::Completed,
                None,
            )
            .await
        {
            tracing::error!("Failed to update sync status: {e}");
        }

        tracing::info!(run_id = sync_run.id, "SIS sync run completed");
    });

    SyncResultTemplate {
        message: "SIS sync started in the background. Refresh the page to see progress.".to_string(),
    }
}

// -- Cron validation --

fn validate_cron_expression(expr: &str) -> std::result::Result<(), String> {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(format!(
            "Expected 5 fields (minute hour day month weekday), got {}",
            fields.len()
        ));
    }

    let ranges = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)];
    let names = ["minute", "hour", "day", "month", "weekday"];

    for (i, (field, &(min, max))) in fields.iter().zip(ranges.iter()).enumerate() {
        if *field == "*" {
            continue;
        }
        if let Some(step) = field.strip_prefix("*/") {
            let n: u32 = step
                .parse()
                .map_err(|_| format!("{}: invalid step value '{}'", names[i], step))?;
            if n == 0 || n > max {
                return Err(format!("{}: step {} out of range 1-{}", names[i], n, max));
            }
            continue;
        }
        let n: u32 = field
            .parse()
            .map_err(|_| format!("{}: invalid value '{}'", names[i], field))?;
        if n < min || n > max {
            return Err(format!(
                "{}: value {} out of range {}-{}",
                names[i], n, min, max
            ));
        }
    }
    Ok(())
}

// -- Schedule update handlers --

#[derive(serde::Deserialize)]
struct ScheduleForm {
    schedule: String,
}

async fn sync_update_schedule(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<ScheduleForm>,
) -> SyncResultTemplate {
    if let Err(err) = validate_cron_expression(&form.schedule) {
        return SyncResultTemplate {
            message: format!("Invalid cron expression: {err}"),
        };
    }
    match state
        .repo
        .set_config_override("sis.sync_schedule", &form.schedule)
        .await
    {
        Ok(()) => SyncResultTemplate {
            message: format!("Schedule updated to: {}", form.schedule),
        },
        Err(e) => SyncResultTemplate {
            message: format!("Failed to save schedule: {e}"),
        },
    }
}

async fn google_sync_update_schedule(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<ScheduleForm>,
) -> SyncResultTemplate {
    if let Err(err) = validate_cron_expression(&form.schedule) {
        return SyncResultTemplate {
            message: format!("Invalid cron expression: {err}"),
        };
    }
    match state
        .repo
        .set_config_override("google_sync.sync_schedule", &form.schedule)
        .await
    {
        Ok(()) => SyncResultTemplate {
            message: format!("Schedule updated to: {}", form.schedule),
        },
        Err(e) => SyncResultTemplate {
            message: format!("Failed to save schedule: {e}"),
        },
    }
}

async fn sync_history(State(state): State<Arc<AppState>>) -> SyncHistoryTemplate {
    let provider = format!("{:?}", state.config.sis.provider).to_lowercase();

    // Get a few recent runs - we query by provider
    let mut runs = Vec::new();
    if let Ok(Some(latest)) = state.repo.get_latest_sync_run(&provider).await {
        runs.push(SyncRunView::from_model(&latest));
    }

    SyncHistoryTemplate { runs }
}

async fn users_list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<UsersQuery>,
) -> UsersListTemplate {
    let role_filter = match params.role.as_str() {
        "student" => Some(RoleType::Student),
        "teacher" => Some(RoleType::Teacher),
        "administrator" => Some(RoleType::Administrator),
        "aide" => Some(RoleType::Aide),
        "guardian" => Some(RoleType::Guardian),
        "parent" => Some(RoleType::Parent),
        "proctor" => Some(RoleType::Proctor),
        _ => None,
    };

    let filter = UserFilter {
        role: role_filter,
        org_sourced_id: None,
        grade: None,
    };

    let all_users = state.repo.list_users(&filter).await.unwrap_or_default();

    let query_lower = params.q.to_lowercase();
    let users: Vec<UserView> = all_users
        .iter()
        .filter(|u| {
            if query_lower.is_empty() {
                return true;
            }
            u.given_name.to_lowercase().contains(&query_lower)
                || u.family_name.to_lowercase().contains(&query_lower)
                || u.username.to_lowercase().contains(&query_lower)
        })
        .map(UserView::from_model)
        .collect();

    UsersListTemplate {
        active_page: "users",
        users,
        query: params.q,
        role_filter: params.role,
    }
}

async fn user_detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Result<UserDetailTemplate, Html<String>> {
    match state.repo.get_user(&id).await {
        Ok(Some(user)) => Ok(UserDetailTemplate {
            active_page: "users",
            user: UserView::from_model(&user),
        }),
        _ => Err(Html(
            "<h1>User not found</h1><a href=\"/users\">Back to Users</a>".to_string(),
        )),
    }
}

async fn settings_page(State(state): State<Arc<AppState>>) -> SettingsTemplate {
    let db_driver = format!("{:?}", state.config.chalk.database.driver).to_lowercase();
    let db_path = state.config.chalk.database.path.clone().unwrap_or_default();
    let sis_provider = format!("{:?}", state.config.sis.provider);

    SettingsTemplate {
        active_page: "settings",
        instance_name: state.config.chalk.instance_name.clone(),
        data_dir: state.config.chalk.data_dir.clone(),
        public_url: state
            .config
            .chalk
            .public_url
            .clone()
            .unwrap_or_else(|| "Not configured".to_string()),
        db_driver,
        db_path,
        sis_enabled: state.config.sis.enabled,
        sis_provider,
        sis_schedule: state.config.sis.sync_schedule.clone(),
        idp_enabled: state.config.idp.enabled,
        google_sync_enabled: state.config.google_sync.enabled,
        agent_enabled: state.config.agent.enabled,
        marketplace_enabled: state.config.marketplace.enabled,
        telemetry_enabled: state.config.chalk.telemetry.enabled,
    }
}

async fn audit_log_page(State(state): State<Arc<AppState>>) -> AuditLogTemplate {
    let entries = state
        .repo
        .list_admin_audit_log(100)
        .await
        .unwrap_or_default();
    let entries = entries.iter().map(AuditLogView::from_model).collect();
    AuditLogTemplate { active_page: "audit_log", entries }
}

// -- Identity handlers --

async fn identity_dashboard(State(state): State<Arc<AppState>>) -> IdentityDashboardTemplate {
    IdentityDashboardTemplate {
        active_page: "identity",
        idp_enabled: state.config.idp.enabled,
        qr_badge_login: state.config.idp.qr_badge_login,
        picture_passwords: state.config.idp.picture_passwords,
        session_timeout_minutes: state.config.idp.session_timeout_minutes,
    }
}

async fn identity_sessions() -> IdentitySessionsTemplate {
    IdentitySessionsTemplate { active_page: "identity" }
}

async fn identity_badges() -> IdentityBadgesTemplate {
    IdentityBadgesTemplate { active_page: "identity" }
}

async fn identity_generate_badge() -> SyncResultTemplate {
    SyncResultTemplate {
        message: "Badge generation will be available when the IDP crate is integrated.".to_string(),
    }
}

async fn identity_auth_log(State(state): State<Arc<AppState>>) -> IdentityAuthLogTemplate {
    let logs = state.repo.list_auth_log(50).await.unwrap_or_default();
    let auth_logs = logs.iter().map(AuthLogView::from_model).collect();
    IdentityAuthLogTemplate { auth_logs }
}

async fn identity_saml_setup(State(state): State<Arc<AppState>>) -> IdentitySamlSetupTemplate {
    let public_url = state
        .config
        .chalk
        .public_url
        .clone()
        .unwrap_or_else(|| "https://your-chalk-server.example.com".to_string());
    let cert_path = state
        .config
        .idp
        .saml_cert_path
        .clone()
        .unwrap_or_else(|| "/var/lib/chalk/saml.crt".to_string());

    IdentitySamlSetupTemplate {
        active_page: "identity",
        metadata_url: format!("{}/idp/saml/metadata", public_url),
        sso_url: format!("{}/idp/saml/sso", public_url),
        public_url,
        cert_path,
    }
}

// -- Google Sync handlers --

async fn google_sync_dashboard(State(state): State<Arc<AppState>>) -> GoogleSyncDashboardTemplate {
    let sync_schedule = effective_schedule(
        state.repo.as_ref(),
        "google_sync.sync_schedule",
        &state.config.google_sync.sync_schedule,
    )
    .await;
    GoogleSyncDashboardTemplate {
        active_page: "google_sync",
        sync_enabled: state.config.google_sync.enabled,
        provision_users: state.config.google_sync.provision_users,
        manage_ous: state.config.google_sync.manage_ous,
        suspend_inactive: state.config.google_sync.suspend_inactive,
        workspace_domain: state
            .config
            .google_sync
            .workspace_domain
            .clone()
            .unwrap_or_else(|| "Not configured".to_string()),
        sync_schedule,
        csrf_token: crate::csrf::generate_csrf_token(),
    }
}

async fn google_sync_trigger(State(state): State<Arc<AppState>>) -> SyncResultTemplate {
    if !state.config.google_sync.enabled {
        return SyncResultTemplate {
            message: "Google Sync is not enabled in configuration.".to_string(),
        };
    }

    let repo = state.repo.clone();
    let config = state.config.clone();

    tokio::spawn(async move {
        tracing::info!("Background Google Workspace sync started");

        let result = async {
            let key_path = config
                .google_sync
                .service_account_key_path
                .as_deref()
                .ok_or_else(|| {
                    chalk_core::error::ChalkError::GoogleSync(
                        "service_account_key_path not configured".into(),
                    )
                })?;
            let admin_email =
                config.google_sync.admin_email.as_deref().ok_or_else(|| {
                    chalk_core::error::ChalkError::GoogleSync(
                        "admin_email not configured".into(),
                    )
                })?;

            let auth = chalk_google_sync::auth::GoogleAuth::from_service_account(
                key_path,
                admin_email,
                &[
                    "https://www.googleapis.com/auth/admin.directory.user",
                    "https://www.googleapis.com/auth/admin.directory.orgunit",
                ],
            )
            .await?;

            let client = chalk_google_sync::client::GoogleAdminClient::new(
                auth.token(),
                "my_customer",
            );
            let engine = chalk_google_sync::sync::GoogleSyncEngine::new(
                repo.clone(),
                client,
                config.google_sync.clone(),
            );

            engine.run_sync(false).await
        }
        .await;

        match result {
            Ok(summary) => {
                tracing::info!(
                    users_created = summary.users_created,
                    users_updated = summary.users_updated,
                    users_suspended = summary.users_suspended,
                    ous_created = summary.ous_created,
                    "Google sync completed"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "Google sync failed");
            }
        }
    });

    SyncResultTemplate {
        message: "Google Workspace sync started in the background. Refresh the page to see progress."
            .to_string(),
    }
}

async fn google_sync_history(State(state): State<Arc<AppState>>) -> GoogleSyncHistoryTemplate {
    let runs = state
        .repo
        .list_google_sync_runs(20)
        .await
        .unwrap_or_default();
    let runs = runs.iter().map(GoogleSyncRunView::from_model).collect();
    GoogleSyncHistoryTemplate { runs }
}

async fn google_sync_users(State(state): State<Arc<AppState>>) -> GoogleSyncUsersTemplate {
    let states = state.repo.list_sync_states().await.unwrap_or_default();
    let users = states.iter().map(GoogleSyncUserView::from_model).collect();
    GoogleSyncUsersTemplate { active_page: "google_sync", users }
}

// -- Migration handlers --

async fn migration_index() -> MigrationIndexTemplate {
    MigrationIndexTemplate { active_page: "migration" }
}

async fn migration_clever() -> MigrationCleverTemplate {
    MigrationCleverTemplate { active_page: "migration" }
}

async fn migration_classlink() -> MigrationClassLinkTemplate {
    MigrationClassLinkTemplate { active_page: "migration" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn test_state() -> Arc<AppState> {
        let pool = chalk_core::db::DatabasePool::new_sqlite_memory()
            .await
            .unwrap();
        let repo = match pool {
            chalk_core::db::DatabasePool::Sqlite(p) => {
                chalk_core::db::sqlite::SqliteRepository::new(p)
            }
        };
        let config = chalk_core::config::ChalkConfig::generate_default();
        Arc::new(AppState { repo: Arc::new(repo), config })
    }

    async fn get_body(response: axum::http::Response<Body>) -> String {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    /// Generate a CSRF token for test POST requests.
    fn test_csrf_token() -> String {
        crate::csrf::generate_csrf_token()
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dashboard_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dashboard_contains_expected_content() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("Dashboard"));
        assert!(html.contains("User Counts"));
        assert!(html.contains("Last Sync"));
        assert!(html.contains("Database"));
    }

    #[tokio::test]
    async fn users_list_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn users_list_contains_expected_content() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("Users"));
        assert!(html.contains("No users found."));
    }

    #[tokio::test]
    async fn users_list_with_search_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/users?q=john&role=student")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn user_detail_not_found() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/users/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("User not found"));
    }

    #[tokio::test]
    async fn user_detail_found() {
        let state = test_state().await;

        // Insert an org and user
        use chalk_core::db::repository::OrgRepository;
        use chalk_core::models::common::{RoleType, Status};
        use chalk_core::models::org::Org;
        use chalk_core::models::user::User;
        use chrono::{TimeZone, Utc};

        let org = Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Test District".to_string(),
            org_type: chalk_core::models::common::OrgType::District,
            identifier: None,
            parent: None,
            children: vec![],
        };
        state.repo.upsert_org(&org).await.unwrap();

        let user = User {
            sourced_id: "user-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "jdoe".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "John".to_string(),
            family_name: "Doe".to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some("jdoe@example.com".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-001".to_string()],
            grades: vec!["09".to_string()],
        };
        state.repo.upsert_user(&user).await.unwrap();

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/users/user-001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("John"));
        assert!(html.contains("Doe"));
        assert!(html.contains("jdoe"));
    }

    #[tokio::test]
    async fn sync_page_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/sync").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sync_page_contains_expected_content() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/sync").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("SIS Sync"));
        assert!(html.contains("Trigger Sync Now"));
    }

    #[tokio::test]
    async fn sync_trigger_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let csrf = test_csrf_token();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sync/trigger")
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("SIS sync started in the background"));
    }

    #[tokio::test]
    async fn sync_history_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sync/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn settings_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn settings_contains_expected_content() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("Settings"));
        assert!(html.contains("My School District"));
        assert!(html.contains("sqlite"));
    }

    #[tokio::test]
    async fn is_enabled_returns_true() {
        assert!(is_enabled());
    }

    #[tokio::test]
    async fn users_list_with_data_returns_users() {
        let state = test_state().await;

        use chalk_core::db::repository::OrgRepository;
        use chalk_core::models::common::{OrgType, RoleType, Status};
        use chalk_core::models::org::Org;
        use chalk_core::models::user::User;
        use chrono::{TimeZone, Utc};

        let org = Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Test District".to_string(),
            org_type: OrgType::District,
            identifier: None,
            parent: None,
            children: vec![],
        };
        state.repo.upsert_org(&org).await.unwrap();

        let user = User {
            sourced_id: "user-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "jdoe".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "John".to_string(),
            family_name: "Doe".to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some("jdoe@example.com".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-001".to_string()],
            grades: vec![],
        };
        state.repo.upsert_user(&user).await.unwrap();

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Doe, John"));
        assert!(html.contains("jdoe"));
    }

    #[tokio::test]
    async fn dashboard_with_sync_data() {
        let state = test_state().await;

        use chalk_core::db::repository::SyncRepository;
        use chalk_core::models::sync::SyncStatus;

        let run = state.repo.create_sync_run("powerschool").await.unwrap();
        state
            .repo
            .update_sync_counts(run.id, 100, 5, 20, 30, 400)
            .await
            .unwrap();
        state
            .repo
            .update_sync_status(run.id, SyncStatus::Completed, None)
            .await
            .unwrap();

        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Completed"));
        assert!(html.contains("powerschool"));
    }

    // -- Identity tests --

    #[tokio::test]
    async fn identity_dashboard_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn identity_dashboard_contains_expected_content() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("Identity Provider"));
        assert!(html.contains("Configuration"));
        assert!(html.contains("Quick Links"));
        assert!(html.contains("480 minutes"));
    }

    #[tokio::test]
    async fn identity_sessions_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn identity_sessions_contains_expected_content() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("Active Sessions"));
        assert!(html.contains("No active sessions."));
    }

    #[tokio::test]
    async fn identity_badges_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity/badges")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn identity_badges_contains_expected_content() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity/badges")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("QR Badge Management"));
    }

    #[tokio::test]
    async fn identity_generate_badge_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let csrf = test_csrf_token();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/identity/badges/user-001/generate")
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Badge generation"));
    }

    #[tokio::test]
    async fn identity_auth_log_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity/auth-log")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn identity_auth_log_empty() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity/auth-log")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("No authentication attempts recorded."));
    }

    #[tokio::test]
    async fn identity_auth_log_with_data() {
        let state = test_state().await;

        use chalk_core::models::idp::{AuthLogEntry, AuthMethod};
        use chrono::Utc;

        let entry = AuthLogEntry {
            id: 0,
            user_sourced_id: Some("user-001".to_string()),
            username: Some("jdoe".to_string()),
            auth_method: AuthMethod::Password,
            success: true,
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("TestAgent".to_string()),
            created_at: Utc::now(),
        };
        state.repo.log_auth_attempt(&entry).await.unwrap();

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity/auth-log")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("jdoe"));
        assert!(html.contains("Password"));
        assert!(html.contains("Success"));
        assert!(html.contains("192.168.1.1"));
    }

    #[tokio::test]
    async fn identity_saml_setup_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity/saml-setup")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn identity_saml_setup_contains_expected_content() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity/saml-setup")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("SAML Setup Guide"));
        assert!(html.contains("/idp/saml/metadata"));
        assert!(html.contains("/idp/saml/sso"));
    }

    // -- Google Sync tests --

    #[tokio::test]
    async fn google_sync_dashboard_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/google-sync")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn google_sync_dashboard_contains_expected_content() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/google-sync")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("Google Workspace Sync"));
        assert!(html.contains("Configuration"));
        assert!(html.contains("Trigger Manual Sync"));
        assert!(html.contains("Not configured"));
    }

    #[tokio::test]
    async fn google_sync_trigger_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let csrf = test_csrf_token();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/google-sync/trigger")
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Google Sync is not enabled"));
    }

    #[tokio::test]
    async fn google_sync_history_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/google-sync/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn google_sync_history_empty() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/google-sync/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("No sync runs recorded."));
    }

    #[tokio::test]
    async fn google_sync_history_with_data() {
        let state = test_state().await;

        use chalk_core::models::google_sync::GoogleSyncRunStatus;

        let run = state.repo.create_google_sync_run(false).await.unwrap();
        state
            .repo
            .update_google_sync_run(run.id, GoogleSyncRunStatus::Completed, 50, 10, 3, 5, None)
            .await
            .unwrap();

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/google-sync/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Completed"));
        assert!(html.contains("50"));
        assert!(html.contains("10"));
    }

    #[tokio::test]
    async fn google_sync_users_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/google-sync/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn google_sync_users_empty() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/google-sync/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("No users synced yet."));
    }

    #[tokio::test]
    async fn google_sync_users_with_data() {
        let state = test_state().await;

        use chalk_core::db::repository::OrgRepository;
        use chalk_core::models::common::{OrgType, RoleType, Status};
        use chalk_core::models::google_sync::{GoogleSyncStatus, GoogleSyncUserState};
        use chalk_core::models::org::Org;
        use chalk_core::models::user::User;
        use chrono::{TimeZone, Utc};

        let org = Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Test District".to_string(),
            org_type: OrgType::District,
            identifier: None,
            parent: None,
            children: vec![],
        };
        state.repo.upsert_org(&org).await.unwrap();

        let user = User {
            sourced_id: "user-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "jdoe".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "John".to_string(),
            family_name: "Doe".to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some("jdoe@example.com".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-001".to_string()],
            grades: vec![],
        };
        state.repo.upsert_user(&user).await.unwrap();

        let sync_state = GoogleSyncUserState {
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
        state.repo.upsert_sync_state(&sync_state).await.unwrap();

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/google-sync/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("user-001"));
        assert!(html.contains("jdoe@school.edu"));
        assert!(html.contains("/Students/HS/09"));
        assert!(html.contains("Synced"));
    }

    #[tokio::test]
    async fn nav_contains_identity_and_google_sync_links() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("href=\"/identity\""));
        assert!(html.contains("href=\"/google-sync\""));
    }

    // Helper: create state with admin password configured
    async fn test_state_with_auth() -> Arc<AppState> {
        let pool = chalk_core::db::DatabasePool::new_sqlite_memory()
            .await
            .unwrap();
        let repo = match pool {
            chalk_core::db::DatabasePool::Sqlite(p) => {
                chalk_core::db::sqlite::SqliteRepository::new(p)
            }
        };
        let mut config = chalk_core::config::ChalkConfig::generate_default();
        config.chalk.admin_password_hash =
            Some(crate::auth::hash_password("test-password").unwrap());
        Arc::new(AppState { repo: Arc::new(repo), config })
    }

    // -- Auth middleware tests --

    #[tokio::test]
    async fn auth_middleware_redirects_unauthenticated() {
        let state = test_state_with_auth().await;
        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "/login");
    }

    #[tokio::test]
    async fn health_bypasses_auth() {
        let state = test_state_with_auth().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn login_page_returns_200() {
        let state = test_state_with_auth().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Admin Password"));
        assert!(html.contains("Sign In"));
    }

    #[tokio::test]
    async fn login_with_correct_password_creates_session() {
        let state = test_state_with_auth().await;
        let app = router(state);
        let body = "password=test-password";
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        // Should have set-cookie header
        let set_cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("chalk_session="));
        assert!(set_cookie.contains("HttpOnly"));
    }

    #[tokio::test]
    async fn login_with_wrong_password_returns_error() {
        let state = test_state_with_auth().await;
        let app = router(state);
        let body = "password=wrong-password";
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Invalid password"));
    }

    #[tokio::test]
    async fn logout_clears_session() {
        let state = test_state_with_auth().await;

        // First login
        let app = router(state.clone());
        let body = "password=test-password";
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let set_cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Extract session token from cookie
        let token = set_cookie
            .split("chalk_session=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();

        // Logout
        let app = router(state.clone());
        let csrf = test_csrf_token();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header(
                        "cookie",
                        format!("chalk_session={token}; chalk_csrf={csrf}"),
                    )
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let clear_cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(clear_cookie.contains("Max-Age=0"));
    }

    // -- CSRF tests --

    #[tokio::test]
    async fn csrf_rejects_post_without_token() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sync/trigger")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_accepts_post_with_matching_token() {
        let state = test_state().await;
        let csrf_token = crate::csrf::generate_csrf_token();
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sync/trigger")
                    .header("cookie", format!("chalk_csrf={csrf_token}"))
                    .header("x-csrf-token", &csrf_token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn csrf_rejects_post_with_mismatched_token() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sync/trigger")
                    .header("cookie", "chalk_csrf=token-a")
                    .header("x-csrf-token", "token-b")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // -- Audit log tests --

    #[tokio::test]
    async fn audit_log_page_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings/audit-log")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Audit Log"));
    }

    #[tokio::test]
    async fn audit_log_page_displays_entries() {
        let state = test_state().await;

        use chalk_core::db::repository::AdminAuditRepository;
        state
            .repo
            .log_admin_action("login", Some("Admin logged in"), Some("10.0.0.1"))
            .await
            .unwrap();

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings/audit-log")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("login"));
        assert!(html.contains("Admin logged in"));
        assert!(html.contains("10.0.0.1"));
    }

    // -- Migration tests --

    #[tokio::test]
    async fn migration_index_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/migration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn migration_index_contains_expected_content() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/migration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("Platform Migration"));
        assert!(html.contains("Clever"));
        assert!(html.contains("ClassLink"));
        assert!(html.contains("Start Clever Migration"));
        assert!(html.contains("Start ClassLink Migration"));
    }

    #[tokio::test]
    async fn migration_clever_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/migration/clever")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn migration_clever_contains_expected_content() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/migration/clever")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("Clever Migration"));
        assert!(html.contains("Export Directory"));
        assert!(html.contains("Parse Export"));
    }

    #[tokio::test]
    async fn migration_classlink_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/migration/classlink")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn migration_classlink_contains_expected_content() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/migration/classlink")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("ClassLink Migration"));
        assert!(html.contains("Export Directory"));
        assert!(html.contains("Parse Export"));
    }

    #[tokio::test]
    async fn nav_contains_migration_link() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("href=\"/migration\""));
    }

    #[tokio::test]
    async fn nav_contains_audit_log_and_logout() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("Audit Log"));
        assert!(html.contains("Logout"));
    }

    // -- Cron validation tests --

    #[test]
    fn cron_valid_standard() {
        assert!(validate_cron_expression("0 2 * * *").is_ok());
    }

    #[test]
    fn cron_valid_all_stars() {
        assert!(validate_cron_expression("* * * * *").is_ok());
    }

    #[test]
    fn cron_valid_step_values() {
        assert!(validate_cron_expression("*/15 */2 * * *").is_ok());
    }

    #[test]
    fn cron_valid_specific_values() {
        assert!(validate_cron_expression("30 3 15 6 1").is_ok());
    }

    #[test]
    fn cron_invalid_too_few_fields() {
        let err = validate_cron_expression("0 2 *").unwrap_err();
        assert!(err.contains("Expected 5 fields"));
    }

    #[test]
    fn cron_invalid_too_many_fields() {
        let err = validate_cron_expression("0 2 * * * *").unwrap_err();
        assert!(err.contains("Expected 5 fields"));
    }

    #[test]
    fn cron_invalid_minute_out_of_range() {
        let err = validate_cron_expression("60 2 * * *").unwrap_err();
        assert!(err.contains("minute"));
    }

    #[test]
    fn cron_invalid_hour_out_of_range() {
        let err = validate_cron_expression("0 24 * * *").unwrap_err();
        assert!(err.contains("hour"));
    }

    #[test]
    fn cron_invalid_non_numeric() {
        let err = validate_cron_expression("abc 2 * * *").unwrap_err();
        assert!(err.contains("minute"));
    }

    #[test]
    fn cron_invalid_step_zero() {
        let err = validate_cron_expression("*/0 * * * *").unwrap_err();
        assert!(err.contains("step"));
    }

    #[test]
    fn cron_valid_weekday_7() {
        assert!(validate_cron_expression("0 0 * * 7").is_ok());
    }

    // -- Schedule update integration tests --

    #[tokio::test]
    async fn sync_schedule_update_persists() {
        let state = test_state().await;
        let csrf = test_csrf_token();
        let app = router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sync/schedule")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::from("schedule=0+4+*+*+*"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = get_body(response).await;
        assert!(body.contains("Schedule updated to: 0 4 * * *"));

        // Verify it persisted
        let saved = state
            .repo
            .get_config_override("sis.sync_schedule")
            .await
            .unwrap();
        assert_eq!(saved, Some("0 4 * * *".to_string()));
    }

    #[tokio::test]
    async fn sync_schedule_rejects_invalid_cron() {
        let state = test_state().await;
        let csrf = test_csrf_token();
        let app = router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sync/schedule")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::from("schedule=not+valid"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = get_body(response).await;
        assert!(body.contains("Invalid cron expression"));
    }

    #[tokio::test]
    async fn google_sync_schedule_update_persists() {
        let state = test_state().await;
        let csrf = test_csrf_token();
        let app = router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/google-sync/schedule")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::from("schedule=30+3+*+*+*"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = get_body(response).await;
        assert!(body.contains("Schedule updated to: 30 3 * * *"));

        let saved = state
            .repo
            .get_config_override("google_sync.sync_schedule")
            .await
            .unwrap();
        assert_eq!(saved, Some("30 3 * * *".to_string()));
    }
}
