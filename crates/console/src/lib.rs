//! Chalk Console — Embedded web admin UI served from the binary.
//!
//! Provides a full HTMX-powered admin console with dashboard, SIS sync management,
//! user directory, and settings pages.

use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    response::Html,
    routing::{get, post},
    Router,
};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{SyncRepository, UserRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::models::common::RoleType;
use chalk_core::models::sync::UserFilter;

/// Shared application state for all console routes.
pub struct AppState {
    pub repo: SqliteRepository,
    pub config: ChalkConfig,
}

/// Build the console router with all routes.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/", get(dashboard))
        .route("/sync", get(sync_page))
        .route("/sync/trigger", post(sync_trigger))
        .route("/sync/history", get(sync_history))
        .route("/users", get(users_list))
        .route("/users/:id", get(user_detail))
        .route("/settings", get(settings_page))
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

// -- Templates --

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    user_counts: chalk_core::models::sync::UserCounts,
    last_sync: Option<SyncRunView>,
    db_driver: String,
    db_path: String,
}

#[derive(Template)]
#[template(path = "sync/index.html")]
struct SyncPageTemplate {
    sis_enabled: bool,
    sis_provider: String,
    sis_schedule: String,
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
    users: Vec<UserView>,
    query: String,
    role_filter: String,
}

#[derive(Template)]
#[template(path = "users/detail.html")]
struct UserDetailTemplate {
    user: UserView,
}

#[derive(Template)]
#[template(path = "settings/index.html")]
struct SettingsTemplate {
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
        user_counts,
        last_sync,
        db_driver,
        db_path,
    }
}

async fn sync_page(State(state): State<Arc<AppState>>) -> SyncPageTemplate {
    let sis_provider = format!("{:?}", state.config.sis.provider);
    SyncPageTemplate {
        sis_enabled: state.config.sis.enabled,
        sis_provider,
        sis_schedule: state.config.sis.sync_schedule.clone(),
    }
}

async fn sync_trigger() -> SyncResultTemplate {
    SyncResultTemplate {
        message:
            "Sync triggered. Full sync wiring will be available when connectors are integrated."
                .to_string(),
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
        Arc::new(AppState { repo, config })
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("SIS Sync"));
        assert!(html.contains("Trigger Sync Now"));
    }

    #[tokio::test]
    async fn sync_trigger_returns_200() {
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
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Sync triggered"));
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Completed"));
        assert!(html.contains("powerschool"));
    }
}
