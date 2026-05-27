//! Chalk Console — Embedded web admin UI served from the binary.
//!
//! Provides a full HTMX-powered admin console with dashboard, SIS sync management,
//! user directory, settings, identity provider, and Google Sync pages.

pub mod api;
pub mod auth;
pub mod csrf;
pub mod sync_settings;
pub mod webhooks;

use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    middleware,
    response::{Html, Redirect},
    routing::{get, post},
    Router,
};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{ChalkRepository, TenantConfigRepo};
use chalk_core::db::sqlite::effective_schedule;
use chalk_core::models::common::RoleType;
use chalk_core::models::sync::UserFilter;

/// Hook invoked after a successful SSO-partner mutation so the hosted runtime
/// can drop its cached `TenantContext` and rebuild it (re-mounting the
/// Clever/ClassLink compat routers with the new partner set).
///
/// The string parameter is the tenant slug to invalidate. In OSS single-tenant
/// mode this hook is `None`; in hosted mode it is wired to
/// `StateCache::invalidate`.
pub type SsoInvalidator = Arc<dyn Fn(&str) + Send + Sync>;

/// Shared application state for all console routes.
pub struct AppState {
    pub repo: Arc<dyn ChalkRepository>,
    pub config: ChalkConfig,
    /// Tenant slug used when invoking `sso_invalidator`. In OSS mode this is
    /// empty and the hook is `None`.
    pub tenant_slug: String,
    /// Optional hook fired after SSO partner CRUD so the multi-tenant cache
    /// can rebuild the tenant's router. See `SsoInvalidator`.
    pub sso_invalidator: Option<SsoInvalidator>,
    /// Per-AppState (per-tenant in hosted mode) guard: prevents the admin
    /// console "Trigger Sync Now" button from racing the cron scheduler or a
    /// double-click. The first attempt flips it to `true` and spawns the
    /// background sync; subsequent attempts return the "already running"
    /// template instead of starting a second concurrent sync (which would
    /// race on `upsert_*` and produce inconsistent state).
    pub sync_in_flight: Arc<std::sync::atomic::AtomicBool>,
    /// Per-IP rate limiter for `POST /login`. Shared across the request
    /// pipeline so all login attempts hit the same bucket map.
    pub login_limiter: Arc<auth::LoginRateLimiter>,
    /// Optional per-tenant config repository. When `Some`, the
    /// `/sync/settings`, `/google-sync/settings`, `/identity/settings`, and
    /// `/ad-sync/settings` admin pages render and persist via this repo. In
    /// hosted mode this is a `SealingTenantConfigRepo` that seals secrets
    /// with the master key before delegating to the underlying postgres
    /// row writer. When `None` the settings pages render a "not configured"
    /// notice instead of crashing.
    pub tenant_config: Option<Arc<dyn TenantConfigRepo>>,
}

impl AppState {
    /// Construct a new `AppState` from its dependencies. The SSO invalidation
    /// hook defaults to `None` (OSS / single-tenant mode).
    pub fn new(repo: Arc<dyn ChalkRepository>, config: ChalkConfig) -> Self {
        Self {
            repo,
            config,
            tenant_slug: String::new(),
            sso_invalidator: None,
            sync_in_flight: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            login_limiter: Arc::new(auth::LoginRateLimiter::default()),
            tenant_config: None,
        }
    }

    /// Builder: attach a tenant-config repo (typically the hosted
    /// `SealingTenantConfigRepo`) so the per-section settings pages can read
    /// and persist DB-backed config.
    pub fn with_tenant_config(mut self, repo: Arc<dyn TenantConfigRepo>) -> Self {
        self.tenant_config = Some(repo);
        self
    }

    /// Builder: attach an SSO-partner invalidation hook for the given tenant
    /// slug. The hosted runtime uses this to invalidate its per-tenant cache
    /// when a partner is created, edited, toggled, or (future) deleted.
    pub fn with_sso_invalidator(mut self, tenant_slug: String, hook: SsoInvalidator) -> Self {
        self.tenant_slug = tenant_slug;
        self.sso_invalidator = Some(hook);
        self
    }

    /// Fire the SSO invalidator if one is wired up. No-op otherwise.
    fn notify_sso_changed(&self) {
        if let Some(hook) = &self.sso_invalidator {
            hook(&self.tenant_slug);
        }
    }

    /// Evict the cached `TenantContext` so the next request rebuilds it from
    /// the freshly-written DB rows. Reuses the same invalidator hook the
    /// SSO-partner handlers use — the hook invalidates the whole tenant
    /// context, not just SSO state, so any config-section save can call it.
    /// No-op when the hook is `None` (OSS / single-tenant mode).
    pub(crate) fn notify_tenant_config_changed(&self) {
        self.notify_sso_changed();
    }
}

/// Lowercase label for the configured SIS provider, used for both display
/// and `sync_runs.provider` querying. Returns `"none"` when the tenant has
/// not chosen a provider (the 1.4+ default — see CHANGELOG breaking change).
fn sis_provider_label(cfg: &ChalkConfig) -> String {
    cfg.sis
        .provider
        .as_ref()
        .map(|p| format!("{p:?}").to_lowercase())
        .unwrap_or_else(|| "none".to_string())
}

/// Display label rendered into the sync/settings templates. We keep the
/// CamelCase form for the rendered cell (matching pre-1.4 behavior), and
/// substitute "Not configured" when the provider is `None`.
fn sis_provider_display(cfg: &ChalkConfig) -> String {
    cfg.sis
        .provider
        .as_ref()
        .map(|p| format!("{p:?}"))
        .unwrap_or_else(|| "Not configured".to_string())
}

/// Generate `byte_count` random bytes and hex-encode them. Used to mint
/// `oidc_client_id` / `oidc_client_secret` for Clever- and ClassLink-compat
/// partners when the admin doesn't supply them.
fn random_hex(byte_count: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; byte_count];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Build the console router with all routes.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/static/htmx-2.0.4.min.js", get(htmx_js))
        .route("/login", get(auth::login_page).post(auth::login_submit))
        .route(
            "/set-password",
            get(auth::set_password_page).post(auth::set_password_submit),
        )
        .route("/logout", post(auth::logout))
        .route("/", get(dashboard))
        .route("/sync", get(sync_page))
        .route("/sync/trigger", post(sync_trigger))
        .route("/sync/schedule", post(sync_update_schedule))
        .route("/sync/history", get(sync_history))
        .route(
            "/sync/settings",
            get(sync_settings::sis_settings_form).post(sync_settings::sis_settings_submit),
        )
        .route(
            "/google-sync/settings",
            get(sync_settings::google_sync_settings_form)
                .post(sync_settings::google_sync_settings_submit)
                .layer(axum::extract::DefaultBodyLimit::max(
                    sync_settings::UPLOAD_BODY_LIMIT,
                )),
        )
        .route(
            "/identity/settings",
            get(sync_settings::identity_settings_form)
                .post(sync_settings::identity_settings_submit)
                .layer(axum::extract::DefaultBodyLimit::max(
                    sync_settings::UPLOAD_BODY_LIMIT,
                )),
        )
        .route("/ad-sync", get(sync_settings::ad_sync_landing))
        .route(
            "/ad-sync/settings",
            get(sync_settings::ad_sync_settings_form)
                .post(sync_settings::ad_sync_settings_submit)
                .layer(axum::extract::DefaultBodyLimit::max(
                    sync_settings::UPLOAD_BODY_LIMIT,
                )),
        )
        .route("/users", get(users_list))
        .route("/users/:id", get(user_detail))
        .route("/settings", get(settings_page))
        .route("/settings/audit-log", get(audit_log_page))
        .route(
            "/settings/api-tokens",
            get(api_tokens_page).post(api_tokens_create),
        )
        .route("/settings/api-tokens/:id/revoke", post(api_tokens_revoke))
        .route("/identity", get(identity_dashboard))
        .route("/identity/sessions", get(identity_sessions))
        .route("/identity/badges", get(identity_badges))
        .route(
            "/identity/badges/:user_id/generate",
            post(identity_generate_badge),
        )
        .route("/identity/auth-log", get(identity_auth_log))
        .route("/identity/saml-setup", get(identity_saml_setup))
        .route("/identity/saml-cert.pem", get(identity_saml_cert_download))
        .route("/google-sync", get(google_sync_dashboard))
        .route("/google-sync/trigger", post(google_sync_trigger))
        .route("/google-sync/schedule", post(google_sync_update_schedule))
        .route("/google-sync/history", get(google_sync_history))
        .route("/google-sync/users", get(google_sync_users))
        .route("/sso-partners", get(sso_partners_list))
        .route(
            "/sso-partners/new",
            get(sso_partners_new_form).post(sso_partners_create),
        )
        .route("/sso-partners/:id", get(sso_partners_detail))
        .route(
            "/sso-partners/:id/edit",
            get(sso_partners_edit_form).post(sso_partners_update),
        )
        .route("/sso-partners/:id/toggle", post(sso_partners_toggle))
        .route("/webhooks", get(webhooks::webhooks_list))
        .route(
            "/webhooks/new",
            get(webhooks::webhooks_new_form).post(webhooks::webhooks_create),
        )
        .route("/webhooks/:id", get(webhooks::webhooks_detail))
        .route(
            "/webhooks/:id/edit",
            get(webhooks::webhooks_edit_form).post(webhooks::webhooks_update),
        )
        .route("/webhooks/:id/delete", post(webhooks::webhooks_delete))
        .route("/webhooks/:id/test", post(webhooks::webhooks_test))
        .route("/migration", get(migration_index))
        .route("/migration/clever", get(migration_clever))
        .route("/migration/classlink", get(migration_classlink))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            csrf::csrf_middleware,
        ))
        .nest(
            "/api/oneroster/v1p1",
            api::oneroster::oneroster_router().layer(middleware::from_fn_with_state(
                state.clone(),
                auth::oneroster_bearer_middleware,
            )),
        )
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

/// Self-hosted htmx so the admin console doesn't need a CSP exception for
/// unpkg.com (and doesn't break if unpkg blips). Version-pinned in the URL
/// so a future bump in `base.html` plus the include_str! source forces a
/// matching browser cache miss.
async fn htmx_js() -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;
    const HTMX: &str = include_str!("../static/htmx-2.0.4.min.js");
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        HTMX,
    )
        .into_response()
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
    /// Label for the second database row — "Path" (sqlite) or "Schema"
    /// (postgres). Empty for unsupported drivers.
    db_location_label: String,
    /// Value matching `db_location_label` — the sqlite path or the postgres
    /// schema name. We deliberately don't render the Postgres URL: it can
    /// contain a password and is operator-only info.
    db_location_value: String,
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
    filter_action: String,
    filter_ip: String,
    filter_since: String,
    filter_until: String,
    total_matched: usize,
    total_scanned: usize,
}

#[derive(serde::Deserialize, Default)]
struct AuditLogFilter {
    /// Substring match on the action column. Case-insensitive.
    #[serde(default)]
    action: Option<String>,
    /// Substring match on the ip_address column. Empty matches all.
    #[serde(default)]
    ip: Option<String>,
    /// ISO date (YYYY-MM-DD). Inclusive lower bound on created_at.
    #[serde(default)]
    since: Option<String>,
    /// ISO date (YYYY-MM-DD). Inclusive upper bound on created_at.
    #[serde(default)]
    until: Option<String>,
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
    /// Server filesystem path to the cert — `None` if IDP isn't configured
    /// yet. Shown in the "Server path" detail line for self-hosters; hosted
    /// admins use the download button instead.
    cert_path: Option<String>,
    /// Browser-facing URL that streams the cert as `application/x-pem-file`
    /// with `Content-Disposition: attachment`. Always set, regardless of
    /// whether the cert file exists yet — the handler returns 404 in that
    /// case and the user fixes IDP settings first.
    cert_download_url: String,
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
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "migration/classlink.html")]
struct MigrationClassLinkTemplate {
    active_page: &'static str,
    csrf_token: String,
}

// -- SSO view model --

struct SsoPartnerView {
    id: String,
    name: String,
    protocol: String,
    enabled: bool,
    is_toml: bool,
    roles: String,
    logo_url: String,
    saml_entity_id: String,
    saml_acs_url: String,
    oidc_client_id: String,
    oidc_client_secret: String,
    oidc_redirect_uris: String,
    created_at: String,
    updated_at: String,
}

impl SsoPartnerView {
    fn from_model(p: &chalk_core::models::sso::SsoPartner) -> Self {
        Self {
            id: p.id.clone(),
            name: p.name.clone(),
            protocol: match p.protocol {
                chalk_core::models::sso::SsoProtocol::Saml => "SAML".to_string(),
                chalk_core::models::sso::SsoProtocol::Oidc => "OIDC".to_string(),
                chalk_core::models::sso::SsoProtocol::CleverCompat => {
                    "Clever-Compatible".to_string()
                }
                chalk_core::models::sso::SsoProtocol::ClassLinkCompat => {
                    "ClassLink-Compatible".to_string()
                }
            },
            enabled: p.enabled,
            is_toml: p.source == chalk_core::models::sso::SsoPartnerSource::Toml,
            roles: p.roles.join(", "),
            logo_url: p.logo_url.clone().unwrap_or_default(),
            saml_entity_id: p.saml_entity_id.clone().unwrap_or_default(),
            saml_acs_url: p.saml_acs_url.clone().unwrap_or_default(),
            oidc_client_id: p.oidc_client_id.clone().unwrap_or_default(),
            oidc_client_secret: p.oidc_client_secret.clone().unwrap_or_default(),
            oidc_redirect_uris: p.oidc_redirect_uris.join(", "),
            created_at: p.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            updated_at: p.updated_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        }
    }

    fn empty() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            protocol: "SAML".to_string(),
            enabled: true,
            is_toml: false,
            roles: String::new(),
            logo_url: String::new(),
            saml_entity_id: String::new(),
            saml_acs_url: String::new(),
            oidc_client_id: String::new(),
            oidc_client_secret: String::new(),
            oidc_redirect_uris: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }
}

// -- SSO templates --

#[derive(Template)]
#[template(path = "sso/list.html")]
struct SsoPartnersListTemplate {
    active_page: &'static str,
    partners: Vec<SsoPartnerView>,
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "sso/form.html")]
struct SsoPartnerFormTemplate {
    active_page: &'static str,
    is_edit: bool,
    partner: SsoPartnerView,
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "sso/detail.html")]
struct SsoPartnerDetailTemplate {
    active_page: &'static str,
    partner: SsoPartnerView,
    public_url: String,
    csrf_token: String,
}

#[derive(serde::Deserialize)]
struct SsoPartnerForm {
    name: String,
    protocol: String,
    #[serde(default)]
    saml_entity_id: String,
    #[serde(default)]
    saml_acs_url: String,
    #[serde(default)]
    oidc_client_id: String,
    #[serde(default)]
    oidc_client_secret: String,
    #[serde(default)]
    oidc_redirect_uris: String,
    #[serde(default)]
    roles: String,
    #[serde(default)]
    logo_url: String,
    #[serde(default)]
    enabled: String,
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

    let provider = sis_provider_label(&state.config);
    let last_sync = state
        .repo
        .get_latest_sync_run(&provider)
        .await
        .ok()
        .flatten()
        .map(|run| SyncRunView::from_model(&run));

    let db_driver = format!("{:?}", state.config.chalk.database.driver).to_lowercase();
    // For SQLite (self-hosted) we surface the on-disk path so operators can
    // find their database. For Postgres (hosted) we hide the per-tenant
    // schema name — it's an internal implementation detail and exposing it
    // to admins offers no value while leaking infrastructure shape.
    let (db_location_label, db_location_value) = match state.config.chalk.database.driver {
        chalk_core::config::DatabaseDriver::Sqlite => (
            "Path".to_string(),
            state.config.chalk.database.path.clone().unwrap_or_default(),
        ),
        chalk_core::config::DatabaseDriver::Postgres => {
            ("Hosting".to_string(), "managed".to_string())
        }
    };

    DashboardTemplate {
        active_page: "dashboard",
        user_counts,
        last_sync,
        db_driver,
        db_location_label,
        db_location_value,
    }
}

async fn sync_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> SyncPageTemplate {
    let sis_provider = sis_provider_display(&state.config);
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
        csrf_token: csrf.0,
    }
}

async fn sync_trigger(State(state): State<Arc<AppState>>) -> SyncResultTemplate {
    use std::sync::atomic::Ordering;

    // Compare-and-swap: only one sync runs at a time per AppState (per tenant
    // in hosted mode, per process in OSS). Reject the second click rather
    // than serialize behind the first — operators almost always want
    // "already running, refresh in a minute" feedback, not a queued sync.
    if state
        .sync_in_flight
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        tracing::info!("sync_trigger rejected: a sync is already running");
        return SyncResultTemplate {
            message: "A SIS sync is already running. Refresh in a minute to see progress."
                .to_string(),
        };
    }

    let repo = state.repo.clone();
    let config = state.config.clone();
    let in_flight = state.sync_in_flight.clone();

    tokio::spawn(async move {
        let provider_label = sis_provider_label(&config);
        tracing::info!(provider = %provider_label, "Background SIS sync started");

        if let Err(e) = run_admin_console_sync(&*repo, &config, &provider_label).await {
            tracing::error!(error = %e, "sync_trigger failed");
            record_failed_sync(&*repo, &provider_label, &e.to_string()).await;
        }
        // Release the guard regardless of outcome so a failed sync doesn't
        // permanently block future attempts.
        in_flight.store(false, Ordering::Release);
    });

    SyncResultTemplate {
        message: "SIS sync started in the background. Refresh the page to see progress."
            .to_string(),
    }
}

/// Run a sync from the admin-console "Trigger Sync Now" button.
///
/// Mirrors `crates/cli/src/commands/sync.rs` but operates against the
/// `Arc<dyn ChalkRepository>` the console holds. Doesn't reach for
/// `SyncEngine<R>` because that's generic over a concrete `R: ChalkRepository`
/// and the Arc<dyn> wrapper doesn't satisfy that bound. We persist the
/// payload directly via repo upserts in dependency order, then fire
/// webhooks with a synthetic `Updated`-action changeset of the synced
/// entities. That mirrors what `SyncEngine::run_with_webhooks` produces
/// for a full sync (no diff vs prior state).
///
/// In hosted mode, `tenant_config_loader` folds the operator's per-tenant
/// SIS row onto `config.sis` before this runs, so the connector receives
/// real credentials. If the tenant hasn't configured a provider yet, the
/// `?` below surfaces a "pick a provider on the SIS Settings page" error
/// and we record a Failed sync_run — the right signal for the operator.
pub async fn run_admin_console_sync(
    repo: &dyn chalk_core::db::repository::ChalkRepository,
    config: &chalk_core::config::ChalkConfig,
    provider_label: &str,
) -> Result<(), chalk_core::error::ChalkError> {
    use chalk_core::config::SisProvider;
    use chalk_core::connectors::{
        infinite_campus::InfiniteCampusConnector, oneroster_csv::OneRosterCsvConnector,
        powerschool::PowerSchoolConnector, skyward::SkywardConnector, SisConnector,
    };
    use chalk_core::error::ChalkError;
    use chalk_core::models::sync::SyncStatus;
    use chalk_core::webhooks::{
        delivery::{load_all_endpoints, WebhookDeliveryEngine},
        models::{ChangeAction, EntityChange, EntityType, SyncChangeset},
    };

    let provider = config.sis.provider.as_ref().ok_or_else(|| {
        ChalkError::Config(
            "sis.provider is not set. Pick a provider on the SIS Settings page \
             before triggering a sync."
                .into(),
        )
    })?;
    let connector: Box<dyn SisConnector> = match provider {
        SisProvider::PowerSchool => Box::new(PowerSchoolConnector::new(&config.sis)),
        SisProvider::InfiniteCampus => Box::new(InfiniteCampusConnector::new(&config.sis)?),
        SisProvider::Skyward => Box::new(SkywardConnector::new(&config.sis)?),
        SisProvider::OneRosterCsv => Box::new(OneRosterCsvConnector::new(&config.sis)?),
    };

    let sync_run = repo.create_sync_run(provider_label).await?;
    let payload = match connector.full_sync().await {
        Ok(p) => p,
        Err(e) => {
            let _ = repo
                .update_sync_status(sync_run.id, SyncStatus::Failed, Some(&e.to_string()))
                .await;
            return Err(e);
        }
    };

    // Persist in OneRoster dependency order (orgs before users that reference
    // them, classes before enrollments, etc.). Any one failure aborts so the
    // operator sees the partial state in the audit log instead of a silent
    // half-finished sync.
    for org in &payload.orgs {
        repo.upsert_org(org).await?;
    }
    for session in &payload.academic_sessions {
        repo.upsert_academic_session(session).await?;
    }
    for user in &payload.users {
        repo.upsert_user(user).await?;
    }
    for course in &payload.courses {
        repo.upsert_course(course).await?;
    }
    for class in &payload.classes {
        repo.upsert_class(class).await?;
    }
    for enrollment in &payload.enrollments {
        repo.upsert_enrollment(enrollment).await?;
    }
    for demographics in &payload.demographics {
        repo.upsert_demographics(demographics).await?;
    }

    repo.update_sync_status(sync_run.id, SyncStatus::Completed, None)
        .await?;

    tracing::info!(
        run_id = sync_run.id,
        users = payload.users.len(),
        classes = payload.classes.len(),
        "SIS sync run completed via admin console"
    );

    // Webhook delivery: build a synthetic changeset (full-sync = treat every
    // synced entity as Updated, which is the conservative interpretation when
    // we don't have a per-entity diff). Skip if no endpoints configured.
    let endpoints = match load_all_endpoints(&config.webhooks, repo).await {
        Ok(eps) if !eps.is_empty() => eps,
        Ok(_) => {
            tracing::info!("No webhook endpoints configured, skipping delivery");
            return Ok(());
        }
        Err(e) => {
            tracing::warn!("Failed to load webhook endpoints: {e}");
            return Ok(());
        }
    };

    let mut changes: Vec<EntityChange> =
        Vec::with_capacity(payload.users.len() + payload.classes.len() + payload.enrollments.len());
    let entity = |t: EntityType, id: &str, json: serde_json::Value| EntityChange {
        entity_type: t,
        action: ChangeAction::Updated,
        sourced_id: id.to_string(),
        entity: json,
    };
    for u in &payload.users {
        let json =
            serde_json::to_value(u).map_err(|e| ChalkError::Serialization(format!("user: {e}")))?;
        changes.push(entity(EntityType::User, &u.sourced_id, json));
    }
    for c in &payload.classes {
        let json = serde_json::to_value(c)
            .map_err(|e| ChalkError::Serialization(format!("class: {e}")))?;
        changes.push(entity(EntityType::Class, &c.sourced_id, json));
    }
    for e in &payload.enrollments {
        let json = serde_json::to_value(e)
            .map_err(|err| ChalkError::Serialization(format!("enrollment: {err}")))?;
        changes.push(entity(EntityType::Enrollment, &e.sourced_id, json));
    }
    let changeset = SyncChangeset {
        changes,
        sync_run_id: sync_run.id,
    };

    let delivery = WebhookDeliveryEngine::new();
    if let Err(e) = delivery.deliver_all(&endpoints, &changeset, repo).await {
        tracing::error!("Webhook delivery failed: {e}");
    } else {
        tracing::info!(count = endpoints.len(), "Webhooks delivered after sync");
    }
    Ok(())
}

/// Drive a Google Workspace sync end-to-end against the given tenant
/// repo+config. Mirrors the body of the `/google-sync/trigger` handler
/// without the axum wrapper, so the hosted cron loop can dispatch it on
/// schedule.
///
/// Records a `google_sync_runs` row up front so failures during engine
/// init (bad service-account key, missing admin_email, etc.) surface in
/// the History tab as a Failed run rather than vanishing into the logs.
/// Returns `Ok(())` on engine success and `Err(ChalkError)` otherwise —
/// the caller can decide whether to propagate.
pub async fn run_google_sync_for_tenant(
    repo: std::sync::Arc<dyn chalk_core::db::repository::ChalkRepository>,
    config: &chalk_core::config::ChalkConfig,
) -> Result<(), chalk_core::error::ChalkError> {
    use chalk_core::error::ChalkError;

    let pre_run = repo.create_google_sync_run(false).await;
    let key_path = config
        .google_sync
        .service_account_key_path
        .as_deref()
        .ok_or_else(|| ChalkError::GoogleSync("service_account_key_path not configured".into()))?;
    let admin_email = config
        .google_sync
        .admin_email
        .as_deref()
        .ok_or_else(|| ChalkError::GoogleSync("admin_email not configured".into()))?;

    let result = async {
        let auth = chalk_google_sync::auth::GoogleAuth::from_service_account(
            key_path,
            admin_email,
            &[
                "https://www.googleapis.com/auth/admin.directory.user",
                "https://www.googleapis.com/auth/admin.directory.orgunit",
            ],
        )
        .await?;
        let client = chalk_google_sync::client::GoogleAdminClient::new(auth.token(), "my_customer");
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
            if let Ok(run) = pre_run {
                let _ = repo
                    .update_google_sync_run(
                        run.id,
                        chalk_core::models::google_sync::GoogleSyncRunStatus::Completed,
                        summary.users_created,
                        summary.users_updated,
                        summary.users_suspended,
                        summary.ous_created,
                        None,
                    )
                    .await;
            }
            Ok(())
        }
        Err(e) => {
            if let Ok(run) = pre_run {
                let _ = repo
                    .update_google_sync_run(
                        run.id,
                        chalk_core::models::google_sync::GoogleSyncRunStatus::Failed,
                        0,
                        0,
                        0,
                        0,
                        Some(&e.to_string()),
                    )
                    .await;
            }
            Err(e)
        }
    }
}

/// Drive an Active Directory sync end-to-end against the given tenant
/// repo+config. Same shape as [`run_google_sync_for_tenant`]; the engine
/// itself manages its `ad_sync_runs` row, so init failures (LDAP bind,
/// missing TLS CA, etc.) propagate as `Err(ChalkError)` without a UI
/// breadcrumb. The cron loop logs those failures with the tenant slug.
pub async fn run_ad_sync_for_tenant(
    repo: std::sync::Arc<dyn chalk_core::db::repository::ChalkRepository>,
    config: &chalk_core::config::ChalkConfig,
) -> Result<(), chalk_core::error::ChalkError> {
    use chalk_core::error::ChalkError;

    let client = chalk_ad_sync::client::AdClient::new(&config.ad_sync.connection)
        .with_schema(config.ad_sync.options.schema);
    let engine = chalk_ad_sync::sync::AdSyncEngine::new(repo, client, config.ad_sync.clone());
    engine
        .run_sync(config.ad_sync.options.dry_run, false)
        .await
        .map(|_| ())
        .map_err(|e| ChalkError::Sync(format!("ad sync: {e}")))
}

/// Record a sync_run row in the Failed state with the given error message.
/// Used by sync_trigger when the connector can't even be constructed —
/// without this the admin console shows nothing in the history table and
/// the operator has no signal that anything went wrong.
async fn record_failed_sync(
    repo: &dyn chalk_core::db::repository::ChalkRepository,
    provider: &str,
    error: &str,
) {
    let run = match repo.create_sync_run(provider).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to record sync_run for failure: {e}");
            return;
        }
    };
    if let Err(e) = repo
        .update_sync_status(
            run.id,
            chalk_core::models::sync::SyncStatus::Failed,
            Some(error),
        )
        .await
    {
        tracing::error!("Failed to mark sync_run as Failed: {e}");
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
    let provider = sis_provider_label(&state.config);

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
    let sis_provider = sis_provider_display(&state.config);

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

async fn audit_log_page(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(filter): axum::extract::Query<AuditLogFilter>,
) -> AuditLogTemplate {
    // Pull a wider window than what we render so filters that narrow the
    // set still have something to operate on. 500 keeps the table render
    // bounded on the worst case; the pruner (see `audit_log_pruner` task)
    // is responsible for keeping the underlying table from unbounded
    // growth.
    let raw = state
        .repo
        .list_admin_audit_log(500)
        .await
        .unwrap_or_default();
    let total_scanned = raw.len();

    let action_needle = filter
        .action
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    let ip_needle = filter
        .ip
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    // ISO date strings — `YYYY-MM-DD` lex order matches chronological
    // order for the substring we compare against (entry.created_at's
    // RFC-3339 prefix), so a direct string comparison is sound for the
    // bounds we offer.
    let since = filter
        .since
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let until = filter
        .until
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let filtered: Vec<AuditLogView> = raw
        .iter()
        .filter(|e| {
            if let Some(ref needle) = action_needle {
                if !e.action.to_ascii_lowercase().contains(needle) {
                    return false;
                }
            }
            if let Some(ref needle) = ip_needle {
                let ip = e.admin_ip.as_deref().unwrap_or("");
                if !ip.contains(needle.as_str()) {
                    return false;
                }
            }
            let ts = e.created_at.format("%Y-%m-%d").to_string();
            if let Some(s) = since {
                if ts.as_str() < s {
                    return false;
                }
            }
            if let Some(u) = until {
                if ts.as_str() > u {
                    return false;
                }
            }
            true
        })
        .map(AuditLogView::from_model)
        .take(100)
        .collect();

    AuditLogTemplate {
        active_page: "audit_log",
        total_matched: filtered.len(),
        total_scanned,
        entries: filtered,
        filter_action: filter.action.unwrap_or_default(),
        filter_ip: filter.ip.unwrap_or_default(),
        filter_since: filter.since.unwrap_or_default(),
        filter_until: filter.until.unwrap_or_default(),
    }
}

// -- API Tokens (admin UI) --

struct ApiTokenView {
    id: String,
    name: String,
    token_prefix: String,
    created_at: String,
    last_used_at: String,
    status: &'static str,
    is_active: bool,
}

impl ApiTokenView {
    fn from_model(t: &chalk_core::models::api_token::ApiToken) -> Self {
        Self {
            id: t.id.clone(),
            name: t.name.clone(),
            token_prefix: t.token_prefix.clone(),
            created_at: t.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            last_used_at: t
                .last_used_at
                .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| "—".to_string()),
            status: if t.is_active() { "active" } else { "revoked" },
            is_active: t.is_active(),
        }
    }
}

struct JustCreatedToken {
    name: String,
    plaintext: String,
}

#[derive(Template)]
#[template(path = "settings/api_tokens.html")]
struct ApiTokensTemplate {
    active_page: &'static str,
    tokens: Vec<ApiTokenView>,
    just_created: Option<JustCreatedToken>,
    csrf_token: String,
}

async fn api_tokens_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> ApiTokensTemplate {
    let tokens = state.repo.list_api_tokens().await.unwrap_or_default();
    ApiTokensTemplate {
        active_page: "settings",
        tokens: tokens.iter().map(ApiTokenView::from_model).collect(),
        just_created: None,
        csrf_token: csrf.0,
    }
}

#[derive(serde::Deserialize)]
struct ApiTokenCreateForm {
    name: String,
}

async fn api_tokens_create(
    State(state): State<Arc<AppState>>,
    // The CSRF middleware only inserts the CsrfToken extension on GETs; on
    // POSTs we read the `chalk_csrf` cookie directly so the re-rendered form
    // keeps using the same token the user's browser already has.
    csrf: Option<axum::Extension<crate::csrf::CsrfToken>>,
    cookies: axum::http::HeaderMap,
    axum::Form(form): axum::Form<ApiTokenCreateForm>,
) -> axum::response::Result<ApiTokensTemplate, Html<String>> {
    let csrf_token = csrf
        .map(|axum::Extension(t)| t.0)
        .or_else(|| api_tokens_csrf_cookie(&cookies))
        .unwrap_or_default();

    let name = form.name.trim();
    if name.is_empty() || name.len() > 120 {
        return Err(Html(
            "<h1>Invalid token name</h1><a href=\"/settings/api-tokens\">Back</a>".to_string(),
        ));
    }

    // 32 random bytes → 64 hex chars, prefixed with `chk_` so admins can spot
    // it as one of ours when grepping logs or env vars.
    let plaintext = format!("chk_{}", random_hex(32));
    let token_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(plaintext.as_bytes());
        h.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    // The 8-char prefix excludes the `chk_` marker so the UI displays
    // something compact while still being recognizable.
    let token_prefix: String = plaintext.chars().skip(4).take(8).collect();

    let now = chrono::Utc::now();
    let token = chalk_core::models::api_token::ApiToken {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        token_hash,
        token_prefix,
        created_at: now,
        last_used_at: None,
        revoked_at: None,
    };

    if let Err(e) = state.repo.create_api_token(&token).await {
        tracing::error!("create_api_token failed: {e}");
        return Err(Html(
            "<h1>Failed to create token</h1><a href=\"/settings/api-tokens\">Back</a>".to_string(),
        ));
    }

    let _ = state
        .repo
        .log_admin_action(
            "api_token_created",
            Some(&format!("name={name}, id={}", token.id)),
            None,
        )
        .await;

    let tokens = state.repo.list_api_tokens().await.unwrap_or_default();
    Ok(ApiTokensTemplate {
        active_page: "settings",
        tokens: tokens.iter().map(ApiTokenView::from_model).collect(),
        just_created: Some(JustCreatedToken {
            name: token.name.clone(),
            plaintext,
        }),
        csrf_token,
    })
}

/// Read the `chalk_csrf` cookie value from raw request headers. Used by the
/// API-token create handler when no extension is set (POST requests don't get
/// one from the CSRF middleware).
fn api_tokens_csrf_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie_str = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for c in cookie_str.split(';') {
        let c = c.trim();
        if let Some(v) = c.strip_prefix("chalk_csrf=") {
            return Some(v.to_string());
        }
    }
    None
}

async fn api_tokens_revoke(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Redirect {
    if let Err(e) = state.repo.revoke_api_token(&id).await {
        tracing::error!("revoke_api_token({id}) failed: {e}");
    } else {
        let _ = state
            .repo
            .log_admin_action("api_token_revoked", Some(&format!("id={id}")), None)
            .await;
    }
    Redirect::to("/settings/api-tokens")
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
    IdentitySessionsTemplate {
        active_page: "identity",
    }
}

async fn identity_badges() -> IdentityBadgesTemplate {
    IdentityBadgesTemplate {
        active_page: "identity",
    }
}

async fn identity_generate_badge() -> SyncResultTemplate {
    // QR badge generation is gated on the user-facing IDP routes (chalk-idp
    // is integrated; this admin-console shortcut still needs wiring to the
    // per-user badge issuer). Until that lands, show a customer-safe message
    // rather than the dev-speak placeholder the route shipped with.
    SyncResultTemplate {
        message: "Badge generation is coming soon. In the meantime, users can authenticate \
                  with picture passwords or SAML SSO."
            .to_string(),
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
    // Admins configuring Google Workspace / Okta / etc. can't see the
    // server filesystem — surface a browser download URL instead of the
    // server path. (The path is still recorded for self-hosters who SSH
    // in to inspect or back up the cert.)
    let cert_path = state.config.idp.saml_cert_path.clone();

    IdentitySamlSetupTemplate {
        active_page: "identity",
        metadata_url: format!("{}/idp/saml/metadata", public_url),
        sso_url: format!("{}/idp/saml/sso", public_url),
        public_url,
        cert_path,
        cert_download_url: "/identity/saml-cert.pem".to_string(),
    }
}

/// GET /identity/saml-cert.pem — serve the tenant's SAML signing
/// certificate as a downloadable .pem file. Admins paste it into their
/// Service Provider's SSO configuration (Google Workspace, Okta, etc.).
async fn identity_saml_cert_download(
    State(state): State<Arc<AppState>>,
) -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;
    let path = match state.config.idp.saml_cert_path.as_deref() {
        Some(p) if !p.is_empty() => p,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                "SAML certificate not configured for this tenant. \
                 Configure IDP on /identity/settings first.",
            )
                .into_response();
        }
    };
    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "SAML cert read failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "SAML certificate file is missing on disk. Re-save the IDP \
                 settings to materialize it, or contact support.",
            )
                .into_response();
        }
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"chalk-saml-cert.pem\"",
            ),
        ],
        bytes,
    )
        .into_response()
}

// -- Google Sync handlers --

async fn google_sync_dashboard(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> GoogleSyncDashboardTemplate {
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
        csrf_token: csrf.0,
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

        // Record a "running" row up front so a pre-engine failure (e.g.
        // service-account key fails to parse) still surfaces in the History
        // table as a failed run rather than vanishing into the logs.
        let pre_run = repo.create_google_sync_run(false).await;

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
            let admin_email = config.google_sync.admin_email.as_deref().ok_or_else(|| {
                chalk_core::error::ChalkError::GoogleSync("admin_email not configured".into())
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

            let client =
                chalk_google_sync::client::GoogleAdminClient::new(auth.token(), "my_customer");
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
                // `engine.run_sync` already updates the run row it created
                // internally; the pre-run row above is harmless duplicate
                // bookkeeping on the success path. Mark it Completed so the
                // history doesn't show a stale "running" entry.
                if let Ok(run) = pre_run {
                    let _ = repo
                        .update_google_sync_run(
                            run.id,
                            chalk_core::models::google_sync::GoogleSyncRunStatus::Completed,
                            summary.users_created,
                            summary.users_updated,
                            summary.users_suspended,
                            summary.ous_created,
                            None,
                        )
                        .await;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Google sync failed");
                if let Ok(run) = pre_run {
                    let _ = repo
                        .update_google_sync_run(
                            run.id,
                            chalk_core::models::google_sync::GoogleSyncRunStatus::Failed,
                            0,
                            0,
                            0,
                            0,
                            Some(&e.to_string()),
                        )
                        .await;
                }
            }
        }
    });

    SyncResultTemplate {
        message:
            "Google Workspace sync started in the background. Refresh the page to see progress."
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
    GoogleSyncUsersTemplate {
        active_page: "google_sync",
        users,
    }
}

// -- SSO handlers --

async fn sso_partners_list(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> SsoPartnersListTemplate {
    let partners = state.repo.list_sso_partners().await.unwrap_or_default();
    let partners = partners.iter().map(SsoPartnerView::from_model).collect();
    SsoPartnersListTemplate {
        active_page: "sso_partners",
        partners,
        csrf_token: csrf.0,
    }
}

async fn sso_partners_new_form(
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> SsoPartnerFormTemplate {
    SsoPartnerFormTemplate {
        active_page: "sso_partners",
        is_edit: false,
        partner: SsoPartnerView::empty(),
        csrf_token: csrf.0,
    }
}

async fn sso_partners_create(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<SsoPartnerForm>,
) -> Redirect {
    let protocol = match form.protocol.as_str() {
        "oidc" => chalk_core::models::sso::SsoProtocol::Oidc,
        "clever_compat" => chalk_core::models::sso::SsoProtocol::CleverCompat,
        "classlink_compat" => chalk_core::models::sso::SsoProtocol::ClassLinkCompat,
        _ => chalk_core::models::sso::SsoProtocol::Saml,
    };

    // For Clever/ClassLink compat partners the form doesn't expose the OIDC
    // fields, but the upstream `clever_compat::find_partner` lookup keys off
    // `oidc_client_id`. Auto-mint a 32-hex-char id + 64-hex-char secret so the
    // /v3.0/* and /v3.1/* routes can resolve the partner. Admins can override
    // by editing the partner row directly.
    let needs_compat_creds = matches!(
        protocol,
        chalk_core::models::sso::SsoProtocol::CleverCompat
            | chalk_core::models::sso::SsoProtocol::ClassLinkCompat
    );
    let mut form = form;
    if needs_compat_creds {
        if form.oidc_client_id.trim().is_empty() {
            form.oidc_client_id = random_hex(16);
        }
        if form.oidc_client_secret.trim().is_empty() {
            form.oidc_client_secret = random_hex(32);
        }
    }

    let roles: Vec<String> = form
        .roles
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let redirect_uris: Vec<String> = form
        .oidc_redirect_uris
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let now = chrono::Utc::now();
    let partner = chalk_core::models::sso::SsoPartner {
        id: uuid::Uuid::new_v4().to_string(),
        name: form.name,
        logo_url: if form.logo_url.is_empty() {
            None
        } else {
            Some(form.logo_url)
        },
        protocol,
        enabled: form.enabled == "true",
        source: chalk_core::models::sso::SsoPartnerSource::Database,
        tenant_id: None,
        roles,
        saml_entity_id: if form.saml_entity_id.is_empty() {
            None
        } else {
            Some(form.saml_entity_id)
        },
        saml_acs_url: if form.saml_acs_url.is_empty() {
            None
        } else {
            Some(form.saml_acs_url)
        },
        oidc_client_id: if form.oidc_client_id.is_empty() {
            None
        } else {
            Some(form.oidc_client_id)
        },
        oidc_client_secret: if form.oidc_client_secret.is_empty() {
            None
        } else {
            Some(form.oidc_client_secret)
        },
        oidc_redirect_uris: redirect_uris,
        created_at: now,
        updated_at: now,
    };

    match state.repo.upsert_sso_partner(&partner).await {
        Ok(_) => {
            state.notify_sso_changed();
            let _ = state
                .repo
                .log_admin_action(
                    "sso_partner_created",
                    Some(&format!(
                        "id={} name={} protocol={:?}",
                        partner.id, partner.name, partner.protocol
                    )),
                    None,
                )
                .await;
        }
        Err(e) => tracing::error!("Failed to create SSO partner: {e}"),
    }

    Redirect::to("/sso-partners")
}

async fn sso_partners_detail(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Path(id): Path<String>,
) -> axum::response::Result<SsoPartnerDetailTemplate, Html<String>> {
    match state.repo.get_sso_partner(&id).await {
        Ok(Some(partner)) => {
            let public_url = state
                .config
                .chalk
                .public_url
                .clone()
                .unwrap_or_else(|| "https://your-chalk-server.example.com".to_string());
            Ok(SsoPartnerDetailTemplate {
                active_page: "sso_partners",
                partner: SsoPartnerView::from_model(&partner),
                public_url,
                csrf_token: csrf.0,
            })
        }
        _ => Err(Html(
            "<h1>SSO Partner not found</h1><a href=\"/sso-partners\">Back to SSO Partners</a>"
                .to_string(),
        )),
    }
}

async fn sso_partners_edit_form(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Path(id): Path<String>,
) -> axum::response::Result<SsoPartnerFormTemplate, Redirect> {
    match state.repo.get_sso_partner(&id).await {
        Ok(Some(partner)) => {
            if partner.source == chalk_core::models::sso::SsoPartnerSource::Toml {
                return Err(Redirect::to(&format!("/sso-partners/{id}")));
            }
            Ok(SsoPartnerFormTemplate {
                active_page: "sso_partners",
                is_edit: true,
                partner: SsoPartnerView::from_model(&partner),
                csrf_token: csrf.0,
            })
        }
        _ => Err(Redirect::to("/sso-partners")),
    }
}

async fn sso_partners_update(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<SsoPartnerForm>,
) -> axum::response::Result<Redirect, Html<String>> {
    let existing = match state.repo.get_sso_partner(&id).await {
        Ok(Some(p)) => p,
        _ => {
            return Err(Html(
                "<h1>SSO Partner not found</h1><a href=\"/sso-partners\">Back</a>".to_string(),
            ))
        }
    };

    if existing.source == chalk_core::models::sso::SsoPartnerSource::Toml {
        return Err(Html(
            "<h1>Cannot edit TOML-configured partner</h1><a href=\"/sso-partners\">Back</a>"
                .to_string(),
        ));
    }

    let protocol = match form.protocol.as_str() {
        "oidc" => chalk_core::models::sso::SsoProtocol::Oidc,
        "clever_compat" => chalk_core::models::sso::SsoProtocol::CleverCompat,
        "classlink_compat" => chalk_core::models::sso::SsoProtocol::ClassLinkCompat,
        _ => chalk_core::models::sso::SsoProtocol::Saml,
    };

    // Same compat-credential auto-mint as the create handler: preserve any
    // existing values from the DB if the (hidden) form fields are blank, then
    // fall back to random hex.
    let needs_compat_creds = matches!(
        protocol,
        chalk_core::models::sso::SsoProtocol::CleverCompat
            | chalk_core::models::sso::SsoProtocol::ClassLinkCompat
    );
    let mut form = form;
    if needs_compat_creds {
        if form.oidc_client_id.trim().is_empty() {
            form.oidc_client_id = existing
                .oidc_client_id
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| random_hex(16));
        }
        if form.oidc_client_secret.trim().is_empty() {
            form.oidc_client_secret = existing
                .oidc_client_secret
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| random_hex(32));
        }
    }

    let roles: Vec<String> = form
        .roles
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let redirect_uris: Vec<String> = form
        .oidc_redirect_uris
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let updated = chalk_core::models::sso::SsoPartner {
        id: existing.id.clone(),
        name: form.name,
        logo_url: if form.logo_url.is_empty() {
            None
        } else {
            Some(form.logo_url)
        },
        protocol,
        enabled: form.enabled == "true",
        source: existing.source,
        tenant_id: existing.tenant_id,
        roles,
        saml_entity_id: if form.saml_entity_id.is_empty() {
            None
        } else {
            Some(form.saml_entity_id)
        },
        saml_acs_url: if form.saml_acs_url.is_empty() {
            None
        } else {
            Some(form.saml_acs_url)
        },
        oidc_client_id: if form.oidc_client_id.is_empty() {
            None
        } else {
            Some(form.oidc_client_id)
        },
        oidc_client_secret: if form.oidc_client_secret.is_empty() {
            None
        } else {
            Some(form.oidc_client_secret)
        },
        oidc_redirect_uris: redirect_uris,
        created_at: existing.created_at,
        updated_at: chrono::Utc::now(),
    };

    match state.repo.upsert_sso_partner(&updated).await {
        Ok(_) => {
            state.notify_sso_changed();
            let _ = state
                .repo
                .log_admin_action(
                    "sso_partner_updated",
                    Some(&format!("id={} name={}", updated.id, updated.name)),
                    None,
                )
                .await;
        }
        Err(e) => tracing::error!("Failed to update SSO partner: {e}"),
    }

    Ok(Redirect::to(&format!("/sso-partners/{}", existing.id)))
}

async fn sso_partners_toggle(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Result<Redirect, Html<String>> {
    let mut partner = match state.repo.get_sso_partner(&id).await {
        Ok(Some(p)) => p,
        _ => {
            return Err(Html(
                "<h1>SSO Partner not found</h1><a href=\"/sso-partners\">Back</a>".to_string(),
            ))
        }
    };

    if partner.source == chalk_core::models::sso::SsoPartnerSource::Toml {
        return Err(Html(
            "<h1>Cannot toggle TOML-configured partner</h1><a href=\"/sso-partners\">Back</a>"
                .to_string(),
        ));
    }

    partner.enabled = !partner.enabled;
    partner.updated_at = chrono::Utc::now();

    match state.repo.upsert_sso_partner(&partner).await {
        Ok(_) => {
            state.notify_sso_changed();
            let action = if partner.enabled {
                "sso_partner_enabled"
            } else {
                "sso_partner_disabled"
            };
            let _ = state
                .repo
                .log_admin_action(action, Some(&format!("id={}", partner.id)), None)
                .await;
        }
        Err(e) => tracing::error!("Failed to toggle SSO partner: {e}"),
    }

    Ok(Redirect::to("/sso-partners"))
}

// -- Migration handlers --

async fn migration_index() -> MigrationIndexTemplate {
    MigrationIndexTemplate {
        active_page: "migration",
    }
}

async fn migration_clever(
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> MigrationCleverTemplate {
    MigrationCleverTemplate {
        active_page: "migration",
        csrf_token: csrf.0,
    }
}

async fn migration_classlink(
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> MigrationClassLinkTemplate {
    MigrationClassLinkTemplate {
        active_page: "migration",
        csrf_token: csrf.0,
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

            chalk_core::db::DatabasePool::Postgres(_) => {
                unreachable!("test setup uses sqlite memory")
            }
        };
        // Tests historically assumed the implicit PowerSchool default; with
        // the 1.4 breaking change `provider` is now `None` by default. Pin
        // it back to PowerSchool here so the dashboard/sync templates have
        // a non-empty provider label to query against the in-memory repo.
        let mut config = chalk_core::config::ChalkConfig::generate_default();
        config.sis.provider = Some(chalk_core::config::SisProvider::PowerSchool);
        let repo: Arc<dyn ChalkRepository> = Arc::new(repo);
        Arc::new(AppState::new(repo, config))
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
    async fn sync_trigger_rejects_concurrent_invocation() {
        // Holding the sync_in_flight guard simulates a sync that's already
        // running. The second trigger must reject with the "already running"
        // message instead of starting a parallel sync (which would race on
        // upsert and produce inconsistent state).
        let state = test_state().await;
        state
            .sync_in_flight
            .store(true, std::sync::atomic::Ordering::Release);

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
        assert!(
            html.contains("already running"),
            "expected 'already running' message, got: {html}"
        );
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

            chalk_core::db::DatabasePool::Postgres(_) => {
                unreachable!("test setup uses sqlite memory")
            }
        };
        let mut config = chalk_core::config::ChalkConfig::generate_default();
        config.chalk.admin_password_hash =
            Some(crate::auth::hash_password("test-password").unwrap());
        let repo: Arc<dyn ChalkRepository> = Arc::new(repo);
        Arc::new(AppState::new(repo, config))
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

    async fn test_state_with_auth_and_url(public_url: &str) -> Arc<AppState> {
        let pool = chalk_core::db::DatabasePool::new_sqlite_memory()
            .await
            .unwrap();
        let repo = match pool {
            chalk_core::db::DatabasePool::Sqlite(p) => {
                chalk_core::db::sqlite::SqliteRepository::new(p)
            }
            chalk_core::db::DatabasePool::Postgres(_) => {
                unreachable!("test setup uses sqlite memory")
            }
        };
        let mut config = chalk_core::config::ChalkConfig::generate_default();
        config.chalk.admin_password_hash =
            Some(crate::auth::hash_password("test-password").unwrap());
        config.chalk.public_url = Some(public_url.to_string());
        let repo: Arc<dyn ChalkRepository> = Arc::new(repo);
        Arc::new(AppState::new(repo, config))
    }

    #[tokio::test]
    async fn login_cookie_omits_secure_on_http() {
        let state = test_state_with_auth_and_url("http://localhost:8080").await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("password=test-password"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let set_cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("chalk_session="));
        assert!(
            !set_cookie.contains("Secure"),
            "Secure must NOT be set on plain HTTP deployments: {set_cookie}"
        );
    }

    #[tokio::test]
    async fn login_cookie_includes_secure_on_https() {
        let state = test_state_with_auth_and_url("https://chalk.example.com").await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("password=test-password"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let set_cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("chalk_session="));
        assert!(
            set_cookie.contains("Secure"),
            "Secure must be set on HTTPS deployments: {set_cookie}"
        );
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

    // -- SSO Partners tests --

    #[tokio::test]
    async fn sso_partners_list_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sso-partners")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("SSO Partners"));
        assert!(html.contains("No SSO partners configured yet."));
    }

    #[tokio::test]
    async fn sso_partners_new_form_returns_200() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sso-partners/new")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Add SSO Partner"));
        assert!(html.contains("Create Partner"));
    }

    #[tokio::test]
    async fn sso_partners_create_redirects() {
        let state = test_state().await;
        let csrf = test_csrf_token();
        let app = router(state.clone());

        let body = "name=Test+App&protocol=saml&saml_entity_id=https%3A%2F%2Fapp.example.com&saml_acs_url=https%3A%2F%2Fapp.example.com%2Fsaml%2Fconsume&roles=student&logo_url=&enabled=true&oidc_client_id=&oidc_client_secret=&oidc_redirect_uris=";
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sso-partners/new")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "/sso-partners");

        // Verify it was persisted
        let partners = state.repo.list_sso_partners().await.unwrap();
        assert_eq!(partners.len(), 1);
        assert_eq!(partners[0].name, "Test App");
        assert_eq!(
            partners[0].protocol,
            chalk_core::models::sso::SsoProtocol::Saml
        );
    }

    #[tokio::test]
    async fn sso_partners_detail_returns_200() {
        let state = test_state().await;

        let partner = chalk_core::models::sso::SsoPartner {
            id: "test-partner-1".to_string(),
            name: "Test SAML App".to_string(),
            logo_url: None,
            protocol: chalk_core::models::sso::SsoProtocol::Saml,
            enabled: true,
            source: chalk_core::models::sso::SsoPartnerSource::Database,
            tenant_id: None,
            roles: vec!["student".to_string()],
            saml_entity_id: Some("https://app.example.com".to_string()),
            saml_acs_url: Some("https://app.example.com/saml/consume".to_string()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_redirect_uris: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.repo.upsert_sso_partner(&partner).await.unwrap();

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sso-partners/test-partner-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Test SAML App"));
        assert!(html.contains("SAML"));
        assert!(html.contains("/idp/saml/metadata"));
    }

    #[tokio::test]
    async fn sso_partners_detail_not_found() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sso-partners/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("SSO Partner not found"));
    }

    #[tokio::test]
    async fn sso_partners_list_with_data() {
        let state = test_state().await;

        let partner = chalk_core::models::sso::SsoPartner {
            id: "p1".to_string(),
            name: "Canvas LMS".to_string(),
            logo_url: None,
            protocol: chalk_core::models::sso::SsoProtocol::Saml,
            enabled: true,
            source: chalk_core::models::sso::SsoPartnerSource::Database,
            tenant_id: None,
            roles: vec![],
            saml_entity_id: Some("https://canvas.example.com".to_string()),
            saml_acs_url: Some("https://canvas.example.com/saml".to_string()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_redirect_uris: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.repo.upsert_sso_partner(&partner).await.unwrap();

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sso-partners")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Canvas LMS"));
        assert!(html.contains("SAML"));
    }

    #[tokio::test]
    async fn sso_partners_toggle_works() {
        let state = test_state().await;

        let partner = chalk_core::models::sso::SsoPartner {
            id: "toggle-test".to_string(),
            name: "Toggle App".to_string(),
            logo_url: None,
            protocol: chalk_core::models::sso::SsoProtocol::Oidc,
            enabled: true,
            source: chalk_core::models::sso::SsoPartnerSource::Database,
            tenant_id: None,
            roles: vec![],
            saml_entity_id: None,
            saml_acs_url: None,
            oidc_client_id: Some("client123".to_string()),
            oidc_client_secret: Some("secret".to_string()),
            oidc_redirect_uris: vec!["https://app.example.com/cb".to_string()],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.repo.upsert_sso_partner(&partner).await.unwrap();

        let csrf = test_csrf_token();
        let app = router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sso-partners/toggle-test/toggle")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        // Verify it was toggled to disabled
        let updated = state
            .repo
            .get_sso_partner("toggle-test")
            .await
            .unwrap()
            .unwrap();
        assert!(!updated.enabled);
    }

    #[tokio::test]
    async fn nav_contains_sso_partners_link() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(html.contains("href=\"/sso-partners\""));
        assert!(html.contains("SSO Partners"));
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

    // -- Per-section settings (sync_settings module) tests --

    /// Build an `AppState` wired up with a fresh in-memory tenant-config
    /// repo so the settings GET/POST handlers have somewhere to read/write.
    async fn test_state_with_tenant_config() -> Arc<AppState> {
        let pool = chalk_core::db::DatabasePool::new_sqlite_memory()
            .await
            .unwrap();
        let pool = match pool {
            chalk_core::db::DatabasePool::Sqlite(p) => p,
            chalk_core::db::DatabasePool::Postgres(_) => unreachable!(),
        };
        // The SqliteRepository implements both `ChalkRepository` and
        // `TenantConfigRepo` against the same connection pool, so we clone
        // the Arc to hand the *same* backing store to both sides of
        // `AppState`.
        let repo_concrete = Arc::new(chalk_core::db::sqlite::SqliteRepository::new(pool));
        let repo: Arc<dyn ChalkRepository> = repo_concrete.clone();
        let tenant_cfg: Arc<dyn TenantConfigRepo> = repo_concrete;
        let mut config = chalk_core::config::ChalkConfig::generate_default();
        config.sis.provider = Some(chalk_core::config::SisProvider::PowerSchool);
        Arc::new(AppState::new(repo, config).with_tenant_config(tenant_cfg))
    }

    /// Construct a `multipart/form-data` body for the given `(name, value)`
    /// text fields plus optional file fields. Boundary is fixed for
    /// reproducibility.
    fn multipart_body(
        text_fields: &[(&str, &str)],
        files: &[(&str, &str, &[u8])],
    ) -> (String, Vec<u8>) {
        let boundary = "----chalk-test-boundary";
        let mut body: Vec<u8> = Vec::new();
        for (name, value) in text_fields {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(value.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
        for (name, filename, bytes) in files {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        (format!("multipart/form-data; boundary={boundary}"), body)
    }

    #[tokio::test]
    async fn sis_settings_get_empty_db_renders_defaults() {
        let state = test_state_with_tenant_config().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sync/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("SIS Settings"));
        assert!(html.contains("Source: TOML"));
        assert!(html.contains("PowerSchool"));
    }

    #[tokio::test]
    async fn sis_settings_post_persists_and_redirects() {
        let state = test_state_with_tenant_config().await;
        let app = router(state.clone());
        let csrf = test_csrf_token();
        let body = "provider=powerschool&powerschool_base_url=https%3A%2F%2Fps.example.com&powerschool_client_id=abc&powerschool_client_secret=topsecret&enabled=true&sync_schedule=0+2+*+*+*";
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sync/settings")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(format!("{body}&csrf_token={csrf}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let loc = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(loc, "/sync/settings?ok=1");

        let cfg = state
            .tenant_config
            .as_ref()
            .unwrap()
            .get_sis_config()
            .await
            .unwrap()
            .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.provider.as_deref(), Some("powerschool"));
        assert_eq!(
            cfg.powerschool_client_secret.as_deref(),
            Some(&b"topsecret"[..])
        );
    }

    #[tokio::test]
    async fn sis_settings_post_without_secret_keeps_existing() {
        use chalk_core::db::repository::SisConfigRecord;
        let state = test_state_with_tenant_config().await;
        state
            .tenant_config
            .as_ref()
            .unwrap()
            .put_sis_config(
                SisConfigRecord {
                    enabled: true,
                    provider: Some("powerschool".into()),
                    powerschool_client_secret: Some(b"stay".to_vec()),
                    ..Default::default()
                },
                "test",
            )
            .await
            .unwrap();
        let app = router(state.clone());
        let csrf = test_csrf_token();
        // Note: powerschool_client_secret intentionally blank.
        let body = format!(
            "provider=powerschool&enabled=true&powerschool_client_secret=&csrf_token={csrf}"
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sync/settings")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let cfg = state
            .tenant_config
            .as_ref()
            .unwrap()
            .get_sis_config()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            cfg.powerschool_client_secret.as_deref(),
            Some(&b"stay"[..]),
            "blank secret field should preserve the existing sealed value"
        );
    }

    #[tokio::test]
    async fn google_sync_settings_get_returns_200() {
        let state = test_state_with_tenant_config().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/google-sync/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Google Sync Settings"));
        assert!(html.contains("Service account JSON"));
    }

    #[tokio::test]
    async fn google_sync_settings_multipart_persists_uploaded_key() {
        let state = test_state_with_tenant_config().await;
        let app = router(state.clone());
        let csrf = test_csrf_token();
        let (ctype, body) = multipart_body(
            &[
                ("csrf_token", &csrf),
                ("enabled", "true"),
                ("workspace_domain", "example.edu"),
                ("admin_email", "admin@example.edu"),
                ("provision_users", "true"),
                ("sync_schedule", "0 3 * * *"),
            ],
            &[(
                "service_account_key_file",
                "sa.json",
                b"{\"type\":\"service_account\",\"private_key\":\"x\"}",
            )],
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/google-sync/settings")
                    .header("content-type", ctype)
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let loc = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(loc, "/google-sync/settings?ok=1");
        let cfg = state
            .tenant_config
            .as_ref()
            .unwrap()
            .get_google_sync_config()
            .await
            .unwrap()
            .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.workspace_domain.as_deref(), Some("example.edu"));
        assert!(cfg
            .service_account_key
            .as_deref()
            .unwrap()
            .starts_with(b"{\"type\":\"service_account\""));
    }

    #[tokio::test]
    async fn identity_settings_get_renders_form() {
        let state = test_state_with_tenant_config().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/identity/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Identity Settings"));
        assert!(html.contains("SAML signing material"));
    }

    #[tokio::test]
    async fn identity_settings_multipart_persists_cert_and_key() {
        let state = test_state_with_tenant_config().await;
        let app = router(state.clone());
        let csrf = test_csrf_token();
        let (ctype, body) = multipart_body(
            &[
                ("csrf_token", &csrf),
                ("enabled", "true"),
                ("qr_badge_login", "true"),
                ("session_timeout_minutes", "90"),
            ],
            &[
                (
                    "saml_cert_file",
                    "cert.pem",
                    b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
                ),
                (
                    "saml_signing_key_file",
                    "key.pem",
                    b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
                ),
            ],
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/identity/settings")
                    .header("content-type", ctype)
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cfg = state
            .tenant_config
            .as_ref()
            .unwrap()
            .get_idp_config()
            .await
            .unwrap()
            .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.session_timeout_minutes, Some(90));
        assert!(cfg.saml_cert.is_some());
        assert!(cfg.saml_signing_key.is_some());
    }

    #[tokio::test]
    async fn ad_sync_landing_renders() {
        let state = test_state_with_tenant_config().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ad-sync")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Active Directory Sync"));
        assert!(html.contains("Edit settings"));
    }

    #[tokio::test]
    async fn ad_sync_settings_multipart_persists() {
        let state = test_state_with_tenant_config().await;
        let app = router(state.clone());
        let csrf = test_csrf_token();
        let (ctype, body) = multipart_body(
            &[
                ("csrf_token", &csrf),
                ("enabled", "true"),
                ("host", "ldap.example.com"),
                ("port", "636"),
                ("bind_dn", "cn=chalk,dc=example,dc=com"),
                ("bind_password", "hunter2"),
                ("base_dn", "dc=example,dc=com"),
                ("use_tls", "true"),
                ("sync_schedule", "0 4 * * *"),
                ("ou_mapping", "{\"students\":\"OU=S,DC=x\"}"),
            ],
            &[(
                "tls_ca_cert_file",
                "ca.pem",
                b"-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
            )],
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ad-sync/settings")
                    .header("content-type", ctype)
                    .header("cookie", format!("chalk_csrf={csrf}"))
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cfg = state
            .tenant_config
            .as_ref()
            .unwrap()
            .get_ad_sync_config()
            .await
            .unwrap()
            .unwrap();
        assert!(cfg.enabled);
        assert!(cfg.use_tls);
        assert_eq!(cfg.host.as_deref(), Some("ldap.example.com"));
        assert_eq!(cfg.bind_password.as_deref(), Some(&b"hunter2"[..]));
        assert!(cfg.tls_ca_cert.is_some());
        assert!(cfg.ou_mapping.is_some());
    }

    #[tokio::test]
    async fn settings_routes_without_tenant_config_return_html_error() {
        // Vanilla `test_state` does not call `.with_tenant_config(...)`, so
        // the handlers should render the friendly "not wired up" notice
        // rather than panicking.
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sync/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = get_body(response).await;
        assert!(html.contains("Tenant config storage not wired up"));
    }
}
