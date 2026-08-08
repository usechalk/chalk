//! Chalk Console — Embedded web admin UI served from the binary.
//!
//! Provides a full HTMX-powered admin console with dashboard, SIS sync management,
//! user directory, settings, identity provider, and Google Sync pages.

pub mod api;
pub mod asset_edit;
pub mod asset_import;
pub mod assets;
pub mod auth;
pub mod connect;
pub mod csrf;
pub mod devices;
pub mod help;
pub mod history;
pub mod inbound;
pub mod nav;
pub mod preview;
pub mod reports;
pub mod sync_progress;
pub mod sync_settings;
pub mod table;
pub mod ticket_files;
pub mod tickets;
pub mod unmatched;
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
    /// Full-PEM SAML signing certificate provisioned for the tenant at
    /// signup time (sealed in `_meta.tenants.saml_keypair` and unsealed on
    /// context build). Surfaced here so `/identity/saml-cert.pem` can offer
    /// it as a download for admins configuring their Service Provider
    /// (Google Workspace, Okta, etc.) — without this fallback, the
    /// download endpoint only sees `idp.saml_cert_path`, which is empty
    /// until the operator goes through the IDP settings upload flow.
    /// `None` in OSS / single-tenant mode (the OSS path uses
    /// `idp.saml_cert_path` directly).
    pub saml_signing_cert_pem: Option<String>,
    /// When `Some`, admin login is **passwordless magic-link**: the login page
    /// emails a one-time link (via this mailer) and `auth_middleware` enforces
    /// the resulting session. When `None`, the OSS password flow is used. The
    /// hosted runtime sets this so cloud tenants never use admin passwords.
    pub magic_login: Option<Arc<dyn chalk_core::mail::Notifier>>,
    /// Asset inventory, for the `/devices` pages.
    ///
    /// `Arc<dyn AssetRepository>` rather than a method on `repo`, because
    /// `AssetRepository` is deliberately not a member of `ChalkRepository`
    /// (see its doc comment: folding it in would force ~40 stub methods into
    /// the hand-written mock that exists to test user provisioning).
    ///
    /// `None` means the inventory is not enabled — the console's own fixtures
    /// and any embedder that has not wired it. The routes say so rather than
    /// 500ing.
    pub assets: Option<Arc<dyn chalk_core::db::repository::AssetRepository>>,
    /// Where attachment bytes live. `None` means uploads are refused and no
    /// existing attachment can be downloaded — the rows may exist, but without
    /// a store there is nothing to read them from, and pretending otherwise
    /// would 500 on a link a person clicked.
    pub attachments: Option<Arc<dyn chalk_core::attachments::AttachmentStore>>,
    /// General outbound mail: the help portal's sign-in links, and ticket
    /// notification when that lands.
    ///
    /// Separate from `magic_login`, which selects how the *admin console*
    /// authenticates. Sharing one field would mean a district that configured
    /// SMTP for its help desk lost its console password.
    pub mailer: Option<Arc<dyn chalk_core::mail::Notifier>>,
    /// `None` means helpdesk is not wired. Every ticket route says so rather
    /// than 500ing.
    pub tickets: Option<Arc<dyn chalk_core::db::repository::TicketRepository>>,
    /// Per-person console accounts (F1). `None` means only the shared-password
    /// admin exists — login and attribution both fall back to the anonymous
    /// "Administrator", exactly as before console users were added.
    pub console_users: Option<Arc<dyn chalk_core::db::repository::ConsoleUserRepository>>,
    /// Fees and fines (F3). `None` means the device-fee features are not wired;
    /// the help desk and inventory work without it.
    pub charges: Option<Arc<dyn chalk_core::db::repository::ChargeRepository>>,
    /// The immutable asset history behind the action-history views. Set by the
    /// same builder call as `assets`, because a device module that can change
    /// an asset but cannot read back who changed it is not a shippable half.
    pub asset_events: Option<Arc<dyn chalk_core::db::repository::AssetEventRepository>>,
    /// Queue a background job. The console only ever *enqueues* — a worker in
    /// the binary owns the handlers, which is what keeps this crate free of a
    /// dependency on `chalk-devices`.
    pub jobs: Option<Arc<dyn chalk_core::db::repository::JobRepository>>,
    /// Read device-sync run rows, for live progress and run history.
    pub device_runs: Option<Arc<dyn chalk_core::db::repository::GoogleDeviceSyncRepository>>,
    /// Plan and preview bulk changes before they are applied.
    pub change_sets: Option<Arc<dyn chalk_core::db::repository::ChangeSetRepository>>,
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
            saml_signing_cert_pem: None,
            magic_login: None,
            assets: None,
            tickets: None,
            console_users: None,
            charges: None,
            attachments: None,
            mailer: None,
            asset_events: None,
            jobs: None,
            device_runs: None,
            change_sets: None,
        }
    }

    /// Builder: enable the `/devices` inventory and its history views.
    ///
    /// Both repositories are taken in one call rather than two builders on
    /// purpose. They are two traits over what is always the same backing
    /// store, and every operator-initiated change writes to both atomically —
    /// an `AppState` holding one without the other would be a device module
    /// that can reassign a student's Chromebook but cannot say who did it.
    /// Builder: general outbound mail.
    pub fn with_mailer(mut self, mailer: Arc<dyn chalk_core::mail::Notifier>) -> Self {
        self.mailer = Some(mailer);
        self
    }

    /// Builder: where attachment bytes are stored.
    pub fn with_attachments(
        mut self,
        store: Arc<dyn chalk_core::attachments::AttachmentStore>,
    ) -> Self {
        self.attachments = Some(store);
        self
    }

    /// Builder: enable the helpdesk.
    pub fn with_tickets(
        mut self,
        tickets: Arc<dyn chalk_core::db::repository::TicketRepository>,
    ) -> Self {
        self.tickets = Some(tickets);
        self
    }

    /// Wire per-person console accounts (F1). When set, the login form accepts
    /// an email and a console user can sign in with their own password; when
    /// unset the console behaves exactly as the shared-password-only build did.
    pub fn with_console_users(
        mut self,
        console_users: Arc<dyn chalk_core::db::repository::ConsoleUserRepository>,
    ) -> Self {
        self.console_users = Some(console_users);
        self
    }

    /// Wire the fees-and-fines ledger (F3).
    pub fn with_charges(
        mut self,
        charges: Arc<dyn chalk_core::db::repository::ChargeRepository>,
    ) -> Self {
        self.charges = Some(charges);
        self
    }

    pub fn with_assets(
        mut self,
        assets: Arc<dyn chalk_core::db::repository::AssetRepository>,
        asset_events: Arc<dyn chalk_core::db::repository::AssetEventRepository>,
    ) -> Self {
        self.assets = Some(assets);
        self.asset_events = Some(asset_events);
        self
    }

    /// Builder: let the console request a device sync and watch it run.
    ///
    /// Both together, for the same reason `with_assets` takes two: a console
    /// that can start a sync but not report on it would show a button that
    /// appears to do nothing.
    pub fn with_device_sync(
        mut self,
        jobs: Arc<dyn chalk_core::db::repository::JobRepository>,
        device_runs: Arc<dyn chalk_core::db::repository::GoogleDeviceSyncRepository>,
    ) -> Self {
        self.jobs = Some(jobs);
        self.device_runs = Some(device_runs);
        self
    }

    /// Builder: enable planning and previewing bulk changes.
    pub fn with_change_sets(
        mut self,
        change_sets: Arc<dyn chalk_core::db::repository::ChangeSetRepository>,
    ) -> Self {
        self.change_sets = Some(change_sets);
        self
    }

    /// Builder: enable passwordless magic-link admin login, sending links via
    /// the given mailer. When set, the console login becomes email-only and
    /// `auth_middleware` enforces the session (closing the OSS "no password ->
    /// no auth" shortcut). The hosted runtime calls this for every tenant.
    pub fn with_magic_login(mut self, mailer: Arc<dyn chalk_core::mail::Notifier>) -> Self {
        self.magic_login = Some(mailer);
        self
    }

    /// Whether magic-link admin login is enabled for this state.
    /// Whether the **admin console** signs in by emailed link instead of a
    /// password.
    ///
    /// Deliberately *not* "is there a mailer". [`Self::mailer`] is general
    /// outbound mail and exists on any deployment that configured SMTP; if the
    /// two were the same field, configuring mail so the help portal could send
    /// a sign-in link would silently switch the admin console to magic-link
    /// mode and stop the operator's password working.
    pub fn magic_login_enabled(&self) -> bool {
        self.magic_login.is_some()
    }

    /// Builder: attach a tenant-config repo (typically the hosted
    /// `SealingTenantConfigRepo`) so the per-section settings pages can read
    /// and persist DB-backed config.
    pub fn with_tenant_config(mut self, repo: Arc<dyn TenantConfigRepo>) -> Self {
        self.tenant_config = Some(repo);
        self
    }

    /// Builder: attach the tenant's provisioned SAML signing certificate
    /// (full PEM, including BEGIN/END CERTIFICATE markers). Surfaced for
    /// download at `/identity/saml-cert.pem`.
    pub fn with_saml_signing_cert(mut self, pem: String) -> Self {
        self.saml_signing_cert_pem = Some(pem);
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
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Build the console router with all routes.
/// Every route the devices module owns.
///
/// Split out so it can be *withheld*. A disabled module has to 404, not merely
/// lose its nav link: `/devices` is a guessable URL, and a link that is absent
/// from the sidebar is a suggestion rather than a control.
fn device_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(devices::DEVICES_PATH, get(devices::devices_page))
        .route("/devices/export.csv", get(devices::export_csv))
        .route(reports::REPORTS_PATH, get(reports::reports_page))
        .route(
            asset_import::IMPORT_PATH,
            get(asset_import::import_form)
                .post(asset_import::import_submit)
                .layer(axum::extract::DefaultBodyLimit::max(
                    asset_import::MAX_UPLOAD_BYTES,
                )),
        )
        .route(
            connect::CONNECT_PATH,
            get(connect::connect_form).post(connect::connect_submit),
        )
        .route("/devices/connect/test", post(connect::connect_test))
        .route(
            sync_progress::SYNC_PATH,
            get(sync_progress::sync_page).post(sync_progress::sync_trigger),
        )
        .route("/devices/sync/status", get(sync_progress::sync_status))
        .route(preview::PREVIEW_PATH, post(preview::plan))
        .route("/devices/changes/:id", get(preview::preview))
        .route("/devices/changes/:id/exclude", post(preview::exclude))
        .route("/devices/changes/:id/commit", post(preview::commit))
        .route("/devices/changes/:id/discard", post(preview::discard))
        .route(unmatched::UNMATCHED_PATH, get(unmatched::unmatched_page))
        .route(history::HISTORY_PATH, get(history::history_page))
        .route(
            asset_edit::NEW_PATH,
            get(asset_edit::new_form).post(asset_edit::create),
        )
        .route(
            "/devices/:id/edit",
            get(asset_edit::edit_form).post(asset_edit::update),
        )
        .route("/devices/:id", get(history::device_detail))
        .route(
            "/devices/:id/resolve",
            get(unmatched::resolve_picker).post(unmatched::resolve_submit),
        )
        .route("/devices/:id/ignore", post(unmatched::ignore_submit))
        .route(
            "/devices/unmatched/bulk-ignore",
            post(unmatched::bulk_ignore_submit),
        )
}

/// The console pages for Chalk serving identity **outward**: who it federates
/// for, what it provisions into Google, and the SAML metadata another system
/// consumes.
///
/// This is the `roster_sso` module — the line the pricing page draws and calls
/// out as the one most likely to be argued at contract time. The SIS
/// connection that *populates* Chalk stays outside it, because the device
/// inventory and the helpdesk are built on that roster and every tier has it.
/// What is gated here is Chalk serving rostering, SSO and Workspace/AD
/// provisioning to the rest of the district.
fn roster_sso_routes() -> Router<Arc<AppState>> {
    Router::new()
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
}

/// The staff help portal.
///
/// Gated on `helpdesk` and deliberately **not** on `roster_sso`: the Devices +
/// Helpdesk tier is sold a help desk, and if the only door were the SAML IdP
/// that tier would have nowhere for its staff to use it.
fn help_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/help/signin",
            get(help::signin_page).post(help::signin_submit),
        )
        .route("/help/verify", get(help::verify))
        .route("/help/signout", post(help::signout))
        // Authenticated by a shared secret, not a session — a mail provider
        // cannot present one. Closed unless configured.
        .route(
            inbound::INBOUND_PATH,
            post(inbound::receive).layer(axum::extract::DefaultBodyLimit::max(
                crate::csrf::MULTIPART_BODY_LIMIT,
            )),
        )
        // Before `/help/:id`, so "new" is the form and not a request id.
        .route(
            "/help/new",
            get(help::new_request_page).post(help::create_request),
        )
        .route(help::HELP_PATH, get(help::my_tickets))
        .route("/help/:id", get(help::my_ticket))
        .route(
            "/help/:id/reply",
            post(help::reply).layer(axum::extract::DefaultBodyLimit::max(
                crate::csrf::MULTIPART_BODY_LIMIT,
            )),
        )
}

fn ticket_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(tickets::TICKETS_PATH, get(tickets::queue_page))
        // Before `/tickets/:id`, so "new" is a page and not a ticket id.
        .route(
            "/tickets/new",
            get(tickets::new_ticket_page).post(tickets::create_ticket),
        )
        .route("/tickets/:id", get(tickets::ticket_detail))
        .route(
            "/tickets/:id/comment",
            post(tickets::add_comment).layer(axum::extract::DefaultBodyLimit::max(
                crate::csrf::MULTIPART_BODY_LIMIT,
            )),
        )
        .route("/attachments/:id", get(ticket_files::download))
        .route("/tickets/:id/status", post(tickets::set_status))
        .route("/tickets/:id/assign", post(tickets::assign))
        .route("/tickets/:id/reclassify", post(tickets::reclassify))
}

pub fn router(state: Arc<AppState>) -> Router {
    // Withheld rather than hidden. `Router::merge` of nothing is the whole
    // mechanism: a disabled module's paths are never registered, so they 404
    // through the ordinary not-found path with no special-casing anywhere.
    let devices = if state.config.modules.devices {
        device_routes()
    } else {
        Router::new()
    };
    let devices_api_enabled = state.config.modules.devices;
    // Same mechanism for the helpdesk: not registered means 404, not hidden.
    let helpdesk = if state.config.modules.helpdesk {
        ticket_routes().merge(help_routes())
    } else {
        Router::new()
    };
    let roster_sso_enabled = state.config.modules.roster_sso;
    let roster_sso = if roster_sso_enabled {
        roster_sso_routes()
    } else {
        Router::new()
    };

    Router::new()
        .merge(devices)
        .merge(helpdesk)
        .merge(roster_sso)
        .route("/health", get(health))
        .route("/static/htmx-2.0.4.min.js", get(htmx_js))
        .route("/static/bricolage-grotesque.woff2", get(brand_font))
        .merge(assets::router())
        .route("/login", get(auth::login_page).post(auth::login_submit))
        .route("/login/verify", get(auth::login_verify))
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
        .route(
            "/settings/console-users",
            get(console_users_page).post(console_users_create),
        )
        .route(
            "/settings/console-users/:id/toggle",
            post(console_users_toggle),
        )
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
        // Serving the roster outward *is* the module — an API that answers for
        // a module the tenant does not have would be the one door left open.
        .merge(if roster_sso_enabled {
            Router::new().nest(
                "/api/oneroster/v1p1",
                api::oneroster::oneroster_router().layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth::oneroster_bearer_middleware,
                )),
            )
        } else {
            Router::new()
        })
        // Gated with the module, like its console routes: an API that answers
        // for a module the tenant does not have would be the one door left
        // open.
        .merge(if devices_api_enabled {
            Router::new().nest(
                "/api/devices/v1",
                api::devices::devices_router().layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth::oneroster_bearer_middleware,
                )),
            )
        } else {
            Router::new()
        })
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

/// Serves the self-hosted Bricolage Grotesque display font (the brand face used
/// for headings across all Chalk surfaces). Embedded in the binary so it works
/// in OSS self-host and cloud alike, same-origin (no external font CDN). The
/// console is always root-mounted, so `/static/bricolage-grotesque.woff2`
/// resolves for the idp and portal routers nested beneath it too.
async fn brand_font() -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;
    const FONT: &[u8] = include_bytes!("../static/bricolage-grotesque.woff2");
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        FONT,
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

/// Console version rendered in the shared footer of `base.html`.
///
/// Templates reference this by path (`{{ crate::CONSOLE_VERSION }}`) rather
/// than carrying a field, so the ~50 handler template structs don't each need
/// to thread a version through.
pub const CONSOLE_VERSION: &str = env!("CARGO_PKG_VERSION");

// -- Templates --

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    nav: crate::nav::Nav,
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

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "sync/index.html")]
struct SyncPageTemplate {
    nav: crate::nav::Nav,
    sis_enabled: bool,
    sis_provider: String,
    sis_schedule: String,
    csrf_token: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "sync/history.html")]
struct SyncHistoryTemplate {
    runs: Vec<SyncRunView>,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "sync/result.html")]
struct SyncResultTemplate {
    message: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "users/list.html")]
struct UsersListTemplate {
    nav: crate::nav::Nav,
    users: Vec<UserView>,
    query: String,
    role_filter: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "users/detail.html")]
struct UserDetailTemplate {
    nav: crate::nav::Nav,
    user: UserView,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "settings/index.html")]
struct SettingsTemplate {
    nav: crate::nav::Nav,
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

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "settings/audit_log.html")]
struct AuditLogTemplate {
    nav: crate::nav::Nav,
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

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "identity/index.html")]
struct IdentityDashboardTemplate {
    nav: crate::nav::Nav,
    idp_enabled: bool,
    qr_badge_login: bool,
    picture_passwords: bool,
    session_timeout_minutes: u32,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "identity/sessions.html")]
struct IdentitySessionsTemplate {
    nav: crate::nav::Nav,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "identity/badges.html")]
struct IdentityBadgesTemplate {
    nav: crate::nav::Nav,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "identity/auth_log.html")]
struct IdentityAuthLogTemplate {
    auth_logs: Vec<AuthLogView>,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "identity/saml_setup.html")]
struct IdentitySamlSetupTemplate {
    nav: crate::nav::Nav,
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

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "google_sync/index.html")]
struct GoogleSyncDashboardTemplate {
    nav: crate::nav::Nav,
    sync_enabled: bool,
    provision_users: bool,
    manage_ous: bool,
    suspend_inactive: bool,
    workspace_domain: String,
    sync_schedule: String,
    csrf_token: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "google_sync/history.html")]
struct GoogleSyncHistoryTemplate {
    runs: Vec<GoogleSyncRunView>,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "google_sync/users.html")]
struct GoogleSyncUsersTemplate {
    nav: crate::nav::Nav,
    users: Vec<GoogleSyncUserView>,
}

// -- Migration templates --

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "migration/index.html")]
struct MigrationIndexTemplate {
    nav: crate::nav::Nav,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "migration/clever.html")]
struct MigrationCleverTemplate {
    nav: crate::nav::Nav,
    csrf_token: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "migration/classlink.html")]
struct MigrationClassLinkTemplate {
    nav: crate::nav::Nav,
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
                chalk_core::models::sso::SsoProtocol::Link => "Link".to_string(),
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

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "sso/list.html")]
struct SsoPartnersListTemplate {
    nav: crate::nav::Nav,
    partners: Vec<SsoPartnerView>,
    csrf_token: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "sso/form.html")]
struct SsoPartnerFormTemplate {
    nav: crate::nav::Nav,
    is_edit: bool,
    partner: SsoPartnerView,
    csrf_token: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "sso/detail.html")]
struct SsoPartnerDetailTemplate {
    nav: crate::nav::Nav,
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
        nav: crate::nav::Nav::new(&state.config, "dashboard"),
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
        nav: crate::nav::Nav::new(&state.config, "sync"),
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

    // The search runs in SQL, not in Rust over the whole roster. It used to
    // fetch every user and `.filter()` the Vec, which at district scale means
    // pulling 20,000 rows — each with its own junction-table round trip — to
    // display a handful. Email is now searchable too, which the Rust filter
    // did not cover.
    //
    // Still outstanding, and deliberately not fixed here: an *unfiltered* list
    // remains uncapped, because this page has no pagination UI to cap it with.
    // Capping silently would hide users with no way to reach them.
    let filter = UserFilter {
        role: role_filter,
        search: (!params.q.trim().is_empty()).then(|| params.q.trim().to_string()),
        ..UserFilter::default()
    };

    let users: Vec<UserView> = state
        .repo
        .list_users(&filter)
        .await
        .unwrap_or_default()
        .iter()
        .map(UserView::from_model)
        .collect();

    UsersListTemplate {
        nav: crate::nav::Nav::new(&state.config, "users"),
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
            nav: crate::nav::Nav::new(&state.config, "users"),
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
        nav: crate::nav::Nav::new(&state.config, "settings"),
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
        nav: crate::nav::Nav::new(&state.config, "audit_log"),
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

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "settings/api_tokens.html")]
struct ApiTokensTemplate {
    nav: crate::nav::Nav,
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
        nav: crate::nav::Nav::new(&state.config, "api_tokens"),
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
        // Admin-minted console tokens are unrestricted. The hosted marketplace
        // mints scoped tokens directly via `create_api_token`.
        scope: None,
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
        nav: crate::nav::Nav::new(&state.config, "api_tokens"),
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

// -- Console account management (F1) --

struct ConsoleUserView {
    id: String,
    email: String,
    display_name: String,
    role: String,
    status: String,
    status_class: String,
    is_active: bool,
}

struct ConsoleUsersFlash {
    kind: String,
    message: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "settings/console_users.html")]
struct ConsoleUsersTemplate {
    nav: crate::nav::Nav,
    users: Vec<ConsoleUserView>,
    flash: Option<ConsoleUsersFlash>,
    csrf_token: String,
}

#[derive(serde::Deserialize)]
struct ConsoleUsersFlashQuery {
    #[serde(default)]
    ok: Option<String>,
    #[serde(default)]
    err: Option<String>,
}

async fn console_users_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Query(flash_q): Query<ConsoleUsersFlashQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(repo) = state.console_users.clone() else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Html("<h1>Console accounts are not available on this build.</h1>".to_string()),
        )
            .into_response();
    };
    let users = repo
        .list_console_users()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|u| ConsoleUserView {
            id: u.id,
            email: u.email,
            display_name: u.display_name,
            role: u.role.as_str().to_string(),
            status: u.status.as_str().to_string(),
            status_class: if matches!(
                u.status,
                chalk_core::models::console_user::ConsoleUserStatus::Active
            ) {
                "ok".to_string()
            } else {
                "muted".to_string()
            },
            is_active: matches!(
                u.status,
                chalk_core::models::console_user::ConsoleUserStatus::Active
            ),
        })
        .collect();
    let flash = flash_q
        .ok
        .map(|m| ConsoleUsersFlash {
            kind: "success".to_string(),
            message: m,
        })
        .or_else(|| {
            flash_q.err.map(|m| ConsoleUsersFlash {
                kind: "warning".to_string(),
                message: m,
            })
        });
    ConsoleUsersTemplate {
        nav: crate::nav::Nav::new(&state.config, "console_users"),
        users,
        flash,
        csrf_token: csrf.0,
    }
    .into_response()
}

#[derive(serde::Deserialize)]
struct ConsoleUserCreateForm {
    email: String,
    name: String,
    role: String,
    password: String,
}

async fn console_users_create(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<ConsoleUserCreateForm>,
) -> Redirect {
    let base = "/settings/console-users";
    let Some(repo) = state.console_users.clone() else {
        return Redirect::to(base);
    };
    let redirect_err = |m: &str| Redirect::to(&format!("{base}?err={}", urlencoding::encode(m)));

    let email = form.email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return redirect_err("Enter a valid email address.");
    }
    if form.name.trim().is_empty() {
        return redirect_err("Enter a display name.");
    }
    if form.password.len() < 8 {
        return redirect_err("The password must be at least 8 characters.");
    }
    let role = match form
        .role
        .trim()
        .parse::<chalk_core::models::console_user::ConsoleRole>()
    {
        Ok(r) => r,
        Err(_) => return redirect_err("Unknown role."),
    };
    if let Ok(Some(_)) = repo.get_console_user_by_email(&email).await {
        return redirect_err("An account already exists for that email.");
    }
    let password_hash = match chalk_core::auth::hash_password(&form.password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("console user password hash failed: {e}");
            return redirect_err("Could not create the account.");
        }
    };
    let now = chrono::Utc::now();
    let user = chalk_core::models::console_user::ConsoleUser {
        id: uuid::Uuid::new_v4().to_string(),
        email: email.clone(),
        display_name: form.name.trim().to_string(),
        password_hash: Some(password_hash),
        role,
        status: chalk_core::models::console_user::ConsoleUserStatus::Active,
        created_at: now,
        updated_at: now,
    };
    if let Err(e) = repo.create_console_user(&user).await {
        tracing::error!("create_console_user failed: {e}");
        return redirect_err("Could not create the account.");
    }
    let _ = state
        .repo
        .log_admin_action("console_user_created", Some(&email), None)
        .await;
    Redirect::to(&format!(
        "{base}?ok={}",
        urlencoding::encode(&format!("Created {email}."))
    ))
}

async fn console_users_toggle(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Redirect {
    let base = "/settings/console-users";
    let Some(repo) = state.console_users.clone() else {
        return Redirect::to(base);
    };
    if let Ok(Some(mut user)) = repo.get_console_user(&id).await {
        use chalk_core::models::console_user::ConsoleUserStatus;
        user.status = match user.status {
            ConsoleUserStatus::Active => ConsoleUserStatus::Disabled,
            ConsoleUserStatus::Disabled => ConsoleUserStatus::Active,
        };
        if let Err(e) = repo.update_console_user(&user).await {
            tracing::error!("update_console_user failed: {e}");
        } else {
            let _ = state
                .repo
                .log_admin_action(
                    "console_user_toggled",
                    Some(&format!("{}={}", user.email, user.status.as_str())),
                    None,
                )
                .await;
        }
    }
    Redirect::to(base)
}

// -- Identity handlers --

async fn identity_dashboard(State(state): State<Arc<AppState>>) -> IdentityDashboardTemplate {
    IdentityDashboardTemplate {
        nav: crate::nav::Nav::new(&state.config, "identity"),
        idp_enabled: state.config.idp.enabled,
        qr_badge_login: state.config.idp.qr_badge_login,
        picture_passwords: state.config.idp.picture_passwords,
        session_timeout_minutes: state.config.idp.session_timeout_minutes,
    }
}

async fn identity_sessions(State(state): State<Arc<AppState>>) -> IdentitySessionsTemplate {
    IdentitySessionsTemplate {
        nav: crate::nav::Nav::new(&state.config, "identity"),
    }
}

async fn identity_badges(State(state): State<Arc<AppState>>) -> IdentityBadgesTemplate {
    IdentityBadgesTemplate {
        nav: crate::nav::Nav::new(&state.config, "identity"),
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
        nav: crate::nav::Nav::new(&state.config, "identity"),
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
///
/// Resolves the cert from two sources, in priority order:
/// 1. `state.saml_signing_cert_pem` — the cert provisioned at tenant
///    signup and unsealed on context build (hosted multi-tenant). Always
///    populated for hosted tenants, so the download Just Works without
///    the operator needing to touch /identity/settings first.
/// 2. `state.config.idp.saml_cert_path` — a filesystem path. Used by
///    self-hosted OSS installs that point `chalk.toml` at a static cert,
///    and by hosted tenants that have explicitly uploaded one via
///    /identity/settings (the loader materializes it under
///    `<data_dir>/tenants/<slug>/saml-cert.pem`).
async fn identity_saml_cert_download(
    State(state): State<Arc<AppState>>,
) -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;

    let headers = [
        (header::CONTENT_TYPE, "application/x-pem-file"),
        (
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"chalk-saml-cert.pem\"",
        ),
    ];

    // 1) Provisioned in-memory cert (hosted tenant fast path).
    if let Some(pem) = state.saml_signing_cert_pem.as_deref() {
        return (StatusCode::OK, headers, pem.to_string()).into_response();
    }

    // 2) File on disk (OSS or hosted-with-uploaded-cert).
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
    match tokio::fs::read(path).await {
        Ok(bytes) => (StatusCode::OK, headers, bytes).into_response(),
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "SAML cert read failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "SAML certificate file is missing on disk. Re-save the IDP \
                 settings to materialize it, or contact support.",
            )
                .into_response()
        }
    }
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
        nav: crate::nav::Nav::new(&state.config, "google_sync"),
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
        nav: crate::nav::Nav::new(&state.config, "google_sync"),
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
        nav: crate::nav::Nav::new(&state.config, "sso_partners"),
        partners,
        csrf_token: csrf.0,
    }
}

async fn sso_partners_new_form(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> SsoPartnerFormTemplate {
    SsoPartnerFormTemplate {
        nav: crate::nav::Nav::new(&state.config, "sso_partners"),
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
        audience: None,
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
        launch_url: None,
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
                nav: crate::nav::Nav::new(&state.config, "sso_partners"),
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
                nav: crate::nav::Nav::new(&state.config, "sso_partners"),
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
        audience: None,
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
        launch_url: None,
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

async fn migration_index(State(state): State<Arc<AppState>>) -> MigrationIndexTemplate {
    MigrationIndexTemplate {
        nav: crate::nav::Nav::new(&state.config, "migration"),
    }
}

async fn migration_clever(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> MigrationCleverTemplate {
    MigrationCleverTemplate {
        nav: crate::nav::Nav::new(&state.config, "migration"),
        csrf_token: csrf.0,
    }
}

async fn migration_classlink(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> MigrationClassLinkTemplate {
    MigrationClassLinkTemplate {
        nav: crate::nav::Nav::new(&state.config, "migration"),
        csrf_token: csrf.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Every module-gated sidebar entry: the flag, the link, and one path the
    /// module owns.
    const GATED_NAV: &[(&str, &str, &str)] = &[
        ("devices", "href=\"/devices\"", "/devices"),
        ("helpdesk", "href=\"/tickets\"", "/tickets"),
        ("roster_sso", "href=\"/identity\"", "/identity"),
        ("roster_sso", "href=\"/sso-partners\"", "/sso-partners"),
        ("roster_sso", "href=\"/google-sync\"", "/google-sync"),
    ];

    pub(crate) fn set_module(config: &mut chalk_core::config::ChalkConfig, module: &str, on: bool) {
        match module {
            "devices" => config.modules.devices = on,
            "helpdesk" => config.modules.helpdesk = on,
            "roster_sso" => config.modules.roster_sso = on,
            other => panic!("unknown module {other}"),
        }
    }

    /// A console with every repository wired, as `chalk serve` wires them.
    ///
    /// Without this a page 404s because its repository is absent rather than
    /// because a module is off, and a nav test would pass while measuring the
    /// wrong thing.
    pub(crate) async fn fully_wired_state(
        config: chalk_core::config::ChalkConfig,
    ) -> Arc<AppState> {
        let pool = chalk_core::db::DatabasePool::new_sqlite_memory()
            .await
            .unwrap();
        let inner = match pool {
            chalk_core::db::DatabasePool::Sqlite(p) => {
                Arc::new(chalk_core::db::sqlite::SqliteRepository::new(p))
            }
            chalk_core::db::DatabasePool::Postgres(_) => unreachable!(),
        };
        let repo: Arc<dyn ChalkRepository> = inner.clone();
        // EVERY builder `chalk serve` calls, not just the ones a given test
        // happens to need. This has now bitten three times: a page 404s
        // because its repository is absent, the test reads that as "the route
        // is not registered", and it passes while measuring nothing. If a new
        // `with_*` appears on AppState, it belongs here.
        Arc::new(
            AppState::new(repo, config)
                .with_assets(inner.clone(), inner.clone())
                .with_tickets(inner.clone())
                .with_console_users(inner.clone())
                .with_charges(inner.clone())
                .with_device_sync(inner.clone(), inner.clone())
                .with_change_sets(inner.clone()),
        )
    }

    pub(crate) fn default_config() -> chalk_core::config::ChalkConfig {
        let mut config = chalk_core::config::ChalkConfig::generate_default();
        config.sis.provider = Some(chalk_core::config::SisProvider::PowerSchool);
        config
    }

    /// The hrefs the sidebar actually rendered, in order.
    fn sidebar_hrefs(html: &str) -> Vec<String> {
        // `href` precedes `class` on each anchor, so scan backwards from every
        // `sidebar-link` occurrence rather than splitting forwards.
        let mut out = Vec::new();
        for (i, _) in html.match_indices("class=\"sidebar-link") {
            let before = &html[..i];
            if let Some(h) = before.rfind("href=\"") {
                let rest = &before[h + 6..];
                if let Some(end) = rest.find('"') {
                    out.push(rest[..end].to_string());
                }
            }
        }
        out
    }

    /// **No page the console renders may link to one it will not serve.**
    ///
    /// The sidebar sweep below covers the shell. This covers everything else:
    /// the page-header links (`Reports`, `Activity`, `Import CSV`, ...), the
    /// empty-state calls to action, the "back to" links. Those are the same
    /// bug class and there are far more of them, so enumerating them by hand
    /// would fail the same way the first nav test did.
    ///
    /// Deliberately a crawl rather than a fixed list: it starts from the pages
    /// a console has and follows what they actually render, so a link added
    /// tomorrow is covered without anyone remembering this test exists.
    #[tokio::test]
    async fn no_page_links_to_one_the_console_will_not_serve() {
        let state = fully_wired_state(default_config()).await;

        async fn fetch(state: &Arc<AppState>, path: &str) -> (StatusCode, String) {
            let res = router(state.clone())
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = res.status();
            let body = axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, String::from_utf8_lossy(&body).to_string())
        }

        // Seeds, so pages that only render links when they have rows do render
        // them. An empty console links to much less than a real one.
        let roots = [
            "/",
            "/sync",
            "/users",
            "/devices",
            "/tickets",
            "/google-sync",
            "/settings",
            "/identity",
            "/sso-partners",
            "/webhooks",
            "/migration",
            "/settings/audit-log",
            "/settings/api-tokens",
            "/devices/reports",
            "/devices/history",
            "/devices/unmatched",
            "/devices/new",
            "/devices/import",
        ];

        let mut checked: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut dead: Vec<(String, String, u16)> = Vec::new();

        for root in roots {
            let (status, html) = fetch(&state, root).await;
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "{root} is in the crawl list but the console does not serve it"
            );
            if status != StatusCode::OK {
                continue;
            }

            for href in hrefs(&html) {
                // Assets are served, but crawling them proves nothing about
                // navigation and makes the failure output noisy.
                if href.starts_with("/static/") || !checked.insert(href.clone()) {
                    continue;
                }
                let (code, _) = fetch(&state, &href).await;
                if code == StatusCode::NOT_FOUND || code.is_server_error() {
                    dead.push((root.to_string(), href, code.as_u16()));
                }
            }
        }

        assert!(
            checked.len() > 20,
            "the crawl should have found real links; found {checked:?}"
        );
        assert!(
            dead.is_empty(),
            "pages link to something this console will not serve: {dead:?}"
        );
    }

    /// Same-origin paths from `href="..."`, minus fragments and query strings.
    fn hrefs(html: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (i, _) in html.match_indices("href=\"/") {
            let rest = &html[i + 6..];
            if let Some(end) = rest.find('"') {
                let path = &rest[..end];
                let path = path.split(['#', '?']).next().unwrap_or(path);
                if !path.is_empty() {
                    out.push(path.to_string());
                }
            }
        }
        out
    }

    /// **Every link the sidebar renders must lead somewhere.**
    ///
    /// This sweeps whatever `base.html` actually drew rather than a list
    /// maintained by hand. That distinction is not academic: the first version
    /// of this guard enumerated the two modules it was written for, passed,
    /// and sat next to a Marketplace entry that had 404'd in every self-hosted
    /// install since it was added — because nobody had put it on the list.
    /// A guard that only checks the cases you thought of is a guard that
    /// certifies your assumptions.
    #[tokio::test]
    async fn every_sidebar_link_leads_somewhere() {
        let state = fully_wired_state(default_config()).await;

        let page = router(state.clone())
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(page.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8_lossy(&body).to_string();

        let hrefs = sidebar_hrefs(&html);
        assert!(
            hrefs.len() >= 10,
            "the sidebar should have rendered its links; found {hrefs:?}"
        );

        let mut dead = Vec::new();
        for href in &hrefs {
            let res = router(state.clone())
                .oneshot(Request::builder().uri(href).body(Body::empty()).unwrap())
                .await
                .unwrap();
            if res.status() == StatusCode::NOT_FOUND {
                dead.push(href.clone());
            }
        }

        assert!(
            dead.is_empty(),
            "the sidebar links to pages this console does not serve: {dead:?} — \
             either register the route or gate the link on the same flag"
        );
    }

    /// **The console must never show a link to a page it will not serve.**
    ///
    /// The two halves of module gating were written months apart: `router`
    /// withholds the routes, and `base.html` draws the sidebar. Nothing
    /// connected them, so turning the helpdesk off left a Helpdesk link that
    /// went straight to a 404 — an operator reasonably reads that as the
    /// product being broken, not as the module being off.
    ///
    /// Asserting both directions matters. Checking only that a disabled
    /// module hides its link would pass if the link were deleted outright.
    #[tokio::test]
    async fn a_sidebar_link_is_shown_exactly_when_its_routes_are_served() {
        for (module, link, path) in GATED_NAV {
            for on in [true, false] {
                let mut config = chalk_core::config::ChalkConfig::generate_default();
                config.sis.provider = Some(chalk_core::config::SisProvider::PowerSchool);
                set_module(&mut config, module, on);

                let pool = chalk_core::db::DatabasePool::new_sqlite_memory()
                    .await
                    .unwrap();
                // Every repository wired, as `chalk serve` wires them. Without
                // this the page 404s because its repository is absent rather
                // than because the module is off, and the test would pass while
                // measuring the wrong thing.
                let inner = match pool {
                    chalk_core::db::DatabasePool::Sqlite(p) => {
                        Arc::new(chalk_core::db::sqlite::SqliteRepository::new(p))
                    }
                    chalk_core::db::DatabasePool::Postgres(_) => unreachable!(),
                };
                let repo: Arc<dyn ChalkRepository> = inner.clone();
                let state = Arc::new(
                    AppState::new(repo, config)
                        .with_assets(inner.clone(), inner.clone())
                        .with_tickets(inner.clone()),
                );

                let page = router(state.clone())
                    .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let body = axum::body::to_bytes(page.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let shown = String::from_utf8_lossy(&body).contains(link);

                let route = router(state)
                    .oneshot(Request::builder().uri(*path).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let served = route.status() != StatusCode::NOT_FOUND;

                assert_eq!(
                    shown,
                    on,
                    "{module} = {on}: sidebar link {link} should be {}",
                    if on { "present" } else { "absent" }
                );
                assert_eq!(
                    shown, served,
                    "{module} = {on}: the sidebar shows {link} = {shown} but {path} \
                     is served = {served} — a visible link to a 404, or a working \
                     page nobody can reach"
                );
            }
        }
    }

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

    /// Every stylesheet must be reachable, correctly typed, and — because
    /// `/static/` is in `PUBLIC_PATHS` — served without a session. If the
    /// exemption ever regressed, the login page would render unstyled.
    #[tokio::test]
    async fn css_routes_serve_unauthenticated_with_immutable_caching() {
        use axum::http::header;

        for (path, expected_body) in [
            (assets::TOKENS_CSS_PATH, assets::TOKENS_CSS),
            (assets::BASE_CSS_PATH, assets::BASE_CSS),
            (assets::COMPONENTS_CSS_PATH, assets::COMPONENTS_CSS),
            (assets::CONSOLE_CSS_PATH, assets::CONSOLE_CSS),
        ] {
            let state = test_state().await;
            let response = router(state)
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "text/css; charset=utf-8",
                "{path}"
            );
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "public, max-age=31536000, immutable",
                "{path}"
            );
            assert_eq!(get_body(response).await, expected_body, "{path}");
        }
    }

    /// The cache-busting query must survive routing: axum matches on path only,
    /// so the versioned href the templates emit has to resolve too.
    #[tokio::test]
    async fn css_routes_serve_the_versioned_href_templates_emit() {
        let state = test_state().await;
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri(assets::tokens_css_href())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Pages built on base.html must *link* the stylesheets, not re-inline
    /// them: an inline `<style>` creeping back is exactly how three divergent
    /// copies of the token block happened in the first place.
    #[tokio::test]
    async fn base_layout_links_stylesheets_instead_of_inlining_them() {
        let state = test_state().await;
        let response = router(state)
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = get_body(response).await;

        for href in [
            assets::tokens_css_href(),
            assets::base_css_href(),
            assets::components_css_href(),
            assets::console_css_href(),
        ] {
            assert!(
                body.contains(&format!(r#"<link rel="stylesheet" href="{href}">"#)),
                "dashboard does not link {href}"
            );
        }
        assert!(
            !body.contains("<style>"),
            "dashboard still carries an inline <style> block"
        );
        assert!(
            !body.contains("--c-primary:"),
            "dashboard still inlines the token block"
        );
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

    /// The footer version used to be hardcoded (`v1.0.0`) and went stale
    /// across six releases. Assert it tracks the crate version instead.
    #[tokio::test]
    async fn footer_renders_crate_version() {
        let state = test_state().await;
        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let html = get_body(response).await;
        assert!(
            html.contains(&format!(
                "Chalk Admin Console v{}",
                env!("CARGO_PKG_VERSION")
            )),
            "footer did not render the crate version {}",
            env!("CARGO_PKG_VERSION")
        );
        assert!(!html.contains("Chalk Admin Console v1.0.0"));
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

    /// A non-admin session is refused the console-account management surface.
    /// A GET, so the CSRF middleware (POST-only) cannot be the thing rejecting
    /// it — this exercises the role branch of `auth_middleware` directly.
    #[tokio::test]
    async fn a_non_admin_session_cannot_reach_console_account_management() {
        use chalk_core::models::audit::AdminSession;
        let state = test_state_with_auth().await;
        let token = "tok_tech_role_test";
        state
            .repo
            .create_admin_session(&AdminSession {
                token: token.into(),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                ip_address: None,
                actor_id: Some("console_user:t".into()),
                actor_label: Some("A Technician".into()),
                actor_role: Some("technician".into()),
            })
            .await
            .unwrap();
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/settings/console-users")
                    .header("cookie", format!("chalk_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// The same surface is reachable by an admin session (the gate is a role
    /// check, not a blanket block).
    #[tokio::test]
    async fn an_admin_session_reaches_console_account_management() {
        use chalk_core::models::audit::AdminSession;
        let state = fully_wired_state(default_config()).await;
        let token = "tok_admin_role_test";
        state
            .repo
            .create_admin_session(&AdminSession {
                token: token.into(),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                ip_address: None,
                actor_id: Some("console_user:a".into()),
                actor_label: Some("An Admin".into()),
                actor_role: Some("admin".into()),
            })
            .await
            .unwrap();
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/settings/console-users")
                    .header("cookie", format!("chalk_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

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
            audience: None,
            saml_entity_id: Some("https://app.example.com".to_string()),
            saml_acs_url: Some("https://app.example.com/saml/consume".to_string()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_redirect_uris: vec![],
            launch_url: None,
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
            audience: None,
            saml_entity_id: Some("https://canvas.example.com".to_string()),
            saml_acs_url: Some("https://canvas.example.com/saml".to_string()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_redirect_uris: vec![],
            launch_url: None,
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
            audience: None,
            saml_entity_id: None,
            saml_acs_url: None,
            oidc_client_id: Some("client123".to_string()),
            oidc_client_secret: Some("secret".to_string()),
            oidc_redirect_uris: vec!["https://app.example.com/cb".to_string()],
            launch_url: None,
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
        // Every provider that needs an OAuth token endpoint must offer a field
        // for it, or the value can never be entered on hosted.
        assert!(html.contains("name=\"powerschool_token_url\""));
        assert!(html.contains("name=\"infinite_campus_token_url\""));
        assert!(html.contains("name=\"skyward_token_url\""));
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

    /// A hosted Skyward admin must be able to type the OAuth token endpoint —
    /// Skyward's is not derivable from the base URL, and the connector refuses
    /// to build without it. Same for Infinite Campus.
    #[tokio::test]
    async fn sis_settings_post_persists_per_provider_token_urls() {
        let state = test_state_with_tenant_config().await;
        let app = router(state.clone());
        let csrf = test_csrf_token();
        let body = "provider=skyward&enabled=true\
            &skyward_base_url=https%3A%2F%2Fskyward.example.org%2FAPI%2Fv1\
            &skyward_token_url=https%3A%2F%2Fskyward.example.org%2FAPI%2Foauth%2Ftoken\
            &skyward_client_id=sky\
            &infinite_campus_token_url=https%3A%2F%2Fcampus.example.org%2Fcampus%2Foauth2%2Ftoken";
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

        let cfg = state
            .tenant_config
            .as_ref()
            .unwrap()
            .get_sis_config()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            cfg.skyward_token_url.as_deref(),
            Some("https://skyward.example.org/API/oauth/token")
        );
        assert_eq!(
            cfg.infinite_campus_token_url.as_deref(),
            Some("https://campus.example.org/campus/oauth2/token")
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

#[cfg(test)]
mod roster_sso_tests {
    use super::tests::*;
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Serving the roster outward is the module, so the API goes with the
    /// pages. An API left answering for a module the tenant does not have is
    /// the one door still open after every link has been hidden — and it is
    /// the door a script uses, not a person.
    #[tokio::test]
    async fn the_oneroster_api_is_withheld_with_the_module() {
        for on in [true, false] {
            let mut config = chalk_core::config::ChalkConfig::generate_default();
            config.sis.provider = Some(chalk_core::config::SisProvider::PowerSchool);
            config.modules.roster_sso = on;
            let state = fully_wired_state(config).await;

            let res = router(state)
                .oneshot(
                    Request::builder()
                        .uri("/api/oneroster/v1p1/users")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            if on {
                // Unauthenticated, so 401 — but registered, which is the point.
                assert_ne!(res.status(), StatusCode::NOT_FOUND);
            } else {
                assert_eq!(
                    res.status(),
                    StatusCode::NOT_FOUND,
                    "the roster API must not answer when the module is off"
                );
            }
        }
    }

    /// Roster *ingestion* is not part of the module. Every tier is sold the
    /// SIS connection that populates Chalk, because the device inventory and
    /// the helpdesk are built on that roster — gating it would break the two
    /// modules it is supposed to be independent of.
    #[tokio::test]
    async fn the_sis_connection_and_the_roster_itself_stay_available() {
        let mut config = chalk_core::config::ChalkConfig::generate_default();
        config.sis.provider = Some(chalk_core::config::SisProvider::PowerSchool);
        config.modules.roster_sso = false;
        let state = fully_wired_state(config).await;

        for path in ["/sync", "/users"] {
            let res = router(state.clone())
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                res.status(),
                StatusCode::OK,
                "{path} is what populates devices and tickets — it is in every tier"
            );
        }
    }
}
