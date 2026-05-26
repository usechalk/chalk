//! Per-section settings handlers for tenant-config DB rows.
//!
//! Exposes admin-console forms for the SIS connector, Google Workspace sync,
//! Identity provider, and Active Directory sync. Each page mirrors the
//! pattern of the SSO partner and webhook forms: render the current record
//! as form defaults, accept a POST, persist via the optional tenant-config
//! repo on `AppState`, redirect 303 back to the GET form with a flash
//! `?ok=1` query param.
//!
//! Secrets (PowerSchool client secret, Google service-account JSON, SAML
//! signing key, AD bind password, ...) are NEVER rendered back into the
//! form. Instead the form shows a `(set)` indicator and a fresh input that,
//! when left blank, leaves the stored value untouched. Submitting a new
//! value replaces it; an explicit `clear_*` checkbox removes it.

use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Multipart, Query, State},
    response::{Html, Redirect},
};
use chalk_core::db::repository::{
    AdSyncConfigRecord, GoogleSyncConfigRecord, IdpConfigRecord, SisConfigRecord,
};

use crate::AppState;

/// Multipart body cap for the upload pages. Service-account JSONs are well
/// under 5 KB, SAML cert + key bundles top out a few KB, AD TLS CAs a few
/// hundred KB. Axum's default 2 MiB is sufficient for everything we accept,
/// but we set the limit explicitly on the upload routes so future operators
/// reading the router can see the policy. 4 MiB chosen so a doubled-up
/// chain certificate still fits.
pub const UPLOAD_BODY_LIMIT: usize = 4 * 1024 * 1024;

/// Audit actor label written by the per-section `put_*_config` calls. The
/// console's auth middleware enforces an admin session before these
/// handlers run, but it does not surface the admin's identity into request
/// extensions — for now we record a fixed actor and rely on the
/// `admin_audit_log` row's timestamp + IP for individual attribution.
const ADMIN_ACTOR: &str = "admin_console";

// ---------------------------------------------------------------------------
// Source-badge label
// ---------------------------------------------------------------------------

/// `"database"` if a DB row exists for this section, `"toml"` otherwise. The
/// settings pages show this badge at the top so an operator can tell at a
/// glance whether their edits will take effect or be overridden by
/// `chalk.toml`.
fn source_label(has_db_row: bool) -> &'static str {
    if has_db_row {
        "database"
    } else {
        "toml"
    }
}

// ---------------------------------------------------------------------------
// Query string for flash messages
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct FlashQuery {
    #[serde(default)]
    pub ok: Option<String>,
    #[serde(default)]
    pub err: Option<String>,
}

impl FlashQuery {
    fn message(&self) -> String {
        match (self.ok.as_deref(), self.err.as_deref()) {
            (Some("1"), _) => "Settings saved.".to_string(),
            (_, Some(e)) if !e.is_empty() => format!("Error: {e}"),
            _ => String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared "missing tenant_config" error response
// ---------------------------------------------------------------------------

fn no_tenant_config_html() -> Html<String> {
    Html(
        "<h1>Tenant config storage not wired up</h1>\
         <p>This console is running without a database-backed tenant-config repository. \
         Configure these settings via <code>chalk.toml</code> or run under the hosted \
         (multi-tenant) runtime.</p>"
            .to_string(),
    )
}

// ===========================================================================
// SIS settings
// ===========================================================================

#[derive(Template)]
#[template(path = "sync_settings.html")]
pub struct SisSettingsTemplate {
    pub active_page: &'static str,
    pub source: &'static str,
    pub flash: String,
    pub enabled: bool,
    pub provider: String,
    pub powerschool_base_url: String,
    pub powerschool_token_url: String,
    pub powerschool_client_id: String,
    pub powerschool_secret_set: bool,
    pub infinite_campus_base_url: String,
    pub infinite_campus_client_id: String,
    pub infinite_campus_secret_set: bool,
    pub skyward_base_url: String,
    pub skyward_client_id: String,
    pub skyward_secret_set: bool,
    pub oneroster_csv_dir: String,
    pub sync_schedule: String,
    pub csrf_token: String,
}

#[derive(serde::Deserialize, Default)]
pub struct SisSettingsForm {
    #[serde(default)]
    pub enabled: Option<String>,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub powerschool_base_url: String,
    #[serde(default)]
    pub powerschool_token_url: String,
    #[serde(default)]
    pub powerschool_client_id: String,
    #[serde(default)]
    pub powerschool_client_secret: String,
    #[serde(default)]
    pub clear_powerschool_secret: Option<String>,
    #[serde(default)]
    pub infinite_campus_base_url: String,
    #[serde(default)]
    pub infinite_campus_client_id: String,
    #[serde(default)]
    pub infinite_campus_client_secret: String,
    #[serde(default)]
    pub clear_infinite_campus_secret: Option<String>,
    #[serde(default)]
    pub skyward_base_url: String,
    #[serde(default)]
    pub skyward_client_id: String,
    #[serde(default)]
    pub skyward_client_secret: String,
    #[serde(default)]
    pub clear_skyward_secret: Option<String>,
    #[serde(default)]
    pub oneroster_csv_dir: String,
    #[serde(default)]
    pub sync_schedule: String,
    #[serde(default)]
    pub csrf_token: String,
}

fn opt_string(s: String) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

pub async fn sis_settings_form(
    State(state): State<Arc<AppState>>,
    Query(flash): Query<FlashQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Result<SisSettingsTemplate, Html<String>> {
    let repo = match &state.tenant_config {
        Some(r) => r.clone(),
        None => return Err(no_tenant_config_html()),
    };
    let record = repo
        .get_sis_config()
        .await
        .map_err(|e| Html(format!("<h1>DB error: {e}</h1>")))?;
    let has_row = record.is_some();
    let r = record.unwrap_or_default();
    Ok(SisSettingsTemplate {
        active_page: "sync",
        source: source_label(has_row),
        flash: flash.message(),
        enabled: r.enabled,
        provider: r.provider.unwrap_or_default(),
        powerschool_base_url: r.powerschool_base_url.unwrap_or_default(),
        powerschool_token_url: r.powerschool_token_url.unwrap_or_default(),
        powerschool_client_id: r.powerschool_client_id.unwrap_or_default(),
        powerschool_secret_set: r.powerschool_client_secret.is_some(),
        infinite_campus_base_url: r.infinite_campus_base_url.unwrap_or_default(),
        infinite_campus_client_id: r.infinite_campus_client_id.unwrap_or_default(),
        infinite_campus_secret_set: r.infinite_campus_client_secret.is_some(),
        skyward_base_url: r.skyward_base_url.unwrap_or_default(),
        skyward_client_id: r.skyward_client_id.unwrap_or_default(),
        skyward_secret_set: r.skyward_client_secret.is_some(),
        oneroster_csv_dir: r.oneroster_csv_dir.unwrap_or_default(),
        sync_schedule: r.sync_schedule.unwrap_or_default(),
        csrf_token: csrf.0,
    })
}

pub async fn sis_settings_submit(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<SisSettingsForm>,
) -> Result<Redirect, Html<String>> {
    let repo = match &state.tenant_config {
        Some(r) => r.clone(),
        None => return Err(no_tenant_config_html()),
    };
    let existing = repo
        .get_sis_config()
        .await
        .map_err(|e| Html(format!("<h1>DB error: {e}</h1>")))?
        .unwrap_or_default();

    let powerschool_client_secret = secret_field_bytes(
        &form.powerschool_client_secret,
        form.clear_powerschool_secret.is_some(),
        existing.powerschool_client_secret,
    );
    let infinite_campus_client_secret = secret_field_bytes(
        &form.infinite_campus_client_secret,
        form.clear_infinite_campus_secret.is_some(),
        existing.infinite_campus_client_secret,
    );
    let skyward_client_secret = secret_field_bytes(
        &form.skyward_client_secret,
        form.clear_skyward_secret.is_some(),
        existing.skyward_client_secret,
    );

    let record = SisConfigRecord {
        enabled: form.enabled.as_deref() == Some("true"),
        provider: opt_string(form.provider),
        powerschool_base_url: opt_string(form.powerschool_base_url),
        powerschool_token_url: opt_string(form.powerschool_token_url),
        powerschool_client_id: opt_string(form.powerschool_client_id),
        powerschool_client_secret,
        infinite_campus_base_url: opt_string(form.infinite_campus_base_url),
        infinite_campus_client_id: opt_string(form.infinite_campus_client_id),
        infinite_campus_client_secret,
        skyward_base_url: opt_string(form.skyward_base_url),
        skyward_client_id: opt_string(form.skyward_client_id),
        skyward_client_secret,
        oneroster_csv_dir: opt_string(form.oneroster_csv_dir),
        sync_schedule: opt_string(form.sync_schedule),
        updated_at: None,
        updated_by: None,
    };

    match repo.put_sis_config(record, ADMIN_ACTOR).await {
        Ok(_) => {
            state.notify_tenant_config_changed();
            Ok(Redirect::to("/sync/settings?ok=1"))
        }
        Err(e) => Ok(Redirect::to(&format!(
            "/sync/settings?err={}",
            urlencoding::encode(&e.to_string())
        ))),
    }
}

/// Resolve a secret-bearing form field against the previously sealed value:
/// - `clear` set => `None`
/// - new value supplied => `Some(new bytes)`
/// - otherwise => previous value passthrough
fn secret_field_bytes(new_text: &str, clear: bool, previous: Option<Vec<u8>>) -> Option<Vec<u8>> {
    if clear {
        return None;
    }
    let trimmed = new_text.trim();
    if !trimmed.is_empty() {
        Some(trimmed.as_bytes().to_vec())
    } else {
        previous
    }
}

// ===========================================================================
// Google Sync settings
// ===========================================================================

#[derive(Template)]
#[template(path = "google_sync_settings.html")]
pub struct GoogleSyncSettingsTemplate {
    pub active_page: &'static str,
    pub source: &'static str,
    pub flash: String,
    pub enabled: bool,
    pub workspace_domain: String,
    pub admin_email: String,
    pub service_account_key_set: bool,
    pub provision_users: bool,
    pub manage_ous: bool,
    pub suspend_inactive: bool,
    pub sync_schedule: String,
    pub csrf_token: String,
}

pub async fn google_sync_settings_form(
    State(state): State<Arc<AppState>>,
    Query(flash): Query<FlashQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Result<GoogleSyncSettingsTemplate, Html<String>> {
    let repo = match &state.tenant_config {
        Some(r) => r.clone(),
        None => return Err(no_tenant_config_html()),
    };
    let record = repo
        .get_google_sync_config()
        .await
        .map_err(|e| Html(format!("<h1>DB error: {e}</h1>")))?;
    let has_row = record.is_some();
    let r = record.unwrap_or_default();
    Ok(GoogleSyncSettingsTemplate {
        active_page: "google_sync",
        source: source_label(has_row),
        flash: flash.message(),
        enabled: r.enabled,
        workspace_domain: r.workspace_domain.unwrap_or_default(),
        admin_email: r.admin_email.unwrap_or_default(),
        service_account_key_set: r.service_account_key.is_some(),
        provision_users: r.provision_users,
        manage_ous: r.manage_ous,
        suspend_inactive: r.suspend_inactive,
        sync_schedule: r.sync_schedule.unwrap_or_default(),
        csrf_token: csrf.0,
    })
}

pub async fn google_sync_settings_submit(
    State(state): State<Arc<AppState>>,
    multipart: Multipart,
) -> Result<Redirect, Html<String>> {
    let repo = match &state.tenant_config {
        Some(r) => r.clone(),
        None => return Err(no_tenant_config_html()),
    };
    let existing = repo
        .get_google_sync_config()
        .await
        .map_err(|e| Html(format!("<h1>DB error: {e}</h1>")))?
        .unwrap_or_default();

    let parts = match read_multipart_parts(multipart).await {
        Ok(p) => p,
        Err(e) => {
            return Ok(Redirect::to(&format!(
                "/google-sync/settings?err={}",
                urlencoding::encode(&e)
            )))
        }
    };

    let new_key = parts.file_bytes("service_account_key_file");
    let clear = parts.text_or_empty("clear_service_account_key") == "true";
    let service_account_key = if clear {
        None
    } else if let Some(bytes) = new_key {
        Some(bytes)
    } else {
        existing.service_account_key
    };

    let record = GoogleSyncConfigRecord {
        enabled: parts.text_or_empty("enabled") == "true",
        workspace_domain: opt_string(parts.text_or_empty("workspace_domain")),
        admin_email: opt_string(parts.text_or_empty("admin_email")),
        service_account_key,
        provision_users: parts.text_or_empty("provision_users") == "true",
        manage_ous: parts.text_or_empty("manage_ous") == "true",
        suspend_inactive: parts.text_or_empty("suspend_inactive") == "true",
        sync_schedule: opt_string(parts.text_or_empty("sync_schedule")),
        updated_at: None,
        updated_by: None,
    };

    match repo.put_google_sync_config(record, ADMIN_ACTOR).await {
        Ok(_) => {
            state.notify_tenant_config_changed();
            Ok(Redirect::to("/google-sync/settings?ok=1"))
        }
        Err(e) => Ok(Redirect::to(&format!(
            "/google-sync/settings?err={}",
            urlencoding::encode(&e.to_string())
        ))),
    }
}

// ===========================================================================
// Identity / IDP settings
// ===========================================================================

#[derive(Template)]
#[template(path = "identity_settings.html")]
pub struct IdentitySettingsTemplate {
    pub active_page: &'static str,
    pub source: &'static str,
    pub flash: String,
    pub enabled: bool,
    pub qr_badge_login: bool,
    pub picture_passwords: bool,
    pub session_timeout_minutes: i32,
    pub default_password_pattern: String,
    pub default_password_roles: String,
    pub saml_cert_set: bool,
    pub saml_signing_key_set: bool,
    pub csrf_token: String,
}

pub async fn identity_settings_form(
    State(state): State<Arc<AppState>>,
    Query(flash): Query<FlashQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Result<IdentitySettingsTemplate, Html<String>> {
    let repo = match &state.tenant_config {
        Some(r) => r.clone(),
        None => return Err(no_tenant_config_html()),
    };
    let record = repo
        .get_idp_config()
        .await
        .map_err(|e| Html(format!("<h1>DB error: {e}</h1>")))?;
    let has_row = record.is_some();
    let r = record.unwrap_or_default();
    Ok(IdentitySettingsTemplate {
        active_page: "identity",
        source: source_label(has_row),
        flash: flash.message(),
        enabled: r.enabled,
        qr_badge_login: r.qr_badge_login,
        picture_passwords: r.picture_passwords,
        session_timeout_minutes: r.session_timeout_minutes.unwrap_or(60),
        default_password_pattern: r.default_password_pattern.unwrap_or_default(),
        default_password_roles: r
            .default_password_roles
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_default(),
        saml_cert_set: r.saml_cert.is_some(),
        saml_signing_key_set: r.saml_signing_key.is_some(),
        csrf_token: csrf.0,
    })
}

pub async fn identity_settings_submit(
    State(state): State<Arc<AppState>>,
    multipart: Multipart,
) -> Result<Redirect, Html<String>> {
    let repo = match &state.tenant_config {
        Some(r) => r.clone(),
        None => return Err(no_tenant_config_html()),
    };
    let existing = repo
        .get_idp_config()
        .await
        .map_err(|e| Html(format!("<h1>DB error: {e}</h1>")))?
        .unwrap_or_default();

    let parts = match read_multipart_parts(multipart).await {
        Ok(p) => p,
        Err(e) => {
            return Ok(Redirect::to(&format!(
                "/identity/settings?err={}",
                urlencoding::encode(&e)
            )))
        }
    };

    let saml_cert = upload_or_keep(
        parts.file_bytes("saml_cert_file"),
        parts.text_or_empty("clear_saml_cert") == "true",
        existing.saml_cert,
    );
    let saml_signing_key = upload_or_keep(
        parts.file_bytes("saml_signing_key_file"),
        parts.text_or_empty("clear_saml_signing_key") == "true",
        existing.saml_signing_key,
    );

    let session_timeout_minutes = parts
        .text_or_empty("session_timeout_minutes")
        .parse::<i32>()
        .ok();

    let default_password_roles = match parse_or_redirect(
        "default_password_roles",
        &parts.text_or_empty("default_password_roles"),
        "/identity/settings",
    ) {
        Ok(v) => v,
        Err(redirect) => return Ok(redirect),
    };

    let record = IdpConfigRecord {
        enabled: parts.text_or_empty("enabled") == "true",
        qr_badge_login: parts.text_or_empty("qr_badge_login") == "true",
        picture_passwords: parts.text_or_empty("picture_passwords") == "true",
        session_timeout_minutes,
        default_password_pattern: opt_string(parts.text_or_empty("default_password_pattern")),
        default_password_roles,
        saml_cert,
        saml_signing_key,
        updated_at: None,
        updated_by: None,
    };

    match repo.put_idp_config(record, ADMIN_ACTOR).await {
        Ok(_) => {
            state.notify_tenant_config_changed();
            Ok(Redirect::to("/identity/settings?ok=1"))
        }
        Err(e) => Ok(Redirect::to(&format!(
            "/identity/settings?err={}",
            urlencoding::encode(&e.to_string())
        ))),
    }
}

/// File-upload variant of `secret_field_bytes`: prefer the uploaded bytes,
/// otherwise honour `clear`, otherwise fall back to the previously stored
/// value.
fn upload_or_keep(
    uploaded: Option<Vec<u8>>,
    clear: bool,
    previous: Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    if clear {
        return None;
    }
    if let Some(b) = uploaded {
        if !b.is_empty() {
            return Some(b);
        }
    }
    previous
}

// ===========================================================================
// AD Sync landing + settings
// ===========================================================================

#[derive(Template)]
#[template(path = "ad_sync.html")]
pub struct AdSyncLandingTemplate {
    pub active_page: &'static str,
    pub source: &'static str,
    pub configured: bool,
    pub enabled: bool,
    pub host: String,
    pub base_dn: String,
}

pub async fn ad_sync_landing(
    State(state): State<Arc<AppState>>,
) -> Result<AdSyncLandingTemplate, Html<String>> {
    let repo = match &state.tenant_config {
        Some(r) => r.clone(),
        None => return Err(no_tenant_config_html()),
    };
    let record = repo
        .get_ad_sync_config()
        .await
        .map_err(|e| Html(format!("<h1>DB error: {e}</h1>")))?;
    let has_row = record.is_some();
    let r = record.unwrap_or_default();
    Ok(AdSyncLandingTemplate {
        active_page: "ad_sync",
        source: source_label(has_row),
        configured: has_row,
        enabled: r.enabled,
        host: r.host.unwrap_or_default(),
        base_dn: r.base_dn.unwrap_or_default(),
    })
}

#[derive(Template)]
#[template(path = "ad_sync_settings.html")]
pub struct AdSyncSettingsTemplate {
    pub active_page: &'static str,
    pub source: &'static str,
    pub flash: String,
    pub enabled: bool,
    pub host: String,
    pub port: i32,
    pub bind_dn: String,
    pub bind_password_set: bool,
    pub base_dn: String,
    pub user_filter: String,
    pub use_tls: bool,
    pub tls_ca_cert_set: bool,
    pub sync_schedule: String,
    pub ou_mapping: String,
    pub groups: String,
    pub csrf_token: String,
}

pub async fn ad_sync_settings_form(
    State(state): State<Arc<AppState>>,
    Query(flash): Query<FlashQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Result<AdSyncSettingsTemplate, Html<String>> {
    let repo = match &state.tenant_config {
        Some(r) => r.clone(),
        None => return Err(no_tenant_config_html()),
    };
    let record = repo
        .get_ad_sync_config()
        .await
        .map_err(|e| Html(format!("<h1>DB error: {e}</h1>")))?;
    let has_row = record.is_some();
    let r = record.unwrap_or_default();
    Ok(AdSyncSettingsTemplate {
        active_page: "ad_sync",
        source: source_label(has_row),
        flash: flash.message(),
        enabled: r.enabled,
        host: r.host.unwrap_or_default(),
        port: r.port.unwrap_or(636),
        bind_dn: r.bind_dn.unwrap_or_default(),
        bind_password_set: r.bind_password.is_some(),
        base_dn: r.base_dn.unwrap_or_default(),
        user_filter: r.user_filter.unwrap_or_default(),
        use_tls: r.use_tls,
        tls_ca_cert_set: r.tls_ca_cert.is_some(),
        sync_schedule: r.sync_schedule.unwrap_or_default(),
        ou_mapping: r
            .ou_mapping
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_default(),
        groups: r.groups.as_ref().map(|v| v.to_string()).unwrap_or_default(),
        csrf_token: csrf.0,
    })
}

pub async fn ad_sync_settings_submit(
    State(state): State<Arc<AppState>>,
    multipart: Multipart,
) -> Result<Redirect, Html<String>> {
    let repo = match &state.tenant_config {
        Some(r) => r.clone(),
        None => return Err(no_tenant_config_html()),
    };
    let existing = repo
        .get_ad_sync_config()
        .await
        .map_err(|e| Html(format!("<h1>DB error: {e}</h1>")))?
        .unwrap_or_default();

    let parts = match read_multipart_parts(multipart).await {
        Ok(p) => p,
        Err(e) => {
            return Ok(Redirect::to(&format!(
                "/ad-sync/settings?err={}",
                urlencoding::encode(&e)
            )))
        }
    };

    let bind_password = {
        let new_pw = parts.text_or_empty("bind_password");
        let clear = parts.text_or_empty("clear_bind_password") == "true";
        secret_field_bytes(&new_pw, clear, existing.bind_password)
    };
    let tls_ca_cert = upload_or_keep(
        parts.file_bytes("tls_ca_cert_file"),
        parts.text_or_empty("clear_tls_ca_cert") == "true",
        existing.tls_ca_cert,
    );

    let ou_mapping = match parse_or_redirect(
        "ou_mapping",
        &parts.text_or_empty("ou_mapping"),
        "/ad-sync/settings",
    ) {
        Ok(v) => v,
        Err(redirect) => return Ok(redirect),
    };
    let groups = match parse_or_redirect(
        "groups",
        &parts.text_or_empty("groups"),
        "/ad-sync/settings",
    ) {
        Ok(v) => v,
        Err(redirect) => return Ok(redirect),
    };

    let port = parts.text_or_empty("port").parse::<i32>().ok();

    let record = AdSyncConfigRecord {
        enabled: parts.text_or_empty("enabled") == "true",
        host: opt_string(parts.text_or_empty("host")),
        port,
        bind_dn: opt_string(parts.text_or_empty("bind_dn")),
        bind_password,
        base_dn: opt_string(parts.text_or_empty("base_dn")),
        user_filter: opt_string(parts.text_or_empty("user_filter")),
        use_tls: parts.text_or_empty("use_tls") == "true",
        tls_ca_cert,
        sync_schedule: opt_string(parts.text_or_empty("sync_schedule")),
        ou_mapping,
        groups,
        updated_at: None,
        updated_by: None,
    };

    match repo.put_ad_sync_config(record, ADMIN_ACTOR).await {
        Ok(_) => {
            state.notify_tenant_config_changed();
            Ok(Redirect::to("/ad-sync/settings?ok=1"))
        }
        Err(e) => Ok(Redirect::to(&format!(
            "/ad-sync/settings?err={}",
            urlencoding::encode(&e.to_string())
        ))),
    }
}

/// Empty input → `None`; otherwise parse as JSON and surface the error so the
/// handler can redirect with `?err=`. Silently swallowing parse failures and
/// returning `None` would wipe a previously-saved value when the operator
/// makes a typo, with no UI feedback.
fn parse_json_field(s: &str) -> Result<Option<serde_json::Value>, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(trimmed)
        .map(Some)
        .map_err(|e| e.to_string())
}

/// Parse a JSON form field for a settings submit handler. On parse failure,
/// log the detail server-side and return an `Err(Redirect)` carrying a
/// generic user-facing message — serde_json error strings can echo input
/// fragments, and the redirect URL ends up in access logs and browser
/// history. Callers `?`-propagate the redirect to abort the handler.
fn parse_or_redirect(
    field: &'static str,
    raw: &str,
    redirect_base: &'static str,
) -> Result<Option<serde_json::Value>, Redirect> {
    parse_json_field(raw).map_err(|detail| {
        tracing::warn!(
            field, detail = %detail,
            "settings form: invalid JSON, aborting save"
        );
        Redirect::to(&format!(
            "{redirect_base}?err={}",
            urlencoding::encode(&format!("{field}: invalid JSON"))
        ))
    })
}

// ===========================================================================
// Multipart helpers
// ===========================================================================

/// Decoded multipart submission. Text fields are stored as strings; file
/// fields are stored as raw bytes keyed by their form name.
#[derive(Default)]
struct MultipartParts {
    fields: std::collections::HashMap<String, String>,
    files: std::collections::HashMap<String, Vec<u8>>,
}

impl MultipartParts {
    fn text_or_empty(&self, name: &str) -> String {
        self.fields.get(name).cloned().unwrap_or_default()
    }

    fn file_bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.files.get(name).cloned().filter(|b| !b.is_empty())
    }
}

async fn read_multipart_parts(mut multipart: Multipart) -> Result<MultipartParts, String> {
    let mut out = MultipartParts::default();
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let name = match field.name() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let has_filename = field.file_name().is_some();
                if has_filename {
                    let bytes = field
                        .bytes()
                        .await
                        .map_err(|e| format!("upload read failed: {e}"))?;
                    out.files.insert(name, bytes.to_vec());
                } else {
                    let text = field
                        .text()
                        .await
                        .map_err(|e| format!("field read failed: {e}"))?;
                    out.fields.insert(name, text);
                }
            }
            Ok(None) => break,
            Err(e) => return Err(format!("multipart error: {e}")),
        }
    }
    Ok(out)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chalk_core::db::repository::TenantConfigRepo;
    use chalk_core::db::sqlite::SqliteRepository;
    use chalk_core::db::DatabasePool;

    async fn make_repo() -> Arc<dyn TenantConfigRepo> {
        let pool = DatabasePool::new_sqlite_memory().await.unwrap();
        match pool {
            DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
            DatabasePool::Postgres(_) => unreachable!(),
        }
    }

    #[test]
    fn source_label_db_when_row_present() {
        assert_eq!(source_label(true), "database");
        assert_eq!(source_label(false), "toml");
    }

    #[test]
    fn opt_string_trims_and_filters_empty() {
        assert_eq!(opt_string("".into()), None);
        assert_eq!(opt_string("   ".into()), None);
        assert_eq!(opt_string(" abc ".into()), Some("abc".to_string()));
    }

    #[test]
    fn secret_field_clear_returns_none() {
        let prev = Some(b"old".to_vec());
        assert_eq!(secret_field_bytes("ignored", true, prev), None);
    }

    #[test]
    fn secret_field_empty_keeps_previous() {
        let prev = Some(b"old".to_vec());
        assert_eq!(
            secret_field_bytes("", false, prev.clone()),
            Some(b"old".to_vec())
        );
    }

    #[test]
    fn secret_field_new_value_overrides() {
        let prev = Some(b"old".to_vec());
        assert_eq!(
            secret_field_bytes("new", false, prev),
            Some(b"new".to_vec())
        );
    }

    #[test]
    fn upload_or_keep_priority_order() {
        // clear wins
        assert_eq!(
            upload_or_keep(Some(b"u".to_vec()), true, Some(b"p".to_vec())),
            None
        );
        // uploaded wins over previous
        assert_eq!(
            upload_or_keep(Some(b"u".to_vec()), false, Some(b"p".to_vec())),
            Some(b"u".to_vec())
        );
        // empty upload falls through to previous
        assert_eq!(
            upload_or_keep(Some(vec![]), false, Some(b"p".to_vec())),
            Some(b"p".to_vec())
        );
        // nothing supplied => previous
        assert_eq!(
            upload_or_keep(None, false, Some(b"p".to_vec())),
            Some(b"p".to_vec())
        );
    }

    #[test]
    fn parse_optional_json_handles_object_and_garbage() {
        assert_eq!(parse_json_field("").unwrap(), None);
        assert_eq!(parse_json_field("   ").unwrap(), None);
        assert!(parse_json_field("{\"k\":1}").unwrap().is_some());
        assert!(parse_json_field("not json").is_err());
    }

    #[test]
    fn flash_message_renders() {
        let f = FlashQuery {
            ok: Some("1".into()),
            err: None,
        };
        assert!(f.message().contains("saved"));
        let f = FlashQuery {
            ok: None,
            err: Some("boom".into()),
        };
        assert!(f.message().contains("boom"));
        let f = FlashQuery {
            ok: None,
            err: None,
        };
        assert!(f.message().is_empty());
    }

    #[tokio::test]
    async fn sis_put_then_get_round_trip() {
        let repo = make_repo().await;
        let rec = SisConfigRecord {
            enabled: true,
            provider: Some("powerschool".into()),
            powerschool_client_id: Some("abc".into()),
            powerschool_client_secret: Some(b"sek".to_vec()),
            ..Default::default()
        };
        repo.put_sis_config(rec.clone(), "actor").await.unwrap();
        let got = repo.get_sis_config().await.unwrap().unwrap();
        assert!(got.enabled);
        assert_eq!(got.provider.as_deref(), Some("powerschool"));
        assert_eq!(got.powerschool_client_id.as_deref(), Some("abc"));
        assert_eq!(got.powerschool_client_secret.as_deref(), Some(&b"sek"[..]));
    }

    #[tokio::test]
    async fn submit_without_new_secret_preserves_existing() {
        // Simulate the handler's resolution path: previous secret is in the
        // repo, the form supplied an empty string + no clear flag.
        let repo = make_repo().await;
        repo.put_sis_config(
            SisConfigRecord {
                enabled: true,
                powerschool_client_secret: Some(b"old".to_vec()),
                ..Default::default()
            },
            "actor",
        )
        .await
        .unwrap();
        let existing = repo.get_sis_config().await.unwrap().unwrap();
        let resolved = secret_field_bytes("", false, existing.powerschool_client_secret);
        assert_eq!(resolved.as_deref(), Some(&b"old"[..]));
    }

    #[tokio::test]
    async fn google_put_get_with_service_account_key() {
        let repo = make_repo().await;
        let rec = GoogleSyncConfigRecord {
            enabled: true,
            workspace_domain: Some("example.com".into()),
            service_account_key: Some(b"{\"type\":\"service_account\"}".to_vec()),
            provision_users: true,
            ..Default::default()
        };
        repo.put_google_sync_config(rec.clone(), "actor")
            .await
            .unwrap();
        let got = repo.get_google_sync_config().await.unwrap().unwrap();
        assert!(got.enabled);
        assert_eq!(got.workspace_domain.as_deref(), Some("example.com"));
        assert!(got.service_account_key.is_some());
    }

    #[tokio::test]
    async fn idp_round_trip_with_saml_blobs() {
        let repo = make_repo().await;
        let rec = IdpConfigRecord {
            enabled: true,
            qr_badge_login: true,
            session_timeout_minutes: Some(120),
            saml_cert: Some(b"-----BEGIN CERTIFICATE-----".to_vec()),
            saml_signing_key: Some(b"-----BEGIN PRIVATE KEY-----".to_vec()),
            ..Default::default()
        };
        repo.put_idp_config(rec, "actor").await.unwrap();
        let got = repo.get_idp_config().await.unwrap().unwrap();
        assert!(got.qr_badge_login);
        assert_eq!(got.session_timeout_minutes, Some(120));
        assert!(got.saml_cert.is_some());
        assert!(got.saml_signing_key.is_some());
    }

    #[tokio::test]
    async fn ad_round_trip() {
        let repo = make_repo().await;
        let rec = AdSyncConfigRecord {
            enabled: true,
            host: Some("ldap.example.com".into()),
            port: Some(636),
            base_dn: Some("dc=example,dc=com".into()),
            bind_password: Some(b"pw".to_vec()),
            use_tls: true,
            ..Default::default()
        };
        repo.put_ad_sync_config(rec, "actor").await.unwrap();
        let got = repo.get_ad_sync_config().await.unwrap().unwrap();
        assert!(got.use_tls);
        assert_eq!(got.host.as_deref(), Some("ldap.example.com"));
        assert_eq!(got.bind_password.as_deref(), Some(&b"pw"[..]));
    }

    #[tokio::test]
    async fn empty_db_landing_marks_unconfigured() {
        let repo = make_repo().await;
        assert!(repo.get_ad_sync_config().await.unwrap().is_none());
        assert!(repo.get_sis_config().await.unwrap().is_none());
        assert!(repo.get_google_sync_config().await.unwrap().is_none());
        assert!(repo.get_idp_config().await.unwrap().is_none());
    }
}
