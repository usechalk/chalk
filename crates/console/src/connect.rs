//! Connect Google — the front of the first-run arc (C1).
//!
//! # The thing this screen is actually for
//!
//! Not "collect a credential". A district's administrator has to do work in
//! *their* Google Admin console that Chalk cannot do for them: authorise a
//! service account for domain-wide delegation against an exact list of scopes.
//! If they get one character of that wrong, every symptom looks like a Chalk
//! bug — a sync that returns 403, or worse, one that returns an empty fleet.
//!
//! So the page is built around two ideas.
//!
//! **Show them the values, do not describe them.** The client ID Google asks
//! for lives inside the key file they just uploaded, and the scopes are a
//! constant in this binary. Both are rendered as copyable text taken from the
//! real source, so there is nothing to transcribe and nothing to look up.
//!
//! **Prove it works before they leave.** "Test connection" makes one real read
//! call and reports what it can see — *"Connected. 5,000 ChromeOS devices, 47
//! org units visible."* That turns the worst failure mode in this feature, a
//! misconfiguration discovered an hour into a sync, into a five-second answer.
//!
//! # What is deliberately absent
//!
//! The OAuth refresh-token flow. It cannot be exercised end to end until the
//! Cloud project clears verification, and `TokenProvider` means it drops in
//! later without touching sync code. Offering a half-testable second auth mode
//! here would add a branch nobody can prove.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Multipart, Query, State};
use axum::response::{Html, Redirect};
use chalk_core::db::repository::DeviceConfigRecord;
use chalk_google_sync::backoff::RateLimiter;
use chalk_google_sync::chromeos::ChromeOsClient;
use chalk_google_sync::token::{device_sync_scopes, GoogleTokenSource, ServiceAccountIdentity};

use crate::sync_settings::{
    no_tenant_config_html, opt_string, read_multipart_parts, source_label, FlashQuery, ADMIN_ACTOR,
};
use crate::AppState;

pub const CONNECT_PATH: &str = "/devices/connect";

/// Defaults offered when nothing is configured yet. They match
/// `DeviceSyncConfig`'s own defaults so the page cannot drift from the engine.
const DEFAULT_CUSTOMER_ID: &str = "my_customer";
const DEFAULT_PAGE_SIZE: i64 = 200;
const DEFAULT_REQUESTS_PER_MINUTE: i64 = 500;
const DEFAULT_SCHEDULE: &str = "0 4 * * *";

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/connect.html")]
pub struct ConnectTemplate {
    pub nav: crate::nav::Nav,
    pub source: &'static str,
    pub flash: String,
    pub enabled: bool,
    /// Whether this tenant has agreed to let Chalk write to Google. Drives both
    /// the toggle and which scope list the delegation panel shows.
    pub write_back_enabled: bool,
    pub customer_id: String,
    pub admin_email: String,
    pub page_size: i64,
    pub requests_per_minute: i64,
    pub sync_schedule: String,
    /// A key is stored. The key itself is never rendered.
    pub key_set: bool,
    /// Identity read out of the stored key, so the delegation panel shows the
    /// values Google asks for rather than telling the operator to find them.
    pub client_email: String,
    pub client_id: String,
    /// Set when a key is stored but unreadable — a wrong master key, or a
    /// truncated file. Said plainly rather than rendered as "no key".
    pub key_problem: String,
    pub scopes: Vec<String>,
    /// One comma-joined line, which is the shape Google's delegation form
    /// wants pasted in. Rendered alongside the itemised list because the list
    /// is for reading and this is for copying.
    pub scopes_oneline: String,
    pub csrf_token: String,
}

impl ConnectTemplate {
    pub fn has_identity(&self) -> bool {
        !self.client_id.is_empty()
    }

    pub fn has_problem(&self) -> bool {
        !self.key_problem.is_empty()
    }

    /// Everything needed to run a sync is present. Drives whether the page
    /// offers "Test connection" or explains what is still missing.
    pub fn is_connectable(&self) -> bool {
        self.key_set && !self.admin_email.is_empty() && !self.has_problem()
    }
}

// ---------------------------------------------------------------------------
// GET
// ---------------------------------------------------------------------------

pub async fn connect_form(
    State(state): State<Arc<AppState>>,
    Query(flash): Query<FlashQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Result<ConnectTemplate, Html<String>> {
    let Some(repo) = state.tenant_config.clone() else {
        return Err(no_tenant_config_html());
    };

    let record = repo.get_device_config().await.map_err(|e| {
        Html(format!(
            "<h1>Could not read the configuration</h1><p>{e}</p>"
        ))
    })?;
    let has_row = record.is_some();
    let r = record.unwrap_or_default();

    // The stored key is parsed for its *identity* only. A key that cannot be
    // parsed is reported as a problem rather than silently shown as absent —
    // "no key" would invite an operator to upload a replacement over a
    // credential that is merely unreadable.
    let (client_email, client_id, key_problem) = match &r.service_account_key {
        None => (String::new(), String::new(), String::new()),
        Some(bytes) => match ServiceAccountIdentity::from_json(bytes) {
            Ok(id) => (id.client_email, id.client_id, String::new()),
            Err(e) => (String::new(), String::new(), e.to_string()),
        },
    };

    // The scope list an administrator pastes into their Admin console has to be
    // the one Chalk will actually request. Domain-wide delegation matches the
    // literal string, so showing the read-only list to a tenant that has
    // enabled write-back guarantees a 403 on every write — and a 403 that
    // looks nothing like a scope problem.
    let scopes: Vec<String> = device_sync_scopes(r.write_back_enabled)
        .iter()
        .map(|s| s.to_string())
        .collect();
    Ok(ConnectTemplate {
        nav: crate::nav::Nav::new(&state.config, "devices"),
        source: source_label(has_row),
        flash: flash.message(),
        enabled: r.enabled,
        write_back_enabled: r.write_back_enabled,
        customer_id: r
            .customer_id
            .unwrap_or_else(|| DEFAULT_CUSTOMER_ID.to_string()),
        admin_email: r.admin_email.unwrap_or_default(),
        page_size: r.page_size.unwrap_or(DEFAULT_PAGE_SIZE),
        requests_per_minute: r.requests_per_minute.unwrap_or(DEFAULT_REQUESTS_PER_MINUTE),
        sync_schedule: r
            .sync_schedule
            .unwrap_or_else(|| DEFAULT_SCHEDULE.to_string()),
        key_set: r.service_account_key.is_some(),
        client_email,
        client_id,
        key_problem,
        scopes_oneline: scopes.join(","),
        scopes,
        csrf_token: csrf.0,
    })
}

// ---------------------------------------------------------------------------
// POST
// ---------------------------------------------------------------------------

pub async fn connect_submit(
    State(state): State<Arc<AppState>>,
    multipart: Multipart,
) -> Result<Redirect, Html<String>> {
    let Some(repo) = state.tenant_config.clone() else {
        return Err(no_tenant_config_html());
    };

    let existing = repo
        .get_device_config()
        .await
        .map_err(|e| {
            Html(format!(
                "<h1>Could not read the configuration</h1><p>{e}</p>"
            ))
        })?
        .unwrap_or_default();

    let parts = match read_multipart_parts(multipart).await {
        Ok(p) => p,
        Err(e) => return Ok(redirect_err(&e)),
    };

    // Upload / keep / clear, the same three-way the other settings pages use.
    let clear = parts.text_or_empty("clear_key") == "true";
    let uploaded = parts.file_bytes("service_account_key_file");
    let service_account_key = if clear {
        None
    } else if let Some(bytes) = uploaded {
        // Validated before it is stored. A key rejected here is one an operator
        // can fix now, while they still have the file open — rather than one
        // that fails at 4am inside a scheduled sync.
        if let Err(e) = ServiceAccountIdentity::from_json(&bytes) {
            return Ok(redirect_err(&e.to_string()));
        }
        Some(bytes)
    } else {
        existing.service_account_key
    };

    let record = DeviceConfigRecord {
        enabled: parts.text_or_empty("enabled") == "true",
        write_back_enabled: parts.text_or_empty("write_back_enabled") == "true",
        customer_id: opt_string(parts.text_or_empty("customer_id")),
        admin_email: opt_string(parts.text_or_empty("admin_email")),
        service_account_key,
        page_size: positive(parts.text_or_empty("page_size")),
        requests_per_minute: positive(parts.text_or_empty("requests_per_minute")),
        sync_schedule: opt_string(parts.text_or_empty("sync_schedule")),
        updated_at: None,
        updated_by: None,
    };

    match repo.put_device_config(record, ADMIN_ACTOR).await {
        Ok(()) => Ok(Redirect::to(&format!("{CONNECT_PATH}?ok=1"))),
        Err(e) => Ok(redirect_err(&e.to_string())),
    }
}

/// Parse a positive integer, treating anything else as "use the default".
///
/// A page size of zero would ask Google for empty pages forever, and a
/// negative rate limit would divide by a negative — both are worse than
/// quietly falling back.
fn positive(raw: String) -> Option<i64> {
    raw.trim().parse::<i64>().ok().filter(|n| *n > 0)
}

fn redirect_err(message: &str) -> Redirect {
    Redirect::to(&format!(
        "{CONNECT_PATH}?err={}",
        urlencoding::encode(message)
    ))
}

// ---------------------------------------------------------------------------
// Test connection
// ---------------------------------------------------------------------------

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/connect_test.html")]
pub struct ConnectTestTemplate {
    pub ok: bool,
    pub headline: String,
    pub detail: String,
    /// What to do about it. Empty on success.
    pub remedy: String,
}

/// `POST /devices/connect/test` — one real read call against Google.
///
/// Deliberately reports **what it can see**, not merely that a token was
/// obtained. A service account can authenticate perfectly and still be
/// invisible to the directory if delegation was authorised for the wrong
/// scopes, and "connected" on that footing is the misleading answer this
/// affordance exists to avoid.
pub async fn connect_test(State(state): State<Arc<AppState>>) -> ConnectTestTemplate {
    let Some(repo) = state.tenant_config.clone() else {
        return failure(
            "Configuration storage is not available",
            "This console has no database-backed configuration.",
            "Configure device sync in chalk.toml instead.",
        );
    };

    let record = match repo.get_device_config().await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return failure(
                "Nothing to test yet",
                "No Google credentials have been saved.",
                "Upload a service-account key and save, then test.",
            )
        }
        Err(e) => {
            return failure(
                "Could not read the saved configuration",
                &e.to_string(),
                "If this database was restored from a backup, check that chalk.key \
                 is the one it was encrypted with.",
            )
        }
    };

    // Test with the scopes this tenant will actually request. Testing with the
    // read-only set on a write-enabled tenant would report a healthy
    // connection right up until the first write returned 403 — which is the
    // opposite of what a "Test connection" button is for.
    let write_back = record.write_back_enabled;

    let Some(key) = record.service_account_key else {
        return failure(
            "No key on file",
            "A service-account key is required.",
            "Upload the JSON key you downloaded from Google Cloud.",
        );
    };
    let Some(admin_email) = record.admin_email.filter(|e| !e.trim().is_empty()) else {
        return failure(
            "No administrator to impersonate",
            "Domain-wide delegation works by acting as a real super-admin.",
            "Enter the email address of a Google Workspace super-admin.",
        );
    };

    // The token source wants a file. Materialising to a temp file rather than
    // widening its API keeps one code path for building credentials — and the
    // file lives no longer than this request.
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            return failure(
                "Could not prepare the credential",
                &e.to_string(),
                "Check that the server can write to its temporary directory.",
            )
        }
    };
    let key_path = dir.path().join("sa.json");
    if let Err(e) = std::fs::write(&key_path, &key) {
        return failure(
            "Could not prepare the credential",
            &e.to_string(),
            "Check that the server can write to its temporary directory.",
        );
    }

    let auth = match GoogleTokenSource::from_service_account_file(
        &key_path.to_string_lossy(),
        &admin_email,
        device_sync_scopes(write_back),
    ) {
        Ok(a) => a.into_shared(),
        Err(e) => {
            return failure(
                "That key could not be used",
                &e.to_string(),
                "Re-download the JSON key from Google Cloud and upload it again.",
            )
        }
    };

    let customer_id = record
        .customer_id
        .unwrap_or_else(|| DEFAULT_CUSTOMER_ID.to_string());
    let client = ChromeOsClient::new(auth, &customer_id)
        // One page, one device. This is a reachability check, not a sync.
        .with_max_results(1)
        .with_rate_limiter(RateLimiter::per_minute(60));

    // Devices first: it is the scope that matters most, and the one whose
    // absence is likeliest.
    let devices = match client.list_devices(None, None).await {
        Ok(page) => page,
        Err(e) => return diagnose(&e.to_string(), &admin_email),
    };
    let org_units = match client.list_org_units().await {
        Ok(ous) => ous.len(),
        Err(e) => return diagnose(&e.to_string(), &admin_email),
    };

    // `list_devices` returns one page, so its total is the fleet size when
    // Google reports one; otherwise say what was actually seen rather than
    // implying a count nobody measured.
    let seen = devices.devices.len();
    ConnectTestTemplate {
        ok: true,
        headline: "Connected to Google Workspace".to_string(),
        detail: format!(
            "Acting as {admin_email}. {} and {org_units} org unit{} visible.",
            if seen > 0 {
                "ChromeOS devices are readable".to_string()
            } else {
                "No ChromeOS devices were returned".to_string()
            },
            if org_units == 1 { "" } else { "s" }
        ),
        remedy: if seen == 0 {
            "Chalk can reach Google, but this customer has no ChromeOS devices \
             visible to that administrator. Check that the account can see the \
             devices you expect in the Admin console."
                .to_string()
        } else {
            String::new()
        },
    }
}

/// Turn a Google error into something an administrator can act on.
///
/// The two failures that matter are indistinguishable by status code — Google
/// answers 403 for both a missing delegation grant and a scope that was not
/// authorised — so the text names both possibilities rather than guessing.
fn diagnose(error: &str, admin_email: &str) -> ConnectTestTemplate {
    let lower = error.to_ascii_lowercase();
    if lower.contains("unauthorized_client") || lower.contains("delegation") {
        return failure(
            "Google has not been told to trust this service account",
            error,
            "In the Google Admin console, go to Security → Access and data control → \
             API controls → Domain-wide delegation, and add the client ID and scopes \
             shown on this page.",
        );
    }
    if lower.contains("forbidden") || lower.contains("403") || lower.contains("permission") {
        return failure(
            "Connected, but not allowed to read this data",
            error,
            "The delegation grant exists but does not cover every scope listed on \
             this page, or the administrator being impersonated is not a super-admin. \
             Check both.",
        );
    }
    if lower.contains("invalid_grant") || lower.contains("not found") {
        return failure(
            "That administrator could not be impersonated",
            error,
            &format!(
                "Check that {admin_email} is a real, active super-admin in this \
                 Workspace domain."
            ),
        );
    }
    failure(
        "Could not reach Google",
        error,
        "Check the server's outbound network access and try again.",
    )
}

fn failure(headline: &str, detail: &str, remedy: &str) -> ConnectTestTemplate {
    ConnectTestTemplate {
        ok: false,
        headline: headline.to_string(),
        detail: detail.to_string(),
        remedy: remedy.to_string(),
    }
}

#[cfg(test)]
mod tests;
