//! Physical inventory (WS-13): scan lookup, label sheets, and audit mode.
//!
//! All three surfaces are built for a barcode scanner in keyboard-wedge mode —
//! a device that types what it reads and presses Enter. That constraint keeps
//! the whole workstream free of hardware dependencies: every flow here is a
//! text input and a form submit, and a human with a keyboard can drive it
//! identically (which is also how the tests drive it).

use std::collections::HashSet;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use chalk_core::db::repository::AssetRepository;
use chalk_core::models::asset::{Asset, AssetFilter};
use chalk_core::models::common::OrgType;
use chalk_core::models::page::PageRequest;
use serde::Deserialize;

use crate::devices::DevicesQuery;
use crate::AppState;

pub const SCAN_PATH: &str = "/devices/scan";
pub const LABELS_PATH: &str = "/devices/labels";
pub const AUDIT_PATH: &str = "/devices/audit";

/// The most labels one sheet will render. Stated on the page when it bites —
/// a silently truncated sheet reads as "covered everything" when it didn't.
pub const MAX_LABELS: i64 = 1_000;

/// The most devices an audit scope may hold. Same honesty rule as
/// [`MAX_LABELS`]: the page says so rather than silently reconciling a subset.
pub const MAX_AUDIT_SCOPE: i64 = 5_000;

// ---------------------------------------------------------------------------
// Scan lookup
// ---------------------------------------------------------------------------

/// Resolve one scanned code to assets, in the order a sticker is trusted:
/// exact asset tag first (it is what the district printed), then exact serial.
///
/// Multiple hits are possible — duplicate tags exist in real inventories — and
/// the caller decides what ambiguity means for its surface.
pub async fn resolve_scan(assets: &Arc<dyn AssetRepository>, code: &str) -> Vec<Asset> {
    let code = code.trim();
    if code.is_empty() {
        return Vec::new();
    }
    match assets.find_assets_by_asset_tag(code).await {
        Ok(hits) if !hits.is_empty() => return hits,
        _ => {}
    }
    match assets.get_asset_by_serial(code).await {
        Ok(Some(a)) => vec![a],
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ScanQuery {
    pub code: String,
}

/// `GET /devices/scan?code=…` — jump straight to the device a scanner read.
///
/// One hit goes to the device page; anything else (none, or a duplicated tag)
/// lands on the inventory searched for the code, whose empty and multi-row
/// states already say the right things.
pub async fn scan(State(state): State<Arc<AppState>>, Query(q): Query<ScanQuery>) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };
    let hits = resolve_scan(&assets, &q.code).await;
    if let [only] = hits.as_slice() {
        return Redirect::to(&format!("/devices/{}", only.id)).into_response();
    }
    let search = urlencoding::encode(q.code.trim()).into_owned();
    Redirect::to(&format!("/devices?q={search}")).into_response()
}

// ---------------------------------------------------------------------------
// Label sheets
// ---------------------------------------------------------------------------

/// One printable label.
pub struct LabelView {
    /// Inline SVG markup for the QR code. Sized by CSS, crisp at any print
    /// resolution — the reason this is SVG and not a PNG data URI.
    pub qr_svg: String,
    pub asset_tag: String,
    pub serial_number: String,
    pub model: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/labels.html")]
pub struct LabelsTemplate {
    pub labels: Vec<LabelView>,
    /// Total devices the filter matched, so the page can state truncation.
    pub total: i64,
    pub max_labels: i64,
    /// The filtered inventory URL these labels came from, to go back to.
    pub back_href: String,
}

impl LabelsTemplate {
    pub fn truncated(&self) -> bool {
        self.total > self.max_labels
    }
}

/// What one label's QR encodes: the same string the scan lookup resolves, tag
/// first. A label for a device with neither tag nor serial would scan to
/// nothing, so those devices get no label and the sheet says how many were
/// skipped.
fn qr_payload(asset: &Asset) -> Option<String> {
    asset
        .asset_tag
        .clone()
        .or_else(|| asset.serial_number.clone())
        .filter(|s| !s.trim().is_empty())
}

fn qr_svg(payload: &str) -> Option<String> {
    let code = qrcode::QrCode::new(payload.as_bytes()).ok()?;
    Some(
        code.render::<qrcode::render::svg::Color>()
            .quiet_zone(false)
            .build(),
    )
}

/// `GET /devices/labels?…` — the current filtered view, as a printable sheet
/// of QR labels. Reuses [`DevicesQuery`] exactly like the CSV export: "give me
/// labels for the 400 Chromebooks at the middle school" is a filter, not a
/// separate picker.
pub async fn labels(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DevicesQuery>,
    axum::Extension(principal): axum::Extension<crate::authz::Principal>,
) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };
    let page = match assets
        .list_assets(
            &principal.scope_asset_filter(query.to_asset_filter()),
            PageRequest::new(MAX_LABELS, 0),
        )
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("label sheet query failed: {e}");
            return load_failed();
        }
    };

    let labels: Vec<LabelView> = page
        .items
        .iter()
        .filter_map(|a| {
            let payload = qr_payload(a)?;
            Some(LabelView {
                qr_svg: qr_svg(&payload)?,
                asset_tag: a.asset_tag.clone().unwrap_or_else(|| "—".into()),
                serial_number: a.serial_number.clone().unwrap_or_else(|| "—".into()),
                model: a.model.clone().unwrap_or_default(),
            })
        })
        .collect();

    let back = {
        let pairs = query.filter_pairs();
        if pairs.is_empty() {
            "/devices".to_string()
        } else {
            format!(
                "/devices?{}",
                serde_urlencoded::to_string(&pairs).unwrap_or_default()
            )
        }
    };

    LabelsTemplate {
        labels,
        total: page.total,
        max_labels: MAX_LABELS,
        back_href: back,
    }
    .into_response()
}

/// `GET /devices/labels/{id}` — one device's label, for the sticker that got
/// damaged or the device that just arrived.
pub async fn label_one(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };
    let asset = match assets.get_asset(&id).await {
        Ok(Some(a)) => a,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("label lookup failed: {e}");
            return load_failed();
        }
    };
    let labels = qr_payload(&asset)
        .and_then(|p| qr_svg(&p))
        .map(|qr_svg| LabelView {
            qr_svg,
            asset_tag: asset.asset_tag.clone().unwrap_or_else(|| "—".into()),
            serial_number: asset.serial_number.clone().unwrap_or_else(|| "—".into()),
            model: asset.model.clone().unwrap_or_default(),
        })
        .into_iter()
        .collect();
    LabelsTemplate {
        labels,
        total: 1,
        max_labels: MAX_LABELS,
        back_href: format!("/devices/{id}"),
    }
    .into_response()
}

// ---------------------------------------------------------------------------
// Audit mode
// ---------------------------------------------------------------------------

/// The audit form's whole state, round-tripped on every scan.
///
/// The server holds nothing between requests: previously scanned codes ride in
/// a hidden field and the reconciliation is recomputed from scratch each time.
/// That makes an audit interruptible (the page *is* the state — bookmark it,
/// lose the session, nothing is half-written) and trivially testable.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AuditForm {
    /// `orgs.sourced_id` of the school being walked.
    pub school: String,
    /// Optional org-unit path prefix narrowing the walk.
    pub ou: String,
    /// Previously scanned codes, newline-separated.
    pub scanned: String,
    /// The code just scanned, if any.
    pub code: String,
    /// Round-tripped so the re-rendered form can carry the same token the
    /// cookie holds (the middleware only surfaces it on GET).
    pub csrf_token: String,
}

impl AuditForm {
    /// Every code scanned so far, oldest first, deduplicated — scanning a
    /// device twice on a walk is inevitable and means nothing.
    pub fn all_codes(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        self.scanned
            .lines()
            .chain(std::iter::once(self.code.as_str()))
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .filter(|c| seen.insert(c.to_string()))
            .map(str::to_string)
            .collect()
    }

    pub fn scoped(&self) -> bool {
        !self.school.trim().is_empty() || !self.ou.trim().is_empty()
    }
}

/// One expected device, as the audit page shows it.
pub struct AuditRow {
    pub id: String,
    pub label: String,
    pub model: String,
    pub status: &'static str,
}

/// A scan that resolved to a device outside the scope, or to nothing.
pub struct StrayRow {
    pub code: String,
    /// Empty when the code resolved to nothing at all.
    pub device_id: String,
    pub note: String,
}

pub struct SchoolOption {
    pub sourced_id: String,
    pub name: String,
    pub selected: bool,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/audit.html")]
pub struct AuditTemplate {
    pub nav: crate::nav::Nav,
    pub form: AuditForm,
    pub schools: Vec<SchoolOption>,
    /// All scanned codes, for the hidden field.
    pub scanned_joined: String,
    pub scanned_count: usize,
    pub expected_total: i64,
    pub found: Vec<AuditRow>,
    pub missing: Vec<AuditRow>,
    pub strays: Vec<StrayRow>,
    /// True when the scope exceeded [`MAX_AUDIT_SCOPE`] and the page must say
    /// the reconciliation is partial.
    pub scope_truncated: bool,
    pub csrf_token: String,
}

impl AuditTemplate {
    pub fn started(&self) -> bool {
        self.form.scoped()
    }
}

fn audit_row(a: &Asset) -> AuditRow {
    AuditRow {
        id: a.id.clone(),
        label: a
            .asset_tag
            .clone()
            .or_else(|| a.serial_number.clone())
            .unwrap_or_else(|| a.id.clone()),
        model: a.model.clone().unwrap_or_default(),
        status: crate::devices::status_label(a.status),
    }
}

/// Whether a scanned code names this asset — the same tag-or-serial identity
/// the labels print and the scan lookup resolves.
fn code_names(asset: &Asset, code: &str) -> bool {
    asset.asset_tag.as_deref() == Some(code) || asset.serial_number.as_deref() == Some(code)
}

/// `GET`/`POST /devices/audit` — scan a room against what the inventory says
/// should be there.
///
/// GET renders the scope picker; each scan POSTs the whole state back and the
/// reconciliation is recomputed. Missing means "expected in this scope, not
/// yet scanned" — it shrinks toward zero as the walk proceeds, and what is
/// left at the end is the finding.
pub async fn audit_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    axum::Extension(principal): axum::Extension<crate::authz::Principal>,
) -> Response {
    render_audit(state, csrf, principal, AuditForm::default()).await
}

/// `POST /devices/audit` — one more scan, or a scope change; same page.
pub async fn audit_scan(
    State(state): State<Arc<AppState>>,
    axum::Extension(principal): axum::Extension<crate::authz::Principal>,
    axum::Form(form): axum::Form<AuditForm>,
) -> Response {
    // The middleware has already validated this token against the cookie —
    // it is safe to re-embed, and on POST it is the only place it lives.
    let csrf = crate::csrf::CsrfToken(form.csrf_token.clone());
    render_audit(state, csrf, principal, form).await
}

async fn render_audit(
    state: Arc<AppState>,
    csrf: crate::csrf::CsrfToken,
    principal: crate::authz::Principal,
    form: AuditForm,
) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };

    let schools = match state.repo.list_orgs().await {
        Ok(orgs) => orgs
            .into_iter()
            .filter(|o| o.org_type == OrgType::School)
            .map(|o| SchoolOption {
                selected: o.sourced_id == form.school,
                sourced_id: o.sourced_id,
                name: o.name,
            })
            .collect(),
        Err(e) => {
            tracing::warn!("could not load schools for the audit picker: {e}");
            Vec::new()
        }
    };

    let (expected, expected_total) = if form.scoped() {
        let filter = principal.scope_asset_filter(AssetFilter {
            school_org_sourced_id: Some(form.school.trim().to_string()).filter(|s| !s.is_empty()),
            org_unit_path_prefix: Some(form.ou.trim().to_string()).filter(|s| !s.is_empty()),
            ..AssetFilter::default()
        });
        match assets
            .list_assets(&filter, PageRequest::new(MAX_AUDIT_SCOPE, 0))
            .await
        {
            Ok(p) => (p.items, p.total),
            Err(e) => {
                tracing::error!("audit scope query failed: {e}");
                return load_failed();
            }
        }
    } else {
        (Vec::new(), 0)
    };

    let codes = form.all_codes();
    let mut found = Vec::new();
    let mut missing = Vec::new();
    let mut matched_codes: HashSet<&str> = HashSet::new();
    for a in &expected {
        match codes.iter().find(|c| code_names(a, c)) {
            Some(c) => {
                matched_codes.insert(c.as_str());
                found.push(audit_row(a));
            }
            None => missing.push(audit_row(a)),
        }
    }

    // Everything scanned that is not accounted for by the scope: a device
    // from another school (misplaced — the audit's other finding) or a code
    // the inventory has never heard of.
    let mut strays = Vec::new();
    for code in &codes {
        if matched_codes.contains(code.as_str()) {
            continue;
        }
        let hits = resolve_scan(&assets, code).await;
        match hits.as_slice() {
            [] => strays.push(StrayRow {
                code: code.clone(),
                device_id: String::new(),
                note: "Not in the inventory at all".to_string(),
            }),
            [a] => strays.push(StrayRow {
                code: code.clone(),
                device_id: a.id.clone(),
                note: "In the inventory, but not in this scope".to_string(),
            }),
            _ => strays.push(StrayRow {
                code: code.clone(),
                device_id: String::new(),
                note: "Ambiguous — more than one device carries this tag".to_string(),
            }),
        }
    }

    AuditTemplate {
        nav: crate::nav::Nav::new(&state.config, "devices"),
        scanned_joined: codes.join("\n"),
        scanned_count: codes.len(),
        expected_total,
        found,
        missing,
        strays,
        scope_truncated: expected_total > MAX_AUDIT_SCOPE,
        form,
        schools,
        csrf_token: csrf.0,
    }
    .into_response()
}

// ---------------------------------------------------------------------------

fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::response::Html("<h1>Devices are not available here.</h1>".to_string()),
    )
        .into_response()
}

fn not_found() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::response::Html("<h1>No such device.</h1>".to_string()),
    )
        .into_response()
}

fn load_failed() -> Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        axum::response::Html("<h1>Could not load the inventory.</h1>".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
