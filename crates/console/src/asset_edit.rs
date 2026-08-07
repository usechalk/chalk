//! Creating and editing a device by hand.
//!
//! # Why this had to exist
//!
//! Until now nothing could enter the inventory that Google did not already
//! know about. That made the module a mirror of a Workspace tenant rather than
//! an asset register: a district's projectors, hotspots and non-Chromebook
//! laptops had no way in, and a wrong serial had no way to be corrected.
//!
//! # Google-sourced fields are not editable here
//!
//! On a device that came from Google, the org unit, the annotated fields, the
//! AUE date and the OS version are read-only — the next sync would overwrite
//! anything typed into them, so offering the field would be offering a change
//! that silently reverts. The page says which fields those are and why, rather
//! than disabling inputs with no explanation.
//!
//! A hand-created device has no such owner, so every field is editable.
//!
//! # Every change is audited
//!
//! Editing goes through `apply_patch_with_event`, the same transactional path
//! the unmatched queue uses, so a device altered by hand appears in its history
//! beside the automatic matches — with the fields that changed, and who did it.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::models::asset::{
    ActorKind, Asset, AssetEventType, AssetPatch, AssetStatus, AssetType, MatchState,
    NewAssetEvent, Patch,
};
use chalk_core::models::common::OrgType;
use serde::Deserialize;

use crate::AppState;

pub const NEW_PATH: &str = "/devices/new";

/// Actor recorded on hand edits, matching what every other console path
/// writes so history reads consistently.
const ACTOR: &str = "console:admin";

// ---------------------------------------------------------------------------
// Form
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AssetForm {
    pub asset_tag: String,
    pub serial_number: String,
    pub asset_type: String,
    pub make: String,
    pub model: String,
    pub status: String,
    pub school: String,
    pub notes: String,
    pub location: String,
    pub funding_source: String,
    pub purchase_date: String,
    pub warranty_expires: String,
}

impl AssetForm {
    /// Everything a device needs to be findable.
    ///
    /// A device with neither a tag nor a serial cannot be looked up by anyone
    /// holding it, which makes it a row rather than an asset — so one of the
    /// two is required. Which one is the district's choice, not ours.
    fn validate(&self) -> Result<(), String> {
        if self.asset_tag.trim().is_empty() && self.serial_number.trim().is_empty() {
            return Err(
                "Give the device an asset tag or a serial number — without one it \
                 cannot be looked up."
                    .into(),
            );
        }
        if AssetType::parse(self.asset_type.trim()).is_err() {
            return Err(format!("{:?} is not a device type.", self.asset_type));
        }
        if AssetStatus::parse(self.status.trim()).is_err() {
            return Err(format!("{:?} is not a device status.", self.status));
        }
        Ok(())
    }
}

fn opt(value: &str) -> Option<String> {
    let t = value.trim();
    (!t.is_empty()).then(|| t.to_string())
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

pub struct SchoolOption {
    pub sourced_id: String,
    pub name: String,
    pub selected: bool,
}

pub struct EnumOption {
    pub value: String,
    pub label: String,
    pub selected: bool,
}

fn type_options(current: &str) -> Vec<EnumOption> {
    [
        ("chromebook", "Chromebook"),
        ("laptop", "Laptop"),
        ("tablet", "Tablet"),
        ("projector", "Projector"),
        ("hotspot", "Hotspot"),
        ("other", "Other"),
    ]
    .iter()
    .map(|(v, l)| EnumOption {
        value: v.to_string(),
        label: l.to_string(),
        selected: *v == current,
    })
    .collect()
}

fn status_options(current: &str) -> Vec<EnumOption> {
    [
        ("active", "Active"),
        ("repair", "Repair"),
        ("storage", "Storage"),
        ("retired", "Retired"),
        ("deprovisioned", "Deprovisioned"),
        ("lost", "Lost"),
    ]
    .iter()
    .map(|(v, l)| EnumOption {
        value: v.to_string(),
        label: l.to_string(),
        selected: *v == current,
    })
    .collect()
}

pub struct AssetFormView {
    /// Empty when creating.
    pub id: String,
    pub is_new: bool,
    pub form: AssetForm,
    pub type_options: Vec<EnumOption>,
    pub status_options: Vec<EnumOption>,
    pub schools: Vec<SchoolOption>,
    /// This device came from Google, so some fields are not ours to edit.
    pub google_owned: bool,
    /// Shown read-only when `google_owned`, so an operator can see the values
    /// without being invited to type over them.
    pub google_user: String,
    pub org_unit_path: String,
    pub aue_date: String,
    pub error: String,
    pub csrf_token: String,
}

impl AssetFormView {
    pub fn heading(&self) -> &'static str {
        if self.is_new {
            "Add a device"
        } else {
            "Edit device"
        }
    }

    pub fn has_error(&self) -> bool {
        !self.error.is_empty()
    }
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/edit.html")]
pub struct AssetFormTemplate {
    pub view: AssetFormView,
    pub nav: crate::nav::Nav,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ErrQuery {
    pub err: String,
}

/// `GET /devices/new`
pub async fn new_form(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ErrQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Response {
    let form = AssetForm {
        asset_type: "chromebook".into(),
        status: "active".into(),
        ..Default::default()
    };
    render(AssetFormTemplate {
        view: AssetFormView {
            id: String::new(),
            is_new: true,
            type_options: type_options(&form.asset_type),
            status_options: status_options(&form.status),
            schools: schools(&state, "").await,
            google_owned: false,
            google_user: String::new(),
            org_unit_path: String::new(),
            aue_date: String::new(),
            error: q.err,
            csrf_token: csrf.0,
            form,
        },
        nav: crate::nav::Nav::new(&state.config, "devices"),
    })
}

/// `GET /devices/{id}/edit`
pub async fn edit_form(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<ErrQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };
    let Ok(Some(asset)) = assets.get_asset(&id).await else {
        return not_found();
    };

    let form = AssetForm {
        asset_tag: asset.asset_tag.clone().unwrap_or_default(),
        serial_number: asset.serial_number.clone().unwrap_or_default(),
        asset_type: asset.asset_type.as_str().to_string(),
        make: asset.make.clone().unwrap_or_default(),
        model: asset.model.clone().unwrap_or_default(),
        status: asset.status.as_str().to_string(),
        school: asset.school_org_sourced_id.clone().unwrap_or_default(),
        notes: asset.notes.clone().unwrap_or_default(),
        location: asset.location.clone().unwrap_or_default(),
        funding_source: asset.funding_source.clone().unwrap_or_default(),
        purchase_date: asset
            .purchase_date
            .map(|d| d.to_string())
            .unwrap_or_default(),
        warranty_expires: asset
            .warranty_expires
            .map(|d| d.to_string())
            .unwrap_or_default(),
    };

    render(AssetFormTemplate {
        view: AssetFormView {
            id: asset.id.clone(),
            is_new: false,
            type_options: type_options(&form.asset_type),
            status_options: status_options(&form.status),
            schools: schools(&state, &form.school).await,
            // The presence of a Google device id is what makes a device
            // Google's — not its type. A hand-added Chromebook is still ours.
            google_owned: asset.google_device_id.is_some(),
            google_user: asset.annotated_user.clone().unwrap_or_default(),
            org_unit_path: asset.org_unit_path.clone().unwrap_or_default(),
            aue_date: asset.aue_date.map(|d| d.to_string()).unwrap_or_default(),
            error: q.err,
            csrf_token: csrf.0,
            form,
        },
        nav: crate::nav::Nav::new(&state.config, "devices"),
    })
}

/// `POST /devices/new`
pub async fn create(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<AssetForm>,
) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };
    if let Err(message) = form.validate() {
        return back(NEW_PATH, &message);
    }

    // D8: the hosted free tier covers Chromebooks only, and this is the single
    // thing that enforces it. Checked on every path that can bring an asset
    // into existence — form, CSV import, API — because a gate on one of three
    // doors is not a gate.
    let asset_type = AssetType::parse(form.asset_type.trim()).unwrap_or_default();
    if !state.config.modules.allows_asset_type(asset_type) {
        return back(
            NEW_PATH,
            &state.config.modules.asset_type_refusal(asset_type),
        );
    }

    // A serial must be unique — the column carries a unique index, and a
    // duplicate would otherwise surface as a raw database error.
    if let Some(serial) = opt(&form.serial_number) {
        if matches!(assets.get_asset_by_serial(&serial).await, Ok(Some(_))) {
            return back(
                NEW_PATH,
                &format!("A device with serial {serial} is already in the inventory."),
            );
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    let mut asset = Asset::new(&id);
    asset.asset_tag = opt(&form.asset_tag);
    asset.serial_number = opt(&form.serial_number);
    asset.asset_type = AssetType::parse(form.asset_type.trim()).unwrap_or_default();
    asset.make = opt(&form.make);
    asset.model = opt(&form.model);
    asset.status = AssetStatus::parse(form.status.trim()).unwrap_or_default();
    asset.school_org_sourced_id = opt(&form.school);
    asset.notes = opt(&form.notes);
    asset.location = opt(&form.location);
    asset.funding_source = opt(&form.funding_source);
    asset.purchase_date = parse_date(&form.purchase_date);
    asset.warranty_expires = parse_date(&form.warranty_expires);
    asset.source = chalk_core::models::asset::AssetSource::Manual;
    // Nobody is expected to own it yet, and it did not come from a matcher, so
    // it must not sit in the unmatched queue asking to be resolved.
    asset.match_state = MatchState::Manual;

    if let Err(e) = assets.create_asset(&asset).await {
        tracing::error!("could not create a device: {e}");
        return back(NEW_PATH, "Could not save the device. Check the server log.");
    }

    // Recorded like every other change, so a hand-added device has a history
    // from its first moment rather than appearing from nowhere.
    if let Some(events) = state.asset_events.clone() {
        let _ = events
            .append_event(&NewAssetEvent {
                asset_id: id.clone(),
                actor: ACTOR.to_string(),
                actor_kind: ActorKind::Admin,
                event_type: AssetEventType::Imported,
                payload: Some(serde_json::json!({ "source": "added by hand" })),
            })
            .await;
    }

    Redirect::to(&format!("/devices/{id}")).into_response()
}

/// `POST /devices/{id}/edit`
pub async fn update(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<AssetForm>,
) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };
    let Ok(Some(existing)) = assets.get_asset(&id).await else {
        return not_found();
    };
    let edit_path = format!("/devices/{id}/edit");
    if let Err(message) = form.validate() {
        return back(&edit_path, &message);
    }

    // A serial may move to another device only if no other device holds it.
    if let Some(serial) = opt(&form.serial_number) {
        if let Ok(Some(other)) = assets.get_asset_by_serial(&serial).await {
            if other.id != id {
                return back(
                    &edit_path,
                    &format!("Serial {serial} belongs to another device already."),
                );
            }
        }
    }

    let patch = AssetPatch {
        asset_tag: patch_opt(opt(&form.asset_tag)),
        serial_number: patch_opt(opt(&form.serial_number)),
        asset_type: AssetType::parse(form.asset_type.trim()).ok(),
        make: patch_opt(opt(&form.make)),
        model: patch_opt(opt(&form.model)),
        status: AssetStatus::parse(form.status.trim()).ok(),
        school_org_sourced_id: patch_opt(opt(&form.school)),
        notes: patch_opt(opt(&form.notes)),
        location: patch_opt(opt(&form.location)),
        funding_source: patch_opt(opt(&form.funding_source)),
        purchase_date: match parse_date(&form.purchase_date) {
            Some(d) => Patch::Set(d),
            None => Patch::Clear,
        },
        warranty_expires: match parse_date(&form.warranty_expires) {
            Some(d) => Patch::Set(d),
            None => Patch::Clear,
        },
        ..Default::default()
    };

    // The event names what actually changed rather than saying "edited", so
    // the history is readable without diffing two versions by hand.
    let changed = changed_fields(&existing, &form);
    let event = NewAssetEvent {
        asset_id: id.clone(),
        actor: ACTOR.to_string(),
        actor_kind: ActorKind::Admin,
        event_type: if existing.status.as_str() != form.status.trim() {
            AssetEventType::StatusChanged
        } else {
            AssetEventType::FieldChanged
        },
        payload: Some(serde_json::json!({
            "fields": changed,
            "via": "manual_edit",
        })),
    };

    match assets.apply_patch_with_event(&id, &patch, &event).await {
        Ok(true) => Redirect::to(&format!("/devices/{id}")).into_response(),
        Ok(false) => not_found(),
        Err(e) => {
            tracing::error!("could not update device {id}: {e}");
            back(
                &edit_path,
                "Could not save the change. Check the server log.",
            )
        }
    }
}

/// Which fields the operator actually changed.
///
/// Must cover **every** editable field. An audit trail that lists only some of
/// what changed is worse than one that says "edited": it looks precise while
/// being wrong, and a reader has no way to know which. This omitted `location`
/// and the purchase fields until an end-to-end edit showed the history
/// reporting a status change while the location had moved too.
fn changed_fields(existing: &Asset, form: &AssetForm) -> Vec<String> {
    let before_dates = (
        existing.purchase_date.map(|d| d.to_string()),
        existing.warranty_expires.map(|d| d.to_string()),
    );
    let pairs: [(&str, Option<String>, Option<String>); 12] = [
        (
            "asset_tag",
            existing.asset_tag.clone(),
            opt(&form.asset_tag),
        ),
        (
            "serial_number",
            existing.serial_number.clone(),
            opt(&form.serial_number),
        ),
        (
            "asset_type",
            Some(existing.asset_type.as_str().to_string()),
            opt(&form.asset_type),
        ),
        ("make", existing.make.clone(), opt(&form.make)),
        ("model", existing.model.clone(), opt(&form.model)),
        (
            "status",
            Some(existing.status.as_str().to_string()),
            opt(&form.status),
        ),
        (
            "school",
            existing.school_org_sourced_id.clone(),
            opt(&form.school),
        ),
        ("notes", existing.notes.clone(), opt(&form.notes)),
        ("location", existing.location.clone(), opt(&form.location)),
        (
            "funding_source",
            existing.funding_source.clone(),
            opt(&form.funding_source),
        ),
        (
            "purchase_date",
            before_dates.0,
            parse_date(&form.purchase_date).map(|d| d.to_string()),
        ),
        (
            "warranty_expires",
            before_dates.1,
            parse_date(&form.warranty_expires).map(|d| d.to_string()),
        ),
    ];
    pairs
        .into_iter()
        .filter(|(_, before, after)| before != after)
        .map(|(name, _, _)| name.to_string())
        .collect()
}

/// An empty field clears the column rather than leaving the old value, which
/// is what "I deleted the text and saved" means to anyone doing it.
fn patch_opt(value: Option<String>) -> Patch<String> {
    match value {
        Some(v) => Patch::Set(v),
        None => Patch::Clear,
    }
}

fn parse_date(raw: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d").ok()
}

async fn schools(state: &AppState, current: &str) -> Vec<SchoolOption> {
    match state.repo.list_orgs().await {
        Ok(orgs) => {
            let mut out: Vec<SchoolOption> = orgs
                .into_iter()
                .filter(|o| o.org_type == OrgType::School)
                .map(|o| SchoolOption {
                    selected: o.sourced_id == current,
                    sourced_id: o.sourced_id,
                    name: o.name,
                })
                .collect();
            out.sort_by(|a, b| a.name.cmp(&b.name));
            out
        }
        Err(e) => {
            tracing::warn!("could not load schools for the device form: {e}");
            Vec::new()
        }
    }
}

fn back(path: &str, message: &str) -> Response {
    Redirect::to(&format!("{path}?err={}", urlencoding::encode(message))).into_response()
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!("device form render failed: {e}");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>Devices</h1><p>The form could not be rendered.</p>".to_string()),
            )
                .into_response()
        }
    }
}

fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Devices</h1><p>The inventory is not enabled here.</p>".to_string()),
    )
        .into_response()
}

fn not_found() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html(
            "<h1>Device not found</h1><p><a href=\"/devices\">Back to devices</a></p>".to_string(),
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
