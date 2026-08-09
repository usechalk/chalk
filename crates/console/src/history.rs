//! Action history — what happened to a device, who did it, and which rule
//! fired.
//!
//! # Why this is worth building rather than dumping rows
//!
//! `asset_events` is already written by the sync engine and the unmatched
//! queue, so the data costs nothing. What costs something is making it
//! *legible*: a row reading `assigned / system:google-sync / {"rule":
//! "annotated_user", …}` is a database record, not an explanation. An IT
//! director evaluating whether to trust an automation with five thousand
//! Chromebooks needs to read *"Matched to a student by the Google user on the
//! device"* and immediately know both what happened and how to check it.
//!
//! So every event is rendered as a sentence naming the rule that fired.
//! [`describe`] is the whole point of this module; the rest is paging.
//!
//! # Immutability is the product feature
//!
//! `AssetEventRepository` has no update and no delete, and nothing here adds
//! one. A correction is a new event. That is what makes the history worth
//! showing to someone deciding whether to believe it.
//!
//! # Unknown events render, they do not vanish
//!
//! [`describe`] falls back to the raw event type rather than skipping a row it
//! does not recognise. A history that silently omits what it cannot explain is
//! worse than one that says "status_changed" — the omission is invisible,
//! and this log's only job is to be complete.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use chalk_core::models::asset::{
    Asset, AssetEvent, AssetEventFilter, AssetEventType, AssetSource, MatchState,
};
use chalk_core::models::page::PageRequest;
use serde::Deserialize;
use serde_json::Value;

use crate::table::{clamp_page_size, TableNav};
use crate::AppState;

/// District-wide history.
pub const HISTORY_PATH: &str = "/devices/history";

/// `id` of the HTMX swap target.
pub const REGION_ID: &str = "history-region";

/// Events shown on a device's own page.
///
/// A device that has been syncing nightly for three years has thousands of
/// rows, and the detail page is a summary rather than an audit export — the
/// district-wide view is where the full trail is paged. Stated in the UI so
/// "that is all of it" is never assumed.
pub const DEVICE_HISTORY_LIMIT: i64 = 50;

/// Tickets shown on a device's own page. A device with a long help-desk
/// history shows its most recent tickets; the full queue is where they page.
pub const DEVICE_TICKETS_LIMIT: i64 = 20;

const NONE_TEXT: &str = "—";

// ---------------------------------------------------------------------------
// Turning an event into a sentence
// ---------------------------------------------------------------------------

/// A human sentence for one event, plus the detail line under it.
///
/// The rule names are the stable strings [`MatchRule::as_str`] writes and
/// promises never to change, because historical rows are read with them. A
/// rule this function does not recognise still renders — naming the raw value
/// rather than dropping the row.
///
/// [`MatchRule::as_str`]: https://docs.rs/chalk-devices
pub fn describe(event: &AssetEvent) -> (String, String) {
    let p = event.payload.as_ref();
    match event.event_type {
        AssetEventType::Assigned => {
            let rule = string_field(p, "rule");
            let who = string_field(p, "matchedEmail")
                .or_else(|| string_field(p, "userSourcedId"))
                .or_else(|| string_field(p, "user"));
            let detail = who.map(|w| format!("Person: {w}")).unwrap_or_default();
            (
                match rule.as_deref() {
                    // The manual case is deliberately worded so it can never be
                    // mistaken for an automatic match. An operator's decision
                    // and a rule firing are the two things this log exists to
                    // tell apart.
                    Some("manual") => "Attached to a person by an administrator".to_string(),
                    Some("annotated_user") => {
                        "Matched by the Google user set on the device".to_string()
                    }
                    Some("recent_user") => {
                        "Matched by the most recent sign-in on the device".to_string()
                    }
                    Some("serial_number") => "Matched to an existing record by serial".to_string(),
                    Some("asset_tag") => "Matched to an existing record by asset tag".to_string(),
                    Some(other) => format!("Matched by {other}"),
                    None => "Attached to a person".to_string(),
                },
                detail,
            )
        }
        AssetEventType::Unassigned => (
            "No longer attached to a person".to_string(),
            match string_field(p, "reason").as_deref() {
                Some("no_rule_matched") => {
                    "No matching rule found a person for this device".to_string()
                }
                Some(other) => format!("Reason: {other}"),
                None => String::new(),
            },
        ),
        AssetEventType::Imported => {
            let source = string_field(p, "source").unwrap_or_else(|| "an import".to_string());
            let merged = string_field(p, "mergeRule");
            (
                match source.as_str() {
                    "google" => "Imported from Google Workspace".to_string(),
                    other => format!("Imported from {other}"),
                },
                // A merge is the interesting case: it means this Google device
                // was joined onto a record that already existed, and *which*
                // rule joined them is what makes a wrong merge diagnosable.
                match merged.as_deref() {
                    Some("serial_number") => "Joined to an existing record by serial".to_string(),
                    Some("asset_tag") => "Joined to an existing record by asset tag".to_string(),
                    Some(other) => format!("Joined to an existing record by {other}"),
                    None => String::new(),
                },
            )
        }
        AssetEventType::Deprovisioned => (
            "Deprovisioned".to_string(),
            match string_field(p, "observedFrom").as_deref() {
                Some("google") => "Observed in Google Workspace, not done by Chalk".to_string(),
                _ => String::new(),
            },
        ),
        AssetEventType::MovedOu => (
            "Moved to a different org unit".to_string(),
            change_detail(p),
        ),
        AssetEventType::StatusChanged => ("Status changed".to_string(), change_detail(p)),
        AssetEventType::Repaired => ("Marked repaired".to_string(), change_detail(p)),
        AssetEventType::FieldChanged => {
            // `match_state` is the field the unmatched queue writes, and it has
            // a plain-language meaning that "field_changed: match_state" does
            // not convey to anyone who has not read the schema.
            if string_field(p, "field").as_deref() == Some("match_state") {
                let new = string_field(p, "new");
                return match new.as_deref() {
                    Some(v) if v == MatchState::Ignored.as_str() => (
                        "Marked as shared — no one owns it".to_string(),
                        "It stays in the inventory and keeps syncing".to_string(),
                    ),
                    Some(v) if v == MatchState::Manual.as_str() => (
                        "Set by an administrator".to_string(),
                        "Future syncs will not change the assignment".to_string(),
                    ),
                    _ => ("Match state changed".to_string(), change_detail(p)),
                };
            }
            (
                match string_field(p, "field") {
                    Some(f) => format!("{f} changed"),
                    None => "A field changed".to_string(),
                },
                change_detail(p),
            )
        }
    }
}

/// `old → new` for the events that carry them.
fn change_detail(payload: Option<&Value>) -> String {
    let old = string_field(payload, "old");
    let new = string_field(payload, "new");
    match (old, new) {
        (Some(o), Some(n)) => format!("{o} → {n}"),
        (None, Some(n)) => format!("Set to {n}"),
        (Some(o), None) => format!("Cleared (was {o})"),
        (None, None) => String::new(),
    }
}

/// Read a payload field as a string, accepting the non-string JSON a future
/// writer might produce rather than rendering an empty cell for it.
fn string_field(payload: Option<&Value>, key: &str) -> Option<String> {
    let value = payload?.get(key)?;
    match value {
        Value::Null => None,
        Value::String(s) if s.trim().is_empty() => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

/// Who did it, in words rather than in the raw actor string.
///
/// `system:google-sync` is the actor on the overwhelming majority of rows, and
/// rendering it verbatim makes the log look like a machine talking to itself.
pub fn describe_actor(event: &AssetEvent) -> String {
    match event.actor.as_str() {
        "system:google-sync" => "Google sync".to_string(),
        "console:admin" => "An administrator".to_string(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

pub struct EventView {
    pub id: i64,
    pub asset_id: String,
    /// Asset tag or serial, so a district-wide row names a device a technician
    /// can find rather than a UUID.
    pub device_label: String,
    pub summary: String,
    pub detail: String,
    pub actor: String,
    pub actor_kind: String,
    /// True when a person did this rather than the sync. The one distinction
    /// worth a visual marker in a log that is otherwise almost all automation.
    pub is_human: bool,
    pub when: String,
    pub event_type: String,
}

impl EventView {
    pub fn new(event: &AssetEvent, device_label: String) -> Self {
        let (summary, detail) = describe(event);
        Self {
            id: event.id,
            asset_id: event.asset_id.clone(),
            device_label,
            summary,
            detail,
            actor: describe_actor(event),
            actor_kind: event.actor_kind.as_str().to_string(),
            is_human: !matches!(
                event.actor_kind,
                chalk_core::models::asset::ActorKind::System
            ),
            when: event.created_at.format("%Y-%m-%d %H:%M").to_string(),
            event_type: event.event_type.as_str().to_string(),
        }
    }

    pub fn has_detail(&self) -> bool {
        !self.detail.is_empty()
    }
}

/// A `<select>` option.
pub struct FilterOption {
    pub value: String,
    pub label: String,
    pub selected: bool,
}

fn options(pairs: &[(&str, &str)], current: &str) -> Vec<FilterOption> {
    pairs
        .iter()
        .map(|(value, label)| FilterOption {
            value: value.to_string(),
            label: label.to_string(),
            selected: *value == current,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// District-wide history
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HistoryQuery {
    /// One of [`AssetEventType`]'s wire strings; anything else means no
    /// constraint.
    pub event_type: String,
    /// `orgs.sourced_id` — "what has happened to my school's devices".
    pub school: String,
    /// Exact actor string. Offered as a closed list rather than a free-text
    /// box: the vocabulary is small and fixed (`system:google-sync`,
    /// `console:admin`), and a typo in a free-text audit filter silently
    /// returns nothing, which reads as "nobody did anything".
    pub actor: String,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

impl HistoryQuery {
    pub fn to_filter(&self) -> AssetEventFilter {
        AssetEventFilter {
            event_type: AssetEventType::parse(&self.event_type).ok(),
            school_org_sourced_id: non_empty(&self.school),
            actor: non_empty(&self.actor),
            ..Default::default()
        }
    }

    pub fn is_filtered(&self) -> bool {
        let f = self.to_filter();
        f.event_type.is_some() || f.school_org_sourced_id.is_some() || f.actor.is_some()
    }

    pub fn page_number(&self) -> i64 {
        self.page.unwrap_or(1).max(1)
    }

    pub fn to_nav(&self, total: i64) -> TableNav {
        // Built from the parsed filter, not the raw query text, so a junk
        // parameter cannot appear in a link claiming to narrow something.
        let f = self.to_filter();
        let mut filter_pairs = Vec::new();
        if let Some(t) = f.event_type {
            filter_pairs.push(("event_type".to_string(), t.as_str().to_string()));
        }
        if let Some(v) = f.school_org_sourced_id {
            filter_pairs.push(("school".to_string(), v));
        }
        if let Some(v) = f.actor {
            filter_pairs.push(("actor".to_string(), v));
        }
        TableNav {
            base_path: HISTORY_PATH.to_string(),
            region_id: REGION_ID.to_string(),
            filter_pairs,
            // The log is append-only and always newest-first: there is no sort
            // control, and offering one would imply a choice the repository
            // does not provide.
            sort: "created_at".to_string(),
            direction: "desc".to_string(),
            page: self.page_number(),
            per_page: clamp_page_size(self.per_page),
            total,
        }
    }
}

pub struct HistoryView {
    pub events: Vec<EventView>,
    pub nav: TableNav,
    pub query: HistoryQuery,
    pub type_options: Vec<FilterOption>,
    pub actor_options: Vec<FilterOption>,
    pub schools: Vec<SchoolOption>,
    pub oob_announcer: bool,
}

/// A school in the filter dropdown.
pub struct SchoolOption {
    pub sourced_id: String,
    pub name: String,
    pub selected: bool,
}

impl HistoryView {
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    pub fn is_filtered_empty(&self) -> bool {
        self.events.is_empty() && self.query.is_filtered()
    }

    pub fn announcement(&self) -> String {
        if self.nav.total == 0 {
            return "No activity recorded yet.".to_string();
        }
        format!(
            "{} events. Showing {}.",
            crate::table::thousands(self.nav.total),
            self.nav.range_summary()
        )
    }
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "history/index.html")]
pub struct HistoryPageTemplate {
    pub view: HistoryView,
    pub nav: crate::nav::Nav,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "history/region.html")]
pub struct HistoryRegionTemplate {
    pub view: HistoryView,
}

/// `GET /devices/history` — everything that has happened, newest first.
pub async fn history_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
    headers: HeaderMap,
) -> Response {
    let (Some(assets), Some(events)) = (state.assets.clone(), state.asset_events.clone()) else {
        return not_configured();
    };

    let filter = query.to_filter();
    let mut query = query;

    let mut page = match events
        .list_events(&filter, query.to_nav(0).page_request())
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("history query failed: {e}");
            return load_failed();
        }
    };

    // The same clamp the inventory and the queue carry: an out-of-range page is
    // empty with a non-zero total, which here would read as "no activity
    // recorded yet" on an instance with a full audit trail.
    if page.items.is_empty() && page.total > 0 {
        let last_page = query.to_nav(page.total).total_pages();
        if query.page_number() > last_page {
            query.page = Some(last_page);
            match events
                .list_events(&filter, query.to_nav(page.total).page_request())
                .await
            {
                Ok(p) => page = p,
                Err(e) => {
                    tracing::error!("history re-query failed: {e}");
                    return load_failed();
                }
            }
        }
    }

    // One lookup per distinct device on the page, not per row: a sync run
    // writes several events against the same device, and this page is capped at
    // 250 rows, so the worst case is 250 lookups and the common case far fewer.
    let mut labels: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for event in &page.items {
        if labels.contains_key(&event.asset_id) {
            continue;
        }
        let label = match assets.get_asset(&event.asset_id).await {
            Ok(Some(a)) => device_label(&a),
            // A device removed from the inventory does not erase its history —
            // the log is append-only, and a row whose device is gone still
            // records something that happened.
            _ => event.asset_id.clone(),
        };
        labels.insert(event.asset_id.clone(), label);
    }

    let events_view: Vec<EventView> = page
        .items
        .iter()
        .map(|e| {
            EventView::new(
                e,
                labels
                    .get(&e.asset_id)
                    .cloned()
                    .unwrap_or_else(|| e.asset_id.clone()),
            )
        })
        .collect();

    let nav = query.to_nav(page.total);
    let view = HistoryView {
        type_options: options(
            &[
                ("", "Everything"),
                ("assigned", "Attached to a person"),
                ("unassigned", "Detached"),
                ("imported", "Imported"),
                ("field_changed", "Field changed"),
                ("status_changed", "Status changed"),
                ("moved_ou", "Moved org unit"),
                ("deprovisioned", "Deprovisioned"),
            ],
            &query.event_type,
        ),
        actor_options: options(
            &[
                ("", "Anyone"),
                ("system:google-sync", "Google sync"),
                ("console:admin", "An administrator"),
            ],
            &query.actor,
        ),
        schools: load_schools(&state, &query.school).await,
        events: events_view,
        nav,
        query,
        oob_announcer: is_htmx(&headers),
    };

    if view.oob_announcer {
        render(HistoryRegionTemplate { view })
    } else {
        render(HistoryPageTemplate {
            view,
            nav: crate::nav::Nav::new(&state.config, "devices"),
        })
    }
}

// ---------------------------------------------------------------------------
// One device
// ---------------------------------------------------------------------------

pub struct DeviceDetailView {
    pub id: String,
    pub label: String,
    pub asset_tag: String,
    pub serial_number: String,
    pub model: String,
    pub make: String,
    pub status_label: String,
    pub status_class: String,
    pub student: String,
    pub student_id: String,
    pub school: String,
    pub org_unit_path: String,
    /// Which console or import this row came from, in words.
    pub source_label: String,
    /// The row's identity in its own console (`assets.external_id`). Empty
    /// for rows that no console owns.
    pub external_id: String,
    /// True when the row is owned by a remote console (Google, Intune, Jamf),
    /// so the "from the console" card renders. Which card is `is_google`'s
    /// job.
    pub console_owned: bool,
    /// True when the owning console is Google Workspace — its card carries
    /// Google-only fields (OU, AUE) the MDM card has no equivalent for.
    pub is_google: bool,
    pub google_user: String,
    pub google_device_id: String,
    pub aue_date: String,
    pub os_version: String,
    pub last_sync: String,
    pub match_state: String,
    pub match_state_note: String,
    /// Procurement block (GP-3): all display-formatted, dash when unknown.
    pub purchase_date: String,
    pub purchase_cost: String,
    pub vendor_name: String,
    pub po_number: String,
    pub funding_source: String,
    pub warranty: String,
    /// "", "ok", or "expired" — drives the badge class.
    pub warranty_class: String,
    pub events: Vec<EventView>,
    /// True when the history was cut at [`DEVICE_HISTORY_LIMIT`], so the page
    /// can say so instead of implying it is complete.
    pub history_truncated: bool,
    pub total_events: i64,
    /// Tickets raised about this device. The join the product exists for: a
    /// technician looking at a device sees its help-desk history without going
    /// to search for the serial. Empty when the help desk is not wired.
    pub tickets: Vec<DeviceTicketView>,
    /// The open loan, when the circulation desk is wired and one exists.
    pub custody: Option<CustodyView>,
    /// Whether the check-out/check-in forms should render at all.
    pub custody_wired: bool,
    /// Circulation-desk feedback ("Checked out.", "Already checked out…").
    pub notice: String,
    /// For the check-out/check-in forms.
    pub csrf_token: String,
    /// The open repair, when the repair surface is wired and one exists.
    pub repair: Option<RepairView>,
    pub repairs_wired: bool,
    /// Charges on this device, newest first.
    pub charges: Vec<ChargeRow>,
    pub charges_wired: bool,
}

/// The open repair as the device page shows it.
pub struct RepairView {
    pub description: String,
    pub vendor: String,
    pub opened: String,
    /// Parts consumed so far (GP-4), oldest first.
    pub parts: Vec<PartRow>,
    /// Sum of the priced lines, formatted; empty when nothing is priced.
    pub parts_total: String,
    /// Consumable items with stock left, for the add-part picker.
    pub part_options: Vec<PartOption>,
}

pub struct PartRow {
    pub name: String,
    pub quantity: i64,
    pub line_total: String,
}

pub struct PartOption {
    pub id: String,
    pub label: String,
}

/// One charge row on the device page.
pub struct ChargeRow {
    pub kind: String,
    pub amount: String,
    pub status: String,
    pub person: String,
    pub reason: String,
    pub insurance: bool,
}

/// The open loan as the device page shows it.
pub struct CustodyView {
    pub holder: String,
    pub checked_out: String,
    pub due: String,
    pub overdue: bool,
    pub agreement: bool,
    /// The drawn signature as a data URL, when one was captured at checkout.
    pub signature_png: String,
}

/// One ticket about this device, as shown on the device page.
pub struct DeviceTicketView {
    pub id: String,
    pub number: i64,
    pub subject: String,
    pub status_label: String,
    pub status_class: String,
    pub opened: String,
}

impl DeviceDetailView {
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    pub fn has_student(&self) -> bool {
        !self.student_id.is_empty()
    }

    pub fn has_tickets(&self) -> bool {
        !self.tickets.is_empty()
    }
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/detail.html")]
pub struct DeviceDetailTemplate {
    pub view: DeviceDetailView,
    pub nav: crate::nav::Nav,
}

/// `GET /devices/{id}` — one device, its fields, and its history.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DeviceNoticeQuery {
    pub notice: String,
}

impl DeviceNoticeQuery {
    /// A closed set of codes rather than reflected text, matching the ticket
    /// page's rule: a crafted link cannot put arbitrary words on the page.
    fn message(&self) -> String {
        match self.notice.as_str() {
            "checked_out" => "Checked out.".to_string(),
            "checked_in" => "Checked in.".to_string(),
            "custody_open" => "This device is already checked out — check it in first.".to_string(),
            "custody_none" => "This device is not checked out.".to_string(),
            "custody_no_user" => {
                "Nobody matched that. Use a roster id or an exact email.".to_string()
            }
            "custody_bad_date" => "That due date did not parse — use YYYY-MM-DD.".to_string(),
            "custody_bad_signature" => {
                "That signature did not come through — try drawing it again.".to_string()
            }
            "repair_opened" => "Repair opened — the device is marked In repair.".to_string(),
            "repair_closed" => "Repair closed — the device is Active again.".to_string(),
            "repair_closed_fee" => {
                "Repair closed, and the cost was assessed as a fee to the holder.".to_string()
            }
            "repair_open" => "A repair is already open — close it first.".to_string(),
            "repair_none" => "There is no open repair on this device.".to_string(),
            "part_added" => "Part recorded against the repair.".to_string(),
            "part_no_stock" => {
                "Not enough of that item in stock — the part was not recorded.".to_string()
            }
            "repair_no_description" => "Say what is being repaired.".to_string(),
            "bad_amount" => "That amount did not parse — use dollars like 129.99.".to_string(),
            "fee_assessed" => "Fee assessed.".to_string(),
            "fee_no_holder" => {
                "Nobody holds this device — name the person the fee is for.".to_string()
            }
            "fee_no_cost" => "The repair closed, but there was no cost to assess.".to_string(),
            "fee_failed" => "The repair closed, but the fee could not be saved.".to_string(),
            "failed" => "That could not be saved. Check the server log.".to_string(),
            _ => String::new(),
        }
    }
}

pub async fn device_detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(notice): Query<DeviceNoticeQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    axum::Extension(principal): axum::Extension<crate::authz::Principal>,
) -> Response {
    let (Some(assets), Some(events)) = (state.assets.clone(), state.asset_events.clone()) else {
        return not_configured();
    };

    let asset = match assets.get_asset(&id).await {
        Ok(Some(a)) => a,
        Ok(None) => return device_not_found(),
        Err(e) => {
            tracing::error!("device detail could not load {id}: {e}");
            return load_failed();
        }
    };
    // Out of the site boundary reads as absent — a guessed id must not
    // confirm the device exists (GP-2).
    if !principal.permits_school(asset.school_org_sourced_id.as_deref()) {
        return device_not_found();
    }

    let page = events
        .list_events(
            &AssetEventFilter::for_asset(&id),
            PageRequest::new(DEVICE_HISTORY_LIMIT, 0),
        )
        .await
        .unwrap_or_else(|e| {
            // History is the point of this page, but a device's own fields are
            // still worth showing if the log cannot be read.
            tracing::error!("device history query failed for {id}: {e}");
            chalk_core::models::page::Page::new(Vec::new(), 0, PageRequest::new(1, 0))
        });

    let label = device_label(&asset);
    let student = match &asset.assigned_user_sourced_id {
        Some(sid) => match state.repo.get_user(sid).await {
            Ok(Some(u)) => format!("{}, {}", u.family_name, u.given_name),
            _ => sid.clone(),
        },
        None => NONE_TEXT.to_string(),
    };
    let school = match &asset.school_org_sourced_id {
        Some(sid) => match state.repo.get_org(sid).await {
            Ok(Some(o)) => o.name,
            _ => sid.clone(),
        },
        None => NONE_TEXT.to_string(),
    };

    let view = DeviceDetailView {
        events: page
            .items
            .iter()
            .map(|e| EventView::new(e, label.clone()))
            .collect(),
        history_truncated: page.total > DEVICE_HISTORY_LIMIT,
        total_events: page.total,
        id: asset.id.clone(),
        label,
        purchase_date: asset
            .purchase_date
            .map(|d| d.to_string())
            .unwrap_or_else(|| "—".to_string()),
        purchase_cost: asset
            .purchase_cost_cents
            .map(|c| format!("${}.{:02}", c / 100, c % 100))
            .unwrap_or_else(|| "—".to_string()),
        vendor_name: or_dash(asset.vendor.as_ref()),
        po_number: or_dash(asset.po_number.as_ref()),
        funding_source: or_dash(asset.funding_source.as_ref()),
        warranty: match asset.warranty_expires {
            Some(d) if d < chrono::Utc::now().date_naive() => format!("Expired {d}"),
            Some(d) => format!("Until {d}"),
            None => "—".to_string(),
        },
        warranty_class: match asset.warranty_expires {
            Some(d) if d < chrono::Utc::now().date_naive() => "expired".to_string(),
            Some(_) => "ok".to_string(),
            None => String::new(),
        },
        asset_tag: or_dash(asset.asset_tag.as_ref()),
        serial_number: or_dash(asset.serial_number.as_ref()),
        model: or_dash(asset.model.as_ref()),
        make: or_dash(asset.make.as_ref()),
        status_label: crate::devices::status_label(asset.status).to_string(),
        status_class: crate::devices::status_badge_class(asset.status).to_string(),
        student,
        student_id: asset.assigned_user_sourced_id.clone().unwrap_or_default(),
        school,
        org_unit_path: or_dash(asset.org_unit_path.as_ref()),
        source_label: crate::devices::source_label(asset.source).to_string(),
        external_id: or_dash(asset.external_id.as_ref()),
        console_owned: matches!(
            asset.source,
            AssetSource::Google | AssetSource::Intune | AssetSource::Jamf
        ),
        is_google: asset.source == AssetSource::Google,
        google_user: or_dash(asset.annotated_user.as_ref()),
        google_device_id: or_dash(asset.google_device_id.as_ref()),
        aue_date: asset
            .aue_date
            .map(|d| d.to_string())
            .unwrap_or_else(|| NONE_TEXT.to_string()),
        os_version: or_dash(asset.os_version.as_ref()),
        last_sync: asset
            .last_sync_at
            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| NONE_TEXT.to_string()),
        match_state: match_state_label(asset.match_state).to_string(),
        match_state_note: match_state_note(asset.match_state).to_string(),
        tickets: device_tickets(&state, &id).await,
        custody: open_custody_view(&state, &id).await,
        custody_wired: state.custody.is_some(),
        notice: notice.message(),
        csrf_token: csrf.0,
        repair: open_repair_view(&state, &id).await,
        repairs_wired: state.repairs.is_some(),
        charges: device_charges(&state, &id).await,
        charges_wired: state.charges.is_some(),
    };

    render(DeviceDetailTemplate {
        view,
        nav: crate::nav::Nav::new(&state.config, "devices"),
    })
}

/// The open loan on one device, rendered for its page. `None` when the desk is
/// not wired or the device is in.
async fn open_custody_view(state: &Arc<AppState>, asset_id: &str) -> Option<CustodyView> {
    let custody = state.custody.as_ref()?;
    let record = custody.open_custody_for_asset(asset_id).await.ok()??;
    let holder = match state.repo.get_user(&record.user_sourced_id).await {
        Ok(Some(u)) => format!("{}, {}", u.family_name, u.given_name),
        _ => record.user_sourced_id.clone(),
    };
    Some(CustodyView {
        holder,
        checked_out: record.checked_out_at.format("%Y-%m-%d").to_string(),
        due: record
            .due_at
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "No date set".to_string()),
        overdue: record.is_overdue(chrono::Utc::now()),
        agreement: record.agreement_acknowledged,
        signature_png: record.signature_png.clone().unwrap_or_default(),
    })
}

/// The open repair on one device. `None` when not wired or nothing is open.
async fn open_repair_view(state: &Arc<AppState>, asset_id: &str) -> Option<RepairView> {
    let repairs = state.repairs.as_ref()?;
    let r = repairs.open_repair_for_asset(asset_id).await.ok()??;
    let dollars = |cents: i64| format!("${}.{:02}", cents / 100, cents % 100);
    let (parts, parts_total) = match state.items.as_ref() {
        Some(items) => {
            let list = items.list_repair_parts(&r.id).await.unwrap_or_default();
            let total: i64 = list.iter().filter_map(|p| p.total_cents()).sum();
            (
                list.iter()
                    .map(|p| PartRow {
                        name: p.item_name.clone(),
                        quantity: p.quantity,
                        line_total: p.total_cents().map(dollars).unwrap_or_default(),
                    })
                    .collect(),
                if total > 0 {
                    dollars(total)
                } else {
                    String::new()
                },
            )
        }
        None => (Vec::new(), String::new()),
    };
    let part_options = match state.items.as_ref() {
        Some(items) => {
            let mut options = Vec::new();
            for item in items.list_all_items().await.unwrap_or_default() {
                let issued = items.issued_quantity(&item.id).await.unwrap_or(0);
                let consumed = items.repair_consumed_quantity(&item.id).await.unwrap_or(0);
                let available = item.quantity_total - issued - consumed;
                if available > 0 {
                    options.push(PartOption {
                        id: item.id.clone(),
                        label: format!("{} ({available} left)", item.name),
                    });
                }
            }
            options
        }
        None => Vec::new(),
    };
    Some(RepairView {
        description: r.description,
        vendor: r.vendor.unwrap_or_else(|| "—".to_string()),
        opened: r.opened_at.format("%Y-%m-%d").to_string(),
        parts,
        parts_total,
        part_options,
    })
}

/// This device's charges, newest first, people named.
async fn device_charges(state: &Arc<AppState>, asset_id: &str) -> Vec<ChargeRow> {
    let Some(charges) = state.charges.as_ref() else {
        return Vec::new();
    };
    let list = charges
        .list_charges_for_asset(asset_id)
        .await
        .unwrap_or_default();
    let mut rows = Vec::with_capacity(list.len());
    for c in list {
        let person = match &c.user_sourced_id {
            Some(sid) => match state.repo.get_user(sid).await {
                Ok(Some(u)) => format!("{}, {}", u.family_name, u.given_name),
                _ => sid.clone(),
            },
            None => "—".to_string(),
        };
        rows.push(ChargeRow {
            kind: charge_kind_label(c.kind).to_string(),
            amount: crate::fees::format_cents(c.amount_cents),
            status: charge_status_label(c.status).to_string(),
            person,
            reason: c.reason.unwrap_or_default(),
            insurance: c.insurance_applied,
        });
    }
    rows
}

pub(crate) fn charge_kind_label(kind: chalk_core::models::charge::ChargeKind) -> &'static str {
    use chalk_core::models::charge::ChargeKind::*;
    match kind {
        RepairFee => "Repair fee",
        DamageFine => "Damage fine",
        LossReplacement => "Loss replacement",
        Other => "Other",
    }
}

pub(crate) fn charge_status_label(
    status: chalk_core::models::charge::ChargeStatus,
) -> &'static str {
    use chalk_core::models::charge::ChargeStatus::*;
    match status {
        Assessed => "Assessed",
        Waived => "Waived",
        SettledExternally => "Settled externally",
    }
}

/// The tickets raised about one device, most recent first, for the device
/// page. Empty (and silent) when the help desk is not wired or the query
/// fails — a device's own fields are still worth showing either way.
///
/// The `asset_id` filter and its index already exist; this is the query that
/// finally uses them, closing the asset→ticket back-link.
async fn device_tickets(state: &Arc<AppState>, asset_id: &str) -> Vec<DeviceTicketView> {
    let Some(tickets) = state.tickets.as_ref() else {
        return Vec::new();
    };
    let filter = chalk_core::models::ticket::TicketFilter {
        asset_id: Some(asset_id.to_string()),
        sort: chalk_core::models::ticket::TicketSort::Number,
        direction: chalk_core::models::page::SortDirection::Desc,
        ..Default::default()
    };
    let page = match tickets
        .list_tickets(
            &filter,
            &chalk_core::models::ticket::TicketScope::Unrestricted,
            PageRequest::new(DEVICE_TICKETS_LIMIT, 0),
        )
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("device ticket query failed for {asset_id}: {e}");
            return Vec::new();
        }
    };
    page.items
        .iter()
        .map(|t| DeviceTicketView {
            id: t.id.clone(),
            number: t.number,
            subject: t.subject.clone(),
            status_label: t.status.label().to_string(),
            status_class: crate::tickets::status_class(t.status).to_string(),
            opened: t.created_at.format("%Y-%m-%d").to_string(),
        })
        .collect()
}

/// Plain language for a match state. The stored values are schema words; these
/// are what an operator is told.
pub fn match_state_label(state: MatchState) -> &'static str {
    match state {
        MatchState::Matched => "Matched automatically",
        MatchState::Unmatched => "Needs a person",
        MatchState::Manual => "Set by an administrator",
        MatchState::Ignored => "Shared — no owner expected",
    }
}

/// What the state means for future syncs, which is the part an operator
/// actually needs and cannot infer from the label.
pub fn match_state_note(state: MatchState) -> &'static str {
    match state {
        MatchState::Matched => "A sync may reassign this if Google changes.",
        MatchState::Unmatched => "It is waiting in the queue.",
        MatchState::Manual | MatchState::Ignored => "Syncs will not change this assignment.",
    }
}

fn device_label(asset: &Asset) -> String {
    asset
        .asset_tag
        .as_deref()
        .or(asset.serial_number.as_deref())
        .unwrap_or(&asset.id)
        .to_string()
}

fn or_dash(value: Option<&String>) -> String {
    match value.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => NONE_TEXT.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Schools for the filter dropdown. A failure here narrows the filter bar; it
/// must not take the log down with it.
async fn load_schools(state: &AppState, current: &str) -> Vec<SchoolOption> {
    use chalk_core::models::common::OrgType;
    match state.repo.list_orgs().await {
        Ok(orgs) => {
            let mut schools: Vec<SchoolOption> = orgs
                .into_iter()
                .filter(|o| o.org_type == OrgType::School)
                .map(|o| SchoolOption {
                    selected: o.sourced_id == current,
                    sourced_id: o.sourced_id,
                    name: o.name,
                })
                .collect();
            schools.sort_by(|a, b| a.name.cmp(&b.name));
            schools
        }
        Err(e) => {
            tracing::warn!("could not load schools for the history filter: {e}");
            Vec::new()
        }
    }
}

fn is_htmx(headers: &HeaderMap) -> bool {
    headers.get("HX-Request").is_some()
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!("history render failed: {e}");
            load_failed()
        }
    }
}

fn not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(
            "<h1>Devices</h1><p>The device inventory is not enabled on this \
             installation.</p>"
                .to_string(),
        ),
    )
        .into_response()
}

fn device_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(
            "<h1>Device not found</h1><p>That device is no longer in the \
             inventory. <a href=\"/devices\">Back to all devices</a></p>"
                .to_string(),
        ),
    )
        .into_response()
}

fn load_failed() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(
            "<h1>Devices</h1><p>The history could not be loaded. Check the \
             server log.</p>"
                .to_string(),
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
