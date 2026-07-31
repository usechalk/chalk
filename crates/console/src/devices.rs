//! Device inventory — the flagship dense table (DESIGN_SYSTEM.md §5.3).
//!
//! The columns *are* the pitch: **student and school sit beside the device**,
//! which is the thing a device-only asset tracker structurally cannot show.
//! Everything else on this page exists to make that column trustworthy at
//! twenty thousand rows.
//!
//! # Three properties this module is built around
//!
//! **Pagination and filtering are SQL, never Rust.** Every filter here maps
//! onto a field of [`AssetFilter`] and every page onto a [`PageRequest`], both
//! of which the repository pushes into `WHERE`/`LIMIT`/`OFFSET`. Nothing loads
//! a `Vec` and narrows it — at 20k devices that is a timeout rather than a slow
//! page, and `console/src/lib.rs`'s `users_list` is the counter-example this
//! module exists not to copy.
//!
//! **State lives in the URL.** Sort, filters and page are query parameters,
//! pushed with `hx-push-url`, so a filtered view is a link a technician can
//! bookmark, share in a ticket, or save as a view (§5.4). Every control is a
//! real `<a href>` or a real `<form method="get">` first; HTMX only intercepts
//! them to swap a region instead of the document.
//!
//! **Selection is filter-scoped.** See [`crate::table::SelectionMode`] — the
//! reasoning is long and lives there.
//!
//! # What is deliberately absent
//!
//! There is **no write path**. The ChromeOS client is read-only and requests
//! only `.readonly` scopes, so the bulk bar renders its scope and its count but
//! every action is disabled with the reason stated in text. Wiring an action
//! here before the diff preview exists would be exactly the failure mode the
//! filter-scoped selection model is designed to prevent: a bulk write whose
//! blast radius the operator never saw.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use chalk_core::models::asset::{AssetFilter, AssetRow, AssetSort, AssetStatus};
use chalk_core::models::common::OrgType;
use chalk_core::models::page::SortDirection;
use chrono::{Datelike, NaiveDate, Utc};
use serde::Deserialize;

use crate::table::{clamp_page_size, Selection, SelectionMode, TableNav};
use crate::AppState;

/// Route the inventory lives at, and the prefix every link is built from.
pub const DEVICES_PATH: &str = "/devices";

/// `id` of the HTMX swap target wrapping toolbar + table + pagination (§5.3's
/// region contract). One region, so a sort never leaves the count stale.
pub const REGION_ID: &str = "devices-region";

/// A device is "expiring soon" inside this many months of its AUE date.
///
/// §8 requires the threshold be stated in words rather than carried by colour
/// alone, so this number appears in the column legend and in each affected
/// cell's text. Changing it here changes both.
pub const AUE_SOON_MONTHS: u32 = 12;

// ---------------------------------------------------------------------------
// Query parsing
// ---------------------------------------------------------------------------

/// The inventory's URL state. Every field is optional and defaulted: a bare
/// `/devices` is a valid, complete request, and a stale bookmark with a
/// nonsense value renders the default view rather than an error page.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DevicesQuery {
    /// `assets.status`, one of the six lifecycle values.
    pub status: String,
    /// `orgs.sourced_id` of the school.
    pub school: String,
    /// `"assigned"` / `"unassigned"`; anything else means no constraint.
    pub assigned: String,
    /// Org-unit path prefix, e.g. `/Students`.
    pub ou: String,
    /// ISO date; matches devices whose AUE falls strictly before it.
    pub aue_before: String,
    /// Free-text search over tag, serial and the Google annotations.
    pub q: String,
    pub sort: String,
    pub dir: String,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

impl DevicesQuery {
    /// The filter half of the query, canonically ordered.
    ///
    /// Derived from [`to_asset_filter`](Self::to_asset_filter) rather than from
    /// the raw request text, and that is load-bearing twice over. The pairs
    /// become the selection scope and its digest, so they have to describe
    /// exactly the `WHERE` clause that will run — `?status=exploded` narrows
    /// nothing, and a scope string claiming otherwise would be a lie the bulk
    /// bar repeats. They also decide first-run versus filtered-to-zero, and a
    /// junk parameter must not push an empty inventory into the wrong one.
    ///
    /// Sort, direction and paging are excluded on purpose: they change *how*
    /// rows are shown, not *which*, so they must not perturb the selection
    /// scope. Re-sorting a page cannot silently redefine what a bulk action
    /// would touch.
    pub fn filter_pairs(&self) -> Vec<(String, String)> {
        let f = self.to_asset_filter();
        let mut pairs: Vec<(String, String)> = Vec::new();
        let mut push = |k: &str, v: String| pairs.push((k.to_string(), v));

        if let Some(status) = f.status {
            push("status", status.as_str().to_string());
        }
        if let Some(school) = f.school_org_sourced_id {
            push("school", school);
        }
        match f.assigned {
            Some(true) => push("assigned", "assigned".to_string()),
            Some(false) => push("assigned", "unassigned".to_string()),
            None => {}
        }
        if let Some(ou) = f.org_unit_path_prefix {
            push("ou", ou);
        }
        if let Some(aue) = f.aue_before {
            push("aue_before", aue.to_string());
        }
        if let Some(q) = f.search {
            push("q", q);
        }
        pairs
    }

    /// True when anything is narrowing the table. Drives the choice between
    /// the first-run and filtered-to-zero empty states (§5.14) — showing
    /// first-run while a filter is active makes a technician think the fleet
    /// was lost.
    pub fn is_filtered(&self) -> bool {
        !self.filter_pairs().is_empty()
    }

    /// Translate into the repository filter. Unparseable values are dropped
    /// rather than rejected, so a hand-edited URL degrades to a wider view
    /// instead of a 400.
    pub fn to_asset_filter(&self) -> AssetFilter {
        AssetFilter {
            status: parse_enum(&self.status, AssetStatus::parse),
            asset_type: None,
            source: None,
            match_state: None,
            school_org_sourced_id: non_empty(&self.school),
            assigned_user_sourced_id: None,
            org_unit_path_prefix: non_empty(&self.ou),
            assigned: match self.assigned.trim() {
                "assigned" => Some(true),
                "unassigned" => Some(false),
                _ => None,
            },
            aue_before: non_empty(&self.aue_before)
                .and_then(|s| NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok()),
            search: non_empty(&self.q),
            sort: self.sort_column(),
            direction: self.sort_direction(),
        }
    }

    /// The whitelisted sort column. [`AssetSort`] is a closed enum precisely so
    /// an `ORDER BY` can never carry request text; an unknown value falls back
    /// to the default rather than erroring.
    pub fn sort_column(&self) -> AssetSort {
        AssetSort::parse(self.sort.trim()).unwrap_or(AssetSort::AssetTag)
    }

    pub fn sort_direction(&self) -> SortDirection {
        if self.dir.trim() == "desc" {
            SortDirection::Desc
        } else {
            SortDirection::Asc
        }
    }

    pub fn per_page(&self) -> i64 {
        clamp_page_size(self.per_page)
    }

    pub fn page_number(&self) -> i64 {
        self.page.unwrap_or(1).max(1)
    }

    /// The navigation state every link on the page is derived from.
    pub fn to_nav(&self, total: i64) -> TableNav {
        TableNav {
            base_path: DEVICES_PATH.to_string(),
            region_id: REGION_ID.to_string(),
            filter_pairs: self.filter_pairs(),
            sort: self.sort_column().as_str().to_string(),
            direction: match self.sort_direction() {
                SortDirection::Desc => "desc".to_string(),
                SortDirection::Asc => "asc".to_string(),
            },
            page: self.page_number(),
            per_page: self.per_page(),
            total,
        }
    }
}

fn non_empty(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

fn parse_enum<T, E>(raw: &str, parse: impl Fn(&str) -> Result<T, E>) -> Option<T> {
    non_empty(raw).and_then(|s| parse(&s).ok())
}

// ---------------------------------------------------------------------------
// View models
// ---------------------------------------------------------------------------

/// AUE urgency (§8). Two-tone by design: past expiry and expiring soon get
/// treatment, everything else stays neutral. A table where most rows shout is
/// a table nobody reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AueUrgency {
    /// The device no longer receives Chrome OS updates.
    Past,
    /// Expiring within [`AUE_SOON_MONTHS`].
    Soon,
    /// Supported for longer than the threshold.
    Later,
    /// Google reported no auto-update expiration for this model.
    Unknown,
}

impl AueUrgency {
    /// Classify an AUE date relative to `today`.
    pub fn of(aue: Option<NaiveDate>, today: NaiveDate) -> Self {
        let Some(aue) = aue else {
            return AueUrgency::Unknown;
        };
        if aue < today {
            return AueUrgency::Past;
        }
        if aue < add_months(today, AUE_SOON_MONTHS) {
            return AueUrgency::Soon;
        }
        AueUrgency::Later
    }

    pub fn css_class(&self) -> &'static str {
        match self {
            AueUrgency::Past => "aue aue--past",
            AueUrgency::Soon => "aue aue--soon",
            AueUrgency::Later | AueUrgency::Unknown => "aue",
        }
    }

    /// The words that carry the urgency. Colour is never the only channel
    /// (§4's design law), so every non-neutral state also says what it is, and
    /// says the threshold rather than assuming the reader knows it.
    pub fn note(&self) -> String {
        match self {
            AueUrgency::Past => "past expiry".to_string(),
            AueUrgency::Soon => format!("within {AUE_SOON_MONTHS} months"),
            AueUrgency::Later | AueUrgency::Unknown => String::new(),
        }
    }
}

/// Add whole months to a date, clamping the day into the target month. Used
/// only for the AUE threshold, where landing on the 28th instead of the 31st is
/// immaterial and panicking is not.
fn add_months(date: NaiveDate, months: u32) -> NaiveDate {
    let zero_based = date.month0() + months;
    let year = date.year() + (zero_based / 12) as i32;
    let month = zero_based % 12 + 1;
    let mut day = date.day();
    loop {
        if let Some(d) = NaiveDate::from_ymd_opt(year, month, day) {
            return d;
        }
        day -= 1;
    }
}

/// §4.2's device-status badge. Text label plus hue, never hue alone; `lost`
/// additionally carries an icon because it is the one status that demands
/// action.
pub fn status_badge_class(status: AssetStatus) -> &'static str {
    match status {
        AssetStatus::Active => "badge badge--success",
        AssetStatus::Repair => "badge badge--warning",
        AssetStatus::Storage => "badge badge--info",
        AssetStatus::Retired => "badge badge--neutral",
        AssetStatus::Deprovisioned => "badge badge--status",
        AssetStatus::Lost => "badge badge--danger",
    }
}

pub fn status_label(status: AssetStatus) -> &'static str {
    match status {
        AssetStatus::Active => "Active",
        AssetStatus::Repair => "Repair",
        AssetStatus::Storage => "Storage",
        AssetStatus::Retired => "Retired",
        AssetStatus::Deprovisioned => "Deprovisioned",
        AssetStatus::Lost => "Lost",
    }
}

/// One rendered row.
///
/// Pre-formatted in Rust rather than in the template: an Askama template that
/// reaches through three `Option`s per cell is where the em-dash placeholders
/// drift, and the checkbox's `aria-label` has to be assembled from whichever
/// identifier the device actually has.
pub struct DeviceRowView {
    pub id: String,
    pub asset_tag: String,
    pub serial_number: String,
    pub model: String,
    /// `"Family, Given"`, or the em-dash placeholder.
    pub student: String,
    /// `users.sourced_id`, for the detail link. Empty when unassigned.
    pub student_id: String,
    pub student_email: String,
    pub school: String,
    pub status_label: String,
    pub status_class: String,
    pub is_lost: bool,
    pub org_unit_path: String,
    pub aue_date: String,
    pub aue_class: String,
    pub aue_note: String,
    pub last_sync: String,
    /// Names the row in the checkbox's accessible name, e.g.
    /// `"Select device CB-01422"`. Never bare "Select".
    pub check_label: String,
}

/// The em-dash placeholder for an absent value. One constant so an empty cell
/// always looks the same, and never renders as a blank a technician reads as a
/// rendering bug.
const NONE_TEXT: &str = "—";

fn or_dash(value: Option<&String>) -> String {
    match value.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => NONE_TEXT.to_string(),
    }
}

impl DeviceRowView {
    pub fn from_row(row: &AssetRow, today: NaiveDate) -> Self {
        let a = &row.asset;
        let urgency = AueUrgency::of(a.aue_date, today);

        // The most specific identifier the device has. A technician reading a
        // cart of unlabelled loaners hears the serial, not "row 47".
        let identity = a
            .asset_tag
            .as_deref()
            .or(a.serial_number.as_deref())
            .unwrap_or(&a.id);

        Self {
            id: a.id.clone(),
            asset_tag: or_dash(a.asset_tag.as_ref()),
            serial_number: or_dash(a.serial_number.as_ref()),
            model: or_dash(a.model.as_ref()),
            student: row
                .assigned_display_name()
                .unwrap_or_else(|| NONE_TEXT.to_string()),
            student_id: a.assigned_user_sourced_id.clone().unwrap_or_default(),
            student_email: row.assigned_email.clone().unwrap_or_default(),
            school: or_dash(row.school_name.as_ref()),
            status_label: status_label(a.status).to_string(),
            status_class: status_badge_class(a.status).to_string(),
            is_lost: a.status == AssetStatus::Lost,
            org_unit_path: or_dash(a.org_unit_path.as_ref()),
            aue_date: a
                .aue_date
                .map(|d| d.to_string())
                .unwrap_or_else(|| NONE_TEXT.to_string()),
            aue_class: urgency.css_class().to_string(),
            aue_note: urgency.note(),
            last_sync: a
                .last_sync_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| NONE_TEXT.to_string()),
            check_label: format!("Select device {identity}"),
        }
    }

    /// True when the device is attached to a roster user — the column that
    /// makes the whole page worth building.
    pub fn has_student(&self) -> bool {
        !self.student_id.is_empty()
    }
}

/// A school in the filter dropdown.
pub struct SchoolOption {
    pub sourced_id: String,
    pub name: String,
    pub selected: bool,
}

/// A `<select>` option that is not a database row.
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

/// Everything both the full page and the HTMX fragment render. Held in one
/// struct so `devices/index.html` can `{% include %}` `devices/region.html`
/// without the two drifting on what is in scope.
pub struct DevicesView {
    pub rows: Vec<DeviceRowView>,
    pub nav: TableNav,
    pub selection: Selection,
    pub query: DevicesQuery,
    pub schools: Vec<SchoolOption>,
    pub status_options: Vec<FilterOption>,
    pub assigned_options: Vec<FilterOption>,
    /// Devices in the whole inventory, ignoring filters. Distinguishes
    /// first-run empty from filtered-to-zero (§5.14).
    pub total_unfiltered: i64,
    /// Devices matching the filter that are attached to a roster user.
    pub matched_count: i64,
    /// Devices still waiting in the unmatched queue, across the whole
    /// inventory rather than the active filter — it is a link to another page,
    /// so a filter-scoped count would be a number that page never shows.
    pub unmatched_count: i64,
    pub aue_soon_months: u32,
    /// Whether this render is an HTMX fragment, and therefore must carry the
    /// out-of-band announcement.
    ///
    /// A full page already contains the permanent `#announcer` from
    /// `base.html`; emitting the OOB copy inline as well would put **two
    /// elements with the same id** in one document. Assistive technology would
    /// then be watching whichever one it found first, which is the one that is
    /// never updated — so the duplicate does not merely fail validation, it
    /// silences every subsequent announcement.
    pub oob_announcer: bool,
    /// Needed because the bulk bar now posts a plan request.
    pub csrf_token: String,
}

impl DevicesView {
    /// Nothing has ever been imported. The only state that may show the
    /// "connect Google" call to action.
    pub fn is_first_run(&self) -> bool {
        self.total_unfiltered == 0
    }

    /// A filter is active and matched nothing. Distinct from first-run, and
    /// checked first everywhere it matters.
    pub fn is_filtered_empty(&self) -> bool {
        self.nav.total == 0 && !self.is_first_run()
    }

    pub fn has_rows(&self) -> bool {
        !self.rows.is_empty()
    }

    /// The one-line result summary announced through the live region after
    /// every swap. Under 120 characters per §5.12, and stating the *result*
    /// rather than the process.
    pub fn announcement(&self) -> String {
        if self.nav.total == 0 {
            return if self.is_first_run() {
                "No devices imported yet.".to_string()
            } else {
                "No devices match these filters.".to_string()
            };
        }
        format!(
            "{} devices match. Showing {}.",
            crate::table::thousands(self.nav.total),
            self.nav.range_summary()
        )
    }

    /// The `<caption>` — the table's accessible name, which must say what is
    /// being shown *and* that it is narrowed.
    pub fn caption(&self) -> String {
        let base = format!(
            "Devices — {} results",
            crate::table::thousands(self.nav.total)
        );
        if self.query.is_filtered() {
            format!("{base}, filtered")
        } else {
            base
        }
    }
}

#[derive(Template)]
#[template(path = "devices/index.html")]
pub struct DevicesPageTemplate {
    pub view: DevicesView,
    pub active_page: &'static str,
}

#[derive(Template)]
#[template(path = "devices/region.html")]
pub struct DevicesRegionTemplate {
    pub view: DevicesView,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /devices` — the inventory.
///
/// Serves the full document to a browser navigation and the bare region to an
/// HTMX request, which is why sorting, filtering and paging can be one round
/// trip that still updates the count, the summary and the pagination together.
pub async fn devices_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DevicesQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    headers: HeaderMap,
) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };

    let filter = query.to_asset_filter();
    let mut query = query;
    let nav_probe = query.to_nav(0);

    let mut page = match assets
        .list_assets_with_roster(&filter, nav_probe.page_request())
        .await
    {
        Ok(page) => page,
        Err(e) => {
            tracing::error!("device inventory query failed: {e}");
            return load_failed();
        }
    };

    // A page past the end of the result set is empty but has a non-zero total,
    // so it matches neither `has_rows` nor `is_filtered_empty` and would fall
    // through to the first-run "No devices yet — connect Google Workspace"
    // state on an instance holding thousands of devices. It also renders a
    // reversed range ("1,201–1,200 of 1,200").
    //
    // This is reachable without typing a URL: a technician bookmarks page 9 of
    // a filter, the devices get resolved, and coming back tells them their
    // fleet is gone. Same "a tech will think data was lost" failure the
    // filtered-empty state exists to prevent, arriving by page number instead
    // of by filter.
    //
    // Clamp to the last page that has rows rather than erroring — a stale
    // bookmark should land on the end of the list, not on a dead end. Costs a
    // second query only in this rare case; the common path stays one windowed
    // query plus its count.
    if page.items.is_empty() && page.total > 0 {
        let last_page = query.to_nav(page.total).total_pages();
        if query.page_number() > last_page {
            query.page = Some(last_page);
            let retry = query.to_nav(page.total).page_request();
            match assets.list_assets_with_roster(&filter, retry).await {
                Ok(p) => page = p,
                Err(e) => {
                    tracing::error!("device inventory re-query failed: {e}");
                    return load_failed();
                }
            }
        }
    }

    // Only asked for when the page came back empty, so the common path is one
    // windowed query plus its count and nothing more.
    let total_unfiltered = if page.total == 0 {
        assets
            .count_assets(&AssetFilter::default())
            .await
            .unwrap_or(0)
    } else {
        page.total
    };

    // "4,812 of 5,000 matched to students" is the headline the whole wedge
    // rests on, so it is counted in SQL against the same filter rather than by
    // tallying the visible page.
    let matched_count = assets
        .count_assets(&AssetFilter {
            assigned: Some(true),
            ..filter.clone()
        })
        .await
        .unwrap_or(0);

    let unmatched_count = assets
        .count_assets(&AssetFilter {
            match_state: Some(chalk_core::models::asset::MatchState::Unmatched),
            ..Default::default()
        })
        .await
        .unwrap_or(0);

    let today = Utc::now().date_naive();
    let rows: Vec<DeviceRowView> = page
        .items
        .iter()
        .map(|r| DeviceRowView::from_row(r, today))
        .collect();

    let nav = query.to_nav(page.total);
    let selection = Selection::new(
        SelectionMode::Matching,
        &query.filter_pairs(),
        page.total,
        rows.len() as i64,
    );

    let schools = match state.repo.list_orgs().await {
        Ok(orgs) => {
            let mut schools: Vec<SchoolOption> = orgs
                .into_iter()
                .filter(|o| o.org_type == OrgType::School)
                .map(|o| SchoolOption {
                    selected: o.sourced_id == query.school,
                    sourced_id: o.sourced_id,
                    name: o.name,
                })
                .collect();
            schools.sort_by(|a, b| a.name.cmp(&b.name));
            schools
        }
        Err(e) => {
            // A missing school list narrows the filter bar; it must not take
            // the inventory down with it.
            tracing::warn!("could not load schools for the device filter: {e}");
            Vec::new()
        }
    };

    let view = DevicesView {
        status_options: options(
            &[
                ("", "Any status"),
                ("active", "Active"),
                ("repair", "Repair"),
                ("storage", "Storage"),
                ("retired", "Retired"),
                ("deprovisioned", "Deprovisioned"),
                ("lost", "Lost"),
            ],
            &query.status,
        ),
        assigned_options: options(
            &[
                ("", "Anyone or no one"),
                ("assigned", "Assigned to a student"),
                ("unassigned", "Unassigned"),
            ],
            &query.assigned,
        ),
        rows,
        nav,
        selection,
        query,
        schools,
        total_unfiltered,
        matched_count,
        unmatched_count,
        aue_soon_months: AUE_SOON_MONTHS,
        oob_announcer: is_htmx(&headers),
        csrf_token: csrf.0,
    };

    if view.oob_announcer {
        render(DevicesRegionTemplate { view })
    } else {
        render(DevicesPageTemplate {
            view,
            active_page: "devices",
        })
    }
}

/// True for a request HTMX issued, which wants the region rather than the
/// document. Absent for a plain navigation, a bookmark, or a browser with
/// JavaScript off — all of which get the full page.
fn is_htmx(headers: &HeaderMap) -> bool {
    headers.get("HX-Request").is_some()
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!("device inventory render failed: {e}");
            load_failed()
        }
    }
}

/// The console was built without an asset repository — self-hosters on a build
/// predating the devices module, and the console's own unit fixtures. Says so
/// rather than 500ing.
fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html(
            "<h1>Devices</h1><p>The device inventory is not enabled on this \
             installation.</p>"
                .to_string(),
        ),
    )
        .into_response()
}

fn load_failed() -> Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Html(
            "<h1>Devices</h1><p>The device inventory could not be loaded. \
             Check the server log.</p>"
                .to_string(),
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
