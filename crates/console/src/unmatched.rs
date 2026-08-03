//! The unmatched queue — devices the matching ladder could not attach to a
//! person.
//!
//! # Why this is the most important screen in the module
//!
//! The inventory's promise is "4,812 of 5,000 devices, already attached to
//! real students". Nobody buying software believes a number like that on its
//! own. What makes it believable is being conspicuously honest about the 188
//! we *couldn't* place — showing them, saying why, and making them fixable in
//! a few keystrokes.
//!
//! So this is a **trust surface, not an error list**. There is no red banner
//! anywhere in it, and nothing here is called "failed". A device with no
//! Google user is not a failure, it is a cart. The framing throughout is
//! work-to-do: *"188 devices need a person. Most are carts or loaners."*
//!
//! # Why each row states its own evidence
//!
//! A queue that says only "unmatched" makes the operator guess. Every row
//! carries [`UnmatchedReason`] — what Google told us and why the ladder could
//! not use it — because the two cases have completely different remedies:
//! a device with *no* `annotatedUser` is almost always a shared cart that
//! should be ignored, and a device whose `annotatedUser` is a real string we
//! could not resolve is usually a person who left the district, or a typo.
//! Telling them apart is the difference between one bulk action and 188
//! individual decisions.
//!
//! # Selection is page-scoped here, and that is deliberate
//!
//! The inventory uses filter-scoped selection ("act on all 400 matching").
//! This queue does **not**. The plan's one hard ordering constraint is that
//! filter-as-selection and C4's diff preview ship together or not at all,
//! because treating a filter as a write scope is only safe when a preview
//! stands between the filter and the write. C4 does not exist yet.
//!
//! Bulk actions here therefore act on **explicitly ticked rows on the current
//! page** — bounded, visible, and countable before the operator commits. When
//! the diff preview lands, this can widen; until then a narrower scope that
//! the operator can literally see is the honest one.
//!
//! # Nothing here writes to Google
//!
//! Resolving and ignoring change Chalk's own records. The ChromeOS client is
//! read-only and requests only `.readonly` scopes. The UI says so rather than
//! letting an operator infer that assigning a student here renames the device
//! in the Admin console.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use chalk_core::cookies::{clear_cookie, set_cookie, CookieAttrs, SameSite};
use chalk_core::email::looks_like_email;
use chalk_core::models::asset::{
    ActorKind, Asset, AssetEventType, AssetFilter, AssetPatch, AssetRow, AssetSort, MatchState,
    NewAssetEvent, Patch,
};
use chalk_core::models::page::SortDirection;
use chalk_core::models::sync::UserFilter;
use serde::Deserialize;

use crate::table::{clamp_page_size, Selection, SelectionMode, TableNav};
use crate::AppState;

/// Route the queue lives at.
pub const UNMATCHED_PATH: &str = "/devices/unmatched";

/// `id` of the HTMX swap target wrapping toolbar + table + pagination.
pub const REGION_ID: &str = "unmatched-region";

/// How many roster matches the resolve picker offers at once.
///
/// A cap rather than a page: the picker is a type-ahead, and an operator who
/// sees twenty near-identical names should type more, not paginate. It also
/// bounds the per-user junction-table round trips `list_users` makes.
pub const ROSTER_PICKER_LIMIT: i64 = 20;

/// The em-dash placeholder, matching the inventory so an empty cell looks the
/// same on both screens.
const NONE_TEXT: &str = "—";

// ---------------------------------------------------------------------------
// Why a device is unmatched
// ---------------------------------------------------------------------------

/// What the matching ladder had to work with, and why it could not finish.
///
/// Derived from the device's stored `annotated_user` rather than from a
/// recorded failure code, because the ladder does not write one — an
/// unsuccessful match writes `match_state = unmatched` and nothing else. That
/// is the right design (a reason recorded at sync time goes stale the moment
/// the roster changes) but it means the reason has to be recomputed here from
/// the same evidence a human would use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmatchedReason {
    /// Google carries no `annotatedUser` at all. Overwhelmingly a shared cart,
    /// kiosk or loaner: the common case, and the one bulk **ignore** exists
    /// for.
    NoGoogleUser,
    /// `annotatedUser` holds something, but it is not an address we can look
    /// up — free text like "Cart 3" or "Mrs Alvarez's room".
    NotAnEmail,
    /// `annotatedUser` is a well-formed address that no roster user claims.
    /// Usually someone who left the district, a personal address, or a typo.
    UnknownAddress,
}

impl UnmatchedReason {
    pub fn of(annotated_user: Option<&str>) -> Self {
        match annotated_user.map(str::trim).filter(|s| !s.is_empty()) {
            None => UnmatchedReason::NoGoogleUser,
            // `looks_like_email` is imported from `chalk-core`, not
            // reimplemented — it is the *same function* the matching ladder
            // calls. An explanation computed by a near-copy would eventually
            // disagree with the decision it claims to explain, telling a
            // technician "that is not an address" about a device the ladder
            // rejected for a different reason.
            Some(v) if !looks_like_email(v) => UnmatchedReason::NotAnEmail,
            Some(_) => UnmatchedReason::UnknownAddress,
        }
    }

    /// Plain language, addressed to a technician. No jargon, no "failed", and
    /// no blame — each of these is a normal state for a school fleet.
    pub fn summary(&self) -> &'static str {
        match self {
            UnmatchedReason::NoGoogleUser => "No Google user on the device",
            UnmatchedReason::NotAnEmail => "Google has a note, not an address",
            UnmatchedReason::UnknownAddress => "Signed in by someone not in the roster",
        }
    }

    /// What to do about it, since a reason a technician cannot act on is
    /// decoration.
    pub fn hint(&self) -> &'static str {
        match self {
            UnmatchedReason::NoGoogleUser => "Usually a cart, kiosk or loaner — ignore it.",
            UnmatchedReason::NotAnEmail => "Assign a person, or ignore it if it is shared.",
            UnmatchedReason::UnknownAddress => "They may have left the district.",
        }
    }

    /// Grouping key for the summary strip.
    pub fn as_str(&self) -> &'static str {
        match self {
            UnmatchedReason::NoGoogleUser => "no_google_user",
            UnmatchedReason::NotAnEmail => "not_an_email",
            UnmatchedReason::UnknownAddress => "unknown_address",
        }
    }
}

// ---------------------------------------------------------------------------
// Query parsing
// ---------------------------------------------------------------------------

/// URL state for the queue. `match_state` is not among them: this page *is*
/// the unmatched filter, and offering to turn it off would make it a second,
/// worse inventory.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UnmatchedQuery {
    /// `orgs.sourced_id` of the school.
    pub school: String,
    /// Org-unit path prefix.
    pub ou: String,
    /// One of [`UnmatchedReason::as_str`]; anything else means no constraint.
    pub reason: String,
    /// Free-text over tag, serial and the Google annotations.
    pub q: String,
    pub sort: String,
    pub dir: String,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

impl UnmatchedQuery {
    /// The repository filter. `match_state` is pinned to `Unmatched`, which is
    /// what makes this a queue rather than a view — `manual` and `ignored`
    /// devices have both been decided about and must not reappear.
    pub fn to_asset_filter(&self) -> AssetFilter {
        AssetFilter {
            match_state: Some(MatchState::Unmatched),
            school_org_sourced_id: non_empty(&self.school),
            org_unit_path_prefix: non_empty(&self.ou),
            search: non_empty(&self.q),
            sort: parse_sort(&self.sort),
            direction: parse_direction(&self.dir),
            ..Default::default()
        }
    }

    /// The reason filter, applied after the query.
    ///
    /// This one predicate cannot go into SQL: the reason is derived from the
    /// shape of `annotated_user`, not stored, so there is no column to filter
    /// on. It is applied to the fetched page only — never by loading the fleet
    /// and narrowing it — which means a reason-filtered page can come back
    /// shorter than the page size. The count beside the filter says how many
    /// of *this page* matched, rather than implying a total it cannot know.
    pub fn reason_filter(&self) -> Option<UnmatchedReason> {
        match self.reason.as_str() {
            "no_google_user" => Some(UnmatchedReason::NoGoogleUser),
            "not_an_email" => Some(UnmatchedReason::NotAnEmail),
            "unknown_address" => Some(UnmatchedReason::UnknownAddress),
            _ => None,
        }
    }

    pub fn is_filtered(&self) -> bool {
        !self.school.is_empty()
            || !self.ou.is_empty()
            || !self.q.is_empty()
            || self.reason_filter().is_some()
    }

    /// Filter pairs for the selection scope, canonically ordered. Derived from
    /// the parsed filter so a junk parameter cannot claim to narrow anything.
    pub fn filter_pairs(&self) -> Vec<(String, String)> {
        let f = self.to_asset_filter();
        let mut pairs: Vec<(String, String)> = Vec::new();
        if let Some(v) = f.school_org_sourced_id {
            pairs.push(("school".into(), v));
        }
        if let Some(v) = f.org_unit_path_prefix {
            pairs.push(("ou".into(), v));
        }
        if let Some(v) = f.search {
            pairs.push(("q".into(), v));
        }
        if let Some(r) = self.reason_filter() {
            pairs.push(("reason".into(), r.as_str().to_string()));
        }
        pairs
    }

    pub fn page_number(&self) -> i64 {
        self.page.unwrap_or(1).max(1)
    }

    pub fn to_nav(&self, total: i64) -> TableNav {
        TableNav {
            base_path: UNMATCHED_PATH.to_string(),
            region_id: REGION_ID.to_string(),
            filter_pairs: self.filter_pairs(),
            sort: parse_sort(&self.sort).as_str().to_string(),
            direction: match parse_direction(&self.dir) {
                SortDirection::Desc => "desc".to_string(),
                SortDirection::Asc => "asc".to_string(),
            },
            page: self.page_number(),
            per_page: clamp_page_size(self.per_page),
            total,
        }
    }
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Unknown sort keys fall back to the default rather than erroring: a stale
/// bookmark should render the queue, not a 400.
fn parse_sort(raw: &str) -> AssetSort {
    match raw {
        "serial_number" => AssetSort::SerialNumber,
        "model" => AssetSort::Model,
        "org_unit_path" => AssetSort::OrgUnitPath,
        "last_sync_at" => AssetSort::LastSyncAt,
        _ => AssetSort::AssetTag,
    }
}

fn parse_direction(raw: &str) -> SortDirection {
    match raw {
        "desc" => SortDirection::Desc,
        _ => SortDirection::Asc,
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/// One queued device.
pub struct UnmatchedRowView {
    pub id: String,
    pub asset_tag: String,
    pub serial_number: String,
    pub model: String,
    pub school: String,
    pub org_unit_path: String,
    /// Raw `annotatedUser` exactly as Google holds it, or the placeholder.
    /// Shown verbatim because a typo is only diagnosable if it is not tidied.
    pub google_user: String,
    pub reason_summary: String,
    pub reason_hint: String,
    pub reason_key: String,
    pub last_sync: String,
    pub check_label: String,
    /// Prefills the resolve picker. Empty unless Google gave us an address.
    pub search_seed: String,
}

impl UnmatchedRowView {
    pub fn from_row(row: &AssetRow) -> Self {
        let a = &row.asset;
        let reason = UnmatchedReason::of(a.annotated_user.as_deref());
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
            school: or_dash(row.school_name.as_ref()),
            org_unit_path: or_dash(a.org_unit_path.as_ref()),
            google_user: or_dash(a.annotated_user.as_ref()),
            reason_summary: reason.summary().to_string(),
            reason_hint: reason.hint().to_string(),
            reason_key: reason.as_str().to_string(),
            last_sync: a
                .last_sync_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| NONE_TEXT.to_string()),
            check_label: format!("Select device {identity}"),
            // Seeding the picker with the local part turns "j.alvarez@old.org"
            // into a search for "j.alvarez", which is what finds the person who
            // changed domains — the single most common resolvable case.
            search_seed: match reason {
                UnmatchedReason::UnknownAddress => a
                    .annotated_user
                    .as_deref()
                    .and_then(|v| v.split('@').next())
                    .unwrap_or_default()
                    .to_string(),
                _ => String::new(),
            },
        }
    }
}

fn or_dash(value: Option<&String>) -> String {
    match value.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => NONE_TEXT.to_string(),
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

/// Everything the page and the fragment both render.
pub struct UnmatchedView {
    pub rows: Vec<UnmatchedRowView>,
    pub nav: TableNav,
    pub selection: Selection,
    pub query: UnmatchedQuery,
    pub schools: Vec<SchoolOption>,
    pub reason_options: Vec<FilterOption>,
    /// Devices in the inventory overall, so an empty queue on a fresh install
    /// reads differently from an empty queue on a fleet that is fully matched.
    pub total_devices: i64,
    /// Devices already attached to a person — the number that makes the queue
    /// look like the remainder of a job rather than a pile of errors.
    pub matched_devices: i64,
    pub oob_announcer: bool,
    /// Set after a resolve or ignore, so the region can confirm what happened.
    pub flash: String,
}

impl UnmatchedView {
    /// No devices at all. The only state that may offer "connect Google".
    pub fn is_first_run(&self) -> bool {
        self.total_devices == 0
    }

    /// The queue is empty because everything is decided — the win state, and
    /// the one place in this module that gets to celebrate.
    pub fn is_all_clear(&self) -> bool {
        self.nav.total == 0 && !self.is_first_run() && !self.query.is_filtered()
    }

    /// A filter matched nothing. Never rendered as first-run: a technician who
    /// sees "no devices yet" after filtering thinks data was lost.
    pub fn is_filtered_empty(&self) -> bool {
        self.nav.total == 0 && !self.is_first_run() && self.query.is_filtered()
    }

    pub fn has_rows(&self) -> bool {
        !self.rows.is_empty()
    }

    /// The headline. Frames the queue as remaining work against a total, never
    /// as a count of failures.
    ///
    /// The three zero cases are *not* interchangeable, and conflating them was
    /// a real bug here: an empty queue rendered "Every device is attached to a
    /// person" over a fresh install with no devices at all, and over a filter
    /// that simply matched nothing. Both are claims about a fleet we have not
    /// looked at — the strongest sentence on the screen, attached to the least
    /// evidence.
    pub fn headline(&self) -> String {
        if self.is_first_run() {
            return "No devices yet".to_string();
        }
        if self.is_filtered_empty() {
            return "No devices match these filters".to_string();
        }
        if self.nav.total == 0 {
            return "Every device is attached to a person.".to_string();
        }
        let noun = if self.nav.total == 1 {
            "device needs"
        } else {
            "devices need"
        };
        format!(
            "{} {noun} a person",
            crate::table::thousands(self.nav.total)
        )
    }

    /// The reassurance under the headline: what is already done, and what the
    /// queue usually turns out to be.
    pub fn subhead(&self) -> String {
        if self.total_devices == 0 {
            return String::new();
        }
        format!(
            "{} of {} devices are already attached. Most of the rest are carts or loaners.",
            crate::table::thousands(self.matched_devices),
            crate::table::thousands(self.total_devices)
        )
    }

    /// Announced through the live region after every swap. Under 120
    /// characters per §5.12, stating the result rather than the process.
    pub fn announcement(&self) -> String {
        if !self.flash.is_empty() {
            return self.flash.clone();
        }
        if self.nav.total == 0 {
            return if self.is_first_run() {
                "No devices imported yet.".to_string()
            } else if self.is_filtered_empty() {
                "No devices match these filters.".to_string()
            } else {
                "Every device is attached to a person.".to_string()
            };
        }
        format!(
            "{} devices need a person. Showing {}.",
            crate::table::thousands(self.nav.total),
            self.nav.range_summary()
        )
    }

    /// The table's accessible name.
    pub fn caption(&self) -> String {
        let base = format!(
            "Devices needing a person — {} results",
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
#[template(path = "unmatched/index.html")]
pub struct UnmatchedPageTemplate {
    pub view: UnmatchedView,
    pub nav: crate::nav::Nav,
}

#[derive(Template)]
#[template(path = "unmatched/region.html")]
pub struct UnmatchedRegionTemplate {
    pub view: UnmatchedView,
}

// ---------------------------------------------------------------------------
// The queue
// ---------------------------------------------------------------------------

/// `GET /devices/unmatched`.
pub async fn unmatched_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<UnmatchedQuery>,
    headers: HeaderMap,
) -> Response {
    let flash = take_flash(&headers);
    let mut response = render_queue(state, query, headers, flash.clone()).await;
    // Expire it on the way out so the message shows exactly once. Done even
    // when there was no flash: clearing an absent cookie is a no-op, and the
    // alternative is a branch that forgets the case where rendering failed.
    if !flash.is_empty() {
        if let Ok(value) = clear_flash_cookie().parse() {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, value);
        }
    }
    response
}

async fn render_queue(
    state: Arc<AppState>,
    query: UnmatchedQuery,
    headers: HeaderMap,
    flash: String,
) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };

    let filter = query.to_asset_filter();
    let mut query = query;

    let mut page = match assets
        .list_assets_with_roster(&filter, query.to_nav(0).page_request())
        .await
    {
        Ok(page) => page,
        Err(e) => {
            tracing::error!("unmatched queue query failed: {e}");
            return load_failed();
        }
    };

    // Same clamp as the inventory: an out-of-range page is empty with a
    // non-zero total, which would otherwise render as "every device is
    // attached" on a queue that is anything but. Resolving the last device on
    // the final page reaches this on the very next render.
    if page.items.is_empty() && page.total > 0 {
        let last_page = query.to_nav(page.total).total_pages();
        if query.page_number() > last_page {
            query.page = Some(last_page);
            match assets
                .list_assets_with_roster(&filter, query.to_nav(page.total).page_request())
                .await
            {
                Ok(p) => page = p,
                Err(e) => {
                    tracing::error!("unmatched queue re-query failed: {e}");
                    return load_failed();
                }
            }
        }
    }

    let total_devices = assets
        .count_assets(&AssetFilter::default())
        .await
        .unwrap_or(0);
    let matched_devices = assets
        .count_assets(&AssetFilter {
            assigned: Some(true),
            ..Default::default()
        })
        .await
        .unwrap_or(0);

    let mut rows: Vec<UnmatchedRowView> =
        page.items.iter().map(UnmatchedRowView::from_row).collect();
    if let Some(reason) = query.reason_filter() {
        rows.retain(|r| r.reason_key == reason.as_str());
    }

    let nav = query.to_nav(page.total);
    // Page-scoped, not filter-scoped — see the module docs. The bulk bar counts
    // ticked checkboxes, all of which are on screen.
    let selection = Selection::new(
        SelectionMode::Picked,
        &query.filter_pairs(),
        page.total,
        rows.len() as i64,
    );

    let schools = load_schools(&state, &query.school).await;

    let view = UnmatchedView {
        reason_options: options(
            &[
                ("", "Any reason"),
                ("no_google_user", "No Google user"),
                ("not_an_email", "A note, not an address"),
                ("unknown_address", "Not in the roster"),
            ],
            &query.reason,
        ),
        rows,
        nav,
        selection,
        query,
        schools,
        total_devices,
        matched_devices,
        oob_announcer: is_htmx(&headers),
        flash,
    };

    if view.oob_announcer {
        render(UnmatchedRegionTemplate { view })
    } else {
        render(UnmatchedPageTemplate {
            view,
            nav: crate::nav::Nav::new(&state.config, "devices"),
        })
    }
}

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
            // A missing school list narrows the filter bar; it must not take
            // the queue down with it.
            tracing::warn!("could not load schools for the unmatched filter: {e}");
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// The resolve picker
// ---------------------------------------------------------------------------

/// One roster candidate offered for a device.
pub struct CandidateView {
    pub sourced_id: String,
    pub name: String,
    pub email: String,
    pub role: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ResolveQuery {
    pub q: String,
}

pub struct ResolveView {
    pub device_id: String,
    pub device_label: String,
    pub google_user: String,
    pub reason_summary: String,
    pub query: String,
    pub candidates: Vec<CandidateView>,
    /// A search ran and matched nobody — distinct from not having searched.
    pub searched: bool,
}

impl ResolveView {
    pub fn has_candidates(&self) -> bool {
        !self.candidates.is_empty()
    }

    pub fn is_empty_search(&self) -> bool {
        self.searched && self.candidates.is_empty()
    }
}

#[derive(Template)]
#[template(path = "unmatched/resolve.html")]
pub struct ResolveTemplate {
    pub view: ResolveView,
}

/// The same panel as a document, for a request HTMX did not make.
#[derive(Template)]
#[template(path = "unmatched/resolve_page.html")]
pub struct ResolvePageTemplate {
    pub view: ResolveView,
    pub nav: crate::nav::Nav,
}

/// `GET /devices/{id}/resolve` — the roster picker for one device.
///
/// Served as a fragment that the queue swaps into a detail row. It is a real
/// URL rather than a JavaScript-only panel so it works with scripting off, can
/// be linked in a ticket, and can be tested with a plain GET.
pub async fn resolve_picker(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<ResolveQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };

    let asset = match assets.get_asset(&id).await {
        Ok(Some(a)) => a,
        Ok(None) => return device_not_found(),
        Err(e) => {
            tracing::error!("resolve picker could not load device {id}: {e}");
            return load_failed();
        }
    };

    let term = query.q.trim().to_string();
    let candidates = if term.is_empty() {
        Vec::new()
    } else {
        match state
            .repo
            .list_users(&UserFilter::search(&term, ROSTER_PICKER_LIMIT))
            .await
        {
            Ok(users) => users
                .iter()
                .map(|u| CandidateView {
                    sourced_id: u.sourced_id.clone(),
                    name: format!("{}, {}", u.family_name, u.given_name),
                    email: u.email.clone().unwrap_or_else(|| NONE_TEXT.to_string()),
                    role: format!("{:?}", u.role).to_lowercase(),
                })
                .collect(),
            Err(e) => {
                tracing::error!("roster search failed: {e}");
                Vec::new()
            }
        }
    };

    let view = ResolveView {
        device_label: device_label(&asset),
        device_id: asset.id.clone(),
        google_user: or_dash(asset.annotated_user.as_ref()),
        reason_summary: UnmatchedReason::of(asset.annotated_user.as_deref())
            .summary()
            .to_string(),
        searched: !term.is_empty(),
        query: term,
        candidates,
    };

    // A bare `<tr>` is a fragment, not a document. HTMX asked for the fragment
    // and swaps it into the queue; anything else — a plain navigation, a
    // browser with scripting off, a link pasted into a ticket — gets a page.
    if is_htmx(&headers) {
        render(ResolveTemplate { view })
    } else {
        render(ResolvePageTemplate {
            view,
            nav: crate::nav::Nav::new(&state.config, "devices"),
        })
    }
}

/// The most specific identifier the device has — what a technician reads off
/// the sticker, not an internal id.
fn device_label(asset: &Asset) -> String {
    asset
        .asset_tag
        .as_deref()
        .or(asset.serial_number.as_deref())
        .unwrap_or(&asset.id)
        .to_string()
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ResolveForm {
    /// `users.sourced_id` of the person to attach.
    #[serde(default)]
    pub user: String,
    /// Where to send the operator back to, preserving their filters and page.
    #[serde(default)]
    pub back: String,
}

/// `POST /devices/{id}/resolve` — attach a roster user to a device.
///
/// Writes `assigned_user_sourced_id` **and** `match_state = manual` in one
/// transaction with its audit event. `manual` is what stops the next sync
/// overwriting the decision: the sync engine refuses to touch `manual` and
/// `ignored` rows, so an operator's judgement outlives the automation.
pub async fn resolve_submit(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Form(form): Form<ResolveForm>,
) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };

    let user_id = form.user.trim();
    if user_id.is_empty() {
        return back_to(&form.back, "Pick a person before assigning.");
    }

    // Confirm the roster user exists before writing. The FK would catch it
    // anyway, but a foreign-key error surfaces as a 500 and this surfaces as
    // a sentence.
    let user = match state.repo.get_user(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return back_to(&form.back, "That person is no longer in the roster."),
        Err(e) => {
            tracing::error!("resolve could not load user {user_id}: {e}");
            return back_to(
                &form.back,
                "Could not reach the roster. Nothing was changed.",
            );
        }
    };

    let patch = AssetPatch {
        assigned_user_sourced_id: Patch::Set(user.sourced_id.clone()),
        match_state: Some(MatchState::Manual),
        ..Default::default()
    };
    let event = NewAssetEvent {
        asset_id: id.clone(),
        actor: actor_id(&state),
        actor_kind: ActorKind::Admin,
        event_type: AssetEventType::Assigned,
        payload: Some(serde_json::json!({
            "user": user.sourced_id,
            "rule": "manual",
            "via": "unmatched_queue",
        })),
    };

    match assets.apply_patch_with_event(&id, &patch, &event).await {
        Ok(true) => back_to(
            &form.back,
            &format!("Attached to {}, {}.", user.family_name, user.given_name),
        ),
        Ok(false) => back_to(&form.back, "That device is no longer in the inventory."),
        Err(e) => {
            tracing::error!("resolve failed for device {id}: {e}");
            back_to(
                &form.back,
                "Could not save the assignment. Nothing changed.",
            )
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct IgnoreForm {
    #[serde(default)]
    pub back: String,
}

/// `POST /devices/{id}/ignore` — take a shared device out of the queue.
///
/// Ignoring does not stop syncing the device and does not hide it from the
/// inventory. It records that nobody expects it to have an owner, so the queue
/// stops asking. The sync engine leaves `ignored` rows alone, so it survives
/// the next run.
pub async fn ignore_submit(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Form(form): Form<IgnoreForm>,
) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };

    match ignore_one(&state, assets.as_ref(), &id).await {
        Ok(true) => back_to(
            &form.back,
            "Marked as shared. It will stay in the inventory.",
        ),
        Ok(false) => back_to(&form.back, "That device is no longer in the inventory."),
        Err(e) => {
            tracing::error!("ignore failed for device {id}: {e}");
            back_to(&form.back, "Could not save. Nothing changed.")
        }
    }
}

async fn ignore_one(
    state: &AppState,
    assets: &dyn chalk_core::db::repository::AssetRepository,
    id: &str,
) -> chalk_core::error::Result<bool> {
    let patch = AssetPatch {
        match_state: Some(MatchState::Ignored),
        ..Default::default()
    };
    let event = NewAssetEvent {
        asset_id: id.to_string(),
        actor: actor_id(state),
        actor_kind: ActorKind::Admin,
        event_type: AssetEventType::FieldChanged,
        payload: Some(serde_json::json!({
            "field": "match_state",
            "old": MatchState::Unmatched.as_str(),
            "new": MatchState::Ignored.as_str(),
            "via": "unmatched_queue",
        })),
    };
    assets.apply_patch_with_event(id, &patch, &event).await
}

/// Ticked row ids plus the return path.
///
/// Parsed by hand rather than with `Form<T>`: axum's form extractor is
/// `serde_urlencoded`, which cannot deserialize repeated keys into a `Vec` and
/// answers 422 for the exact shape a checkbox column produces. Adding a second
/// urlencoding crate to the tree for one endpoint is the worse trade.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BulkForm {
    pub ids: Vec<String>,
    pub back: String,
}

impl BulkForm {
    /// Decode an `application/x-www-form-urlencoded` body.
    ///
    /// `+` means space in this encoding — a detail that silently corrupts
    /// values when missed, so it is handled before percent-decoding rather
    /// than after.
    pub fn parse(body: &str) -> Self {
        let mut form = BulkForm::default();
        for pair in body.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            let decoded = urlencoding::decode(&value.replace('+', " "))
                .map(|v| v.into_owned())
                .unwrap_or_default();
            match key {
                "ids" if !decoded.is_empty() => form.ids.push(decoded),
                "back" => form.back = decoded,
                _ => {}
            }
        }
        form
    }
}

/// `POST /devices/unmatched/bulk-ignore` — ignore every ticked row.
///
/// Page-scoped by construction: the ids come from checkboxes that were on
/// screen. There is no "all matching" variant here, and there must not be one
/// until C4's diff preview exists — see the module docs.
///
/// Applied one at a time rather than as a single statement. Each device gets
/// its own transaction and its own audit row, so a failure part-way through
/// leaves a partial result that is fully recorded rather than an all-or-nothing
/// write whose audit trail claims more than happened.
pub async fn bulk_ignore_submit(State(state): State<Arc<AppState>>, body: String) -> Response {
    let form = BulkForm::parse(&body);
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };

    if form.ids.is_empty() {
        return back_to(&form.back, "Tick at least one device first.");
    }

    let mut ignored = 0usize;
    let mut missing = 0usize;
    let mut failed = 0usize;
    for id in &form.ids {
        match ignore_one(&state, assets.as_ref(), id).await {
            Ok(true) => ignored += 1,
            Ok(false) => missing += 1,
            Err(e) => {
                tracing::error!("bulk ignore failed for device {id}: {e}");
                failed += 1;
            }
        }
    }

    back_to(&form.back, &bulk_summary(ignored, missing, failed))
}

/// States exactly what happened, including the parts that did not work.
/// A bulk action that reports only its successes is how an operator comes to
/// believe a fleet is tidier than it is.
fn bulk_summary(ignored: usize, missing: usize, failed: usize) -> String {
    let mut parts = vec![format!(
        "Marked {ignored} {} as shared.",
        if ignored == 1 { "device" } else { "devices" }
    )];
    if missing > 0 {
        parts.push(format!("{missing} were no longer in the inventory."));
    }
    if failed > 0 {
        parts.push(format!(
            "{failed} could not be saved — check the server log."
        ));
    }
    parts.join(" ")
}

/// The signed-in operator, for the audit trail.
///
/// The console authenticates a single admin rather than individual staff
/// accounts, so there is no per-person identity to record yet. Recording
/// `console:admin` is honest about that; inventing a name would put a
/// fabricated actor in an immutable audit trail.
fn actor_id(_state: &AppState) -> String {
    "console:admin".to_string()
}

/// Name of the one-shot flash cookie.
const FLASH_COOKIE: &str = "chalk_devices_flash";

/// Longest flash we will render. A cookie is far harder to plant than a URL,
/// but it is still client-side storage, so the value is bounded and stripped
/// of control characters before it reaches a template.
const FLASH_MAX_LEN: usize = 200;

/// Send the operator back where they came from, with a message.
///
/// The message travels in a one-shot cookie rather than a query parameter.
/// Reflecting it through the URL would mean any crafted link could render
/// arbitrary text inside a success banner shown to a signed-in administrator —
/// escaped, so not script injection, but a ready-made phishing surface
/// ("Session expired, call this number"). A cookie can only be set by this
/// origin, so what comes back is what we sent.
///
/// `back` is validated to a path on this console. It arrives in a form field,
/// so an unchecked redirect would let a crafted page bounce a signed-in admin
/// to an external site.
fn back_to(back: &str, message: &str) -> Response {
    let cookie = set_cookie(
        FLASH_COOKIE,
        &urlencoding::encode(message),
        &CookieAttrs {
            same_site: SameSite::Lax,
            http_only: true,
            // Not marked Secure: the flash carries no secret, and forcing it on
            // would silently drop the message on a plain-HTTP self-hosted
            // install, which is a supported deployment.
            secure: false,
            path: "/devices",
            // A session cookie with no Max-Age. It is cleared on read, so the
            // only way it outlives one render is if the response never arrives.
            max_age_secs: None,
        },
    );
    (
        StatusCode::SEE_OTHER,
        [
            (axum::http::header::SET_COOKIE, cookie),
            (axum::http::header::LOCATION, safe_back(back)),
        ],
    )
        .into_response()
}

/// Read the flash cookie, if the browser sent one.
fn take_flash(headers: &HeaderMap) -> String {
    let Some(raw) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    else {
        return String::new();
    };
    for cookie in raw.split(';') {
        if let Some(value) = cookie.trim().strip_prefix(&format!("{FLASH_COOKIE}=")) {
            let decoded = urlencoding::decode(value)
                .map(|s| s.into_owned())
                .unwrap_or_default();
            return decoded
                .chars()
                .filter(|c| !c.is_control())
                .take(FLASH_MAX_LEN)
                .collect();
        }
    }
    String::new()
}

/// The `Set-Cookie` that expires the flash, so a message is shown exactly once
/// and a refresh does not repeat "Attached to Doe, Jane" indefinitely.
fn clear_flash_cookie() -> String {
    clear_cookie(
        FLASH_COOKIE,
        &CookieAttrs {
            same_site: SameSite::Lax,
            http_only: true,
            secure: false,
            path: "/devices",
            max_age_secs: None,
        },
    )
}

/// Only same-origin, absolute paths under the queue are accepted; anything
/// else falls back to the bare queue. `//evil.example` is rejected explicitly:
/// it is a protocol-relative URL, not a local path, and passes a naive
/// "starts with /" check.
fn safe_back(back: &str) -> String {
    let trimmed = back.trim();
    if trimmed.starts_with(UNMATCHED_PATH) && !trimmed.starts_with("//") {
        trimmed.to_string()
    } else {
        UNMATCHED_PATH.to_string()
    }
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

fn is_htmx(headers: &HeaderMap) -> bool {
    headers.get("HX-Request").is_some()
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!("unmatched queue render failed: {e}");
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
        Html("<p>That device is no longer in the inventory.</p>".to_string()),
    )
        .into_response()
}

fn load_failed() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(
            "<h1>Devices</h1><p>The queue could not be loaded. Check the \
             server log.</p>"
                .to_string(),
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
