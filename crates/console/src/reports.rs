//! Device reports (WS-3).
//!
//! # Three numbers a district actually asks for
//!
//! Replacement runway, the fleet broken down by school, and what nobody is
//! holding. Each answers a question someone is asked by a superintendent or a
//! business office, which is the test for whether a report earns its screen.
//!
//! # Every row is a link, and there is no separate export
//!
//! A report cell is a filter over the inventory, so it navigates there rather
//! than rendering its own table. The inventory already sorts, paginates and
//! exports CSV; a second path to the same rows would be a second place for the
//! filter semantics to drift, and the first thing an operator does with
//! "47 devices expire this year" is look at the 47.
//!
//! # Why the AUE bands are cumulative queries
//!
//! `AssetFilter` carries `aue_before`, an upper bound. Bands are built by
//! subtracting successive cumulative counts rather than by adding a range
//! filter nothing else needs — five cheap counting queries against an indexed
//! column, and no new filter dimension to keep in step across two backends.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use chalk_core::models::asset::{AssetFilter, AssetStatus};
use chalk_core::models::common::OrgType;
use chrono::{Datelike, NaiveDate, Utc};

use crate::AppState;

pub const REPORTS_PATH: &str = "/devices/reports";

/// One row of the auto-update-expiration runway.
pub struct AueBand {
    pub label: String,
    /// What this band means for planning, in the words a budget conversation
    /// uses. A date range alone tells an operator nothing they cannot read off
    /// the column.
    pub note: String,
    pub count: i64,
    /// Inventory URL showing exactly these devices.
    pub href: String,
    /// Past expiry — the row that should read as a problem.
    pub overdue: bool,
}

/// One school's fleet, split by status.
pub struct SchoolRow {
    pub name: String,
    pub total: i64,
    pub cells: Vec<StatusCell>,
    pub href: String,
}

pub struct StatusCell {
    pub label: String,
    pub class: String,
    pub count: i64,
    pub href: String,
}

pub struct ReportsView {
    pub aue_bands: Vec<AueBand>,
    /// Warranty runway (GP-3): same band machinery, counting
    /// `warranty_expires` instead of `aue_date`. Empty when no device
    /// carries a warranty date, so the section can stay off the page.
    pub warranty_bands: Vec<AueBand>,
    pub aue_unknown: i64,
    pub aue_unknown_href: String,
    pub schools: Vec<SchoolRow>,
    pub statuses: Vec<String>,
    pub unassigned: i64,
    pub unassigned_href: String,
    pub total: i64,
}

impl ReportsView {
    pub fn has_fleet(&self) -> bool {
        self.total > 0
    }

    pub fn has_schools(&self) -> bool {
        !self.schools.is_empty()
    }

    /// Devices whose AUE date has already passed. The headline number, because
    /// it is the one that is already costing something.
    pub fn overdue(&self) -> i64 {
        self.aue_bands
            .iter()
            .filter(|b| b.overdue)
            .map(|b| b.count)
            .sum()
    }
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/reports.html")]
pub struct ReportsTemplate {
    pub view: ReportsView,
    pub nav: crate::nav::Nav,
}

/// The band boundaries, as months from today.
///
/// Chosen to match how a district buys: what is already dead, what dies this
/// budget year, what dies next year, and everything else. Not even intervals —
/// even intervals would be tidier and less useful.
const BAND_MONTHS: &[(i64, &str, &str)] = &[
    (
        0,
        "Already expired",
        "No more ChromeOS updates. These are the security exposure.",
    ),
    (
        12,
        "Within 12 months",
        "Expire inside this budget year — replacement is already a line item.",
    ),
    (
        24,
        "Within 24 months",
        "Next budget cycle. Enough warning to plan a purchase rather than react.",
    ),
    (
        36,
        "Within 36 months",
        "Comfortable. Worth knowing when negotiating a refresh.",
    ),
];

fn add_months(from: NaiveDate, months: i64) -> NaiveDate {
    let total = from.year() as i64 * 12 + (from.month0() as i64) + months;
    let year = total.div_euclid(12) as i32;
    let month0 = total.rem_euclid(12) as u32;
    // Clamp the day so adding a month to the 31st never produces an invalid
    // date — the alternative is a panic on a page nobody expects to be risky.
    let mut day = from.day();
    while day > 28 {
        if let Some(d) = NaiveDate::from_ymd_opt(year, month0 + 1, day) {
            return d;
        }
        day -= 1;
    }
    NaiveDate::from_ymd_opt(year, month0 + 1, day).unwrap_or(from)
}

/// Turn cumulative "expires before X" counts into disjoint bands.
///
/// Pulled out of the handler because this subtraction is the only arithmetic on
/// the page, and arithmetic that runs off cumulative totals is exactly where a
/// boundary device gets counted twice. Testable without a database or a
/// rendered page.
fn bands_from_cumulative(cumulative: &[(NaiveDate, i64)]) -> Vec<AueBand> {
    let mut bands = Vec::new();
    let mut previous = 0i64;
    for (i, (months, label, note)) in BAND_MONTHS.iter().enumerate() {
        let Some((boundary, running)) = cumulative.get(i) else {
            break;
        };
        bands.push(AueBand {
            label: (*label).to_string(),
            note: (*note).to_string(),
            // Clamped at zero: the counts come from separate queries, so a
            // device syncing between two of them could in principle make a
            // later total smaller. A negative band would be nonsense on a page
            // someone reads to a superintendent.
            count: (running - previous).max(0),
            href: href(&[("aue_before", &boundary.to_string())]),
            overdue: *months == 0,
        });
        previous = *running;
    }
    bands
}

fn href(pairs: &[(&str, &str)]) -> String {
    let query: Vec<String> = pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
        .collect();
    if query.is_empty() {
        crate::devices::DEVICES_PATH.to_string()
    } else {
        format!("{}?{}", crate::devices::DEVICES_PATH, query.join("&"))
    }
}

/// `GET /devices/reports`
pub async fn reports_page(State(state): State<Arc<AppState>>) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_configured();
    };

    let today = Utc::now().date_naive();
    let all = AssetFilter::default();
    let total = assets.count_assets(&all).await.unwrap_or(0);

    // Cumulative counts, then differences. Five counting queries beats a new
    // range filter that only this page would ever use.
    let mut cumulative = Vec::new();
    for (months, _, _) in BAND_MONTHS {
        let boundary = add_months(today, *months);
        let filter = AssetFilter {
            aue_before: Some(boundary),
            ..Default::default()
        };
        cumulative.push((boundary, assets.count_assets(&filter).await.unwrap_or(0)));
    }

    let aue_bands = bands_from_cumulative(&cumulative);

    // The warranty runway rides the same cumulative-band machinery, counting
    // warranty_expires. iiQ and VIZOR make warranty a headline; for the half
    // of the market with no warranty tracking at all this section IS the gap
    // being closed, so it earns its place beside AUE.
    let mut w_cumulative = Vec::new();
    for (months, _, _) in BAND_MONTHS {
        let boundary = add_months(today, *months);
        let filter = AssetFilter {
            warranty_before: Some(boundary),
            ..Default::default()
        };
        w_cumulative.push((boundary, assets.count_assets(&filter).await.unwrap_or(0)));
    }
    let any_warranty = assets
        .count_assets(&AssetFilter {
            warranty_before: Some(add_months(today, 600)),
            ..Default::default()
        })
        .await
        .unwrap_or(0);
    let warranty_bands = if any_warranty == 0 {
        Vec::new()
    } else {
        let mut bands = bands_from_cumulative(&w_cumulative);
        for band in &mut bands {
            band.href = band.href.replace("aue_before", "warranty_before");
            band.note = band
                .note
                .replace("security updates", "warranty coverage")
                .clone();
        }
        bands
    };

    // Devices Google has never told us about. Called out rather than folded
    // into the last band: "we do not know" and "expires in three years" are
    // different answers, and only one of them is actionable by syncing.
    let with_aue = cumulative.last().map(|(_, n)| *n).unwrap_or(0);
    let far_future = AssetFilter {
        aue_before: Some(add_months(today, 600)),
        ..Default::default()
    };
    let any_aue = assets.count_assets(&far_future).await.unwrap_or(with_aue);
    let aue_unknown = (total - any_aue).max(0);

    let unassigned = assets
        .count_assets(&AssetFilter {
            assigned: Some(false),
            ..Default::default()
        })
        .await
        .unwrap_or(0);

    // One query for the whole breakdown.
    let groups = assets
        .count_assets_by_school_and_status(&all)
        .await
        .unwrap_or_default();

    let statuses = [
        AssetStatus::Active,
        AssetStatus::Repair,
        AssetStatus::Storage,
        AssetStatus::Retired,
        AssetStatus::Lost,
    ];
    let school_names = school_names(&state).await;

    let mut schools: Vec<SchoolRow> = Vec::new();
    let mut seen: Vec<Option<String>> = Vec::new();
    for g in &groups {
        if !seen.contains(&g.school_org_sourced_id) {
            seen.push(g.school_org_sourced_id.clone());
        }
    }
    for school in seen {
        let key = school.clone().unwrap_or_default();
        let name = school
            .as_ref()
            .and_then(|id| {
                school_names
                    .iter()
                    .find(|(sid, _)| sid == id)
                    .map(|(_, n)| n.clone())
            })
            // `assets.school_org_sourced_id` references `orgs`, not schools,
            // and `ON DELETE SET NULL` means the row can never dangle — so the
            // only way to land here is a device attached to an org that is not
            // a school, usually a district. Named rather than blanked, because
            // a nameless row is one nobody can chase.
            .or_else(|| school.as_ref().map(|id| format!("Not a school ({id})")))
            .unwrap_or_else(|| "No school".to_string());

        let cells: Vec<StatusCell> = statuses
            .iter()
            .map(|st| StatusCell {
                label: crate::devices::status_label(*st).to_string(),
                class: crate::devices::status_badge_class(*st).to_string(),
                count: groups
                    .iter()
                    .filter(|g| g.school_org_sourced_id == school && g.status == *st)
                    .map(|g| g.count)
                    .sum(),
                href: href(&[("school", &key), ("status", st.as_str())]),
            })
            .collect();

        schools.push(SchoolRow {
            total: cells.iter().map(|c| c.count).sum(),
            name,
            cells,
            href: href(&[("school", &key)]),
        });
    }

    render(ReportsTemplate {
        view: ReportsView {
            aue_bands,
            warranty_bands,
            aue_unknown,
            aue_unknown_href: href(&[]),
            schools,
            statuses: statuses
                .iter()
                .map(|s| crate::devices::status_label(*s).to_string())
                .collect(),
            unassigned,
            unassigned_href: href(&[("assigned", "unassigned")]),
            total,
        },
        nav: crate::nav::Nav::new(&state.config, "devices"),
    })
}

/// `(sourced_id, name)` for every school, so the report reads in names.
async fn school_names(state: &Arc<AppState>) -> Vec<(String, String)> {
    state
        .repo
        .list_orgs()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|o| o.org_type == OrgType::School)
        .map(|o| (o.sourced_id, o.name))
        .collect()
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!("reports render failed: {e}");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>Reports</h1><p>The report could not be built.</p>".to_string()),
            )
                .into_response()
        }
    }
}

fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Reports</h1><p>Devices are not enabled here.</p>".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
