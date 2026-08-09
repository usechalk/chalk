//! Report-builder-lite (SS-5): saved asset reports.
//!
//! A report is the inventory's own filter query string with a name and one
//! group-by dimension — the URL-as-saved-view idea given a page. No query
//! language, no chart engine: the questions districts actually ask ("how
//! many repair-status devices per school?") are one filter and one GROUP BY.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::models::console_user::Actor;
use chalk_core::models::report::{AssetReport, ReportDimension};
use chrono::Utc;
use serde::Deserialize;

use crate::devices::DevicesQuery;
use crate::AppState;

pub const REPORT_BUILDER_PATH: &str = "/devices/reports/custom";

// ---------------------------------------------------------------------------
// List + create
// ---------------------------------------------------------------------------

pub struct ReportListRow {
    pub id: String,
    pub name: String,
    pub dimension: &'static str,
    pub filter_summary: String,
}

pub struct DimensionOption {
    pub value: &'static str,
    pub label: &'static str,
}

pub struct SchoolOption {
    pub sourced_id: String,
    pub name: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/report_builder.html")]
pub struct ReportBuilderTemplate {
    pub nav: crate::nav::Nav,
    pub rows: Vec<ReportListRow>,
    pub dimensions: Vec<DimensionOption>,
    pub schools: Vec<SchoolOption>,
    pub notice: String,
    pub csrf_token: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ReportNoticeQuery {
    pub notice: String,
}

fn notice_message(notice: &str) -> String {
    match notice {
        "created" => "Report saved.".into(),
        "deleted" => "Report deleted.".into(),
        "bad_input" => "Give the report a name and a valid group-by.".into(),
        "failed" => "That did not work — try again.".into(),
        _ => String::new(),
    }
}

/// Human words for a stored filter query string, so the list says what a
/// report covers without the reader parsing a URL.
fn summarize_filter(query: &str) -> String {
    if query.trim().is_empty() {
        return "every device".to_string();
    }
    let q: DevicesQuery = serde_urlencoded::from_str(query).unwrap_or_default();
    let pairs = q.filter_pairs();
    if pairs.is_empty() {
        return "every device".to_string();
    }
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `GET /devices/reports/custom`
pub async fn builder_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Query(q): Query<ReportNoticeQuery>,
) -> Response {
    let Some(reports) = state.asset_reports.clone() else {
        return not_configured();
    };
    let rows = reports
        .list_asset_reports()
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| ReportListRow {
            id: r.id.clone(),
            name: r.name.clone(),
            dimension: r.group_by.label(),
            filter_summary: summarize_filter(&r.query),
        })
        .collect();
    let schools = match state.repo.list_orgs().await {
        Ok(orgs) => orgs
            .into_iter()
            .filter(|o| o.org_type == chalk_core::models::common::OrgType::School)
            .map(|o| SchoolOption {
                sourced_id: o.sourced_id,
                name: o.name,
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    ReportBuilderTemplate {
        nav: crate::nav::Nav::new(&state.config, "devices"),
        rows,
        dimensions: ReportDimension::ALL
            .iter()
            .map(|d| DimensionOption {
                value: d.as_str(),
                label: d.label(),
            })
            .collect(),
        schools,
        notice: notice_message(&q.notice),
        csrf_token: csrf.0,
    }
    .into_response()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewReportForm {
    pub name: String,
    pub group_by: String,
    // The filter fields, mirroring the inventory's own query parameters.
    pub status: String,
    pub school: String,
    pub source: String,
    pub q: String,
}

/// `POST /devices/reports/custom` — save a report. The filter is stored as
/// the same query string the inventory would put in its URL, so the two
/// surfaces can never disagree about what a filter means.
pub async fn create_report(
    State(state): State<Arc<AppState>>,
    axum::Extension(actor): axum::Extension<Actor>,
    axum::Form(form): axum::Form<NewReportForm>,
) -> Response {
    let Some(reports) = state.asset_reports.clone() else {
        return back("failed");
    };
    let name = form.name.trim();
    let Some(group_by) = ReportDimension::parse(form.group_by.trim()) else {
        return back("bad_input");
    };
    if name.is_empty() {
        return back("bad_input");
    }
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for (k, v) in [
        ("status", form.status.trim()),
        ("school", form.school.trim()),
        ("source", form.source.trim()),
        ("q", form.q.trim()),
    ] {
        if !v.is_empty() {
            pairs.push((k, v));
        }
    }
    let query = serde_urlencoded::to_string(&pairs).unwrap_or_default();
    let report = AssetReport {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        query,
        group_by,
        actor: actor.audit_actor(),
        created_at: Utc::now(),
    };
    match reports.create_asset_report(&report).await {
        Ok(()) => back("created"),
        Err(e) => {
            tracing::error!("could not save a report: {e}");
            back("failed")
        }
    }
}

/// `POST /devices/reports/custom/{id}/delete`
pub async fn delete_report(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some(reports) = state.asset_reports.clone() else {
        return back("failed");
    };
    match reports.delete_asset_report(&id).await {
        Ok(true) => back("deleted"),
        _ => back("failed"),
    }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

pub struct BucketRow {
    pub label: String,
    pub count: i64,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/report_view.html")]
pub struct ReportViewTemplate {
    pub nav: crate::nav::Nav,
    pub id: String,
    pub name: String,
    pub dimension: &'static str,
    pub filter_summary: String,
    pub buckets: Vec<BucketRow>,
    pub total: i64,
    /// The filtered inventory this report counts, for the drill-down link.
    pub inventory_href: String,
}

async fn bucket_label(
    state: &Arc<AppState>,
    dimension: ReportDimension,
    value: &Option<String>,
) -> String {
    let Some(v) = value else {
        return match dimension {
            ReportDimension::School => "No school".to_string(),
            _ => "—".to_string(),
        };
    };
    match dimension {
        // School ids resolve to names; every other dimension's values are
        // already words.
        ReportDimension::School => match state.repo.get_org(v).await {
            Ok(Some(o)) => o.name,
            _ => v.clone(),
        },
        _ => v.clone(),
    }
}

/// `GET /devices/reports/custom/{id}` — run it.
pub async fn view_report(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Extension(principal): axum::Extension<crate::authz::Principal>,
) -> Response {
    let Some(reports) = state.asset_reports.clone() else {
        return not_configured();
    };
    let Ok(Some(report)) = reports.get_asset_report(&id).await else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Html("<h1>No such report.</h1>".to_string()),
        )
            .into_response();
    };
    let q: DevicesQuery = serde_urlencoded::from_str(&report.query).unwrap_or_default();
    let filter = principal.scope_asset_filter(q.to_asset_filter());
    let buckets_raw = reports
        .count_assets_by_dimension(&filter, report.group_by)
        .await
        .unwrap_or_default();
    let mut buckets = Vec::with_capacity(buckets_raw.len());
    let mut total = 0i64;
    for b in &buckets_raw {
        total += b.count;
        buckets.push(BucketRow {
            label: bucket_label(&state, report.group_by, &b.group_value).await,
            count: b.count,
        });
    }
    let inventory_href = if report.query.is_empty() {
        "/devices".to_string()
    } else {
        format!("/devices?{}", report.query)
    };
    ReportViewTemplate {
        nav: crate::nav::Nav::new(&state.config, "devices"),
        id: report.id.clone(),
        name: report.name.clone(),
        dimension: report.group_by.label(),
        filter_summary: summarize_filter(&report.query),
        buckets,
        total,
        inventory_href,
    }
    .into_response()
}

/// `GET /devices/reports/custom/{id}/export.csv`
pub async fn export_report(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Extension(principal): axum::Extension<crate::authz::Principal>,
) -> Response {
    let Some(reports) = state.asset_reports.clone() else {
        return not_configured();
    };
    let Ok(Some(report)) = reports.get_asset_report(&id).await else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Html("<h1>No such report.</h1>".to_string()),
        )
            .into_response();
    };
    let q: DevicesQuery = serde_urlencoded::from_str(&report.query).unwrap_or_default();
    let buckets = reports
        .count_assets_by_dimension(
            &principal.scope_asset_filter(q.to_asset_filter()),
            report.group_by,
        )
        .await
        .unwrap_or_default();
    let mut out = String::from("group,count\n");
    for b in &buckets {
        let label = bucket_label(&state, report.group_by, &b.group_value).await;
        out.push_str(&format!("\"{}\",{}\n", label.replace('"', "\"\""), b.count));
    }
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"report.csv\"",
            ),
        ],
        out,
    )
        .into_response()
}

fn back(notice: &str) -> Response {
    Redirect::to(&format!("{REPORT_BUILDER_PATH}?notice={notice}")).into_response()
}

fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Reports are not available here.</h1>".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
