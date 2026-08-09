//! The fleet dashboard (GP-5): every saved report as a widget, the live
//! operational numbers above them, a tokened read-only share link, and the
//! same content as an email digest.
//!
//! Deliberately server-rendered: bars are widths computed here and drawn by
//! CSS, so the page needs no chart library and the share view carries no
//! scripts at all. The share renders **counts only** — bucket labels and
//! numbers, never device rows or student names — which is what makes handing
//! the URL to a superintendent safe by construction.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::models::asset::AssetFilter;
use chrono::Utc;

use crate::AppState;

pub const DASHBOARD_PATH: &str = "/devices/dashboard";
pub const SHARE_PREFIX: &str = "/share/dashboard/";

pub struct StatCard {
    pub label: &'static str,
    pub value: i64,
    /// Console-only drill-down; stripped on the share view.
    pub href: &'static str,
    pub alarm: bool,
}

pub struct WidgetRow {
    pub label: String,
    pub count: i64,
    /// 0–100, of the widget's largest bucket — the bar width.
    pub pct: i64,
}

pub struct Widget {
    pub name: String,
    pub total: i64,
    pub rows: Vec<WidgetRow>,
}

pub struct DashboardData {
    pub stats: Vec<StatCard>,
    pub widgets: Vec<Widget>,
}

/// Gather everything the dashboard shows. The session view passes the
/// caller's principal so scoped technicians see their schools' numbers; the
/// share and the digest pass `None` and speak for the district.
pub async fn collect(
    state: &Arc<AppState>,
    principal: Option<&crate::authz::Principal>,
) -> DashboardData {
    let scope_filter = |f: AssetFilter| match principal {
        Some(p) => p.scope_asset_filter(f),
        None => f,
    };
    let mut stats = Vec::new();
    if let Some(assets) = &state.assets {
        let total = assets
            .count_assets(&scope_filter(AssetFilter::default()))
            .await
            .unwrap_or(0);
        stats.push(StatCard {
            label: "Devices",
            value: total,
            href: "/devices",
            alarm: false,
        });
        let unassigned = assets
            .count_assets(&scope_filter(AssetFilter {
                assigned: Some(false),
                ..Default::default()
            }))
            .await
            .unwrap_or(0);
        stats.push(StatCard {
            label: "Unassigned",
            value: unassigned,
            href: "/devices?assigned=unassigned",
            alarm: false,
        });
        let expiring = assets
            .count_assets(&scope_filter(AssetFilter {
                warranty_before: Some(Utc::now().date_naive() + chrono::Duration::days(90)),
                ..Default::default()
            }))
            .await
            .unwrap_or(0);
        stats.push(StatCard {
            label: "Warranty ends within 90 days",
            value: expiring,
            href: "/devices/reports",
            alarm: expiring > 0,
        });
    }
    if let Some(custody) = &state.custody {
        let open = custody.list_open_custody().await.unwrap_or_default();
        let now = Utc::now();
        let overdue = open
            .iter()
            .filter(|c| c.due_at.is_some_and(|d| d < now))
            .count() as i64;
        stats.push(StatCard {
            label: "Devices out",
            value: open.len() as i64,
            href: "/devices/circulation",
            alarm: false,
        });
        stats.push(StatCard {
            label: "Overdue",
            value: overdue,
            href: "/devices/circulation",
            alarm: overdue > 0,
        });
    }
    if let Some(items) = &state.items {
        let mut low = 0i64;
        for item in items.list_all_items().await.unwrap_or_default() {
            let issued = items.issued_quantity(&item.id).await.unwrap_or(0);
            let consumed = items.repair_consumed_quantity(&item.id).await.unwrap_or(0);
            if item
                .low_stock_threshold
                .is_some_and(|t| item.quantity_total - issued - consumed <= t)
            {
                low += 1;
            }
        }
        stats.push(StatCard {
            label: "Items low on stock",
            value: low,
            href: "/items",
            alarm: low > 0,
        });
    }

    let mut widgets = Vec::new();
    if let Some(reports) = &state.asset_reports {
        for report in reports.list_asset_reports().await.unwrap_or_default() {
            let q: crate::devices::DevicesQuery =
                serde_urlencoded::from_str(&report.query).unwrap_or_default();
            let filter = scope_filter(q.to_asset_filter());
            let buckets = reports
                .count_assets_by_dimension(&filter, report.group_by)
                .await
                .unwrap_or_default();
            let max = buckets.iter().map(|b| b.count).max().unwrap_or(0).max(1);
            let total = buckets.iter().map(|b| b.count).sum();
            widgets.push(Widget {
                name: report.name.clone(),
                total,
                rows: buckets
                    .iter()
                    .map(|b| WidgetRow {
                        label: b.group_value.clone().unwrap_or_else(|| "—".to_string()),
                        count: b.count,
                        pct: b.count * 100 / max,
                    })
                    .collect(),
            });
        }
    }
    DashboardData { stats, widgets }
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/dashboard.html")]
pub struct DashboardTemplate {
    pub nav: crate::nav::Nav,
    pub stats: Vec<StatCard>,
    pub widgets: Vec<Widget>,
    /// False on the tokened share: no nav links, no manage forms.
    pub console: bool,
    pub shares: Vec<String>,
    pub public_base: String,
    pub csrf_token: String,
}

/// `GET /devices/dashboard`
pub async fn dashboard_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    axum::Extension(principal): axum::Extension<crate::authz::Principal>,
) -> Response {
    let data = collect(&state, Some(&principal)).await;
    let shares = match &state.dashboard_shares {
        Some(s) => s.list_dashboard_shares().await.unwrap_or_default(),
        None => Vec::new(),
    };
    DashboardTemplate {
        nav: crate::nav::Nav::new(&state.config, "devices"),
        stats: data.stats,
        widgets: data.widgets,
        console: true,
        shares,
        public_base: state.config.chalk.public_url.clone().unwrap_or_default(),
        csrf_token: csrf.0,
    }
    .into_response()
}

/// `POST /devices/dashboard/share` — mint a link.
pub async fn create_share(State(state): State<Arc<AppState>>) -> Response {
    let Some(shares) = state.dashboard_shares.clone() else {
        return Redirect::to(DASHBOARD_PATH).into_response();
    };
    let token = crate::csrf::generate_csrf_token();
    if let Err(e) = shares.create_dashboard_share(&token).await {
        tracing::error!("create_dashboard_share failed: {e}");
    }
    Redirect::to(DASHBOARD_PATH).into_response()
}

/// `POST /devices/dashboard/share/{token}/revoke`
pub async fn revoke_share(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    if let Some(shares) = state.dashboard_shares.clone() {
        let _ = shares.revoke_dashboard_share(&token).await;
    }
    Redirect::to(DASHBOARD_PATH).into_response()
}

/// `GET /share/dashboard/{token}` — the read-only view, no session.
pub async fn shared_dashboard(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    let Some(shares) = state.dashboard_shares.clone() else {
        return not_found();
    };
    match shares.dashboard_share_exists(&token).await {
        Ok(true) => {}
        _ => return not_found(),
    }
    let data = collect(&state, None).await;
    SharedDashboardTemplate {
        stats: data.stats,
        widgets: data.widgets,
    }
    .into_response()
}

/// The tokened view: a standalone document with no console chrome at all.
#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/dashboard_shared.html")]
pub struct SharedDashboardTemplate {
    pub stats: Vec<StatCard>,
    pub widgets: Vec<Widget>,
}

/// The same numbers as plain text, for the scheduled digest email.
pub fn digest_text(data: &DashboardData) -> String {
    let mut out = String::from("Chalk fleet digest\n\n");
    for s in &data.stats {
        out.push_str(&format!("{}: {}\n", s.label, s.value));
    }
    for w in &data.widgets {
        out.push_str(&format!("\n{} ({} devices)\n", w.name, w.total));
        for r in &w.rows {
            out.push_str(&format!("  {}: {}\n", r.label, r.count));
        }
    }
    out
}

/// Send the digest to `[chalk] alerts_email`, when both it and a mailer are
/// configured. `chalk serve` calls this once a day when
/// `[chalk] daily_digest = true`; it is also the "email it now" button.
pub async fn send_digest(state: &Arc<AppState>) -> bool {
    let (Some(mailer), Some(to)) = (
        state.mailer.clone(),
        state.config.chalk.alerts_email.clone(),
    ) else {
        return false;
    };
    let data = collect(state, None).await;
    mailer
        .send_email(&chalk_core::mail::EmailMessage::new(
            &to,
            "Chalk fleet digest",
            digest_text(&data),
        ))
        .await
        .is_ok()
}

/// `POST /devices/dashboard/email` — the send-now button.
pub async fn email_now(State(state): State<Arc<AppState>>) -> Response {
    let sent = send_digest(&state).await;
    let notice = if sent { "digest_sent" } else { "digest_failed" };
    Redirect::to(&format!("{DASHBOARD_PATH}?notice={notice}")).into_response()
}

fn not_found() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>No such dashboard.</h1>".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
