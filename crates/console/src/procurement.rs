//! Procurement surfaces (GP-3): purchase orders and the managed
//! funding-source list.
//!
//! Receiving against a PO deliberately reuses the CSV import diff preview —
//! the PO page links to `/devices/import` rather than growing a second
//! import pipeline. "Received" on this page means "assets whose po_number
//! matches", counted by the repository join.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::models::procurement::{FundingSource, PurchaseOrder};
use chrono::{NaiveDate, Utc};
use serde::Deserialize;

use crate::AppState;

pub const PURCHASE_ORDERS_PATH: &str = "/devices/purchase-orders";
pub const FUNDING_SOURCES_PATH: &str = "/settings/funding-sources";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NoticeQuery {
    pub notice: String,
}

fn notice_message(notice: &str) -> String {
    match notice {
        "created" => "Saved.".into(),
        "deleted" => "Deleted.".into(),
        "in_use" => "Devices still reference that, so it cannot be deleted.".into(),
        "duplicate" => "That already exists.".into(),
        "bad_input" => "Give it a name.".into(),
        "failed" => "That did not work — try again.".into(),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Purchase orders
// ---------------------------------------------------------------------------

pub struct PoRow {
    pub id: String,
    pub po_number: String,
    pub vendor: String,
    pub funding_source: String,
    pub po_date: String,
    pub notes: String,
    pub asset_count: i64,
    /// The filtered inventory of devices received against this PO.
    pub inventory_href: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "devices/purchase_orders.html")]
pub struct PurchaseOrdersTemplate {
    pub nav: crate::nav::Nav,
    pub rows: Vec<PoRow>,
    pub funding_options: Vec<String>,
    pub notice: String,
    pub csrf_token: String,
}

/// `GET /devices/purchase-orders`
pub async fn po_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Query(q): Query<NoticeQuery>,
) -> Response {
    let Some(store) = state.procurement.clone() else {
        return not_configured();
    };
    let rows = store
        .list_purchase_orders()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| PoRow {
            inventory_href: format!("/devices?q={}", urlencoding::encode(&r.po.po_number)),
            id: r.po.id,
            po_number: r.po.po_number,
            vendor: r.po.vendor.unwrap_or_default(),
            funding_source: r.po.funding_source.unwrap_or_default(),
            po_date: r.po.po_date.map(|d| d.to_string()).unwrap_or_default(),
            notes: r.po.notes,
            asset_count: r.asset_count,
        })
        .collect();
    let funding_options = store
        .list_funding_sources()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|f| f.name)
        .collect();
    PurchaseOrdersTemplate {
        nav: crate::nav::Nav::new(&state.config, "devices"),
        rows,
        funding_options,
        notice: notice_message(&q.notice),
        csrf_token: csrf.0,
    }
    .into_response()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewPoForm {
    pub po_number: String,
    pub vendor: String,
    pub funding_source: String,
    pub po_date: String,
    pub notes: String,
}

/// `POST /devices/purchase-orders`
pub async fn create_po(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<NewPoForm>,
) -> Response {
    let Some(store) = state.procurement.clone() else {
        return back_po("failed");
    };
    let po_number = form.po_number.trim();
    if po_number.is_empty() {
        return back_po("bad_input");
    }
    let opt = |s: &str| {
        let t = s.trim();
        (!t.is_empty()).then(|| t.to_string())
    };
    let po = PurchaseOrder {
        id: uuid::Uuid::new_v4().to_string(),
        po_number: po_number.to_string(),
        vendor: opt(&form.vendor),
        funding_source: opt(&form.funding_source),
        po_date: NaiveDate::parse_from_str(form.po_date.trim(), "%Y-%m-%d").ok(),
        notes: form.notes.trim().to_string(),
        created_at: Utc::now(),
    };
    match store.create_purchase_order(&po).await {
        Ok(()) => back_po("created"),
        // The UNIQUE constraint on po_number is the realistic failure; say
        // that rather than a generic shrug.
        Err(_) => back_po("duplicate"),
    }
}

/// `POST /devices/purchase-orders/{id}/delete`
pub async fn delete_po(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some(store) = state.procurement.clone() else {
        return back_po("failed");
    };
    match store.delete_purchase_order(&id).await {
        Ok(true) => back_po("deleted"),
        Ok(false) => back_po("in_use"),
        Err(e) => {
            tracing::error!("delete_purchase_order failed: {e}");
            back_po("failed")
        }
    }
}

// ---------------------------------------------------------------------------
// Funding sources
// ---------------------------------------------------------------------------

pub struct SourceRow {
    pub id: String,
    pub name: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "settings/funding_sources.html")]
pub struct FundingSourcesTemplate {
    pub nav: crate::nav::Nav,
    pub rows: Vec<SourceRow>,
    pub notice: String,
    pub csrf_token: String,
}

/// `GET /settings/funding-sources`
pub async fn sources_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Query(q): Query<NoticeQuery>,
) -> Response {
    let Some(store) = state.procurement.clone() else {
        return not_configured();
    };
    let rows = store
        .list_funding_sources()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|f| SourceRow {
            id: f.id,
            name: f.name,
        })
        .collect();
    FundingSourcesTemplate {
        nav: crate::nav::Nav::new(&state.config, "settings"),
        rows,
        notice: notice_message(&q.notice),
        csrf_token: csrf.0,
    }
    .into_response()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewSourceForm {
    pub name: String,
}

/// `POST /settings/funding-sources`
pub async fn create_source(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<NewSourceForm>,
) -> Response {
    let Some(store) = state.procurement.clone() else {
        return back_fs("failed");
    };
    let name = form.name.trim();
    if name.is_empty() {
        return back_fs("bad_input");
    }
    let source = FundingSource {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        created_at: Utc::now(),
    };
    match store.create_funding_source(&source).await {
        Ok(()) => back_fs("created"),
        Err(_) => back_fs("duplicate"),
    }
}

/// `POST /settings/funding-sources/{id}/delete`
pub async fn delete_source(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some(store) = state.procurement.clone() else {
        return back_fs("failed");
    };
    match store.delete_funding_source(&id).await {
        Ok(true) => back_fs("deleted"),
        Ok(false) => back_fs("in_use"),
        Err(e) => {
            tracing::error!("delete_funding_source failed: {e}");
            back_fs("failed")
        }
    }
}

fn back_po(notice: &str) -> Response {
    Redirect::to(&format!("{PURCHASE_ORDERS_PATH}?notice={notice}")).into_response()
}

fn back_fs(notice: &str) -> Response {
    Redirect::to(&format!("{FUNDING_SOURCES_PATH}?notice={notice}")).into_response()
}

fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Procurement is not available here.</h1>".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
