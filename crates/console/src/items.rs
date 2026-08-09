//! Quantity item classes (SS-4): the counted stuff beside the serialized
//! devices — chargers, hotspots, styluses. Accessories come back;
//! consumables are consumed at issue and the holding is the ledger.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::models::console_user::Actor;
use chalk_core::models::item::{Item, ItemHolding, ItemType};
use chrono::Utc;
use serde::Deserialize;

use crate::AppState;

pub const ITEMS_PATH: &str = "/items";

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

pub struct ItemRow {
    pub id: String,
    pub name: String,
    pub kind: &'static str,
    pub total: i64,
    pub issued: i64,
    pub available: i64,
    /// At or under the item's alert threshold (GP-4).
    pub low: bool,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "items/index.html")]
pub struct ItemsTemplate {
    pub nav: crate::nav::Nav,
    pub rows: Vec<ItemRow>,
    pub notice: String,
    pub csrf_token: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ItemsNoticeQuery {
    pub notice: String,
}

fn notice_message(notice: &str) -> String {
    match notice {
        "created" => "Item added.".into(),
        "issued" => "Issued.".into(),
        "returned" => "Returned to stock.".into(),
        "adjusted" => "Stock adjusted.".into(),
        "deleted" => "Item removed.".into(),
        "no_user" => "No roster user matches that id or email.".into(),
        "not_enough" => "Not that many available.".into(),
        "bad_input" => "Check the form — something did not parse.".into(),
        "failed" => "That did not work — try again.".into(),
        _ => String::new(),
    }
}

/// `GET /items`
pub async fn items_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    axum::extract::Query(q): axum::extract::Query<ItemsNoticeQuery>,
) -> Response {
    let Some(items) = state.items.clone() else {
        return not_configured();
    };
    let all = items.list_all_items().await.unwrap_or_default();
    let mut rows = Vec::with_capacity(all.len());
    for i in &all {
        let issued = items.issued_quantity(&i.id).await.unwrap_or(0);
        // Repair consumption reduces availability just like an issue does —
        // a hinge in a Chromebook is not on the shelf (GP-4).
        let consumed = items.repair_consumed_quantity(&i.id).await.unwrap_or(0);
        let available = i.quantity_total - issued - consumed;
        rows.push(ItemRow {
            id: i.id.clone(),
            name: i.name.clone(),
            kind: i.item_type.as_str(),
            total: i.quantity_total,
            issued: issued + consumed,
            available,
            low: i.low_stock_threshold.is_some_and(|t| available <= t),
        });
    }
    ItemsTemplate {
        nav: crate::nav::Nav::new(&state.config, "devices"),
        rows,
        notice: notice_message(&q.notice),
        csrf_token: csrf.0,
    }
    .into_response()
}

// ---------------------------------------------------------------------------
// Create / adjust / delete
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewItemForm {
    pub name: String,
    pub item_type: String,
    pub quantity: String,
    pub notes: String,
    pub unit_cost: String,
    pub low_stock: String,
}

/// `POST /items` — add a stock line.
pub async fn create_item(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<NewItemForm>,
) -> Response {
    let Some(items) = state.items.clone() else {
        return back("failed");
    };
    let name = form.name.trim();
    let Some(item_type) = ItemType::parse(form.item_type.trim()) else {
        return back("bad_input");
    };
    let Ok(quantity) = form.quantity.trim().parse::<i64>() else {
        return back("bad_input");
    };
    if name.is_empty() || quantity < 0 {
        return back("bad_input");
    }
    let now = Utc::now();
    let item = Item {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        item_type,
        notes: {
            let n = form.notes.trim();
            (!n.is_empty()).then(|| n.to_string())
        },
        quantity_total: quantity,
        school_org_sourced_id: None,
        unit_cost_cents: crate::fees::parse_dollars_to_cents(&form.unit_cost).filter(|c| *c > 0),
        low_stock_threshold: form.low_stock.trim().parse::<i64>().ok().filter(|t| *t > 0),
        created_at: now,
        updated_at: now,
    };
    match items.create_item(&item).await {
        Ok(()) => back("created"),
        Err(e) => {
            tracing::error!("could not create an item: {e}");
            back("failed")
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AdjustForm {
    pub quantity: String,
}

/// `POST /items/{id}/adjust` — set the total stock. Refuses a total below
/// what is currently issued: stock in students' hands cannot be adjusted
/// away on paper.
pub async fn adjust_item(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<AdjustForm>,
) -> Response {
    let Some(items) = state.items.clone() else {
        return detail_back(&id, "failed");
    };
    let Ok(quantity) = form.quantity.trim().parse::<i64>() else {
        return detail_back(&id, "bad_input");
    };
    let Ok(Some(mut item)) = items.get_item(&id).await else {
        return back("failed");
    };
    let issued = items.issued_quantity(&id).await.unwrap_or(0);
    let consumed = items.repair_consumed_quantity(&id).await.unwrap_or(0);
    if quantity < issued + consumed {
        return detail_back(&id, "not_enough");
    }
    item.quantity_total = quantity;
    match items.update_item(&item).await {
        Ok(_) => detail_back(&id, "adjusted"),
        Err(e) => {
            tracing::error!("could not adjust an item: {e}");
            detail_back(&id, "failed")
        }
    }
}

/// `POST /items/{id}/delete` — refuse while stock is out.
pub async fn delete_item(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some(items) = state.items.clone() else {
        return back("failed");
    };
    if items.issued_quantity(&id).await.unwrap_or(0) > 0 {
        return detail_back(&id, "not_enough");
    }
    match items.delete_item(&id).await {
        Ok(true) => back("deleted"),
        _ => back("failed"),
    }
}

// ---------------------------------------------------------------------------
// Detail + issue + return
// ---------------------------------------------------------------------------

pub struct HoldingRow {
    pub id: String,
    pub holder: String,
    pub quantity: i64,
    pub issued: String,
    pub open: bool,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "items/detail.html")]
pub struct ItemDetailTemplate {
    pub nav: crate::nav::Nav,
    pub id: String,
    pub name: String,
    pub kind: &'static str,
    pub is_accessory: bool,
    pub notes: String,
    pub total: i64,
    pub issued: i64,
    pub available: i64,
    pub holdings: Vec<HoldingRow>,
    pub notice: String,
    pub csrf_token: String,
}

/// `GET /items/{id}`
pub async fn item_detail(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<ItemsNoticeQuery>,
) -> Response {
    let Some(items) = state.items.clone() else {
        return not_configured();
    };
    let Ok(Some(item)) = items.get_item(&id).await else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Html("<h1>No such item.</h1>".to_string()),
        )
            .into_response();
    };
    let issued = items.issued_quantity(&id).await.unwrap_or(0);
    let consumed = items.repair_consumed_quantity(&id).await.unwrap_or(0);
    let all = items.list_holdings_for_item(&id).await.unwrap_or_default();
    let mut holdings = Vec::with_capacity(all.len());
    for h in &all {
        let holder = match state.repo.get_user(&h.user_sourced_id).await {
            Ok(Some(u)) => format!("{}, {}", u.family_name, u.given_name),
            _ => h.user_sourced_id.clone(),
        };
        holdings.push(HoldingRow {
            id: h.id.clone(),
            holder,
            quantity: h.quantity,
            issued: h.issued_at.format("%Y-%m-%d").to_string(),
            open: h.open(),
        });
    }
    ItemDetailTemplate {
        nav: crate::nav::Nav::new(&state.config, "devices"),
        id: item.id.clone(),
        name: item.name.clone(),
        kind: item.item_type.as_str(),
        is_accessory: item.item_type == ItemType::Accessory,
        notes: item.notes.clone().unwrap_or_default(),
        total: item.quantity_total,
        issued: issued + consumed,
        available: item.quantity_total - issued - consumed,
        holdings,
        notice: notice_message(&q.notice),
        csrf_token: csrf.0,
    }
    .into_response()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IssueForm {
    /// Roster sourced_id or exact email.
    pub user: String,
    pub quantity: String,
}

/// `POST /items/{id}/issue`
pub async fn issue_item(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Extension(actor): axum::Extension<Actor>,
    axum::Form(form): axum::Form<IssueForm>,
) -> Response {
    let Some(items) = state.items.clone() else {
        return detail_back(&id, "failed");
    };
    let Ok(Some(item)) = items.get_item(&id).await else {
        return back("failed");
    };
    let Ok(quantity) = form.quantity.trim().parse::<i64>() else {
        return detail_back(&id, "bad_input");
    };
    if quantity < 1 {
        return detail_back(&id, "bad_input");
    }
    // The availability gate, said in words before it is enforced in numbers:
    // stock that is out is not stock you can hand out again.
    let issued = items.issued_quantity(&id).await.unwrap_or(0);
    let consumed = items.repair_consumed_quantity(&id).await.unwrap_or(0);
    if quantity > item.quantity_total - issued - consumed {
        return detail_back(&id, "not_enough");
    }
    let Some(user) = crate::custody::resolve_user(&state, &form.user).await else {
        return detail_back(&id, "no_user");
    };
    let holding = ItemHolding {
        id: uuid::Uuid::new_v4().to_string(),
        item_id: id.clone(),
        user_sourced_id: user.sourced_id.clone(),
        quantity,
        issued_at: Utc::now(),
        returned_at: None,
        actor: actor.audit_actor(),
    };
    match items.create_holding(&holding).await {
        Ok(()) => detail_back(&id, "issued"),
        Err(e) => {
            tracing::error!("could not issue an item: {e}");
            detail_back(&id, "failed")
        }
    }
}

/// `POST /items/{id}/holdings/{holding_id}/return` — accessories only; a
/// consumable's holding is the permanent record of consumption.
pub async fn return_item(
    State(state): State<Arc<AppState>>,
    Path((id, holding_id)): Path<(String, String)>,
) -> Response {
    let Some(items) = state.items.clone() else {
        return detail_back(&id, "failed");
    };
    let Ok(Some(item)) = items.get_item(&id).await else {
        return back("failed");
    };
    if item.item_type != ItemType::Accessory {
        return detail_back(&id, "failed");
    }
    match items.return_holding(&holding_id).await {
        Ok(true) => detail_back(&id, "returned"),
        _ => detail_back(&id, "failed"),
    }
}

fn back(notice: &str) -> Response {
    Redirect::to(&format!("{ITEMS_PATH}?notice={notice}")).into_response()
}

fn detail_back(id: &str, notice: &str) -> Response {
    Redirect::to(&format!("{ITEMS_PATH}/{id}?notice={notice}")).into_response()
}

fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Items are not available here.</h1>".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
