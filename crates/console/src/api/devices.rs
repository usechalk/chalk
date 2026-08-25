//! Device inventory REST API.
//!
//! # Read-only, on purpose
//!
//! There are no write endpoints and that is a design decision, not an
//! omission. Every fleet change in Chalk goes through plan → preview → commit,
//! and the preview is the property that makes acting on "all 400 devices
//! matching this filter" defensible. A `POST /devices/{id}/move` would step
//! around it. If API writes are wanted later they compile to a change set like
//! everything else, and that is its own design with its own review.
//!
//! # Scope is applied in SQL, not to the rows afterwards
//!
//! `api/oneroster.rs` filters scoped rows in Rust after fetching them, because
//! its repository methods return whole collections. The asset repository takes
//! a filter and a page, so here the token's schools go **into the query**.
//!
//! That matters for more than speed. Filtering after the fact means the
//! database returned rows the caller may not read, and — worse — the total
//! this endpoint reports would be computed over rows they cannot see, so
//! `X-Total-Count` would leak the size of the part of the fleet they were
//! denied.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use chalk_core::models::asset::{
    AssetEventFilter, AssetFilter, AssetSort, AssetStatus, AssetType, MatchState,
};
use chalk_core::models::page::{PageRequest, SortDirection};
use chalk_core::models::token_scope::{OneRosterResource, TokenScope};

use crate::auth::ScopeContext;
use crate::AppState;

/// Mounted under `/api/devices/v1` by the parent router.
pub fn devices_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/devices", get(list_devices))
        .route("/devices/{id}", get(get_device))
        .route("/devices/{id}/events", get(list_device_events))
}

const DEFAULT_LIMIT: i64 = 100;

/// Matches the OneRoster API's ceiling, for one reason: a client that already
/// talks to `/api/oneroster` should not have to learn a second limit.
const MAX_LIMIT: i64 = 1000;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DeviceQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    status: Option<String>,
    asset_type: Option<String>,
    school: Option<String>,
    match_state: Option<String>,
    /// Case-insensitive substring over asset tag, serial and the annotated
    /// fields — the same search the console offers.
    q: Option<String>,
}

impl DeviceQuery {
    fn page(&self) -> PageRequest {
        PageRequest::new(
            self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT),
            self.offset.unwrap_or(0).max(0),
        )
    }

    /// Build the repository filter, then narrow it by the token's scope.
    ///
    /// Narrowing happens **after** the caller's own filters are applied and can
    /// only ever remove rows: a token scoped to three schools that asks for a
    /// fourth gets nothing, not the fourth.
    fn to_filter(&self, scope: Option<&TokenScope>) -> AssetFilter {
        let mut filter = AssetFilter {
            status: self
                .status
                .as_deref()
                .and_then(|v| AssetStatus::parse(v).ok()),
            asset_type: self
                .asset_type
                .as_deref()
                .and_then(|v| AssetType::parse(v).ok()),
            match_state: self
                .match_state
                .as_deref()
                .and_then(|v| MatchState::parse(v).ok()),
            school_org_sourced_id: self.school.clone().filter(|v| !v.is_empty()),
            search: self.q.clone().filter(|v| !v.is_empty()),
            sort: AssetSort::AssetTag,
            direction: SortDirection::Asc,
            ..Default::default()
        };
        if let Some(orgs) = scope.map(|s| &s.orgs).filter(|o| !o.is_empty()) {
            filter.school_org_sourced_ids = orgs.clone();
        }
        filter
    }
}

/// True when the scope permits this school. Used for single-resource fetches,
/// where there is no query to push the boundary into.
fn scope_allows_school(scope: Option<&TokenScope>, school: Option<&str>) -> bool {
    let Some(scope) = scope else { return true };
    if scope.orgs.is_empty() {
        return true;
    }
    // A device with no school is visible only to an unscoped token. A scoped
    // token was granted *specific* schools, and "belongs to none of them" is
    // not one of them — silently showing it would widen the grant.
    school.is_some_and(|s| scope.orgs.iter().any(|o| o == s))
}

fn resolve_scope(ext: Option<Extension<ScopeContext>>) -> Option<TokenScope> {
    ext.and_then(|Extension(ScopeContext(scope))| scope)
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": "token scope does not permit access to 'devices'"})),
    )
        .into_response()
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "no such device"})),
    )
        .into_response()
}

fn not_enabled() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "the devices module is not enabled"})),
    )
        .into_response()
}

fn server_error(e: impl std::fmt::Display) -> Response {
    tracing::error!("device API: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "internal error"})),
    )
        .into_response()
}

fn total_header(total: i64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&total.to_string()) {
        headers.insert(HeaderName::from_static("x-total-count"), v);
    }
    headers
}

/// `GET /api/devices/v1/devices`
async fn list_devices(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DeviceQuery>,
    scope_ext: Option<Extension<ScopeContext>>,
) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_enabled();
    };
    let scope = resolve_scope(scope_ext);
    if scope
        .as_ref()
        .is_some_and(|s| !s.allows_resource(OneRosterResource::Devices))
    {
        return forbidden();
    }

    let filter = query.to_filter(scope.as_ref());
    match assets.list_assets(&filter, query.page()).await {
        Ok(page) => (
            total_header(page.total),
            Json(json!({ "devices": page.items })),
        )
            .into_response(),
        Err(e) => server_error(e),
    }
}

/// `GET /api/devices/v1/devices/{id}`
async fn get_device(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    scope_ext: Option<Extension<ScopeContext>>,
) -> Response {
    let Some(assets) = state.assets.clone() else {
        return not_enabled();
    };
    let scope = resolve_scope(scope_ext);
    if scope
        .as_ref()
        .is_some_and(|s| !s.allows_resource(OneRosterResource::Devices))
    {
        return forbidden();
    }

    match assets.get_asset(&id).await {
        Ok(Some(asset)) => {
            // 404, not 403. A token that may not see this school should not be
            // able to learn that the device exists by the shape of the refusal.
            if !scope_allows_school(scope.as_ref(), asset.school_org_sourced_id.as_deref()) {
                return not_found();
            }
            Json(json!({ "device": asset })).into_response()
        }
        Ok(None) => not_found(),
        Err(e) => server_error(e),
    }
}

/// `GET /api/devices/v1/devices/{id}/events`
///
/// The audit trail for one device. Offered because the history *is* the
/// product feature — a district evaluating Chalk against a spreadsheet is
/// buying the record of who changed what.
async fn list_device_events(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<DeviceQuery>,
    scope_ext: Option<Extension<ScopeContext>>,
) -> Response {
    let (Some(assets), Some(events)) = (state.assets.clone(), state.asset_events.clone()) else {
        return not_enabled();
    };
    let scope = resolve_scope(scope_ext);
    if scope
        .as_ref()
        .is_some_and(|s| !s.allows_resource(OneRosterResource::Devices))
    {
        return forbidden();
    }

    // The device is fetched first so its school can be checked. Listing events
    // for a device the token cannot see would leak both its existence and its
    // history through a route that never mentions a school.
    match assets.get_asset(&id).await {
        Ok(Some(asset)) => {
            if !scope_allows_school(scope.as_ref(), asset.school_org_sourced_id.as_deref()) {
                return not_found();
            }
        }
        Ok(None) => return not_found(),
        Err(e) => return server_error(e),
    }

    let filter = AssetEventFilter {
        asset_id: Some(id),
        ..Default::default()
    };
    match events.list_events(&filter, query.page()).await {
        Ok(page) => (
            total_header(page.total),
            Json(json!({ "events": page.items })),
        )
            .into_response(),
        Err(e) => server_error(e),
    }
}

#[cfg(test)]
mod tests;
