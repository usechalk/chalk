//! Help-desk ticket REST API.
//!
//! # Read-only, on purpose
//!
//! Like the device API, there are no write endpoints. A ticket's lifecycle —
//! assign, reply, resolve — is a console flow with attribution and a disclosure
//! boundary (an internal note must never reach a requester), and a bare
//! `POST /tickets/{id}/comment` would step around the identity the console
//! attaches. Read access covers the case districts actually ask for: feeding a
//! reporting dashboard or a data warehouse. Writes, if wanted, are their own
//! design.
//!
//! # Scope is applied in SQL, not to the rows afterwards
//!
//! A scoped token's schools go into the query through [`TicketScope`], exactly
//! as the device API pushes them into the asset filter — so the `X-Total-Count`
//! this endpoint reports is computed only over rows the caller may read, and
//! never leaks the size of the part of the help desk they were denied.
//!
//! # Internal notes are included
//!
//! The comment endpoint returns internal notes with their `isInternal` flag
//! intact. The disclosure rule is that a note must not reach a *requester*; an
//! API token is the district's own, held by IT, so withholding its own notes
//! from its own integration would be theatre, not privacy.

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

use chalk_core::models::page::{PageRequest, SortDirection};
use chalk_core::models::ticket::{
    TicketFilter, TicketPriority, TicketScope, TicketSort, TicketStatus,
};
use chalk_core::models::token_scope::{OneRosterResource, TokenScope};

use crate::auth::ScopeContext;
use crate::AppState;

/// Mounted under `/api/helpdesk/v1` by the parent router.
pub fn tickets_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/tickets", get(list_tickets))
        .route("/tickets/{id}", get(get_ticket))
        .route("/tickets/{id}/comments", get(list_ticket_comments))
}

const DEFAULT_LIMIT: i64 = 100;

/// Matches the device and OneRoster APIs' ceiling, so a client that already
/// talks to one Chalk API need not learn a second limit.
const MAX_LIMIT: i64 = 1000;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TicketQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    status: Option<String>,
    priority: Option<String>,
    school: Option<String>,
    /// A technician's console_user id — the assignee namespace.
    assignee: Option<String>,
    /// `"true"` narrows to tickets no technician has claimed.
    unassigned: Option<String>,
    /// Case-insensitive substring over subject and body.
    q: Option<String>,
}

impl TicketQuery {
    fn page(&self) -> PageRequest {
        PageRequest::new(
            self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT),
            self.offset.unwrap_or(0).max(0),
        )
    }

    /// The caller's own filters. Scope is applied separately, through
    /// [`TicketScope`], so it can only ever remove rows.
    fn to_filter(&self) -> TicketFilter {
        TicketFilter {
            status: self
                .status
                .as_deref()
                .and_then(|v| TicketStatus::parse(v).ok()),
            priority: self
                .priority
                .as_deref()
                .and_then(|v| TicketPriority::parse(v).ok()),
            school_org_sourced_id: self.school.clone().filter(|v| !v.is_empty()),
            assignee_console_user_id: self.assignee.clone().filter(|v| !v.is_empty()),
            unassigned: matches!(self.unassigned.as_deref(), Some("true")).then_some(true),
            search: self.q.clone().filter(|v| !v.is_empty()),
            sort: TicketSort::Number,
            direction: SortDirection::Desc,
            ..Default::default()
        }
    }
}

/// The read scope for this request. A token granted specific schools sees only
/// those; an unscoped token (or none) sees the whole help desk.
fn ticket_scope(scope: Option<&TokenScope>) -> TicketScope {
    match scope.map(|s| &s.orgs).filter(|o| !o.is_empty()) {
        Some(orgs) => TicketScope::Schools(orgs.clone()),
        None => TicketScope::Unrestricted,
    }
}

/// True when the scope permits a ticket in this school. Used for single-ticket
/// fetches, where there is no list query to push the boundary into.
fn scope_allows_school(scope: Option<&TokenScope>, school: Option<&str>) -> bool {
    let Some(scope) = scope else { return true };
    if scope.orgs.is_empty() {
        return true;
    }
    // A ticket with no school is visible only to an unscoped token: a scoped
    // token was granted *specific* schools, and "belongs to none of them" is
    // not one of them.
    school.is_some_and(|s| scope.orgs.iter().any(|o| o == s))
}

fn resolve_scope(ext: Option<Extension<ScopeContext>>) -> Option<TokenScope> {
    ext.and_then(|Extension(ScopeContext(scope))| scope)
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": "token scope does not permit access to 'tickets'"})),
    )
        .into_response()
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "no such ticket"})),
    )
        .into_response()
}

fn not_enabled() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "the help desk module is not enabled"})),
    )
        .into_response()
}

fn server_error(e: impl std::fmt::Display) -> Response {
    tracing::error!("ticket API: {e}");
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

fn scope_denies_tickets(scope: Option<&TokenScope>) -> bool {
    scope.is_some_and(|s| !s.allows_resource(OneRosterResource::Tickets))
}

/// `GET /api/helpdesk/v1/tickets`
async fn list_tickets(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TicketQuery>,
    scope_ext: Option<Extension<ScopeContext>>,
) -> Response {
    let Some(tickets) = state.tickets.clone() else {
        return not_enabled();
    };
    let scope = resolve_scope(scope_ext);
    if scope_denies_tickets(scope.as_ref()) {
        return forbidden();
    }

    let filter = query.to_filter();
    let ticket_scope = ticket_scope(scope.as_ref());
    match tickets
        .list_tickets(&filter, &ticket_scope, query.page())
        .await
    {
        Ok(page) => (
            total_header(page.total),
            Json(json!({ "tickets": page.items })),
        )
            .into_response(),
        Err(e) => server_error(e),
    }
}

/// `GET /api/helpdesk/v1/tickets/{id}`
async fn get_ticket(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    scope_ext: Option<Extension<ScopeContext>>,
) -> Response {
    let Some(tickets) = state.tickets.clone() else {
        return not_enabled();
    };
    let scope = resolve_scope(scope_ext);
    if scope_denies_tickets(scope.as_ref()) {
        return forbidden();
    }

    match tickets.get_ticket(&id).await {
        Ok(Some(ticket)) => {
            // 404, not 403: a token that may not see this school should not be
            // able to learn the ticket exists from the shape of the refusal.
            if !scope_allows_school(scope.as_ref(), ticket.school_org_sourced_id.as_deref()) {
                return not_found();
            }
            Json(json!({ "ticket": ticket })).into_response()
        }
        Ok(None) => not_found(),
        Err(e) => server_error(e),
    }
}

/// `GET /api/helpdesk/v1/tickets/{id}/comments`
///
/// The full thread for one ticket, internal notes included (see the module
/// note). The ticket is fetched first so its school can be checked — listing a
/// thread for a ticket the token cannot see would leak both its existence and
/// its contents through a route that never mentions a school.
async fn list_ticket_comments(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    scope_ext: Option<Extension<ScopeContext>>,
) -> Response {
    let Some(tickets) = state.tickets.clone() else {
        return not_enabled();
    };
    let scope = resolve_scope(scope_ext);
    if scope_denies_tickets(scope.as_ref()) {
        return forbidden();
    }

    match tickets.get_ticket(&id).await {
        Ok(Some(ticket)) => {
            if !scope_allows_school(scope.as_ref(), ticket.school_org_sourced_id.as_deref()) {
                return not_found();
            }
        }
        Ok(None) => return not_found(),
        Err(e) => return server_error(e),
    }

    match tickets.list_comments(&id, true).await {
        Ok(comments) => Json(json!({ "comments": comments })).into_response(),
        Err(e) => server_error(e),
    }
}

#[cfg(test)]
mod tests;
