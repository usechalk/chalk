//! OneRoster 1.1 REST API endpoints.
//!
//! Provides JSON API endpoints that wrap database queries in the standard
//! OneRoster JSON envelope format: `{ "<entityType>": [ ... ] }` for
//! collections and `{ "<entityType>": { ... } }` for single entities.
//!
//! ## Pagination
//!
//! All list endpoints accept `?limit=N&offset=N` per the OneRoster 1.1 spec
//! and emit `X-Total-Count` plus RFC 5988 `Link` headers (`rel="next"`,
//! `"prev"`, `"first"`, `"last"`). Defaults: `limit=100`, `offset=0`. Clever
//! / ClassLink and most third-party importers paginate by default; without
//! these headers they would silently re-ingest the full collection per page.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use chalk_core::error::ChalkError;
use chalk_core::models::sync::UserFilter;
use chalk_core::models::token_scope::{OneRosterResource, TokenScope};
use chalk_core::models::user::User;

use crate::auth::ScopeContext;
use crate::AppState;

/// Build the OneRoster API sub-router.
///
/// All routes are mounted under `/api/oneroster/v1p1` by the parent router.
pub fn oneroster_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/orgs", get(list_orgs))
        .route("/orgs/:id", get(get_org))
        .route("/academicSessions", get(list_academic_sessions))
        .route("/academicSessions/:id", get(get_academic_session))
        .route("/users", get(list_users))
        .route("/users/:id", get(get_user))
        .route("/courses", get(list_courses))
        .route("/courses/:id", get(get_course))
        .route("/classes", get(list_classes))
        .route("/classes/:id", get(get_class))
        .route("/enrollments", get(list_enrollments))
        .route("/enrollments/:id", get(get_enrollment))
        .route("/demographics", get(list_demographics))
        .route("/demographics/:id", get(get_demographics))
}

/// OneRoster 1.1 spec defaults — limit defaults to 100 with no documented
/// upper bound. We cap at 1000 so a misbehaving client can't ask the server
/// to JSON-serialize hundreds of thousands of rows in one response.
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

#[derive(Debug, Deserialize)]
struct Pagination {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

impl Pagination {
    fn resolved(&self) -> (usize, usize) {
        let limit = self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let offset = self.offset.unwrap_or(0);
        (limit, offset)
    }
}

fn envelope(key: &str, value: Value) -> Value {
    json!({ key: value })
}

fn not_found(entity_type: &str, id: &str) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": format!("{entity_type} with sourcedId '{id}' not found")
        })),
    )
}

/// Build the pagination response headers (`X-Total-Count` + RFC 5988 `Link`).
fn pagination_headers(total: usize, limit: usize, offset: usize, uri: &Uri) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-total-count"),
        HeaderValue::from_str(&total.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

    // Construct Link header relative to the path the client called. We
    // preserve their `?limit` if explicit; otherwise emit the default so
    // a client following Link headers gets stable URIs.
    let base = uri.path();
    let mut links: Vec<String> = Vec::with_capacity(4);
    let push = |links: &mut Vec<String>, off: usize, rel: &str| {
        links.push(format!(
            "<{base}?limit={limit}&offset={off}>; rel=\"{rel}\""
        ));
    };
    push(&mut links, 0, "first");
    if offset > 0 {
        let prev = offset.saturating_sub(limit);
        push(&mut links, prev, "prev");
    }
    if offset + limit < total {
        push(&mut links, offset + limit, "next");
    }
    // `last`: largest offset that still returns rows, rounded down to a
    // multiple of `limit`. For total=0 we still emit offset=0.
    let last_offset = if total == 0 {
        0
    } else {
        ((total.saturating_sub(1)) / limit) * limit
    };
    push(&mut links, last_offset, "last");

    if let Ok(v) = HeaderValue::from_str(&links.join(", ")) {
        headers.insert(axum::http::header::LINK, v);
    }
    headers
}

/// Slice a fully-materialized list by `(limit, offset)` and assemble the
/// paginated OneRoster response: `(StatusCode, Headers, Json envelope)`.
fn paginated<T: serde::Serialize>(
    key: &'static str,
    items: Vec<T>,
    pagination: &Pagination,
    uri: &Uri,
) -> impl IntoResponse {
    let (limit, offset) = pagination.resolved();
    let total = items.len();
    let page: Vec<&T> = items.iter().skip(offset).take(limit).collect();
    let value = serde_json::to_value(&page).unwrap_or(Value::Array(vec![]));
    let headers = pagination_headers(total, limit, offset, uri);
    (StatusCode::OK, headers, Json(envelope(key, value)))
}

// -- Scope enforcement helpers --
//
// Tokens minted by the hosted marketplace carry a `TokenScope` narrowing which
// rows/fields they may read. OSS tokens carry `None` (unrestricted). The
// bearer middleware stashes the scope as a `ScopeContext` extension; these
// helpers read it and apply the policy. Filtering happens here, post-query and
// pre-pagination, so a scoped token never sees an out-of-scope row.

/// Pull the optional scope out of the request extensions. An absent extension
/// (unit tests that skip the bearer middleware) or a `None` scope both mean
/// "unrestricted".
fn resolve_scope(ext: Option<Extension<ScopeContext>>) -> Option<TokenScope> {
    ext.and_then(|Extension(ScopeContext(scope))| scope)
}

/// `403 Forbidden` for a resource the token's scope denies outright.
fn forbidden(resource: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": format!("token scope does not permit access to '{resource}'")})),
    )
        .into_response()
}

fn server_error(e: impl std::fmt::Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": e.to_string()})),
    )
        .into_response()
}

/// `true` if the scope (when present) denies this resource.
fn resource_denied(scope: &Option<TokenScope>, resource: OneRosterResource) -> bool {
    scope.as_ref().is_some_and(|s| !s.allows_resource(resource))
}

/// Serialize each item to JSON, applying field redaction when a scope is
/// present. Used for the PII-bearing `users`/`demographics` collections.
fn to_values_redacted<T: serde::Serialize>(items: &[T], scope: Option<&TokenScope>) -> Vec<Value> {
    items
        .iter()
        .map(|item| {
            let mut v = serde_json::to_value(item).unwrap_or(Value::Null);
            if let Some(s) = scope {
                s.redact(&mut v);
            }
            v
        })
        .collect()
}

/// Build the in-scope class id set plus a `user -> enrolled class ids` map.
/// Only needed when the scope carries a section/subject constraint.
async fn section_index(
    state: &AppState,
    scope: &TokenScope,
) -> Result<(BTreeSet<String>, BTreeMap<String, BTreeSet<String>>), ChalkError> {
    let classes = state.repo.list_classes().await?;
    let in_scope = scope.classes_in_scope(&classes);
    let mut by_user: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for e in state.repo.list_enrollments().await? {
        by_user.entry(e.user).or_default().insert(e.class);
    }
    Ok((in_scope, by_user))
}

/// Filter a list of users down to those visible under `scope`.
async fn users_in_scope(
    state: &AppState,
    scope: &TokenScope,
    users: Vec<User>,
) -> Result<Vec<User>, ChalkError> {
    if !scope.restricts_rows() {
        return Ok(users);
    }
    if scope.has_section_constraint() {
        let (in_scope_classes, by_user) = section_index(state, scope).await?;
        let empty = BTreeSet::new();
        Ok(users
            .into_iter()
            .filter(|u| {
                let enrolled = by_user.get(&u.sourced_id).unwrap_or(&empty);
                scope.user_in_scope(u, &in_scope_classes, enrolled)
            })
            .collect())
    } else {
        Ok(users
            .into_iter()
            .filter(|u| scope.user_passes_org_grade(u))
            .collect())
    }
}

/// Whether a single user is visible under `scope` (used by `get_user` and to
/// gate demographics, which key off the user's sourcedId).
async fn user_is_in_scope(
    state: &AppState,
    scope: &TokenScope,
    user: &User,
) -> Result<bool, ChalkError> {
    if !scope.restricts_rows() {
        return Ok(true);
    }
    if scope.has_section_constraint() {
        let classes = state.repo.list_classes().await?;
        let in_scope = scope.classes_in_scope(&classes);
        let enrolled: BTreeSet<String> = state
            .repo
            .list_enrollments_for_user(&user.sourced_id)
            .await?
            .into_iter()
            .map(|e| e.class)
            .collect();
        Ok(scope.user_in_scope(user, &in_scope, &enrolled))
    } else {
        Ok(scope.user_passes_org_grade(user))
    }
}

// -- Orgs --

async fn list_orgs(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Query(pg): Query<Pagination>,
    uri: Uri,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::Orgs) {
        return forbidden("orgs");
    }
    let orgs = match state.repo.list_orgs().await {
        Ok(o) => o,
        Err(e) => return server_error(e),
    };
    let orgs = match &scope {
        Some(s) if s.restricts_rows() => orgs
            .into_iter()
            .filter(|o| s.org_in_scope(&o.sourced_id))
            .collect(),
        _ => orgs,
    };
    paginated("orgs", orgs, &pg, &uri).into_response()
}

async fn get_org(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Path(id): Path<String>,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::Orgs) {
        return forbidden("orgs");
    }
    match state.repo.get_org(&id).await {
        Ok(Some(org)) => {
            // Out-of-scope reads as not-found so a scoped token can't probe
            // the existence of orgs it can't see.
            if let Some(s) = &scope {
                if s.restricts_rows() && !s.org_in_scope(&org.sourced_id) {
                    return not_found("org", &id).into_response();
                }
            }
            let value = serde_json::to_value(&org).unwrap_or(Value::Null);
            (StatusCode::OK, Json(envelope("org", value))).into_response()
        }
        Ok(None) => not_found("org", &id).into_response(),
        Err(e) => server_error(e),
    }
}

// -- Academic Sessions --

async fn list_academic_sessions(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Query(pg): Query<Pagination>,
    uri: Uri,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::AcademicSessions) {
        return forbidden("academicSessions");
    }
    match state.repo.list_academic_sessions().await {
        Ok(sessions) => paginated("academicSessions", sessions, &pg, &uri).into_response(),
        Err(e) => server_error(e),
    }
}

async fn get_academic_session(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Path(id): Path<String>,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::AcademicSessions) {
        return forbidden("academicSessions");
    }
    match state.repo.get_academic_session(&id).await {
        Ok(Some(session)) => {
            let value = serde_json::to_value(&session).unwrap_or(Value::Null);
            (StatusCode::OK, Json(envelope("academicSession", value))).into_response()
        }
        Ok(None) => not_found("academicSession", &id).into_response(),
        Err(e) => server_error(e),
    }
}

// -- Users --

async fn list_users(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Query(pg): Query<Pagination>,
    uri: Uri,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::Users) {
        return forbidden("users");
    }
    let users = match state.repo.list_users(&UserFilter::default()).await {
        Ok(u) => u,
        Err(e) => return server_error(e),
    };
    let users = match &scope {
        Some(s) => match users_in_scope(&state, s, users).await {
            Ok(u) => u,
            Err(e) => return server_error(e),
        },
        None => users,
    };
    let values = to_values_redacted(&users, scope.as_ref());
    paginated("users", values, &pg, &uri).into_response()
}

async fn get_user(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Path(id): Path<String>,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::Users) {
        return forbidden("users");
    }
    match state.repo.get_user(&id).await {
        Ok(Some(user)) => {
            if let Some(s) = &scope {
                match user_is_in_scope(&state, s, &user).await {
                    Ok(true) => {}
                    Ok(false) => return not_found("user", &id).into_response(),
                    Err(e) => return server_error(e),
                }
            }
            let mut value = serde_json::to_value(&user).unwrap_or(Value::Null);
            if let Some(s) = &scope {
                s.redact(&mut value);
            }
            (StatusCode::OK, Json(envelope("user", value))).into_response()
        }
        Ok(None) => not_found("user", &id).into_response(),
        Err(e) => server_error(e),
    }
}

// -- Courses --
//
// Courses carry no student PII and are not org-scoped in the OneRoster model,
// so the scope gate is resource-level only (no per-row filtering).

async fn list_courses(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Query(pg): Query<Pagination>,
    uri: Uri,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::Courses) {
        return forbidden("courses");
    }
    match state.repo.list_courses().await {
        Ok(courses) => paginated("courses", courses, &pg, &uri).into_response(),
        Err(e) => server_error(e),
    }
}

async fn get_course(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Path(id): Path<String>,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::Courses) {
        return forbidden("courses");
    }
    match state.repo.get_course(&id).await {
        Ok(Some(course)) => {
            let value = serde_json::to_value(&course).unwrap_or(Value::Null);
            (StatusCode::OK, Json(envelope("course", value))).into_response()
        }
        Ok(None) => not_found("course", &id).into_response(),
        Err(e) => server_error(e),
    }
}

// -- Classes --

async fn list_classes(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Query(pg): Query<Pagination>,
    uri: Uri,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::Classes) {
        return forbidden("classes");
    }
    let classes = match state.repo.list_classes().await {
        Ok(c) => c,
        Err(e) => return server_error(e),
    };
    let classes = match &scope {
        Some(s) if s.restricts_rows() => classes
            .into_iter()
            .filter(|c| s.class_in_scope(c))
            .collect(),
        _ => classes,
    };
    paginated("classes", classes, &pg, &uri).into_response()
}

async fn get_class(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Path(id): Path<String>,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::Classes) {
        return forbidden("classes");
    }
    match state.repo.get_class(&id).await {
        Ok(Some(class)) => {
            if let Some(s) = &scope {
                if s.restricts_rows() && !s.class_in_scope(&class) {
                    return not_found("class", &id).into_response();
                }
            }
            let value = serde_json::to_value(&class).unwrap_or(Value::Null);
            (StatusCode::OK, Json(envelope("class", value))).into_response()
        }
        Ok(None) => not_found("class", &id).into_response(),
        Err(e) => server_error(e),
    }
}

// -- Enrollments --

async fn list_enrollments(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Query(pg): Query<Pagination>,
    uri: Uri,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::Enrollments) {
        return forbidden("enrollments");
    }
    let enrollments = match state.repo.list_enrollments().await {
        Ok(e) => e,
        Err(e) => return server_error(e),
    };
    let enrollments = match &scope {
        Some(s) if s.restricts_rows() => {
            // An enrollment is visible iff its class is in scope (which already
            // accounts for org/grade/subject/section) and its school org is in
            // scope. Deriving the in-scope class set once keeps this O(n).
            let classes = match state.repo.list_classes().await {
                Ok(c) => c,
                Err(e) => return server_error(e),
            };
            let in_scope = s.classes_in_scope(&classes);
            enrollments
                .into_iter()
                .filter(|e| s.org_in_scope(&e.school) && in_scope.contains(&e.class))
                .collect()
        }
        _ => enrollments,
    };
    paginated("enrollments", enrollments, &pg, &uri).into_response()
}

async fn get_enrollment(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Path(id): Path<String>,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::Enrollments) {
        return forbidden("enrollments");
    }
    match state.repo.get_enrollment(&id).await {
        Ok(Some(enrollment)) => {
            if let Some(s) = &scope {
                if s.restricts_rows() {
                    let in_scope = match state.repo.list_classes().await {
                        Ok(c) => s.classes_in_scope(&c),
                        Err(e) => return server_error(e),
                    };
                    if !(s.org_in_scope(&enrollment.school) && in_scope.contains(&enrollment.class))
                    {
                        return not_found("enrollment", &id).into_response();
                    }
                }
            }
            let value = serde_json::to_value(&enrollment).unwrap_or(Value::Null);
            (StatusCode::OK, Json(envelope("enrollment", value))).into_response()
        }
        Ok(None) => not_found("enrollment", &id).into_response(),
        Err(e) => server_error(e),
    }
}

// -- Demographics --
//
// Demographics share the user's sourcedId, so a scoped token sees a
// demographics row only for users it can see. Birth date and other sensitive
// fields can additionally be stripped via `redact_fields`.

async fn list_demographics(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Query(pg): Query<Pagination>,
    uri: Uri,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::Demographics) {
        return forbidden("demographics");
    }
    let demographics = match state.repo.list_demographics().await {
        Ok(d) => d,
        Err(e) => return server_error(e),
    };
    let demographics = match &scope {
        Some(s) if s.restricts_rows() => {
            let users = match state.repo.list_users(&UserFilter::default()).await {
                Ok(u) => u,
                Err(e) => return server_error(e),
            };
            let allowed: BTreeSet<String> = match users_in_scope(&state, s, users).await {
                Ok(u) => u.into_iter().map(|u| u.sourced_id).collect(),
                Err(e) => return server_error(e),
            };
            demographics
                .into_iter()
                .filter(|d| allowed.contains(&d.sourced_id))
                .collect()
        }
        _ => demographics,
    };
    let values = to_values_redacted(&demographics, scope.as_ref());
    paginated("demographics", values, &pg, &uri).into_response()
}

async fn get_demographics(
    State(state): State<Arc<AppState>>,
    scope_ext: Option<Extension<ScopeContext>>,
    Path(id): Path<String>,
) -> Response {
    let scope = resolve_scope(scope_ext);
    if resource_denied(&scope, OneRosterResource::Demographics) {
        return forbidden("demographics");
    }
    match state.repo.get_demographics(&id).await {
        Ok(Some(demo)) => {
            if let Some(s) = &scope {
                if s.restricts_rows() {
                    // Gate on the matching user's visibility.
                    match state.repo.get_user(&demo.sourced_id).await {
                        Ok(Some(user)) => match user_is_in_scope(&state, s, &user).await {
                            Ok(true) => {}
                            Ok(false) => return not_found("demographics", &id).into_response(),
                            Err(e) => return server_error(e),
                        },
                        // No matching user -> can't prove it's in scope -> hide.
                        Ok(None) => return not_found("demographics", &id).into_response(),
                        Err(e) => return server_error(e),
                    }
                }
            }
            let mut value = serde_json::to_value(&demo).unwrap_or(Value::Null);
            if let Some(s) = &scope {
                s.redact(&mut value);
            }
            (StatusCode::OK, Json(envelope("demographics", value))).into_response()
        }
        Ok(None) => not_found("demographics", &id).into_response(),
        Err(e) => server_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn test_state() -> Arc<AppState> {
        let pool = chalk_core::db::DatabasePool::new_sqlite_memory()
            .await
            .unwrap();
        let repo = match pool {
            chalk_core::db::DatabasePool::Sqlite(p) => {
                chalk_core::db::sqlite::SqliteRepository::new(p)
            }

            chalk_core::db::DatabasePool::Postgres(_) => {
                unreachable!("test setup uses sqlite memory")
            }
        };
        let config = chalk_core::config::ChalkConfig::generate_default();
        let repo: Arc<dyn chalk_core::db::repository::ChalkRepository> = Arc::new(repo);
        Arc::new(AppState::new(repo, config))
    }

    async fn get_json(response: axum::http::Response<Body>) -> Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn api_router(state: Arc<AppState>) -> Router {
        Router::new()
            .nest("/api/oneroster/v1p1", oneroster_router())
            .with_state(state)
    }

    /// Router that injects a `ScopeContext` extension, standing in for what the
    /// bearer middleware does in production.
    fn scoped_router(state: Arc<AppState>, scope: TokenScope) -> Router {
        Router::new()
            .nest("/api/oneroster/v1p1", oneroster_router())
            .layer(Extension(ScopeContext(Some(scope))))
            .with_state(state)
    }

    async fn get(app: Router, uri: &str) -> axum::http::Response<Body> {
        app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// Seed two schools with users/classes/enrollments/demographics so scope
    /// filtering has something to bite on.
    async fn seed_two_schools(state: &Arc<AppState>) {
        use chalk_core::models::class::Class;
        use chalk_core::models::common::{ClassType, EnrollmentRole, OrgType, RoleType, Status};
        use chalk_core::models::demographics::Demographics;
        use chalk_core::models::enrollment::Enrollment;
        use chalk_core::models::org::Org;
        use chalk_core::models::user::User;
        use chrono::{NaiveDate, TimeZone, Utc};

        let now = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let mk_org = |id: &str| Org {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: now,
            metadata: None,
            name: id.to_string(),
            org_type: OrgType::School,
            identifier: None,
            parent: None,
            children: vec![],
        };
        state.repo.upsert_org(&mk_org("school-a")).await.unwrap();
        state.repo.upsert_org(&mk_org("school-b")).await.unwrap();

        let mk_user = |id: &str, role: RoleType, org: &str, grade: &str| User {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: now,
            metadata: None,
            username: id.to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "G".to_string(),
            family_name: "F".to_string(),
            middle_name: None,
            role,
            identifier: None,
            email: Some(format!("{id}@ex.com")),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec![org.to_string()],
            grades: if grade.is_empty() {
                vec![]
            } else {
                vec![grade.to_string()]
            },
        };
        state
            .repo
            .upsert_user(&mk_user("stu-a", RoleType::Student, "school-a", "09"))
            .await
            .unwrap();
        state
            .repo
            .upsert_user(&mk_user("stu-b", RoleType::Student, "school-b", "10"))
            .await
            .unwrap();
        state
            .repo
            .upsert_user(&mk_user("tea-a", RoleType::Teacher, "school-a", ""))
            .await
            .unwrap();

        // Course rows are referenced by classes; insert minimal ones.
        use chalk_core::models::course::Course;
        let mk_course = |id: &str, org: &str| Course {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: now,
            metadata: None,
            title: id.to_string(),
            course_code: None,
            grades: vec![],
            subjects: vec![],
            org: org.to_string(),
            school_year: None,
        };
        state
            .repo
            .upsert_course(&mk_course("crs-m", "school-a"))
            .await
            .unwrap();
        state
            .repo
            .upsert_course(&mk_course("crs-s", "school-b"))
            .await
            .unwrap();

        let mk_class = |id: &str, school: &str, course: &str, grade: &str, subject: &str| Class {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: now,
            metadata: None,
            title: id.to_string(),
            class_code: None,
            class_type: ClassType::Scheduled,
            location: None,
            grades: vec![grade.to_string()],
            subjects: vec![subject.to_string()],
            course: course.to_string(),
            school: school.to_string(),
            terms: vec![],
            periods: vec![],
        };
        state
            .repo
            .upsert_class(&mk_class(
                "c-math",
                "school-a",
                "crs-m",
                "09",
                "Mathematics",
            ))
            .await
            .unwrap();
        state
            .repo
            .upsert_class(&mk_class("c-sci", "school-b", "crs-s", "10", "Science"))
            .await
            .unwrap();

        let mk_enr = |id: &str, user: &str, class: &str, school: &str| Enrollment {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: now,
            metadata: None,
            user: user.to_string(),
            class: class.to_string(),
            school: school.to_string(),
            role: EnrollmentRole::Student,
            primary: None,
            begin_date: None,
            end_date: None,
        };
        state
            .repo
            .upsert_enrollment(&mk_enr("e-a", "stu-a", "c-math", "school-a"))
            .await
            .unwrap();
        state
            .repo
            .upsert_enrollment(&mk_enr("e-b", "stu-b", "c-sci", "school-b"))
            .await
            .unwrap();

        let mk_demo = |id: &str| Demographics {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: now,
            metadata: None,
            birth_date: Some(NaiveDate::from_ymd_opt(2010, 5, 1).unwrap()),
            sex: None,
            american_indian_or_alaska_native: None,
            asian: None,
            black_or_african_american: None,
            native_hawaiian_or_other_pacific_islander: None,
            white: None,
            demographic_race_two_or_more_races: None,
            hispanic_or_latino_ethnicity: None,
            country_of_birth_code: None,
            state_of_birth_abbreviation: None,
            city_of_birth: None,
            public_school_residence_status: None,
        };
        state
            .repo
            .upsert_demographics(&mk_demo("stu-a"))
            .await
            .unwrap();
        state
            .repo
            .upsert_demographics(&mk_demo("stu-b"))
            .await
            .unwrap();
    }

    // -- Scope enforcement --

    #[tokio::test]
    async fn org_scope_filters_orgs_and_users() {
        let state = test_state().await;
        seed_two_schools(&state).await;
        let scope = TokenScope {
            orgs: vec!["school-a".to_string()],
            ..Default::default()
        };

        // Orgs: only school-a.
        let resp = get(
            scoped_router(state.clone(), scope.clone()),
            "/api/oneroster/v1p1/orgs",
        )
        .await;
        let json = get_json(resp).await;
        let orgs = json["orgs"].as_array().unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0]["sourcedId"], "school-a");

        // Users: stu-a + tea-a (school-a), never stu-b.
        let resp = get(
            scoped_router(state.clone(), scope.clone()),
            "/api/oneroster/v1p1/users",
        )
        .await;
        let json = get_json(resp).await;
        let ids: Vec<&str> = json["users"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["sourcedId"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"stu-a"));
        assert!(ids.contains(&"tea-a"));
        assert!(!ids.contains(&"stu-b"));
    }

    #[tokio::test]
    async fn out_of_scope_user_reads_as_not_found() {
        let state = test_state().await;
        seed_two_schools(&state).await;
        let scope = TokenScope {
            orgs: vec!["school-a".to_string()],
            ..Default::default()
        };
        let resp = get(
            scoped_router(state, scope),
            "/api/oneroster/v1p1/users/stu-b",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn denied_resource_returns_forbidden() {
        let state = test_state().await;
        seed_two_schools(&state).await;
        let mut scope = TokenScope::default();
        scope
            .resources
            .insert(OneRosterResource::Demographics, false);
        let resp = get(
            scoped_router(state, scope),
            "/api/oneroster/v1p1/demographics",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn redact_strips_birth_date_from_demographics() {
        let state = test_state().await;
        seed_two_schools(&state).await;
        let scope = TokenScope {
            redact_fields: vec!["birthDate".to_string()],
            ..Default::default()
        };
        let resp = get(
            scoped_router(state, scope),
            "/api/oneroster/v1p1/demographics",
        )
        .await;
        let json = get_json(resp).await;
        for d in json["demographics"].as_array().unwrap() {
            assert!(d.get("birthDate").is_none(), "birthDate must be redacted");
            assert!(d.get("sourcedId").is_some());
        }
    }

    #[tokio::test]
    async fn subject_scope_limits_users_to_enrolled_sections() {
        let state = test_state().await;
        seed_two_schools(&state).await;
        // Math sections only: stu-a is enrolled in c-math; tea-a is not enrolled
        // anywhere; stu-b is in a science section.
        let scope = TokenScope {
            subjects: vec!["Mathematics".to_string()],
            ..Default::default()
        };
        let resp = get(scoped_router(state, scope), "/api/oneroster/v1p1/users").await;
        let json = get_json(resp).await;
        let ids: Vec<&str> = json["users"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["sourcedId"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["stu-a"]);
    }

    #[tokio::test]
    async fn class_scope_filters_classes_and_enrollments() {
        let state = test_state().await;
        seed_two_schools(&state).await;
        let scope = TokenScope {
            classes: vec!["c-math".to_string()],
            ..Default::default()
        };

        let resp = get(
            scoped_router(state.clone(), scope.clone()),
            "/api/oneroster/v1p1/classes",
        )
        .await;
        let json = get_json(resp).await;
        let classes = json["classes"].as_array().unwrap();
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0]["sourcedId"], "c-math");

        let resp = get(
            scoped_router(state, scope),
            "/api/oneroster/v1p1/enrollments",
        )
        .await;
        let json = get_json(resp).await;
        let enrs = json["enrollments"].as_array().unwrap();
        assert_eq!(enrs.len(), 1);
        assert_eq!(enrs[0]["class"], "c-math");
    }

    #[tokio::test]
    async fn no_scope_extension_is_unrestricted() {
        let state = test_state().await;
        seed_two_schools(&state).await;
        // Plain api_router (no ScopeContext layer) must behave as before.
        let resp = get(api_router(state), "/api/oneroster/v1p1/users").await;
        let json = get_json(resp).await;
        assert_eq!(json["users"].as_array().unwrap().len(), 3);
    }

    // -- List endpoints return empty arrays --

    #[tokio::test]
    async fn list_orgs_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/orgs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-total-count").unwrap(), "0");
        let json = get_json(response).await;
        assert!(json["orgs"].is_array());
        assert_eq!(json["orgs"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn list_users_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["users"].is_array());
    }

    #[tokio::test]
    async fn list_courses_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/courses")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["courses"].is_array());
    }

    #[tokio::test]
    async fn list_classes_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/classes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["classes"].is_array());
    }

    #[tokio::test]
    async fn list_enrollments_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/enrollments")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["enrollments"].is_array());
    }

    #[tokio::test]
    async fn list_academic_sessions_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/academicSessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["academicSessions"].is_array());
    }

    #[tokio::test]
    async fn list_demographics_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/demographics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["demographics"].is_array());
    }

    // -- 404 for missing entities --

    #[tokio::test]
    async fn get_org_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/orgs/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = get_json(response).await;
        assert!(json["error"].as_str().unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn get_user_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/users/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_course_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/courses/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_class_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/classes/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_enrollment_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/enrollments/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_academic_session_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/academicSessions/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_demographics_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/demographics/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // -- With data --

    #[tokio::test]
    async fn list_and_get_org_with_data() {
        let state = test_state().await;

        use chalk_core::models::common::{OrgType, Status};
        use chalk_core::models::org::Org;
        use chrono::{TimeZone, Utc};

        let org = Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Test District".to_string(),
            org_type: OrgType::District,
            identifier: None,
            parent: None,
            children: vec![],
        };
        state.repo.upsert_org(&org).await.unwrap();

        let app = api_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/orgs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-total-count").unwrap(), "1");
        let json = get_json(response).await;
        assert_eq!(json["orgs"].as_array().unwrap().len(), 1);
        assert_eq!(json["orgs"][0]["sourcedId"], "org-001");

        // Get single
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/orgs/org-001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert_eq!(json["org"]["sourcedId"], "org-001");
        assert_eq!(json["org"]["name"], "Test District");
    }

    #[tokio::test]
    async fn list_and_get_user_with_data() {
        let state = test_state().await;

        use chalk_core::models::common::{OrgType, RoleType, Status};
        use chalk_core::models::org::Org;
        use chalk_core::models::user::User;
        use chrono::{TimeZone, Utc};

        let org = Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Test District".to_string(),
            org_type: OrgType::District,
            identifier: None,
            parent: None,
            children: vec![],
        };
        state.repo.upsert_org(&org).await.unwrap();

        let user = User {
            sourced_id: "user-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "jdoe".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "John".to_string(),
            family_name: "Doe".to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some("jdoe@example.com".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-001".to_string()],
            grades: vec!["09".to_string()],
        };
        state.repo.upsert_user(&user).await.unwrap();

        let app = api_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert_eq!(json["users"].as_array().unwrap().len(), 1);
        assert_eq!(json["users"][0]["username"], "jdoe");

        // Get single
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/users/user-001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert_eq!(json["user"]["sourcedId"], "user-001");
        assert_eq!(json["user"]["givenName"], "John");
    }

    // -- Pagination --

    #[tokio::test]
    async fn pagination_slices_results_and_emits_link_header() {
        let state = test_state().await;

        use chalk_core::models::common::{OrgType, Status};
        use chalk_core::models::org::Org;
        use chrono::{TimeZone, Utc};

        // Insert 5 orgs so we can paginate.
        for i in 0..5 {
            let org = Org {
                sourced_id: format!("org-{i:03}"),
                status: Status::Active,
                date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
                metadata: None,
                name: format!("District {i}"),
                org_type: OrgType::District,
                identifier: None,
                parent: None,
                children: vec![],
            };
            state.repo.upsert_org(&org).await.unwrap();
        }

        // Page 1: limit=2 offset=0 — expect 2 results, Link with next + last.
        let app = api_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/orgs?limit=2&offset=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers().get("x-total-count").unwrap(), "5");
        let link = response.headers().get("link").unwrap().to_str().unwrap();
        assert!(link.contains("rel=\"next\""));
        assert!(link.contains("rel=\"last\""));
        assert!(link.contains("offset=2"));
        let json = get_json(response).await;
        assert_eq!(json["orgs"].as_array().unwrap().len(), 2);

        // Page 2: limit=2 offset=2 — expect 2 results, Link with prev + next.
        let app = api_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/orgs?limit=2&offset=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let link = response.headers().get("link").unwrap().to_str().unwrap();
        assert!(link.contains("rel=\"prev\""));
        assert!(link.contains("rel=\"next\""));
        let json = get_json(response).await;
        assert_eq!(json["orgs"].as_array().unwrap().len(), 2);

        // Page 3: limit=2 offset=4 — expect 1 result, Link with prev (no next).
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/orgs?limit=2&offset=4")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let link = response.headers().get("link").unwrap().to_str().unwrap();
        assert!(link.contains("rel=\"prev\""));
        assert!(!link.contains("rel=\"next\""));
        let json = get_json(response).await;
        assert_eq!(json["orgs"].as_array().unwrap().len(), 1);
    }
}
