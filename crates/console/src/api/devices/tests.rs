//! Device API tests.
//!
//! Almost all of these are about the scope boundary, because that is the part
//! that can be wrong while looking right. A scoped token is how the hosted
//! marketplace lets a district share *part* of its fleet with a third-party
//! app; a leak here is a district's data going somewhere they did not agree to.

use super::*;

use axum::body::Body;
use axum::http::Request;
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetEventRepository, AssetRepository, ChalkRepository, OrgRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::asset::{ActorKind, Asset, AssetEventType, NewAssetEvent};
use chalk_core::models::common::{OrgType, Status};
use chalk_core::models::org::Org;
use chrono::{TimeZone, Utc};
use serde_json::Value;
use tower::ServiceExt;

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    for (id, name) in [("org-a", "Alpha High"), ("org-b", "Beta Middle")] {
        repo.upsert_org(&Org {
            sourced_id: id.into(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            name: name.into(),
            org_type: OrgType::School,
            identifier: None,
            parent: None,
            children: vec![],
        })
        .await
        .unwrap();
    }

    let assets: Arc<dyn AssetRepository> = repo.clone();
    let events: Arc<dyn AssetEventRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, ChalkConfig::generate_default()).with_assets(assets, events),
    );
    Fx { state, repo }
}

/// A device at a school, with one audit event so the events route has content.
async fn device(f: &Fx, id: &str, school: Option<&str>) {
    let mut a = Asset::new(id);
    a.asset_tag = Some(format!("CB-{id}"));
    a.serial_number = Some(format!("SN-{id}"));
    a.school_org_sourced_id = school.map(str::to_string);
    f.repo.create_asset(&a).await.unwrap();
    f.repo
        .append_event(&NewAssetEvent::simple(
            id,
            "system:test",
            ActorKind::System,
            AssetEventType::Imported,
        ))
        .await
        .unwrap();
}

/// Call the API directly with a scope, bypassing the bearer middleware — the
/// middleware's job is turning a token into a `ScopeContext`, and that is
/// tested where it lives. What matters here is what the handlers do with one.
async fn call(state: Arc<AppState>, uri: &str, scope: Option<TokenScope>) -> (StatusCode, Value) {
    let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    req.extensions_mut().insert(ScopeContext(scope));
    let response = devices_router()
        .with_state(state)
        .oneshot(req)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn scoped_to(orgs: &[&str]) -> TokenScope {
    TokenScope {
        orgs: orgs.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

fn tags(v: &Value, key: &str) -> Vec<String> {
    v[key]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|d| d["assetTag"].as_str().map(str::to_string))
        .collect()
}

// ---------------------------------------------------------------------------
// The unscoped case
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unscoped_token_sees_the_whole_fleet() {
    let f = fixture().await;
    device(&f, "a", Some("org-a")).await;
    device(&f, "b", Some("org-b")).await;
    device(&f, "c", None).await;

    let (status, body) = call(f.state.clone(), "/devices", None).await;
    assert_eq!(status, StatusCode::OK);
    let mut got = tags(&body, "devices");
    got.sort();
    assert_eq!(got, vec!["CB-a", "CB-b", "CB-c"]);
}

// ---------------------------------------------------------------------------
// The scope boundary
// ---------------------------------------------------------------------------

/// A scoped token sees only its schools — and the boundary is applied in the
/// query, so the reported total matches what was returned.
///
/// A total computed over the whole fleet would leak the size of the part the
/// caller was denied, through a header they are allowed to read.
#[tokio::test]
async fn a_scoped_token_sees_only_its_schools_and_a_matching_total() {
    let f = fixture().await;
    device(&f, "a", Some("org-a")).await;
    device(&f, "b", Some("org-b")).await;
    device(&f, "c", None).await;

    let mut req = Request::builder()
        .uri("/devices")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ScopeContext(Some(scoped_to(&["org-a"]))));
    let response = devices_router()
        .with_state(f.state.clone())
        .oneshot(req)
        .await
        .unwrap();
    let total = response
        .headers()
        .get("x-total-count")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(tags(&body, "devices"), vec!["CB-a"]);
    assert_eq!(
        total.as_deref(),
        Some("1"),
        "the total must count what the caller may see, not the fleet"
    );
}

/// A device with no school is invisible to a scoped token. The token was
/// granted *specific* schools, and "belongs to none of them" is not one of
/// them — showing it would quietly widen the grant.
#[tokio::test]
async fn a_device_with_no_school_is_invisible_to_a_scoped_token() {
    let f = fixture().await;
    device(&f, "c", None).await;

    let (_, list) = call(f.state.clone(), "/devices", Some(scoped_to(&["org-a"]))).await;
    assert!(tags(&list, "devices").is_empty());

    let (status, _) = call(f.state.clone(), "/devices/c", Some(scoped_to(&["org-a"]))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Asking for a school outside the scope returns nothing rather than that
/// school. A caller's filter narrows within the boundary; it never widens it.
#[tokio::test]
async fn filtering_to_a_school_outside_the_scope_returns_nothing() {
    let f = fixture().await;
    device(&f, "a", Some("org-a")).await;
    device(&f, "b", Some("org-b")).await;

    let (status, body) = call(
        f.state.clone(),
        "/devices?school=org-b",
        Some(scoped_to(&["org-a"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        tags(&body, "devices").is_empty(),
        "the filter must intersect with the scope, not replace it"
    );
}

/// A token scoped to several schools sees all of them.
#[tokio::test]
async fn a_multi_school_scope_sees_every_school_it_names() {
    let f = fixture().await;
    device(&f, "a", Some("org-a")).await;
    device(&f, "b", Some("org-b")).await;

    let (_, body) = call(
        f.state.clone(),
        "/devices",
        Some(scoped_to(&["org-a", "org-b"])),
    )
    .await;
    let mut got = tags(&body, "devices");
    got.sort();
    assert_eq!(got, vec!["CB-a", "CB-b"]);
}

/// Fetching one device outside the scope is **404, not 403**. A 403 would
/// confirm the device exists, which is precisely what the scope withholds.
#[tokio::test]
async fn a_device_outside_the_scope_is_indistinguishable_from_one_that_is_absent() {
    let f = fixture().await;
    device(&f, "b", Some("org-b")).await;

    let (denied, _) = call(f.state.clone(), "/devices/b", Some(scoped_to(&["org-a"]))).await;
    let (absent, _) = call(
        f.state.clone(),
        "/devices/nonexistent",
        Some(scoped_to(&["org-a"])),
    )
    .await;
    assert_eq!(denied, StatusCode::NOT_FOUND);
    assert_eq!(absent, denied, "the two must be the same answer");
}

/// The events route checks the *device's* school before listing anything.
/// Without that, a route that never mentions a school would leak both a
/// device's existence and its whole history.
#[tokio::test]
async fn events_for_a_device_outside_the_scope_are_refused() {
    let f = fixture().await;
    device(&f, "a", Some("org-a")).await;
    device(&f, "b", Some("org-b")).await;

    let (allowed, body) = call(
        f.state.clone(),
        "/devices/a/events",
        Some(scoped_to(&["org-a"])),
    )
    .await;
    assert_eq!(allowed, StatusCode::OK);
    assert_eq!(body["events"].as_array().map(Vec::len), Some(1));

    let (refused, refused_body) = call(
        f.state.clone(),
        "/devices/b/events",
        Some(scoped_to(&["org-a"])),
    )
    .await;
    assert_eq!(refused, StatusCode::NOT_FOUND);
    assert!(refused_body["events"].is_null(), "no history leaks");
}

/// A token denied the devices resource outright gets 403 on every route —
/// including the ones that would otherwise 404.
#[tokio::test]
async fn a_token_denied_devices_is_refused_everywhere() {
    let f = fixture().await;
    device(&f, "a", Some("org-a")).await;

    let mut scope = TokenScope::default();
    scope.resources.insert(OneRosterResource::Devices, false);

    for path in ["/devices", "/devices/a", "/devices/a/events"] {
        let (status, _) = call(f.state.clone(), path, Some(scope.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path} was not refused");
    }
}

// ---------------------------------------------------------------------------
// Ordinary behaviour
// ---------------------------------------------------------------------------

/// The limit is clamped rather than trusted: a client asking for a million
/// rows should not be able to make the server serialize the whole fleet.
#[tokio::test]
async fn the_page_limit_is_clamped_at_both_ends() {
    let f = fixture().await;
    for i in 0..5 {
        device(&f, &format!("d{i}"), Some("org-a")).await;
    }

    let (_, body) = call(f.state.clone(), "/devices?limit=2", None).await;
    assert_eq!(tags(&body, "devices").len(), 2);

    let (_, huge) = call(f.state.clone(), "/devices?limit=999999", None).await;
    assert_eq!(tags(&huge, "devices").len(), 5, "clamped, not rejected");

    let (status, _) = call(f.state.clone(), "/devices?limit=0", None).await;
    assert_eq!(status, StatusCode::OK, "a zero limit degrades, never 500s");
}

/// An unparseable filter value widens rather than 400s, matching the console:
/// a hand-edited URL should degrade to a broader view, not an error page.
#[tokio::test]
async fn an_unparseable_filter_is_ignored_rather_than_rejected() {
    let f = fixture().await;
    device(&f, "a", Some("org-a")).await;

    let (status, body) = call(f.state.clone(), "/devices?status=nonsense", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tags(&body, "devices"), vec!["CB-a"]);
}

/// There are no write routes, and that is deliberate: every fleet change goes
/// through plan → preview → commit, and an API POST would step around the
/// preview that makes filter-scoped action defensible.
#[tokio::test]
async fn the_api_offers_no_way_to_change_a_device() {
    let f = fixture().await;
    device(&f, "a", Some("org-a")).await;

    for (method, path) in [
        ("POST", "/devices"),
        ("PATCH", "/devices/a"),
        ("PUT", "/devices/a"),
        ("DELETE", "/devices/a"),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let response = devices_router()
            .with_state(f.state.clone())
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} must not be routable"
        );
    }
}
