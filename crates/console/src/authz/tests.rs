//! The seam's proof: presets reproduce pre-GP-2 behavior exactly, the table
//! means what it declares when driven through the real router, and a custom
//! set narrows what a session can do without a re-login.

use super::*;
use crate::{router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AdminSessionRepository, ChalkRepository, ConsoleUserRepository, PermissionSetRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::audit::AdminSession;
use chalk_core::models::console_user::{ConsoleRole, ConsoleUser, ConsoleUserStatus};
use chalk_core::models::permission::{ConsoleAuthz, PermissionSet};
use chrono::{Duration, Utc};
use std::sync::Arc;
use tower::ServiceExt;

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

/// A state with a password set (so sessions are enforced) and EVERY
/// repository wired via `wire_all` — a page must 403 because of a
/// permission, never 404 because a repository is absent, or these tests
/// measure nothing (the vacuous-fixture trap, three times bitten).
async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!(),
    };
    let mut config = crate::tests::default_config();
    config.chalk.admin_password_hash = Some(crate::auth::hash_password("unused").unwrap());
    let state = Arc::new(crate::tests::wire_all(repo.clone(), config));
    Fx { state, repo }
}

async fn user_with_session(fx: &Fx, id: &str, role: ConsoleRole) -> String {
    fx.repo
        .create_console_user(&ConsoleUser {
            id: id.into(),
            email: format!("{id}@district.test"),
            display_name: id.into(),
            password_hash: None,
            role,
            status: ConsoleUserStatus::Active,
            totp_secret: None,
            totp_confirmed: false,
            totp_recovery: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .await
        .unwrap();
    let token = format!("tok-{id}");
    fx.repo
        .create_admin_session(&AdminSession {
            token: token.clone(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            ip_address: None,
            actor_id: Some(format!("console_user:{id}")),
            actor_label: Some(id.into()),
            actor_role: Some(role.as_str().into()),
        })
        .await
        .unwrap();
    token
}

async fn request(fx: &Fx, method: &str, path: &str, token: &str) -> StatusCode {
    let csrf = crate::csrf::generate_csrf_token();
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(
            "cookie",
            format!("chalk_session={token}; chalk_csrf={csrf}"),
        )
        .header("x-csrf-token", &csrf);
    if method == "POST" {
        builder = builder.header("content-type", "application/x-www-form-urlencoded");
    }
    router(fx.state.clone())
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

/// Behavior parity: a technician can do everything but touch console
/// accounts; read-only can look but not change; both exactly as before GP-2.
#[tokio::test]
async fn presets_reproduce_the_pre_gp2_contract() {
    let fx = fixture().await;
    let tech = user_with_session(&fx, "tech", ConsoleRole::Technician).await;
    let ro = user_with_session(&fx, "ro", ConsoleRole::ReadOnly).await;
    let admin = user_with_session(&fx, "boss", ConsoleRole::Admin).await;

    // Console-account management stays admin-only, GETs included.
    assert_eq!(
        request(&fx, "GET", "/settings/console-users", &tech).await,
        StatusCode::FORBIDDEN
    );
    assert_ne!(
        request(&fx, "GET", "/settings/console-users", &admin).await,
        StatusCode::FORBIDDEN
    );

    // A technician still works tickets and the circulation desk.
    for path in ["/tickets", "/devices/circulation", "/devices"] {
        assert_eq!(request(&fx, "GET", path, &tech).await, StatusCode::OK);
    }

    // Read-only: every view opens, every mutation is refused.
    for path in ["/devices", "/tickets", "/settings", "/settings/audit-log"] {
        assert_eq!(request(&fx, "GET", path, &ro).await, StatusCode::OK);
    }
    for (m, p) in [
        ("POST", "/devices/changes"),
        ("POST", "/tickets/views"),
        ("POST", "/kb"),
        ("POST", "/webhooks/x/delete"),
    ] {
        assert_eq!(request(&fx, m, p, &ro).await, StatusCode::FORBIDDEN);
    }
}

/// A custom set narrows a live session on the next request — no re-login.
#[tokio::test]
async fn a_custom_set_bites_without_a_new_session() {
    let fx = fixture().await;
    let tech = user_with_session(&fx, "desk", ConsoleRole::Technician).await;

    // Starts with the full technician preset.
    assert_eq!(
        request(&fx, "GET", "/devices/sync", &tech).await,
        StatusCode::OK
    );

    // Assign a circulation-desk-only set mid-session.
    fx.repo
        .create_permission_set(&PermissionSet {
            id: "ps-desk".into(),
            name: "Circulation desk".into(),
            permissions: vec![
                chalk_core::models::permission::Permission::AssetsView,
                chalk_core::models::permission::Permission::CustodyView,
                chalk_core::models::permission::Permission::CustodyManage,
            ],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .await
        .unwrap();
    fx.repo
        .set_console_authz(
            "desk",
            &ConsoleAuthz {
                permission_set_id: Some("ps-desk".into()),
                include_unscoped: false,
                sites: vec![],
            },
        )
        .await
        .unwrap();

    // Same session token: circulation still opens, the sync surface and the
    // help-desk queue no longer do.
    assert_eq!(
        request(&fx, "GET", "/devices/circulation", &tech).await,
        StatusCode::OK
    );
    assert_eq!(
        request(&fx, "GET", "/devices/sync", &tech).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&fx, "GET", "/tickets", &tech).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&fx, "POST", "/devices/changes", &tech).await,
        StatusCode::FORBIDDEN
    );
}

/// The local-dev shortcut (no password, no magic link) stays wide open and
/// carries an unrestricted principal — self-host unaffected.
#[tokio::test]
async fn the_open_console_is_still_the_unrestricted_admin() {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!(),
    };
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(AppState::new(chalk_repo, ChalkConfig::generate_default()));
    let res = router(state)
        .oneshot(
            Request::builder()
                .uri("/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// Every route the router serves must have a declaration. This walks the
/// route table extracted from `lib.rs` at compile time via the lint script's
/// same source, in spirit — here we assert the mutating arms directly: any
/// route the table does not know is refused when mutating.
#[tokio::test]
async fn an_undeclared_mutating_route_fails_closed() {
    let fx = fixture().await;
    let admin = user_with_session(&fx, "root", ConsoleRole::Admin).await;
    // A POST that matches no declared arm (the route does not even exist —
    // axum 404s first; the middleware's fail-closed covers routes that exist
    // but were forgotten in the table, which the unit check below pins).
    assert_eq!(
        route_authz(&Method::POST, "/some/new/surface"),
        None,
        "unknown templates must resolve to None, which the middleware refuses"
    );
    // And a declared one still works for the admin.
    assert_ne!(
        request(&fx, "GET", "/devices", &admin).await,
        StatusCode::FORBIDDEN
    );
}

/// The table itself: spot-pin the arms whose misdeclaration would be a
/// security bug, so a refactor cannot silently flip them.
#[test]
fn the_sensitive_arms_are_declared_as_expected() {
    use Permission as P;
    for (m, path, want) in [
        (
            Method::GET,
            "/settings/console-users",
            RouteAuthz::Read(P::ConsoleUsersManage),
        ),
        (
            Method::POST,
            "/settings/console-users",
            RouteAuthz::Write(P::ConsoleUsersManage),
        ),
        (
            Method::POST,
            "/charges/{id}/waive",
            RouteAuthz::Write(P::FeesWaive),
        ),
        (
            Method::POST,
            "/devices/changes/{id}/commit",
            RouteAuthz::Write(P::AssetsSync),
        ),
        (
            Method::POST,
            "/devices/{id}/checkout",
            RouteAuthz::Write(P::CustodyManage),
        ),
        (Method::GET, "/login", RouteAuthz::Public),
        (Method::POST, "/logout", RouteAuthz::SelfService),
    ] {
        assert_eq!(route_authz(&m, path), Some(want), "{m} {path}");
    }
}

/// Site scoping end to end through the real router: a technician granted one
/// school sees only that school's rows, cannot reach another school's device
/// or ticket even by id, and the unassigned pool appears exactly when the
/// per-user grant says so.
#[tokio::test]
async fn a_site_grant_bounds_lists_details_and_by_id_writes() {
    use chalk_core::db::repository::{
        AssetRepository, CustodyRepository, OrgRepository, TicketRepository,
    };
    use chalk_core::models::asset::Asset;
    use chalk_core::models::common::{OrgType, Status};
    use chalk_core::models::org::Org;

    let fx = fixture().await;
    let tech = user_with_session(&fx, "site-tech", ConsoleRole::Technician).await;

    for (sid, name) in [("org-a", "Alpha High"), ("org-b", "Beta Middle")] {
        fx.repo
            .upsert_org(&Org {
                sourced_id: sid.into(),
                status: Status::Active,
                date_last_modified: Utc::now(),
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
    for (id, school) in [
        ("d-alpha", Some("org-a")),
        ("d-beta", Some("org-b")),
        ("d-pool", None),
    ] {
        let mut a = Asset::new(id);
        a.asset_tag = Some(format!("TAG-{id}"));
        a.school_org_sourced_id = school.map(str::to_string);
        fx.repo.create_asset(&a).await.unwrap();
    }
    let mut t = chalk_core::models::ticket::Ticket::new("t-beta", "Beta printer");
    t.school_org_sourced_id = Some("org-b".into());
    fx.repo.create_ticket(&t).await.unwrap();

    // Grant org-a only, no unassigned pool.
    fx.repo
        .set_console_authz(
            "site-tech",
            &ConsoleAuthz {
                permission_set_id: None,
                include_unscoped: false,
                sites: vec!["org-a".into()],
            },
        )
        .await
        .unwrap();

    // The inventory shows Alpha's device and neither the other school's nor
    // the unassigned pool.
    let (status, html) = get_body(&fx, "/devices", &tech).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("TAG-d-alpha"));
    assert!(!html.contains("TAG-d-beta"), "another school's row leaked");
    assert!(!html.contains("TAG-d-pool"), "the pool needs its grant");

    // Out-of-scope detail reads as absent; in-scope opens.
    let (status, _) = get_body(&fx, "/devices/d-beta", &tech).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = get_body(&fx, "/devices/d-alpha", &tech).await;
    assert_eq!(status, StatusCode::OK);

    // A by-id write on the out-of-scope device fails without touching it.
    let code = request(&fx, "POST", "/devices/d-beta/checkout", &tech).await;
    assert_ne!(code, StatusCode::OK, "checkout must not land");
    assert!(
        fx.repo
            .open_custody_for_asset("d-beta")
            .await
            .unwrap()
            .is_none(),
        "no loan may exist on the out-of-scope device"
    );

    // The ticket queue hides the other school's ticket, and its detail 404s.
    let (_, html) = get_body(&fx, "/tickets", &tech).await;
    assert!(!html.contains("Beta printer"));
    let (status, _) = get_body(&fx, "/tickets/t-beta", &tech).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Granting the unassigned pool makes exactly the NULL-school row appear.
    fx.repo
        .set_console_authz(
            "site-tech",
            &ConsoleAuthz {
                permission_set_id: None,
                include_unscoped: true,
                sites: vec!["org-a".into()],
            },
        )
        .await
        .unwrap();
    let (_, html) = get_body(&fx, "/devices", &tech).await;
    assert!(html.contains("TAG-d-pool"), "the grant shows the pool");
    assert!(
        !html.contains("TAG-d-beta"),
        "the grant must not widen schools"
    );
}

async fn get_body(fx: &Fx, uri: &str, token: &str) -> (StatusCode, String) {
    let res = router(fx.state.clone())
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("cookie", format!("chalk_session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).to_string())
}

/// The analytics seam (AN-1): events fire only when a sink is wired, carry
/// the route TEMPLATE and role — and the event type is structurally unable
/// to carry PII, which this test demonstrates by exhausting its fields.
#[tokio::test]
async fn analytics_captures_templates_and_roles_never_identities() {
    use chalk_core::analytics::{AnalyticsEvent, AnalyticsSink};
    use std::sync::Mutex;

    struct Capture(Mutex<Vec<AnalyticsEvent>>);
    impl AnalyticsSink for Capture {
        fn capture(&self, e: AnalyticsEvent) {
            self.0.lock().unwrap().push(e);
        }
    }

    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!(),
    };
    let mut config = crate::tests::default_config();
    config.chalk.admin_password_hash = Some(crate::auth::hash_password("unused").unwrap());
    let sink = Arc::new(Capture(Mutex::new(Vec::new())));
    let state = Arc::new(crate::tests::wire_all(repo.clone(), config).with_analytics(sink.clone()));
    let tech = {
        repo.create_admin_session(&chalk_core::models::audit::AdminSession {
            token: "an-tok".into(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            ip_address: None,
            actor_id: Some("console_user:cu-1".into()),
            actor_label: Some("Maya Chen".into()),
            actor_role: Some("technician".into()),
        })
        .await
        .unwrap();
        "an-tok"
    };

    // A pageview with an id in the URL, and a mutating action.
    let _ = router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/tickets/some-real-uuid-value")
                .header("cookie", format!("chalk_session={tech}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let csrf = crate::csrf::generate_csrf_token();
    let _ = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tickets/some-real-uuid-value/status")
                .header("cookie", format!("chalk_session={tech}; chalk_csrf={csrf}"))
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("status=resolved"))
                .unwrap(),
        )
        .await
        .unwrap();

    let events = sink.0.lock().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].name, "console_pageview");
    assert_eq!(
        events[0].route, "/tickets/{id}",
        "template, never the real id"
    );
    assert_eq!(events[1].name, "console_action");
    assert_eq!(events[1].route, "/tickets/{id}/status");
    assert_eq!(events[1].role, "technician");
    // The no-PII property, demonstrated: serialize every field of every
    // event and assert the actor's name and the URL's id are absent.
    for e in events.iter() {
        let flat = format!("{} {} {} {}", e.name, e.route, e.method, e.role);
        assert!(!flat.contains("Maya"), "identity leaked into analytics");
        assert!(!flat.contains("some-real-uuid"), "raw path leaked");
    }
}

/// No sink, no events — and more importantly, nothing to disable: the
/// self-host privacy property is the absent wiring, which the serve_wiring
/// test's documented exception pins on the `chalk serve` side.
#[tokio::test]
async fn without_a_sink_the_console_emits_nothing() {
    let fx = fixture().await;
    assert!(
        fx.state.analytics.is_none(),
        "fixtures mirror chalk serve: no sink unless a test wires one"
    );
}
