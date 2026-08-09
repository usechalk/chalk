//! The settings surfaces drive the same repo the middleware reads, so these
//! prove the full loop: build a set in the UI, assign it, and the account's
//! very next request obeys it.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::db::repository::{
    AdminSessionRepository, ConsoleUserRepository, OrgRepository, PermissionSetRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::audit::AdminSession;
use chalk_core::models::common::{OrgType, Status};
use chalk_core::models::console_user::{ConsoleRole, ConsoleUser, ConsoleUserStatus};
use chalk_core::models::org::Org;
use chrono::{Duration, Utc};
use tower::ServiceExt;

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!(),
    };
    let mut config = crate::tests::default_config();
    config.chalk.admin_password_hash = Some(crate::auth::hash_password("unused").unwrap());
    let state = Arc::new(crate::tests::wire_all(repo.clone(), config));
    // An admin to drive the pages, and a technician to point them at.
    for (id, role) in [
        ("boss", ConsoleRole::Admin),
        ("tech", ConsoleRole::Technician),
    ] {
        repo.create_console_user(&ConsoleUser {
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
    }
    repo.create_admin_session(&AdminSession {
        token: "boss-tok".into(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: None,
        actor_id: Some("console_user:boss".into()),
        actor_label: Some("boss".into()),
        actor_role: Some("admin".into()),
    })
    .await
    .unwrap();
    repo.upsert_org(&Org {
        sourced_id: "org-a".into(),
        status: Status::Active,
        date_last_modified: Utc::now(),
        metadata: None,
        name: "Alpha High".into(),
        org_type: OrgType::School,
        identifier: None,
        parent: None,
        children: vec![],
    })
    .await
    .unwrap();
    Fx { state, repo }
}

async fn post(fx: &Fx, uri: &str, body: &str) -> (StatusCode, String) {
    let csrf = crate::csrf::generate_csrf_token();
    let res = crate::router(fx.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(
                    "cookie",
                    format!("chalk_session=boss-tok; chalk_csrf={csrf}"),
                )
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let loc = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, loc)
}

async fn get_html(fx: &Fx, uri: &str) -> (StatusCode, String) {
    let res = crate::router(fx.state.clone())
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("cookie", "chalk_session=boss-tok")
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

/// Build a set with repeated checkbox keys, see it listed, and refuse junk.
#[tokio::test]
async fn a_set_builds_from_checkboxes_and_junk_is_refused() {
    let fx = fixture().await;
    let (_, loc) = post(
        &fx,
        "/settings/permission-sets",
        "name=Circulation+desk&perm=assets.view&perm=custody.view&perm=custody.manage",
    )
    .await;
    assert!(loc.contains("notice=created"), "got {loc}");
    let sets = fx.repo.list_permission_sets().await.unwrap();
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].permissions.len(), 3);

    let (_, html) = get_html(&fx, "/settings/permission-sets").await;
    assert!(html.contains("Circulation desk"));
    assert!(html.contains("custody.manage"));

    // A key this build does not know refuses the whole submission.
    let (_, loc) = post(
        &fx,
        "/settings/permission-sets",
        "name=Broken&perm=assets.teleport",
    )
    .await;
    assert!(loc.contains("notice=bad_input"));
    assert_eq!(fx.repo.list_permission_sets().await.unwrap().len(), 1);
}

/// The whole loop: assign the set + a school through the access form, and
/// the technician's next request is narrowed — then a delete is refused
/// while assigned.
#[tokio::test]
async fn assigning_access_narrows_the_account_and_pins_the_set() {
    let fx = fixture().await;
    post(
        &fx,
        "/settings/permission-sets",
        "name=Desk&perm=assets.view&perm=custody.view&perm=custody.manage",
    )
    .await;
    let set_id = fx.repo.list_permission_sets().await.unwrap()[0].id.clone();

    let (_, loc) = post(
        &fx,
        "/settings/console-users/tech/access",
        &format!("permissions={set_id}&site=org-a&include_unscoped=1"),
    )
    .await;
    assert!(loc.contains("ok="), "got {loc}");

    let authz = fx.repo.get_console_authz("tech").await.unwrap().unwrap();
    assert_eq!(authz.permission_set_id.as_deref(), Some(set_id.as_str()));
    assert_eq!(authz.sites, vec!["org-a".to_string()]);
    assert!(authz.include_unscoped);

    // The access page reflects it back.
    let (status, html) = get_html(&fx, "/settings/console-users/tech/access").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("checked"), "the granted school is ticked");

    // While assigned, the set cannot be deleted.
    let (_, loc) = post(
        &fx,
        &format!("/settings/permission-sets/{set_id}/delete"),
        "",
    )
    .await;
    assert!(loc.contains("notice=in_use"), "got {loc}");

    // Ghost set ids are refused rather than silently reverting to the role.
    let (_, loc) = post(
        &fx,
        "/settings/console-users/tech/access",
        "permissions=no-such-set",
    )
    .await;
    assert!(loc.contains("err="), "got {loc}");

    // Back to the role preset frees the set.
    post(
        &fx,
        "/settings/console-users/tech/access",
        "permissions=role",
    )
    .await;
    let (_, loc) = post(
        &fx,
        &format!("/settings/permission-sets/{set_id}/delete"),
        "",
    )
    .await;
    assert!(loc.contains("notice=deleted"), "got {loc}");
}

/// The builder speaks human: labels lead, keys stay visible as identifiers,
/// and every permission's consequence sentence renders (GP-9 watch-list #2).
#[tokio::test]
async fn the_set_builder_shows_labels_not_just_keys() {
    let fx = fixture().await;
    let (_, html) = get_html(&fx, "/settings/permission-sets").await;
    assert!(html.contains("Check devices in and out"), "label renders");
    assert!(
        html.contains("<code>custody.manage</code>"),
        "the stable key stays visible beside it"
    );
    assert!(
        html.contains("Money-out: forgive a charge"),
        "the consequence sentence renders"
    );
}
