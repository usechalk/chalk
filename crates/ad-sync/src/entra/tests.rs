//! Entra provisioning tests against a mocked Graph API and a real
//! sqlite-memory repository. The discipline under test is the AD sync's:
//! a run row around every sync, hash-gated deltas, adoption before creation,
//! departures disabled once, and a secret that never reaches an error.

use super::*;

use chalk_core::db::repository::{
    EntraSyncRunRepository, EntraSyncStateRepository, UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::common::RoleType;
use chrono::TimeZone;
use wiremock::matchers::{body_string_contains, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn repo() -> Arc<SqliteRepository> {
    match DatabasePool::new_sqlite_memory().await.unwrap() {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    }
}

fn config(server: &MockServer) -> EntraConfig {
    EntraConfig {
        enabled: true,
        tenant_id: "t-1".into(),
        client_id: "app-1".into(),
        client_secret: "app-secret".into(),
        domain: "district.org".into(),
        base_url: Some(server.uri()),
    }
}

fn roster_user(sourced_id: &str, username: &str, given: &str, family: &str) -> User {
    User {
        sourced_id: sourced_id.into(),
        status: Status::Active,
        date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        metadata: None,
        username: username.into(),
        user_ids: vec![],
        enabled_user: true,
        given_name: given.into(),
        family_name: family.into(),
        middle_name: None,
        role: RoleType::Student,
        identifier: None,
        email: Some(format!("{username}@district.org")),
        sms: None,
        phone: None,
        agents: vec![],
        orgs: vec![],
        grades: vec![],
    }
}

async fn mount_token(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/t-1/oauth2/v2.0/token"))
        .and(body_string_contains("client_credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "graph-token", "expires_in": 3599
        })))
        .mount(server)
        .await;
}

fn engine(repo: &Arc<SqliteRepository>, server: &MockServer) -> EntraSyncEngine<SqliteRepository> {
    let cfg = config(server);
    EntraSyncEngine::new(repo.clone(), GraphClient::new(cfg.clone()), cfg)
}

/// First contact: an unknown roster user with no existing Graph account is
/// created, state lands with the object id, and the run row records it.
#[tokio::test]
async fn a_first_sync_creates_and_records_state() {
    let repo = repo().await;
    repo.upsert_user(&roster_user("u-1", "Maya.Chen", "Maya", "Chen"))
        .await
        .unwrap();
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path("/v1.0/users/maya.chen@district.org"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1.0/users"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "obj-1", "accountEnabled": true
        })))
        .mount(&server)
        .await;

    let summary = engine(&repo, &server).run_sync(false).await.unwrap();
    assert_eq!(summary.users_created, 1);
    assert_eq!(summary.errors, 0);

    let state = repo.get_entra_sync_state("u-1").await.unwrap().unwrap();
    assert_eq!(state.entra_object_id, "obj-1");
    assert_eq!(state.upn, "maya.chen@district.org", "UPN is lowercased");
    assert_eq!(state.sync_status, EntraSyncStatus::Synced);

    let run = repo.get_latest_entra_sync_run().await.unwrap().unwrap();
    assert_eq!(run.status, EntraRunStatus::Completed);
    assert_eq!(run.users_created, 1);

    // The create body carried the essentials.
    let create = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.method == wiremock::http::Method::POST && r.url.path() == "/v1.0/users")
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&create.body).unwrap();
    assert_eq!(body["userPrincipalName"], "maya.chen@district.org");
    assert_eq!(body["accountEnabled"], true);
    assert_eq!(
        body["passwordProfile"]["forceChangePasswordNextSignIn"],
        true
    );
}

/// An account that already exists under the UPN is adopted and updated in
/// place — never a colliding create.
#[tokio::test]
async fn a_preexisting_account_is_adopted_not_duplicated() {
    let repo = repo().await;
    repo.upsert_user(&roster_user("u-1", "maya.chen", "Maya", "Chen"))
        .await
        .unwrap();
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path("/v1.0/users/maya.chen@district.org"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "obj-existing", "accountEnabled": true
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/v1.0/users/obj-existing"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let summary = engine(&repo, &server).run_sync(false).await.unwrap();
    assert_eq!(summary.users_created, 1, "adoption counts as provisioning");
    let state = repo.get_entra_sync_state("u-1").await.unwrap().unwrap();
    assert_eq!(state.entra_object_id, "obj-existing");
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.method == wiremock::http::Method::POST && r.url.path() == "/v1.0/users"),
        "no create was attempted"
    );
}

/// The hash gate: an unchanged user is skipped without a single Graph call;
/// a renamed user is patched.
#[tokio::test]
async fn a_second_sync_skips_unchanged_and_patches_changed() {
    let repo = repo().await;
    repo.upsert_user(&roster_user("u-1", "maya.chen", "Maya", "Chen"))
        .await
        .unwrap();
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v1.0/users/maya\.chen@district\.org$"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1.0/users"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "obj-1"
        })))
        .mount(&server)
        .await;
    let eng = engine(&repo, &server);
    eng.run_sync(false).await.unwrap();

    // Unchanged: skipped, and the only new request is the token.
    let before = server.received_requests().await.unwrap().len();
    let summary = eng.run_sync(false).await.unwrap();
    assert_eq!(summary.users_skipped, 1);
    assert_eq!(summary.users_updated, 0);
    let after = server.received_requests().await.unwrap().len();
    assert_eq!(after - before, 1, "only the token call");

    // Renamed: patched.
    repo.upsert_user(&roster_user("u-1", "maya.chen", "Maya", "Chen-Lopez"))
        .await
        .unwrap();
    Mock::given(method("PATCH"))
        .and(path("/v1.0/users/obj-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let summary = eng.run_sync(false).await.unwrap();
    assert_eq!(summary.users_updated, 1);
}

/// A departure is disabled exactly once: the PATCH flips accountEnabled off,
/// the state records Disabled, and the next run does not touch it again.
#[tokio::test]
async fn a_departed_user_is_disabled_once() {
    let repo = repo().await;
    let mut u = roster_user("u-1", "maya.chen", "Maya", "Chen");
    repo.upsert_user(&u).await.unwrap();
    let now = Utc::now();
    repo.upsert_entra_sync_state(&EntraUserState {
        user_sourced_id: "u-1".into(),
        entra_object_id: "obj-1".into(),
        upn: "maya.chen@district.org".into(),
        field_hash: compute_field_hash(&u),
        sync_status: EntraSyncStatus::Synced,
        last_synced_at: Some(now),
        created_at: now,
        updated_at: now,
    })
    .await
    .unwrap();
    // She leaves the district.
    u.status = Status::ToBeDeleted;
    repo.upsert_user(&u).await.unwrap();

    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("PATCH"))
        .and(path("/v1.0/users/obj-1"))
        .and(body_string_contains("false"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let eng = engine(&repo, &server);
    let summary = eng.run_sync(false).await.unwrap();
    assert_eq!(summary.users_disabled, 1);
    let state = repo.get_entra_sync_state("u-1").await.unwrap().unwrap();
    assert_eq!(state.sync_status, EntraSyncStatus::Disabled);

    let before = server.received_requests().await.unwrap().len();
    let summary = eng.run_sync(false).await.unwrap();
    assert_eq!(summary.users_disabled, 0, "not disabled twice");
    let after = server.received_requests().await.unwrap().len();
    assert_eq!(after - before, 1, "only the token call");
}

/// A dry run counts the work and contacts nothing — not even the token
/// endpoint.
#[tokio::test]
async fn a_dry_run_counts_and_contacts_nothing() {
    let repo = repo().await;
    repo.upsert_user(&roster_user("u-1", "maya.chen", "Maya", "Chen"))
        .await
        .unwrap();
    let server = MockServer::start().await;

    let summary = engine(&repo, &server).run_sync(true).await.unwrap();
    assert_eq!(summary.users_created, 1, "counted");
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "nothing was sent"
    );
    assert!(
        repo.get_entra_sync_state("u-1").await.unwrap().is_none(),
        "nothing was recorded"
    );
    let run = repo.get_latest_entra_sync_run().await.unwrap().unwrap();
    assert!(run.dry_run, "except the run row, which says dry run");
}

/// A refused token fails the run without echoing the client secret, and the
/// run row records the failure.
#[tokio::test]
async fn a_refused_token_does_not_echo_the_secret() {
    let repo = repo().await;
    repo.upsert_user(&roster_user("u-1", "maya.chen", "Maya", "Chen"))
        .await
        .unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/t-1/oauth2/v2.0/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_client", "error_description": "secret app-secret is wrong"
        })))
        .mount(&server)
        .await;

    let err = engine(&repo, &server).run_sync(false).await.unwrap_err();
    assert!(
        !err.to_string().contains("app-secret"),
        "no secret in errors"
    );
    let run = repo.get_latest_entra_sync_run().await.unwrap().unwrap();
    assert_eq!(run.status, EntraRunStatus::Failed);
    assert!(!run.error_details.unwrap_or_default().contains("app-secret"));
}

/// One user failing does not sink the run: the error is counted with its
/// detail, the state marks Error with an empty hash so the next run retries,
/// and the other users still provision.
#[tokio::test]
async fn a_per_user_failure_is_isolated_and_retried() {
    let repo = repo().await;
    repo.upsert_user(&roster_user("u-ok", "devon.price", "Devon", "Price"))
        .await
        .unwrap();
    repo.upsert_user(&roster_user("u-bad", "bad.upn", "Bad", "Upn"))
        .await
        .unwrap();
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v1.0/users/.*@district\.org$"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1.0/users"))
        .and(body_string_contains("devon.price"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": "obj-ok"})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1.0/users"))
        .and(body_string_contains("bad.upn"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;

    let summary = engine(&repo, &server).run_sync(false).await.unwrap();
    assert_eq!(summary.users_created, 1, "the good one landed");
    assert_eq!(summary.errors, 1);
    assert!(summary
        .error_details
        .as_deref()
        .unwrap_or_default()
        .contains("u-bad"));

    let bad = repo.get_entra_sync_state("u-bad").await.unwrap().unwrap();
    assert_eq!(bad.sync_status, EntraSyncStatus::Error);
    assert!(bad.field_hash.is_empty(), "an empty hash forces a retry");
}
