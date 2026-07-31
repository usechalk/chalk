//! Connect-page tests.
//!
//! The credential is the sensitive thing on this screen, so most of these are
//! about what does *not* happen: the key is never rendered, an unreadable key
//! is never mistaken for an absent one, and a bad upload is refused before it
//! reaches storage rather than at 4am inside a scheduled sync.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{ChalkRepository, TenantConfigRepo};
use chalk_core::db::sealing::SealingConfigRepo;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use tower::ServiceExt;

use crate::router;

const MASTER_KEY: [u8; 32] = [11u8; 32];

struct Fixture {
    state: Arc<AppState>,
    /// The sealing repo, for arranging state the way the console would.
    config: Arc<dyn TenantConfigRepo>,
    /// The unsealed repo, for asserting what actually reaches storage.
    raw: Arc<SqliteRepository>,
}

async fn fixture() -> Fixture {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    let config: Arc<dyn TenantConfigRepo> =
        Arc::new(SealingConfigRepo::new(repo.clone(), MASTER_KEY));
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, ChalkConfig::generate_default())
            .with_tenant_config(config.clone()),
    );
    Fixture {
        state,
        config,
        raw: repo,
    }
}

/// A realistic service-account key. The private key is a marker string rather
/// than a real PEM — nothing here parses it, and a test fixture holding
/// something that looks like a usable credential is its own hazard.
fn key_json() -> Vec<u8> {
    br#"{"type":"service_account","project_id":"chalk-test",
         "private_key_id":"abc123",
         "private_key":"-----BEGIN PRIVATE KEY-----\nNOT-A-REAL-KEY\n-----END PRIVATE KEY-----\n",
         "client_email":"chalk-sync@chalk-test.iam.gserviceaccount.com",
         "client_id":"109876543210987654321"}"#
        .to_vec()
}

async fn get(state: Arc<AppState>, uri: &str) -> (StatusCode, String) {
    let response = router(state)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn save(f: &Fixture, key: Option<Vec<u8>>, admin_email: &str) {
    f.config
        .put_device_config(
            DeviceConfigRecord {
                enabled: true,
                customer_id: Some("my_customer".into()),
                admin_email: Some(admin_email.into()),
                service_account_key: key,
                ..Default::default()
            },
            "test",
        )
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// What the page never shows
// ---------------------------------------------------------------------------

/// The private key must never reach the browser, in any encoding. Everything
/// else on this page is arranged around that.
#[tokio::test]
async fn the_stored_key_is_never_rendered() {
    let f = fixture().await;
    save(&f, Some(key_json()), "admin@example.edu").await;

    let (status, body) = get(f.state.clone(), CONNECT_PATH).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("NOT-A-REAL-KEY"));
    assert!(!body.contains("BEGIN PRIVATE KEY"));
    assert!(!body.contains("private_key"));
    assert!(!body.contains("abc123"), "not even the key id");

    // What it *does* show: the identity, so an operator can tell which key.
    assert!(body.contains("chalk-sync@chalk-test.iam.gserviceaccount.com"));
    assert!(body.contains("On file"));
}

/// The values Google's delegation form asks for come from the key Chalk holds,
/// so nobody has to open the JSON file they downloaded once.
#[tokio::test]
async fn the_delegation_panel_shows_the_client_id_and_the_exact_scopes() {
    let f = fixture().await;
    save(&f, Some(key_json()), "admin@example.edu").await;

    let (_, body) = get(f.state.clone(), CONNECT_PATH).await;
    assert!(body.contains("109876543210987654321"), "the client ID");
    for scope in DEVICE_SYNC_READ_SCOPES {
        assert!(body.contains(scope), "missing scope {scope}");
    }
    // Comma-joined, which is the shape Google's form wants pasted.
    assert!(body.contains(&DEVICE_SYNC_READ_SCOPES.join(",")));
    assert!(body.contains("Domain-wide delegation"));
}

/// Every scope requested is a `.readonly` variant, and the page says so. A
/// district reviewing this screen is deciding how much access to grant.
#[tokio::test]
async fn every_advertised_scope_is_read_only() {
    let f = fixture().await;
    save(&f, Some(key_json()), "admin@example.edu").await;

    let (_, body) = get(f.state.clone(), CONNECT_PATH).await;
    for scope in DEVICE_SYNC_READ_SCOPES {
        assert!(
            scope.ends_with(".readonly"),
            "{scope} is not read-only, but this page claims all three are"
        );
    }
    assert!(body.contains("read-only"));
    assert!(body.contains("never writes to Google"));
}

/// Before a key exists the page says what to do rather than showing an empty
/// delegation panel that looks broken.
#[tokio::test]
async fn with_no_key_the_page_explains_what_is_needed() {
    let f = fixture().await;

    let (status, body) = get(f.state.clone(), CONNECT_PATH).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Upload a key above and save"));
    assert!(
        !body.contains("Test connection"),
        "there is nothing to test yet"
    );
}

/// A stored key that cannot be read — a wrong master key after a restore — must
/// be reported as a problem, not as an absent key. "No key" would invite an
/// operator to overwrite a credential that is merely unreadable.
#[tokio::test]
async fn an_unreadable_key_is_reported_rather_than_shown_as_missing() {
    let f = fixture().await;
    save(
        &f,
        Some(b"{\"not\":\"a service account\"}".to_vec()),
        "admin@example.edu",
    )
    .await;

    let (_, body) = get(f.state.clone(), CONNECT_PATH).await;
    assert!(body.contains("Chalk cannot read it"));
    assert!(body.contains("chalk.key"), "names the likely cause");
    assert!(
        !body.contains("Test connection"),
        "testing a key we cannot parse would report a confusing failure"
    );
}

// ---------------------------------------------------------------------------
// Saving
// ---------------------------------------------------------------------------

fn multipart_body(boundary: &str, key: Option<&[u8]>, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in extra {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                .as_bytes(),
        );
    }
    if let Some(bytes) = key {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; \
                 name=\"service_account_key_file\"; filename=\"key.json\"\r\n\
                 Content-Type: application/json\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

async fn post_form(state: Arc<AppState>, key: Option<&[u8]>, extra: &[(&str, &str)]) -> StatusCode {
    let boundary = "----chalktest";
    let token = crate::csrf::generate_csrf_token();
    let response = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(CONNECT_PATH)
                .header("cookie", format!("chalk_csrf={token}"))
                .header("x-csrf-token", &token)
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart_body(boundary, key, extra)))
                .unwrap(),
        )
        .await
        .unwrap();
    response.status()
}

/// The saved key reaches storage **sealed**, not as the JSON that was uploaded.
#[tokio::test]
async fn an_uploaded_key_is_stored_sealed() {
    let f = fixture().await;
    let status = post_form(
        f.state.clone(),
        Some(&key_json()),
        &[("enabled", "true"), ("admin_email", "admin@example.edu")],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // Through the console's own repo: the plaintext key.
    let via_console = f.config.get_device_config().await.unwrap().unwrap();
    assert_eq!(
        via_console.service_account_key.as_deref(),
        Some(&key_json()[..])
    );

    // Straight from the table: not the plaintext.
    let stored = f
        .raw
        .get_device_config()
        .await
        .unwrap()
        .unwrap()
        .service_account_key
        .expect("a key is on file");
    assert_ne!(stored, key_json(), "the database is holding plaintext");
    assert!(!stored.windows(11).any(|w| w == b"private_key"));
}

/// A bad upload is refused before it is stored. An operator can fix it now,
/// while the file is still open — rather than discovering it at 4am when a
/// scheduled sync fails.
#[tokio::test]
async fn a_file_that_is_not_a_service_account_key_is_refused_before_storage() {
    let f = fixture().await;

    for junk in [
        &br#"{"type":"authorized_user","client_id":"x"}"#[..],
        b"not json at all",
        b"",
    ] {
        let status = post_form(
            f.state.clone(),
            if junk.is_empty() { None } else { Some(junk) },
            &[("enabled", "true"), ("admin_email", "a@b.edu")],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "redirects with a message");
    }

    // The empty upload is "no file", which legitimately saves the other
    // fields — but no key was ever written.
    let stored = f.config.get_device_config().await.unwrap();
    assert!(
        stored
            .map(|c| c.service_account_key)
            .unwrap_or(None)
            .is_none(),
        "no junk file may reach storage"
    );
}

/// A rejected upload must not destroy the key already on file. An operator
/// who grabs the wrong JSON out of their downloads folder should lose nothing
/// — and this is the path where an over-eager "clear then write" would quietly
/// take a working credential with it.
#[tokio::test]
async fn a_rejected_upload_leaves_the_existing_key_untouched() {
    let f = fixture().await;
    save(&f, Some(key_json()), "admin@example.edu").await;

    let status = post_form(
        f.state.clone(),
        Some(br#"{"type":"authorized_user","client_id":"x"}"#),
        &[("enabled", "true"), ("admin_email", "admin@example.edu")],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let after = f.config.get_device_config().await.unwrap().unwrap();
    assert_eq!(
        after.service_account_key.as_deref(),
        Some(&key_json()[..]),
        "the working key was replaced or cleared by a rejected upload"
    );
}

/// Saving without choosing a file keeps the existing key. Re-uploading a
/// credential to change a schedule would be an absurd thing to require.
#[tokio::test]
async fn saving_without_choosing_a_file_keeps_the_existing_key() {
    let f = fixture().await;
    save(&f, Some(key_json()), "admin@example.edu").await;

    post_form(
        f.state.clone(),
        None,
        &[
            ("enabled", "true"),
            ("admin_email", "someone-else@example.edu"),
            ("sync_schedule", "0 5 * * *"),
        ],
    )
    .await;

    let after = f.config.get_device_config().await.unwrap().unwrap();
    assert_eq!(after.service_account_key.as_deref(), Some(&key_json()[..]));
    assert_eq!(
        after.admin_email.as_deref(),
        Some("someone-else@example.edu")
    );
    assert_eq!(after.sync_schedule.as_deref(), Some("0 5 * * *"));
}

/// Clearing removes it. The control exists so a district can revoke access from
/// the console rather than by editing the database.
#[tokio::test]
async fn clearing_removes_the_stored_key() {
    let f = fixture().await;
    save(&f, Some(key_json()), "admin@example.edu").await;

    post_form(
        f.state.clone(),
        None,
        &[
            ("enabled", "false"),
            ("admin_email", "admin@example.edu"),
            ("clear_key", "true"),
        ],
    )
    .await;

    let after = f.config.get_device_config().await.unwrap().unwrap();
    assert_eq!(after.service_account_key, None);
    assert!(!after.enabled);
}

/// Nonsense numbers fall back rather than being stored. A page size of zero
/// would ask Google for empty pages forever.
#[test]
fn only_positive_numbers_are_accepted() {
    assert_eq!(positive("200".into()), Some(200));
    assert_eq!(positive("  50 ".into()), Some(50));
    assert_eq!(positive("0".into()), None);
    assert_eq!(positive("-5".into()), None);
    assert_eq!(positive("".into()), None);
    assert_eq!(positive("lots".into()), None);
}

// ---------------------------------------------------------------------------
// Test connection
// ---------------------------------------------------------------------------

/// Every failure names a cause and a remedy. "Connection failed" would leave an
/// administrator guessing between four different mistakes, all of them common.
#[test]
fn every_diagnosis_names_something_to_do() {
    let cases = [
        "unauthorized_client: Client is unauthorized",
        "403 Forbidden: insufficientPermissions",
        "invalid_grant: account not found",
        "connection refused",
    ];
    for error in cases {
        let r = diagnose(error, "admin@example.edu");
        assert!(!r.ok);
        assert!(!r.headline.is_empty());
        assert!(
            !r.remedy.is_empty(),
            "no remedy offered for {error:?} — the operator is left guessing"
        );
    }
}

/// The two failures that matter are indistinguishable by status code — Google
/// answers 403 both for "delegation was never granted" and for "granted, but
/// not these scopes" — so they must not produce the same advice.
#[tokio::test]
async fn a_missing_delegation_and_a_missing_scope_read_differently() {
    let missing_grant = diagnose("unauthorized_client", "a@b.edu");
    let missing_scope = diagnose("403 Forbidden: insufficientPermissions", "a@b.edu");

    assert_ne!(missing_grant.headline, missing_scope.headline);
    assert!(missing_grant.remedy.contains("Domain-wide delegation"));
    assert!(
        missing_scope.remedy.contains("scope"),
        "a granted-but-incomplete delegation must point at the scope list"
    );
}

/// Testing before anything is saved says so plainly instead of reporting a
/// connection failure that would send someone looking at Google.
#[tokio::test]
async fn testing_with_nothing_configured_says_there_is_nothing_to_test() {
    let f = fixture().await;
    let token = crate::csrf::generate_csrf_token();
    let response = router(f.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/connect/test")
                .header("cookie", format!("chalk_csrf={token}"))
                .header("x-csrf-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes).to_string();

    assert!(body.contains("Nothing to test yet"));
    assert!(body.contains("Upload a service-account key"));
}

/// A key with no administrator cannot be tested: delegation works by acting as
/// a real person, and saying that is more useful than a Google error.
#[tokio::test]
async fn testing_without_an_admin_email_explains_why() {
    let f = fixture().await;
    save(&f, Some(key_json()), "").await;

    let token = crate::csrf::generate_csrf_token();
    let response = router(f.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/devices/connect/test")
                .header("cookie", format!("chalk_csrf={token}"))
                .header("x-csrf-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes).to_string();

    assert!(body.contains("No administrator to impersonate"));
    assert!(body.contains("super-admin"));
}
