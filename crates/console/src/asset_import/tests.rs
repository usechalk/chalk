//! CSV import screen tests.
//!
//! The property that matters most is that the upload **writes nothing**: it
//! ends on a preview, and the inventory is untouched until the operator
//! commits. After that, it is about the upload not being a trap — a body the
//! CSRF middleware silently refuses, a spreadsheet uploaded instead of a CSV,
//! a picker submitted empty.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetRepository, ChalkRepository, ChangeSetRepository, JobRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::asset::{Asset, AssetStatus};
use chalk_core::models::page::PageRequest;
use tower::ServiceExt;

use crate::router;

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fx {
    fixture_with(ChalkConfig::generate_default()).await
}

/// A fixture whose config the test chooses — used for the module gates, which
/// are config-driven by design so hosted can set them per tenant.
async fn fixture_with(config: ChalkConfig) -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    let assets: Arc<dyn AssetRepository> = repo.clone();
    let events: Arc<dyn chalk_core::db::repository::AssetEventRepository> = repo.clone();
    let jobs: Arc<dyn JobRepository> = repo.clone();
    let runs: Arc<dyn chalk_core::db::repository::GoogleDeviceSyncRepository> = repo.clone();
    let sets: Arc<dyn ChangeSetRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();

    let state = Arc::new(
        AppState::new(chalk_repo, config)
            .with_assets(assets, events)
            .with_device_sync(jobs, runs)
            .with_change_sets(sets),
    );
    Fx { state, repo }
}

async fn device(f: &Fx, id: &str, status: AssetStatus) {
    let mut a = Asset::new(id);
    a.asset_tag = Some(format!("CB-{id}"));
    a.serial_number = Some(format!("SN-{id}"));
    a.status = status;
    f.repo.create_asset(&a).await.unwrap();
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

/// A real `multipart/form-data` body, built the way a browser builds one —
/// including the `csrf_token` part the middleware scans for before the handler
/// ever runs.
fn multipart_body(boundary: &str, token: &str, filename: &str, content: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n\
             {token}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; \
             filename=\"{filename}\"\r\nContent-Type: text/csv\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

/// Upload a file and return the status plus the `Location` header.
async fn upload(state: Arc<AppState>, content: &[u8]) -> (StatusCode, String) {
    upload_named(state, "devices.csv", content).await
}

async fn upload_named(
    state: Arc<AppState>,
    filename: &str,
    content: &[u8],
) -> (StatusCode, String) {
    let token = crate::csrf::generate_csrf_token();
    let boundary = "----ChalkTestBoundary";
    let body = multipart_body(boundary, &token, filename, content);

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(IMPORT_PATH)
                .header("cookie", format!("chalk_csrf={token}"))
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, location)
}

// ---------------------------------------------------------------------------
// The upload page
// ---------------------------------------------------------------------------

/// The page has to say the two things that stop an operator building an
/// unusable file: which columns are read, and that the export writes them.
#[tokio::test]
async fn the_upload_page_names_the_columns_and_points_at_the_export() {
    let f = fixture().await;
    let (status, body) = get(f.state.clone(), IMPORT_PATH).await;
    assert_eq!(status, StatusCode::OK);

    for col in IMPORTABLE_COLUMNS {
        assert!(body.contains(col), "{col} is not named on the page");
    }
    assert!(
        body.contains("/devices/export.csv"),
        "export → edit → import is the path that works"
    );
    assert!(
        body.contains("enctype=\"multipart/form-data\""),
        "without this the browser posts filenames, not files"
    );
}

/// The page must not imply anything is about to be written. It is the sentence
/// that makes an operator willing to try it on a real fleet.
#[tokio::test]
async fn the_upload_page_says_nothing_is_changed_by_uploading() {
    let f = fixture().await;
    let (_, body) = get(f.state.clone(), IMPORT_PATH).await;
    assert!(body.contains("Nothing is changed by uploading"));
}

// ---------------------------------------------------------------------------
// The upload itself
// ---------------------------------------------------------------------------

/// The whole point: an upload ends on the preview and touches nothing.
#[tokio::test]
async fn an_upload_lands_on_a_preview_and_writes_nothing() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active).await;

    let (status, location) = upload(f.state.clone(), b"serial_number,status\nSN-a,repair\n").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location.starts_with(crate::preview::PREVIEW_PATH),
        "landed on {location}"
    );

    let after = f.repo.get_asset("a").await.unwrap().unwrap();
    assert_eq!(
        after.status,
        AssetStatus::Active,
        "the device is untouched until the operator commits"
    );
}

/// And the preview it lands on shows the change, with both values.
#[tokio::test]
async fn the_preview_it_lands_on_shows_the_proposed_change() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active).await;

    let (_, location) = upload(f.state.clone(), b"serial_number,status\nSN-a,repair\n").await;
    let (status, body) = get(f.state.clone(), &location).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("CB-a"));
    assert!(body.contains("active"), "what it holds now");
    assert!(body.contains("repair"), "what it would hold");
}

/// A row that matches nothing is announced as an addition, in words. A create
/// is the one thing in a preview that planning the opposite cannot undo.
#[tokio::test]
async fn new_devices_are_announced_on_the_preview_not_left_to_be_counted() {
    let f = fixture().await;

    let (_, location) = upload(
        f.state.clone(),
        b"serial_number,status\nSN-new,storage\nSN-other,storage\n",
    )
    .await;
    let (_, body) = get(f.state.clone(), &location).await;
    assert!(body.contains("adds 2 devices Chalk has not seen before"));
    assert!(
        body.contains("will be added"),
        "and each row says so rather than showing a blob of JSON"
    );
    assert!(
        !body.contains("\"serialNumber\""),
        "the create payload must never be rendered into a table cell"
    );
}

/// Rows the file could not use are shown beside what it will do, naming their
/// line — not flashed into a message that vanishes on reload.
#[tokio::test]
async fn rejected_rows_are_listed_on_the_preview_by_line() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active).await;

    let (_, location) = upload(
        f.state.clone(),
        b"serial_number,status\nSN-a,repair\nSN-b,exploded\n",
    )
    .await;
    let (_, body) = get(f.state.clone(), &location).await;
    assert!(body.contains("1 row could not be used"));
    assert!(body.contains("Row 3"));
    assert!(body.contains("exploded"));
    // And it survives a reload, because it lives on the change set.
    let (_, again) = get(f.state.clone(), &location).await;
    assert!(again.contains("Row 3"));
}

/// A file whose rows are all unusable must not read as a successful no-op.
/// "Every device is already in the state you asked for" would tell an operator
/// their file worked.
#[tokio::test]
async fn a_file_with_nothing_usable_does_not_claim_everything_was_correct() {
    let f = fixture().await;

    let (_, location) = upload(f.state.clone(), b"serial_number,status\nSN-a,exploded\n").await;
    let (_, body) = get(f.state.clone(), &location).await;
    assert!(body.contains("None of the rows above could be used"));
    assert!(!body.contains("already in the state you asked for"));
}

// ---------------------------------------------------------------------------
// Files that are not what they claim
// ---------------------------------------------------------------------------

/// A picker submitted empty says so, rather than planning a change set of
/// nothing and dropping the operator on a blank preview.
#[tokio::test]
async fn an_empty_upload_is_refused_with_a_reason() {
    let f = fixture().await;
    let (status, location) = upload(f.state.clone(), b"").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("err=nofile"), "landed on {location}");

    let (_, body) = get(f.state.clone(), &location).await;
    assert!(body.contains("Choose a CSV file"));
}

/// A spreadsheet or a PDF is rejected as unreadable rather than parsed as one
/// enormous single-column row, which would report four thousand unmatched
/// lines instead of "this is not a CSV".
#[tokio::test]
async fn a_binary_file_is_refused_rather_than_parsed_as_one_giant_row() {
    let f = fixture().await;
    // The XLSX magic number — a real .xlsx is a zip.
    let (status, location) = upload_named(
        f.state.clone(),
        "devices.xlsx",
        &[0x50, 0x4b, 0x03, 0x04, 0xff, 0xfe, 0x00, 0x01],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("err=notutf8"), "landed on {location}");

    let (_, body) = get(f.state.clone(), &location).await;
    assert!(body.contains("Save it as CSV"));
}

/// A file with a header and no rows is not an error, and not a change set
/// either — it is a file with nothing to do.
#[tokio::test]
async fn a_header_with_no_rows_is_reported_as_empty() {
    let f = fixture().await;
    let (status, location) = upload(f.state.clone(), b"serial_number,status\n").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("err=empty"), "landed on {location}");
}

// ---------------------------------------------------------------------------
// The cap that used to be two numbers in two files
// ---------------------------------------------------------------------------

/// The CSRF middleware buffers a multipart body before this route's own limit
/// applies, so a route limit above the middleware's cap rejects at 400 with
/// the handler never running — and the failure looks like a broken upload
/// rather than a misconfigured cap. A `const` assertion covers the two
/// existing routes; this covers the behaviour.
#[tokio::test]
async fn a_large_but_permitted_file_actually_reaches_the_handler() {
    let f = fixture().await;

    // Comfortably past the old 4 MiB middleware cap, comfortably under the
    // current one — the exact band that used to 400.
    let mut file = String::from("serial_number,status\n");
    while file.len() < 5 * 1024 * 1024 {
        file.push_str("SN-0000000000000000000000000000000000000000,storage\n");
    }
    assert!(file.len() < MAX_UPLOAD_BYTES);

    let (status, location) = upload(f.state.clone(), file.as_bytes()).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a file inside the limit must reach the handler, not 400"
    );
    assert!(location.starts_with(crate::preview::PREVIEW_PATH));
}

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

/// Upload, then commit the change set the way the job runner does, and the
/// inventory reflects the file. This is the whole arc in one test.
#[tokio::test]
async fn committing_an_uploaded_plan_changes_the_inventory() {
    let f = fixture().await;
    device(&f, "a", AssetStatus::Active).await;

    let (_, location) = upload(
        f.state.clone(),
        b"serial_number,status,location\nSN-a,repair,Room 14\nSN-new,storage,Warehouse\n",
    )
    .await;
    let id = location.rsplit('/').next().unwrap().to_string();

    let sets: Arc<dyn ChangeSetRepository> = f.repo.clone();
    let set = sets.get_change_set(&id).await.unwrap().unwrap();
    let outcome = chalk_core::change_commit::commit_change_set(
        &sets,
        &id,
        &set.plan_hash,
        set.expected_item_count,
        "console:admin",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(outcome.failed, 0);

    let changed = f.repo.get_asset("a").await.unwrap().unwrap();
    assert_eq!(changed.status, AssetStatus::Repair);
    assert_eq!(changed.location.as_deref(), Some("Room 14"));

    let made = f
        .repo
        .get_asset_by_serial("SN-new")
        .await
        .unwrap()
        .expect("the new device exists");
    assert_eq!(made.location.as_deref(), Some("Warehouse"));

    // And it is findable in the inventory, which is the operator's actual test.
    let listed = f
        .repo
        .list_assets(&Default::default(), PageRequest::new(50, 0))
        .await
        .unwrap();
    assert_eq!(listed.total, 2);
}

// ---------------------------------------------------------------------------
// Module gating (D8)
// ---------------------------------------------------------------------------

/// A tenant limited to Chromebooks keeps the Chromebook rows and is told,
/// **by line**, which others were left out.
///
/// Failing the whole file would be the easy implementation and the wrong one:
/// a district uploading a mixed inventory should get the part their plan
/// covers, plus a list they can act on.
#[tokio::test]
async fn a_restricted_plan_refuses_rows_by_line_and_keeps_the_rest() {
    let mut config = ChalkConfig::generate_default();
    config.modules.asset_types_allowed = vec!["chromebook".into()];
    let f = fixture_with(config).await;

    let (_, location) = upload(
        f.state.clone(),
        b"serial_number,asset_type\nSN-1,chromebook\nSN-2,projector\nSN-3,chromebook\n",
    )
    .await;
    let (_, body) = get(f.state.clone(), &location).await;

    assert!(
        body.contains("adds 2 devices"),
        "the two Chromebooks still import"
    );
    assert!(body.contains("1 row could not be used"));
    assert!(body.contains("Row 3"), "named by line, so it can be fixed");
    assert!(
        body.contains("only these device types: chromebook"),
        "and what the plan covers"
    );
    assert!(body.contains("projector"), "and what was refused");
}

/// With no restriction — every self-hosted install (D2) — nothing is refused.
#[tokio::test]
async fn an_unrestricted_plan_refuses_nothing() {
    let f = fixture().await;
    let (_, location) = upload(
        f.state.clone(),
        b"serial_number,asset_type\nSN-1,chromebook\nSN-2,projector\n",
    )
    .await;
    let (_, body) = get(f.state.clone(), &location).await;
    assert!(body.contains("adds 2 devices"));
    assert!(!body.contains("could not be used"));
}
