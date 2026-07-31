//! Sync-progress tests.
//!
//! The two properties worth the most here are both about *stopping*: polling
//! must stop when the work does, and a second sync must not start while one is
//! already pending. Both fail silently in manual testing — a tab that polls
//! forever looks fine, and two concurrent syncs look like one slow one.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{ChalkRepository, GoogleDeviceSyncRepository, JobRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::device_sync::{DeviceSyncCounters, DeviceSyncMode};

use crate::router;

struct Fixture {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

async fn fixture(enabled: bool) -> Fixture {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    let mut config = ChalkConfig::generate_default();
    config.device_sync.enabled = enabled;

    let jobs: Arc<dyn JobRepository> = repo.clone();
    let runs: Arc<dyn GoogleDeviceSyncRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(AppState::new(chalk_repo, config).with_device_sync(jobs, runs));
    Fixture { state, repo }
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

async fn trigger(state: Arc<AppState>) -> StatusCode {
    let token = crate::csrf::generate_csrf_token();
    let response = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(SYNC_PATH)
                .header("cookie", format!("chalk_csrf={token}"))
                .header("x-csrf-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    response.status()
}

use tower::ServiceExt;

/// A finished run with the given counters.
async fn finished_run(f: &Fixture, seen: i64, matched: i64) {
    let run = f.repo.start_run(DeviceSyncMode::Full, false).await.unwrap();
    let counters = DeviceSyncCounters {
        devices_seen: seen,
        devices_matched: matched,
        devices_unmatched: seen - matched,
        ..Default::default()
    };
    f.repo.update_run_counters(run.id, &counters).await.unwrap();
    f.repo
        .finish_run(run.id, DeviceSyncRunStatus::Succeeded, &counters, None)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Triggering
// ---------------------------------------------------------------------------

/// The console enqueues; it does not run. That is the whole reason this crate
/// has no dependency on `chalk-devices`.
#[tokio::test]
async fn triggering_enqueues_a_job_rather_than_running_anything() {
    let f = fixture(true).await;
    assert_eq!(trigger(f.state.clone()).await, StatusCode::SEE_OTHER);

    let queued = f
        .repo
        .list_jobs(
            &JobFilter {
                kind: Some(JobKind::GoogleDeviceSync),
                status: Some(JobStatus::Queued),
            },
            PageRequest::new(10, 0),
        )
        .await
        .unwrap();
    assert_eq!(queued.total, 1, "exactly one job was queued");
}

/// Two concurrent full syncs would race on the same resume cursor and each
/// would see the other's partial writes. A second request must be refused,
/// not queued.
#[tokio::test]
async fn a_second_sync_is_refused_while_one_is_pending() {
    let f = fixture(true).await;
    trigger(f.state.clone()).await;
    trigger(f.state.clone()).await;
    trigger(f.state.clone()).await;

    let all = f
        .repo
        .list_jobs(
            &JobFilter {
                kind: Some(JobKind::GoogleDeviceSync),
                ..Default::default()
            },
            PageRequest::new(10, 0),
        )
        .await
        .unwrap();
    assert_eq!(all.total, 1, "the extra requests must not have queued jobs");

    let (_, body) = get(f.state.clone(), &format!("{SYNC_PATH}?notice=already")).await;
    assert!(body.contains("already queued or running"));
}

/// A claimed job still counts as pending. Without this the page would offer a
/// second sync the moment the worker picked the first one up.
#[tokio::test]
async fn a_running_job_still_blocks_a_new_one() {
    let f = fixture(true).await;
    trigger(f.state.clone()).await;

    let job = f
        .repo
        .next_claimable(Utc::now())
        .await
        .unwrap()
        .expect("a job is queued");
    assert!(f.repo.claim(&job.id, Utc::now()).await.unwrap());

    trigger(f.state.clone()).await;
    let all = f
        .repo
        .list_jobs(
            &JobFilter {
                kind: Some(JobKind::GoogleDeviceSync),
                ..Default::default()
            },
            PageRequest::new(10, 0),
        )
        .await
        .unwrap();
    assert_eq!(all.total, 1);
}

// ---------------------------------------------------------------------------
// Polling stops
// ---------------------------------------------------------------------------

/// The property that is invisible in manual testing: a finished sync must
/// leave a static page. Emitting `hx-trigger` unconditionally would leave every
/// open tab requesting this fragment every two seconds until it is closed.
#[tokio::test]
async fn polling_stops_once_the_work_is_done() {
    let f = fixture(true).await;
    finished_run(&f, 5000, 4812).await;

    let (status, body) = get(f.state.clone(), SYNC_PATH).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("hx-trigger"),
        "a finished sync must not keep polling"
    );
}

/// And it does poll while work is pending, or the counters would never move.
#[tokio::test]
async fn polling_runs_while_work_is_pending() {
    let f = fixture(true).await;
    trigger(f.state.clone()).await;

    let (_, body) = get(f.state.clone(), SYNC_PATH).await;
    assert!(body.contains(r#"hx-trigger="every 2s""#));
    assert!(body.contains("/devices/sync/status"));
}

// ---------------------------------------------------------------------------
// What the page says
// ---------------------------------------------------------------------------

/// The sentence the whole module exists to produce. "5,000 records processed"
/// would be true and worthless — the count that matters is the one a
/// device-only asset tracker cannot produce at all.
#[tokio::test]
async fn a_finished_sync_leads_with_devices_matched_to_students() {
    let f = fixture(true).await;
    finished_run(&f, 5000, 4812).await;

    let (_, body) = get(f.state.clone(), SYNC_PATH).await;
    assert!(body.contains("4,812 of 5,000 devices matched to students"));
    assert!(
        body.contains("188 devices need a person"),
        "the remainder is linked, not hidden"
    );
}

/// A run whose worker died is reported as interrupted, not left spinning. The
/// row can never be closed by anyone, so a spinner would run forever — exactly
/// the failure this module exists not to imitate.
#[tokio::test]
async fn an_abandoned_run_reads_as_interrupted_rather_than_running() {
    let f = fixture(true).await;
    let run = f.repo.start_run(DeviceSyncMode::Full, false).await.unwrap();

    // Fresh: in progress.
    let fresh = RunView::new(&run, run.started_at);
    assert!(fresh.in_progress);
    assert_eq!(fresh.status_label, "Running");

    // Past the liveness window: interrupted, and no longer polling.
    let stale = RunView::new(&run, run.started_at + LIVENESS + Duration::minutes(1));
    assert!(!stale.in_progress, "polling must stop for a dead run");
    assert_eq!(stale.status_label, "Interrupted");
}

/// Nothing has run yet — say so, and explain what the first sync does.
#[tokio::test]
async fn a_fresh_install_says_no_sync_has_run() {
    let f = fixture(true).await;
    let (status, body) = get(f.state.clone(), SYNC_PATH).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No sync has run yet"));
    assert!(!body.contains("hx-trigger"), "nothing to poll for");
}

/// With no credentials the button is disabled and points at the connect page,
/// rather than queueing work that can only fail.
#[tokio::test]
async fn without_a_connection_the_button_points_at_setup() {
    let f = fixture(false).await;
    let (_, body) = get(f.state.clone(), SYNC_PATH).await;
    assert!(body.contains("disabled"));
    assert!(body.contains("/devices/connect"));

    assert_eq!(trigger(f.state.clone()).await, StatusCode::SEE_OTHER);
    let all = f
        .repo
        .list_jobs(&JobFilter::default(), PageRequest::new(10, 0))
        .await
        .unwrap();
    assert_eq!(all.total, 0, "an unconfigured trigger must queue nothing");
}

/// §5.3 requires recording throttling. This is where it becomes an answer to
/// "why was the sync slow" instead of a mystery someone escalates.
#[tokio::test]
async fn throttling_is_visible_in_the_run_history() {
    let f = fixture(true).await;
    // Two runs, so one lands in history rather than as the headline.
    finished_run(&f, 10, 10).await;
    let run = f.repo.start_run(DeviceSyncMode::Full, false).await.unwrap();
    let counters = DeviceSyncCounters {
        devices_seen: 100,
        devices_matched: 90,
        api_calls: 12,
        throttle_events: 4,
        ..Default::default()
    };
    f.repo.update_run_counters(run.id, &counters).await.unwrap();
    f.repo
        .finish_run(run.id, DeviceSyncRunStatus::Succeeded, &counters, None)
        .await
        .unwrap();

    let (_, body) = get(f.state.clone(), SYNC_PATH).await;
    assert!(body.contains("Earlier syncs"));
    assert!(
        body.contains("Slowed by Google") || body.contains("rate-limit pauses"),
        "throttling must be visible, not buried in a counter nobody reads"
    );
}

/// The notice is a closed set of codes. Text from the query string must never
/// reach the page — a crafted link could otherwise tell a signed-in
/// administrator something untrue about their fleet.
#[tokio::test]
async fn arbitrary_notice_text_is_not_rendered() {
    let f = fixture(true).await;
    let (status, body) = get(
        f.state.clone(),
        &format!("{SYNC_PATH}?notice=Your+fleet+was+deleted+call+555-0100"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("555-0100"));
    assert!(!body.contains("deleted"));
}

#[test]
fn known_notice_codes_map_to_text_and_unknown_ones_to_nothing() {
    for code in ["queued", "already", "disabled", "checkfailed", "failed"] {
        let q = NoticeQuery {
            notice: code.to_string(),
        };
        assert!(!q.message().is_empty(), "{code} has no message");
    }
    assert_eq!(
        NoticeQuery {
            notice: "anything else".into()
        }
        .message(),
        ""
    );
}

/// Zero devices seen must not render "0 of 0 matched", which reads as a
/// failure when it usually means the run has only just started.
#[test]
fn a_run_with_nothing_seen_yet_says_so() {
    let run = DeviceSyncRun {
        id: 1,
        started_at: Utc::now(),
        completed_at: None,
        status: DeviceSyncRunStatus::Running,
        mode: DeviceSyncMode::Full,
        counters: DeviceSyncCounters::default(),
        dry_run: false,
        error_message: None,
    };
    assert_eq!(
        RunView::new(&run, Utc::now()).headline(),
        "No devices seen yet."
    );
}
