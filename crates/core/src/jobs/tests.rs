//! Runner tests.
//!
//! `tick()` is deliberately separate from the loop so the whole protocol can be
//! driven without a clock or a spawned task. Every test here is a single tick
//! against a real SQLite repository — the claim protocol is SQL, so a mock of
//! it would be testing the mock.

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::db::sqlite::SqliteRepository;
use crate::db::DatabasePool;
use crate::error::ChalkError;
use crate::models::job::NewJob;

async fn repo() -> Arc<SqliteRepository> {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    }
}

/// Records every job it is handed, and fails on demand.
struct SpyHandler {
    kind: JobKind,
    calls: Mutex<Vec<(String, i64)>>,
    /// Number of leading calls that should fail.
    fail_first: AtomicUsize,
}

impl SpyHandler {
    fn new(kind: JobKind) -> Arc<Self> {
        Arc::new(Self {
            kind,
            calls: Mutex::new(Vec::new()),
            fail_first: AtomicUsize::new(0),
        })
    }

    fn failing(kind: JobKind, times: usize) -> Arc<Self> {
        let h = Self::new(kind);
        h.fail_first.store(times, Ordering::SeqCst);
        h
    }

    /// `(job id, attempt)` for every call, in order.
    fn calls(&self) -> Vec<(String, i64)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl JobHandler for SpyHandler {
    fn kind(&self) -> JobKind {
        self.kind
    }

    async fn run(&self, job: &Job) -> Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push((job.id.clone(), job.attempt));
        let remaining = self.fail_first.load(Ordering::SeqCst);
        if remaining > 0 {
            self.fail_first.store(remaining - 1, Ordering::SeqCst);
            return Err(ChalkError::Sync("handler failed".into()));
        }
        Ok(())
    }
}

#[tokio::test]
async fn an_empty_queue_is_idle() {
    let repo = repo().await;
    let runner = JobRunner::new(repo.clone());
    assert_eq!(runner.tick().await.unwrap(), Tick::Idle);
}

#[tokio::test]
async fn a_job_is_claimed_run_and_marked_succeeded() {
    let repo = repo().await;
    let handler = SpyHandler::new(JobKind::GoogleDeviceSync);
    let runner = JobRunner::new(repo.clone()).register(handler.clone());

    let job = repo
        .enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
        .await
        .unwrap();
    assert_eq!(runner.tick().await.unwrap(), Tick::Succeeded);

    assert_eq!(handler.calls().len(), 1);
    let done = repo.get_job(&job.id).await.unwrap().unwrap();
    assert_eq!(done.status, JobStatus::Succeeded);
    assert_eq!(done.attempt, 1);
    assert!(done.finished_at.is_some());
    assert_eq!(done.last_error, None);

    // And the queue is empty again.
    assert_eq!(runner.tick().await.unwrap(), Tick::Idle);
}

/// The handler sees the attempt number *after* the claim spent it, so a retry
/// can behave differently from a first try.
#[tokio::test]
async fn the_handler_sees_the_attempt_it_is_actually_on() {
    let repo = repo().await;
    let handler = SpyHandler::new(JobKind::GoogleDeviceSync);
    let runner = JobRunner::new(repo.clone()).register(handler.clone());

    repo.enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
        .await
        .unwrap();
    runner.tick().await.unwrap();

    assert_eq!(handler.calls()[0].1, 1, "first run is attempt 1, not 0");
}

/// A failure with budget left goes back on the queue, delayed, and runs again.
#[tokio::test]
async fn a_retryable_failure_is_requeued_and_eventually_succeeds() {
    let repo = repo().await;
    let handler = SpyHandler::failing(JobKind::GoogleDeviceSync, 1);
    let runner = JobRunner::new(repo.clone())
        .register(handler.clone())
        // Zero delay so the second tick can claim it immediately.
        .with_retry_delay(Duration::zero());

    let job = repo
        .enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
        .await
        .unwrap();
    assert_eq!(job.max_attempts, 3, "a read-only kind retries");

    assert_eq!(runner.tick().await.unwrap(), Tick::Requeued);
    let after_fail = repo.get_job(&job.id).await.unwrap().unwrap();
    assert_eq!(after_fail.status, JobStatus::Queued);
    assert_eq!(after_fail.attempt, 1, "the attempt is not refunded");
    assert!(
        after_fail
            .last_error
            .as_deref()
            .unwrap()
            .contains("handler failed"),
        "the handler's own message must survive into the row an operator reads"
    );

    assert_eq!(runner.tick().await.unwrap(), Tick::Succeeded);
    assert_eq!(handler.calls().len(), 2);
    assert_eq!(
        handler.calls()[1].1,
        2,
        "the second run knows it is a retry"
    );
    assert_eq!(
        repo.get_job(&job.id).await.unwrap().unwrap().status,
        JobStatus::Succeeded
    );
}

/// The property that makes at-most-once real: a Google-writing job gets one
/// attempt, and a failure is terminal rather than retried.
#[tokio::test]
async fn a_google_writing_job_is_never_retried_after_failing() {
    let repo = repo().await;
    let handler = SpyHandler::failing(JobKind::ChangeSetCommit, 5);
    let runner = JobRunner::new(repo.clone())
        .register(handler.clone())
        .with_retry_delay(Duration::zero());

    let job = repo
        .enqueue(&NewJob::now(JobKind::ChangeSetCommit))
        .await
        .unwrap();
    assert_eq!(job.max_attempts, 1);

    assert_eq!(runner.tick().await.unwrap(), Tick::Failed);
    assert_eq!(
        runner.tick().await.unwrap(),
        Tick::Idle,
        "a failed commit must not come back on its own — a human re-arms it"
    );
    assert_eq!(
        handler.calls().len(),
        1,
        "running a partially-applied fleet mutation twice is the whole thing \
         at-most-once exists to prevent"
    );

    let failed = repo.get_job(&job.id).await.unwrap().unwrap();
    assert_eq!(failed.status, JobStatus::Failed);
    assert!(failed
        .last_error
        .as_deref()
        .unwrap()
        .contains("handler failed"));
}

/// A job whose kind has no handler fails loudly rather than being claimed and
/// dropped, which would leave it `running` forever.
#[tokio::test]
async fn a_job_with_no_handler_fails_instead_of_stalling() {
    let repo = repo().await;
    let runner = JobRunner::new(repo.clone());

    let job = repo
        .enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
        .await
        .unwrap();
    assert_eq!(runner.tick().await.unwrap(), Tick::Unhandled);

    let failed = repo.get_job(&job.id).await.unwrap().unwrap();
    assert_eq!(failed.status, JobStatus::Failed);
    assert!(failed.last_error.as_deref().unwrap().contains("no handler"));
}

/// Every kind should have a handler in a real binary. This is what turns
/// "someone added a JobKind and forgot the handler" from a stalled queue into
/// a startup warning.
#[tokio::test]
async fn unhandled_kinds_are_reportable() {
    let repo = repo().await;

    let none = JobRunner::new(repo.clone());
    assert_eq!(none.unhandled_kinds().len(), JobKind::ALL.len());

    let partial = JobRunner::new(repo.clone()).register(SpyHandler::new(JobKind::GoogleDeviceSync));
    assert_eq!(
        partial.unhandled_kinds(),
        vec![JobKind::ChangeSetCommit],
        "the one without a handler is named"
    );

    let full = JobRunner::new(repo.clone())
        .register(SpyHandler::new(JobKind::GoogleDeviceSync))
        .register(SpyHandler::new(JobKind::ChangeSetCommit));
    assert!(full.unhandled_kinds().is_empty());
}

/// Registering twice for one kind replaces rather than accumulating. Running
/// two handlers for one job would be worse than the last-wins surprise.
#[tokio::test]
async fn registering_a_second_handler_for_a_kind_replaces_the_first() {
    let repo = repo().await;
    let first = SpyHandler::new(JobKind::GoogleDeviceSync);
    let second = SpyHandler::new(JobKind::GoogleDeviceSync);
    let runner = JobRunner::new(repo.clone())
        .register(first.clone())
        .register(second.clone());

    repo.enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
        .await
        .unwrap();
    runner.tick().await.unwrap();

    assert!(first.calls().is_empty());
    assert_eq!(second.calls().len(), 1);
}

/// Startup recovery fails jobs a dead process left claimed, and leaves live
/// ones alone.
#[tokio::test]
async fn recovery_sweeps_only_jobs_older_than_the_liveness_window() {
    let repo = repo().await;
    let runner = JobRunner::new(repo.clone()).with_liveness(Duration::minutes(30));

    let stale = repo
        .enqueue(&NewJob::now(JobKind::ChangeSetCommit))
        .await
        .unwrap();
    repo.claim(&stale.id, Utc::now() - Duration::hours(2))
        .await
        .unwrap();

    let fresh = repo
        .enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
        .await
        .unwrap();
    repo.claim(&fresh.id, Utc::now()).await.unwrap();

    assert_eq!(runner.recover_abandoned().await.unwrap(), 1);
    assert_eq!(
        repo.get_job(&stale.id).await.unwrap().unwrap().status,
        JobStatus::Failed
    );
    assert_eq!(
        repo.get_job(&fresh.id).await.unwrap().unwrap().status,
        JobStatus::Running,
        "a worker inside the window is alive, not abandoned"
    );
}

/// A delayed retry is not picked up before its time — otherwise the backoff
/// does nothing and a failing job spins.
#[tokio::test]
async fn a_requeued_job_waits_out_its_delay() {
    let repo = repo().await;
    let handler = SpyHandler::failing(JobKind::GoogleDeviceSync, 1);
    let runner = JobRunner::new(repo.clone())
        .register(handler.clone())
        .with_retry_delay(Duration::hours(1));

    repo.enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
        .await
        .unwrap();
    assert_eq!(runner.tick().await.unwrap(), Tick::Requeued);
    assert_eq!(
        runner.tick().await.unwrap(),
        Tick::Idle,
        "still inside the retry delay"
    );
    assert_eq!(handler.calls().len(), 1);
}

/// Jobs are taken oldest first, so a backlog drains in the order it was asked
/// for.
#[tokio::test]
async fn the_runner_drains_the_queue_in_order() {
    let repo = repo().await;
    let handler = SpyHandler::new(JobKind::GoogleDeviceSync);
    let runner = JobRunner::new(repo.clone()).register(handler.clone());

    let mut ids = Vec::new();
    for i in 0..3 {
        ids.push(
            repo.enqueue(
                &NewJob::now(JobKind::GoogleDeviceSync).with_payload(serde_json::json!({"seq": i})),
            )
            .await
            .unwrap()
            .id,
        );
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    }

    for _ in 0..3 {
        assert_eq!(runner.tick().await.unwrap(), Tick::Succeeded);
    }
    assert_eq!(runner.tick().await.unwrap(), Tick::Idle);

    let ran: Vec<String> = handler.calls().into_iter().map(|(id, _)| id).collect();
    assert_eq!(ran, ids);
}
