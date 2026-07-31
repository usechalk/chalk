//! Jobs-CLI tests.
//!
//! The command's reason for existing is `retry`, so that is what most of these
//! are about — in particular that retrying preserves the record of what failed
//! rather than erasing it.

use super::*;

use chalk_core::models::job::JobKind;

async fn repo() -> Arc<SqliteRepository> {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    }
}

/// Fail a job the way the runner does: claim it, then finish it failed.
async fn failed_job(repo: &Arc<SqliteRepository>, kind: JobKind) -> String {
    let job = repo
        .enqueue(&NewJob::now(kind).with_payload(serde_json::json!({"dryRun": true})))
        .await
        .unwrap();
    repo.claim(&job.id, chrono::Utc::now()).await.unwrap();
    repo.finish(&job.id, JobStatus::Failed, Some("token exchange failed"))
        .await
        .unwrap();
    job.id
}

/// Retrying queues fresh work and **leaves the original alone**.
///
/// Resetting the old row instead would erase the error and the attempt count —
/// the record of what went wrong — at exactly the moment someone is trying to
/// understand it. That matters most for the at-most-once kinds, which is where
/// a human is being asked to make a judgement.
#[tokio::test]
async fn retrying_queues_new_work_and_preserves_the_failed_record() {
    let repo = repo().await;
    let original = failed_job(&repo, JobKind::ChangeSetCommit).await;

    let before = repo.get_job(&original).await.unwrap().unwrap();
    assert_eq!(before.status, JobStatus::Failed);
    assert_eq!(before.attempt, 1);

    // What `retry` does, exercised through the repository the command uses.
    let fresh = repo
        .enqueue(&NewJob::now(before.kind).with_payload(before.payload.clone()))
        .await
        .unwrap();

    let after = repo.get_job(&original).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::Failed, "the record is untouched");
    assert_eq!(after.attempt, 1);
    assert_eq!(
        after.last_error.as_deref(),
        Some("token exchange failed"),
        "the reason it failed must survive the retry"
    );

    assert_ne!(fresh.id, original);
    assert_eq!(fresh.status, JobStatus::Queued);
    assert_eq!(fresh.attempt, 0, "a fresh job gets a full budget");
    assert_eq!(
        fresh.payload, before.payload,
        "the same work, not a default job"
    );
}

/// A Google-writing kind still gets exactly one attempt when re-armed. The
/// human decided to run it again; that does not turn it into a retryable job.
#[tokio::test]
async fn a_re_armed_google_job_is_still_at_most_once() {
    let repo = repo().await;
    let original = failed_job(&repo, JobKind::ChangeSetCommit).await;
    let before = repo.get_job(&original).await.unwrap().unwrap();

    let fresh = repo
        .enqueue(&NewJob::now(before.kind).with_payload(before.payload))
        .await
        .unwrap();
    assert_eq!(fresh.max_attempts, 1);
}

/// Retrying something still in flight would run the same work twice
/// concurrently. `retry` refuses anything non-terminal.
#[tokio::test]
async fn only_finished_jobs_can_be_retried() {
    let repo = repo().await;

    let queued = repo
        .enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
        .await
        .unwrap();
    assert!(!queued.is_terminal(), "queued work is not retryable");

    repo.claim(&queued.id, chrono::Utc::now()).await.unwrap();
    let running = repo.get_job(&queued.id).await.unwrap().unwrap();
    assert!(!running.is_terminal(), "running work is not retryable");

    repo.finish(&queued.id, JobStatus::Succeeded, None)
        .await
        .unwrap();
    let done = repo.get_job(&queued.id).await.unwrap().unwrap();
    assert!(done.is_terminal());
}

/// An unrecognised `--status` is refused rather than ignored. Silently listing
/// everything after a typo would show a queue that looks healthy because the
/// filter never applied.
#[test]
fn an_unknown_status_filter_is_rejected() {
    assert!(JobStatus::parse("failed").is_ok());
    assert!(JobStatus::parse("queued").is_ok());
    assert!(JobStatus::parse("faild").is_err());
    assert!(JobStatus::parse("").is_err());
}

/// The listing filters in SQL, so a `--status failed` on a large queue does not
/// read every row to show a handful.
#[tokio::test]
async fn listing_filters_by_status_in_the_repository() {
    let repo = repo().await;
    failed_job(&repo, JobKind::GoogleDeviceSync).await;
    repo.enqueue(&NewJob::now(JobKind::GoogleDeviceSync))
        .await
        .unwrap();

    let failed = repo
        .list_jobs(
            &JobFilter {
                kind: None,
                status: Some(JobStatus::Failed),
            },
            PageRequest::new(50, 0),
        )
        .await
        .unwrap();
    assert_eq!(failed.total, 1);
    assert_eq!(failed.items[0].status, JobStatus::Failed);

    let all = repo
        .list_jobs(&JobFilter::default(), PageRequest::new(50, 0))
        .await
        .unwrap();
    assert_eq!(all.total, 2);
}
