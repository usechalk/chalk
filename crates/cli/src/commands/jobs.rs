//! `chalk jobs` — see the background queue, and re-arm what failed.
//!
//! # Why this exists
//!
//! The runner is deliberately at-most-once for anything that writes to Google:
//! a failed commit is *not* retried automatically, because re-running a
//! partially-applied fleet mutation is the failure that design exists to
//! prevent. The rule is that a human decides.
//!
//! That rule shipped without giving the human anything to decide *with*.
//! Before this, an operator whose sync was not running had no way to see the
//! queue at all short of opening the database with `sqlite3`, and no way to
//! re-arm a job that had used up its attempts. This closes that gap — it is
//! the other half of a promise the runner already makes.

use std::path::Path;
use std::sync::Arc;

use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::JobRepository;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::job::{JobFilter, JobStatus, NewJob};
use chalk_core::models::page::PageRequest;

use super::common;

/// Rows shown by `jobs list` unless `--limit` says otherwise.
const DEFAULT_LIMIT: i64 = 20;

async fn open(config_path: &str) -> anyhow::Result<Arc<SqliteRepository>> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    common::assert_sqlite_only(&config.chalk.database.driver)?;
    let path = config
        .chalk
        .database
        .path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SQLite path not configured"))?;
    let pool = DatabasePool::new_sqlite(&format!("sqlite:{path}?mode=rwc")).await?;
    Ok(Arc::new(SqliteRepository::new(common::unwrap_sqlite_pool(
        pool,
    )?)))
}

/// `chalk jobs list [--status queued] [--limit 20]`
pub async fn list(
    config_path: &str,
    status: Option<String>,
    limit: Option<i64>,
) -> anyhow::Result<()> {
    let repo = open(config_path).await?;

    // An unrecognised status is refused rather than ignored. Silently listing
    // everything after a typo would show a queue that looks healthy because
    // the filter never applied.
    let status = match status.as_deref() {
        None => None,
        Some(raw) => Some(JobStatus::parse(raw).map_err(|_| {
            anyhow::anyhow!(
                "unknown status {raw:?}. Use one of: queued, running, succeeded, \
                 failed, cancelled"
            )
        })?),
    };

    let page = repo
        .list_jobs(
            &JobFilter { kind: None, status },
            PageRequest::new(limit.unwrap_or(DEFAULT_LIMIT), 0),
        )
        .await?;

    if page.items.is_empty() {
        println!(
            "No jobs{}.",
            match status {
                Some(s) => format!(" with status {}", s.as_str()),
                None => String::new(),
            }
        );
        return Ok(());
    }

    println!(
        "{:<38} {:<20} {:<10} {:<8} CREATED",
        "ID", "KIND", "STATUS", "ATTEMPT"
    );
    for job in &page.items {
        println!(
            "{:<38} {:<20} {:<10} {:<8} {}",
            job.id,
            job.kind.as_str(),
            job.status.as_str(),
            format!("{}/{}", job.attempt, job.max_attempts),
            job.created_at.format("%Y-%m-%d %H:%M")
        );
    }

    println!();
    println!("{} of {} shown.", page.items.len(), page.total);

    // Surfaced without being asked for: a failed job is the reason someone
    // runs this command, and it is the one thing that needs a decision.
    let failed = repo
        .list_jobs(
            &JobFilter {
                kind: None,
                status: Some(JobStatus::Failed),
            },
            PageRequest::new(1, 0),
        )
        .await?;
    if failed.total > 0 {
        println!(
            "{} failed. `chalk jobs show <id>` for the reason, \
             `chalk jobs retry <id>` to run it again.",
            failed.total
        );
    }
    Ok(())
}

/// `chalk jobs show <id>`
pub async fn show(config_path: &str, id: &str) -> anyhow::Result<()> {
    let repo = open(config_path).await?;
    let Some(job) = repo.get_job(id).await? else {
        anyhow::bail!("no job with id {id}");
    };

    println!("id           {}", job.id);
    println!("kind         {}", job.kind.as_str());
    println!("status       {}", job.status.as_str());
    println!("attempt      {} of {}", job.attempt, job.max_attempts);
    println!(
        "created      {}",
        job.created_at.format("%Y-%m-%d %H:%M:%S")
    );
    if let Some(t) = job.run_after {
        println!("run after    {}", t.format("%Y-%m-%d %H:%M:%S"));
    }
    if let Some(t) = job.started_at {
        println!("started      {}", t.format("%Y-%m-%d %H:%M:%S"));
    }
    if let Some(t) = job.finished_at {
        println!("finished     {}", t.format("%Y-%m-%d %H:%M:%S"));
    }
    if job.payload != serde_json::json!({}) {
        println!("payload      {}", job.payload);
    }
    if let Some(err) = &job.last_error {
        println!();
        println!("error        {err}");
    }

    if job.status == JobStatus::Failed {
        println!();
        if job.kind.default_max_attempts() == 1 {
            // The at-most-once kinds. Say plainly that re-running may repeat
            // work already done, because that is the whole reason this is a
            // human decision rather than an automatic retry.
            println!(
                "This job writes to Google, so it is never retried automatically. \
                 Part of its work may already have been applied — check before \
                 re-running it."
            );
        }
        println!("Run it again with: chalk jobs retry {}", job.id);
    }
    Ok(())
}

/// `chalk jobs retry <id>` — queue a fresh job with the same work.
///
/// Deliberately a **new** job rather than resetting the old row's status. The
/// original stays in the table with its error and its attempt count intact, so
/// the history of what failed is not erased by the act of trying again — which
/// matters most for exactly the jobs that are not retried automatically.
pub async fn retry(config_path: &str, id: &str) -> anyhow::Result<()> {
    let repo = open(config_path).await?;
    let Some(job) = repo.get_job(id).await? else {
        anyhow::bail!("no job with id {id}");
    };

    if !job.is_terminal() {
        anyhow::bail!(
            "job {id} is {} — it has not finished, so there is nothing to retry",
            job.status.as_str()
        );
    }

    let fresh = repo
        .enqueue(&NewJob::now(job.kind).with_payload(job.payload.clone()))
        .await?;

    println!("Queued {} as a new job: {}", job.kind.as_str(), fresh.id);
    println!("The original {} is left in place with its error.", job.id);
    Ok(())
}

#[cfg(test)]
mod tests;
