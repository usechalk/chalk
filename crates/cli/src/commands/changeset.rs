//! `chalk devices changeset` — inspect and re-arm a proposed fleet change.
//!
//! # Why this exists
//!
//! Write-back is at-most-once by design: a change set that fails partway is
//! never retried automatically, because re-running a partially applied fleet
//! mutation is the failure that whole design prevents. A human decides.
//!
//! The console can show a change set, but the moment an operator most needs to
//! look at one is when something went wrong — and that is exactly when they may
//! be on a terminal, over SSH, with the server misbehaving. Before this, the
//! answer to "which twelve of my five hundred devices actually moved?" was to
//! open the database with `sqlite3`.
//!
//! # `retry-failed` re-arms; it does not apply
//!
//! It moves failed and indeterminate items back to `pending` and the set back
//! to `planned`, then stops. The worker applies them. That keeps one path for
//! every write, and one place where at-most-once is enforced.
//!
//! **Indeterminate items are re-armed too, and that is a considered choice.**
//! Their outcome is unknown, so retrying may repeat a write that already
//! landed. Both operations Chalk performs are idempotent — moving a device to
//! the org unit it already occupies is a no-op, and Google answers a redundant
//! status change with 412, which the commit path reads as already-applied — so
//! the repeat is safe. The command says how many are unknown before it acts,
//! because "safe" is a property of today's two operations, not a law.

use std::path::Path;
use std::sync::Arc;

use chalk_core::config::ChalkConfig;
use chalk_core::db::DatabasePool;

use chalk_core::db::repository::{ChangeSetRepository, JobRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::models::change_set::{ChangeSetFilter, ChangeSetStatus};
use chalk_core::models::job::{JobKind, NewJob};
use chalk_core::models::page::PageRequest;

use super::common;

/// Change sets shown by `changeset list` unless `--limit` says otherwise.
const DEFAULT_LIMIT: i64 = 20;

/// Items shown by `changeset show` unless `--limit` says otherwise. Generous:
/// the reason to run this is to read the rows.
const DEFAULT_ITEM_LIMIT: i64 = 200;

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

/// `chalk devices changeset list [--status planned] [--limit 20]`
pub async fn list(
    config_path: &str,
    status: Option<String>,
    limit: Option<i64>,
) -> anyhow::Result<()> {
    let repo = open(config_path).await?;
    let sets: Arc<dyn ChangeSetRepository> = repo.clone();

    let filter = ChangeSetFilter {
        status: match status.as_deref() {
            None => None,
            Some(raw) => Some(ChangeSetStatus::parse(raw).map_err(|_| {
                anyhow::anyhow!(
                    "{raw:?} is not a change set status — try planned, committing, \
                     committed or discarded"
                )
            })?),
        },
        ..Default::default()
    };
    let page = sets
        .list_change_sets(&filter, PageRequest::new(limit.unwrap_or(DEFAULT_LIMIT), 0))
        .await?;

    if page.items.is_empty() {
        println!("No change sets.");
        return Ok(());
    }

    println!(
        "{:<38} {:<16} {:<13} {:>6}  CREATED",
        "ID", "KIND", "STATUS", "ITEMS"
    );
    for set in &page.items {
        let progress = sets.item_status_counts(&set.id).await?;
        // The *display* status, not the stored one: a `committing` row whose
        // worker died reads as interrupted, and a committed set with failures
        // reads as partial. Neither is a value the column can hold.
        let shown = progress.display_status(set, chrono::Utc::now());
        println!(
            "{:<38} {:<16} {:<13} {:>6}  {}",
            set.id,
            set.kind.as_str(),
            shown.as_str(),
            progress.total(),
            set.created_at.format("%Y-%m-%d %H:%M")
        );
    }
    println!("\n{} of {} shown.", page.items.len(), page.total);
    Ok(())
}

/// `chalk devices changeset show <id> [--limit 200]`
pub async fn show(config_path: &str, id: &str, limit: Option<i64>) -> anyhow::Result<()> {
    let repo = open(config_path).await?;
    let sets: Arc<dyn ChangeSetRepository> = repo.clone();

    let Some(set) = sets.get_change_set(id).await? else {
        anyhow::bail!("no change set {id}");
    };
    let progress = sets.item_status_counts(id).await?;
    let shown = progress.display_status(&set, chrono::Utc::now());

    println!("Change set {}", set.id);
    println!("  kind      {}", set.kind.as_str());
    println!("  status    {}", shown.as_str());
    println!(
        "  created   {} by {}",
        set.created_at.format("%Y-%m-%d %H:%M"),
        set.created_by
    );
    if let Some(at) = set.committed_at {
        println!("  committed {}", at.format("%Y-%m-%d %H:%M"));
    }
    if shown.as_str() == "interrupted" {
        println!(
            "\n  This set claimed a commit and never finished it. Nothing resumes\n  \
             automatically — see the per-item states below, then re-arm with\n  \
             `chalk devices changeset retry-failed {}`.",
            set.id
        );
    }

    println!(
        "\n  applied {}  failed {}  unknown {}  pending {}  struck out {}",
        progress.applied,
        progress.failed,
        progress.indeterminate,
        progress.pending,
        progress.skipped
    );

    let page = sets
        .list_items(
            id,
            None,
            PageRequest::new(limit.unwrap_or(DEFAULT_ITEM_LIMIT), 0),
        )
        .await?;
    if page.items.is_empty() {
        println!("\nNo items.");
        return Ok(());
    }

    println!(
        "\n{:<20} {:<14} {:<18} {:<26} DETAIL",
        "DEVICE", "STATUS", "FIELD", "NEW VALUE"
    );
    for item in &page.items {
        println!(
            "{:<20} {:<14} {:<18} {:<26} {}",
            truncate(item.target_ref.as_deref().unwrap_or("—"), 20),
            item.status.as_str(),
            truncate(item.field.as_deref().unwrap_or("—"), 18),
            truncate(item.new_value.as_deref().unwrap_or("(cleared)"), 26),
            // The error is the whole reason to run this, so it is never
            // truncated — a message cut at the terminal width is a message
            // that cannot be acted on.
            item.error.as_deref().unwrap_or("")
        );
    }
    if page.total > page.items.len() as i64 {
        println!("\n{} of {} items shown.", page.items.len(), page.total);
    }
    Ok(())
}

/// `chalk devices changeset retry-failed <id>`
pub async fn retry_failed(config_path: &str, id: &str) -> anyhow::Result<()> {
    let repo = open(config_path).await?;
    let sets: Arc<dyn ChangeSetRepository> = repo.clone();

    let Some(set) = sets.get_change_set(id).await? else {
        anyhow::bail!("no change set {id}");
    };
    let before = sets.item_status_counts(id).await?;
    if before.retryable() == 0 {
        println!("Nothing to re-arm — no failed, unknown or pending items.");
        return Ok(());
    }

    // Said before acting, not after. An item whose outcome is unknown may have
    // already been applied, and the operator is the one deciding that a repeat
    // is acceptable.
    if before.indeterminate > 0 {
        println!(
            "{} item{} have an unknown outcome and may already have been applied \
             in Google.\nBoth operations Chalk performs are idempotent — moving a \
             device to the org unit it\nalready occupies does nothing, and a \
             redundant status change returns 412, which\ncounts as already done — \
             so re-arming them is safe.\n",
            before.indeterminate,
            if before.indeterminate == 1 { "" } else { "s" }
        );
    }

    let rearmed = sets.rearm_failed_items(id).await?;
    println!(
        "Re-armed {rearmed} item{} on change set {}.",
        if rearmed == 1 { "" } else { "s" },
        set.id
    );

    // Queue the work rather than doing it here: one path for every write, and
    // one place where at-most-once lives.
    let job = repo
        .enqueue(
            &NewJob::now(JobKind::ChangeSetCommit).with_payload(serde_json::json!({
                "changeSetId": set.id,
                // Re-read after the re-arm: the hash and count that matter are
                // the ones the worker will check, and re-arming changed them.
                "planHash": set.plan_hash,
                "expectedItemCount": sets.item_status_counts(id).await?.total(),
            })),
        )
        .await?;
    println!("Queued commit job {}.", job.id);
    println!(
        "\nThe worker applies it. If `chalk serve` is not running, nothing \
         happens until it is."
    );
    Ok(())
}

/// Cut a cell to `max` characters, marking that it was cut.
///
/// Characters, not bytes: an asset tag with an accent must not be sliced
/// mid-codepoint, which panics.
fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let kept: String = value.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests;
