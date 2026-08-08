//! `chalk mdm sync` — pull the Intune and/or Jamf fleets into the inventory.
//!
//! Read-only against the MDM, like every sync. `--dry-run` walks the whole
//! fleet and prints what would happen without writing a row — the same
//! contract `chalk sync --dry-run` honors.

use std::sync::Arc;

use chalk_core::config::ChalkConfig;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_devices::mdm::{MdmSource, MdmSyncEngine, MdmSyncSummary};

use super::common;

pub async fn sync(config_path: &str, source: &str, dry_run: bool) -> anyhow::Result<()> {
    let config = ChalkConfig::load(std::path::Path::new(config_path))?;
    config.validate()?;
    common::assert_sqlite_only(&config.chalk.database.driver)?;
    let path = config
        .chalk
        .database
        .path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SQLite path not configured"))?;
    let pool = DatabasePool::new_sqlite(&format!("sqlite:{path}?mode=rwc")).await?;
    let repo = Arc::new(SqliteRepository::new(common::unwrap_sqlite_pool(pool)?));

    let sources: Vec<MdmSource> = match source.trim().to_ascii_lowercase().as_str() {
        "all" => {
            let mut all = Vec::new();
            if config.mdm.intune.is_configured() {
                all.push(MdmSource::Intune);
            }
            if config.mdm.jamf.is_configured() {
                all.push(MdmSource::Jamf);
            }
            if all.is_empty() {
                anyhow::bail!(
                    "no MDM connector is configured — add [mdm.intune] or [mdm.jamf] \
                     to chalk.toml first"
                );
            }
            all
        }
        other => match MdmSource::parse(other) {
            Some(s) => vec![s],
            None => anyhow::bail!("unknown MDM source {other:?} — use intune, jamf, or all"),
        },
    };

    for s in sources {
        let connector = match s {
            MdmSource::Intune => {
                if !config.mdm.intune.is_configured() {
                    anyhow::bail!("[mdm.intune] is not configured in chalk.toml");
                }
                chalk_devices::intune::connector(config.mdm.intune.clone())
            }
            MdmSource::Jamf => {
                if !config.mdm.jamf.is_configured() {
                    anyhow::bail!("[mdm.jamf] is not configured in chalk.toml");
                }
                chalk_devices::jamf::connector(config.mdm.jamf.clone())
            }
        };
        let engine = MdmSyncEngine::new(repo.clone(), repo.clone(), repo.clone(), connector);
        let summary = engine.run_sync(dry_run).await?;
        print_summary(s, dry_run, &summary);
    }
    Ok(())
}

fn print_summary(source: MdmSource, dry_run: bool, s: &MdmSyncSummary) {
    let mode = if dry_run {
        " (dry run — nothing written)"
    } else {
        ""
    };
    println!("{} sync{mode}:", source.as_str());
    println!("  fetched:   {}", s.fetched);
    println!("  created:   {}", s.created);
    println!("  updated:   {}", s.updated);
    println!("  matched:   {}", s.matched);
    println!("  unmatched: {}", s.unmatched);
}
