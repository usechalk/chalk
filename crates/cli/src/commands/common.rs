use anyhow::{bail, Result};
use chalk_core::config::DatabaseDriver;
use chalk_core::db::DatabasePool;
use sqlx::SqlitePool;

/// Returns Err with a uniform message if the driver isn't SQLite.
/// CLI subcommands other than `serve` only support SQLite today.
pub fn assert_sqlite_only(driver: &DatabaseDriver) -> Result<()> {
    match driver {
        DatabaseDriver::Sqlite => Ok(()),
        DatabaseDriver::Postgres => bail!(
            "this CLI subcommand only supports the SQLite driver; \
             Postgres is supported by `chalk serve` and `chalk-hosted` only"
        ),
    }
}

/// Extracts the SqlitePool from a DatabasePool, erroring with a clear message
/// if the variant is Postgres.
pub fn unwrap_sqlite_pool(pool: DatabasePool) -> Result<SqlitePool> {
    match pool {
        DatabasePool::Sqlite(p) => Ok(p),
        DatabasePool::Postgres(_) => bail!(
            "this CLI subcommand only supports the SQLite driver; \
             Postgres is supported by `chalk serve` and `chalk-hosted` only"
        ),
    }
}
