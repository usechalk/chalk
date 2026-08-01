pub mod postgres;
pub mod repository;
pub mod sealing;
pub mod sqlite;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, SqlitePool};
use std::str::FromStr;

use crate::config::is_valid_pg_schema;
use crate::error::{ChalkError, Result};

pub enum DatabasePool {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

/// Every Postgres migration, in apply order, keyed by the version string
/// recorded in `_meta_schema_migrations`. Applied once each, whole-file, via
/// `sqlx::raw_sql` — so these files are unconstrained.
const POSTGRES_MIGRATIONS: &[(&str, &str)] = &[
    (
        "001_initial_schema",
        include_str!("../../../../migrations/postgres/001_initial_schema.sql"),
    ),
    (
        "002_idp_google_sync",
        include_str!("../../../../migrations/postgres/002_idp_google_sync.sql"),
    ),
    (
        "003_admin_audit",
        include_str!("../../../../migrations/postgres/003_admin_audit.sql"),
    ),
    (
        "004_config_overrides",
        include_str!("../../../../migrations/postgres/004_config_overrides.sql"),
    ),
    (
        "005_webhooks",
        include_str!("../../../../migrations/postgres/005_webhooks.sql"),
    ),
    (
        "006_sso_partners",
        include_str!("../../../../migrations/postgres/006_sso_partners.sql"),
    ),
    (
        "007_sso_compat",
        include_str!("../../../../migrations/postgres/007_sso_compat.sql"),
    ),
    (
        "008_access_tokens",
        include_str!("../../../../migrations/postgres/008_access_tokens.sql"),
    ),
    (
        "009_ad_sync_groups",
        include_str!("../../../../migrations/postgres/009_ad_sync_groups.sql"),
    ),
    (
        "010_password_reset_tokens",
        include_str!("../../../../migrations/postgres/010_password_reset_tokens.sql"),
    ),
    (
        "011_junction_indexes",
        include_str!("../../../../migrations/postgres/011_junction_indexes.sql"),
    ),
    (
        "012_api_tokens",
        include_str!("../../../../migrations/postgres/012_api_tokens.sql"),
    ),
    (
        "013_tenant_config",
        include_str!("../../../../migrations/postgres/013_tenant_config.sql"),
    ),
    (
        "014_webhook_deliveries_cascade",
        include_str!("../../../../migrations/postgres/014_webhook_deliveries_cascade.sql"),
    ),
    (
        "015_api_token_scope",
        include_str!("../../../../migrations/postgres/015_api_token_scope.sql"),
    ),
    (
        "016_magic_login_tokens",
        include_str!("../../../../migrations/postgres/016_magic_login_tokens.sql"),
    ),
    (
        "017_sso_partner_audience",
        include_str!("../../../../migrations/postgres/017_sso_partner_audience.sql"),
    ),
    (
        "018_sso_partner_launch_url",
        include_str!("../../../../migrations/postgres/018_sso_partner_launch_url.sql"),
    ),
    (
        "019_assets",
        include_str!("../../../../migrations/postgres/019_assets.sql"),
    ),
    (
        "021_google_device_sync",
        include_str!("../../../../migrations/postgres/021_google_device_sync.sql"),
    ),
    (
        "022_change_sets",
        include_str!("../../../../migrations/postgres/022_change_sets.sql"),
    ),
    (
        "023_jobs",
        include_str!("../../../../migrations/postgres/023_jobs.sql"),
    ),
    (
        "024_tenant_config_devices",
        include_str!("../../../../migrations/postgres/024_tenant_config_devices.sql"),
    ),
    (
        "025_sis_token_urls",
        include_str!("../../../../migrations/postgres/025_sis_token_urls.sql"),
    ),
    (
        "026_device_write_back",
        include_str!("../../../../migrations/postgres/026_device_write_back.sql"),
    ),
];

/// Every SQLite migration, in apply order, paired with its filename for test
/// diagnostics.
///
/// **SQLite has no migration version table.** [`DatabasePool::run_migrations`]
/// re-executes every one of these files on every process start, splitting each
/// on the semicolon character with no SQL parsing, and swallowing only errors
/// containing "duplicate column" or "already exists". Every file must
/// therefore be re-runnable and must contain no semicolon outside a statement
/// terminator — including inside comments. `sqlite_migrations_are_re_runnable`
/// and `sqlite_migrations_have_no_semicolons_in_comments` below enforce both.
const SQLITE_MIGRATIONS: &[(&str, &str)] = &[
    (
        "001_initial_schema.sql",
        include_str!("../../../../migrations/sqlite/001_initial_schema.sql"),
    ),
    (
        "002_idp_google_sync.sql",
        include_str!("../../../../migrations/sqlite/002_idp_google_sync.sql"),
    ),
    (
        "003_admin_audit.sql",
        include_str!("../../../../migrations/sqlite/003_admin_audit.sql"),
    ),
    (
        "004_config_overrides.sql",
        include_str!("../../../../migrations/sqlite/004_config_overrides.sql"),
    ),
    (
        "005_webhooks.sql",
        include_str!("../../../../migrations/sqlite/005_webhooks.sql"),
    ),
    (
        "006_sso_partners.sql",
        include_str!("../../../../migrations/sqlite/006_sso_partners.sql"),
    ),
    (
        "007_sso_compat.sql",
        include_str!("../../../../migrations/sqlite/007_sso_compat.sql"),
    ),
    (
        "008_access_tokens.sql",
        include_str!("../../../../migrations/sqlite/008_access_tokens.sql"),
    ),
    (
        "009_ad_sync_groups.sql",
        include_str!("../../../../migrations/sqlite/009_ad_sync_groups.sql"),
    ),
    (
        "010_password_reset_tokens.sql",
        include_str!("../../../../migrations/sqlite/010_password_reset_tokens.sql"),
    ),
    (
        "011_junction_indexes.sql",
        include_str!("../../../../migrations/sqlite/011_junction_indexes.sql"),
    ),
    (
        "012_api_tokens.sql",
        include_str!("../../../../migrations/sqlite/012_api_tokens.sql"),
    ),
    (
        "013_tenant_config.sql",
        include_str!("../../../../migrations/sqlite/013_tenant_config.sql"),
    ),
    (
        "014_webhook_deliveries_cascade.sql",
        include_str!("../../../../migrations/sqlite/014_webhook_deliveries_cascade.sql"),
    ),
    (
        "015_api_token_scope.sql",
        include_str!("../../../../migrations/sqlite/015_api_token_scope.sql"),
    ),
    (
        "016_magic_login_tokens.sql",
        include_str!("../../../../migrations/sqlite/016_magic_login_tokens.sql"),
    ),
    (
        "017_sso_partner_audience.sql",
        include_str!("../../../../migrations/sqlite/017_sso_partner_audience.sql"),
    ),
    (
        "018_sso_partner_launch_url.sql",
        include_str!("../../../../migrations/sqlite/018_sso_partner_launch_url.sql"),
    ),
    // 020 (tickets) and 023/024 are reserved in ARCHITECTURE §4.2 but not
    // written yet. Gaps are fine: this list is ordered, not indexed.
    (
        "019_assets.sql",
        include_str!("../../../../migrations/sqlite/019_assets.sql"),
    ),
    (
        "021_google_device_sync.sql",
        include_str!("../../../../migrations/sqlite/021_google_device_sync.sql"),
    ),
    (
        "022_change_sets.sql",
        include_str!("../../../../migrations/sqlite/022_change_sets.sql"),
    ),
    (
        "023_jobs.sql",
        include_str!("../../../../migrations/sqlite/023_jobs.sql"),
    ),
    (
        "024_tenant_config_devices.sql",
        include_str!("../../../../migrations/sqlite/024_tenant_config_devices.sql"),
    ),
    (
        "025_sis_token_urls.sql",
        include_str!("../../../../migrations/sqlite/025_sis_token_urls.sql"),
    ),
    (
        "026_device_write_back.sql",
        include_str!("../../../../migrations/sqlite/026_device_write_back.sql"),
    ),
];

impl DatabasePool {
    /// Create a new SQLite database pool from a file path and run migrations.
    pub async fn new_sqlite(path: &str) -> Result<Self> {
        let pool = SqlitePool::connect(path).await?;
        Self::run_migrations(&pool).await?;
        Ok(DatabasePool::Sqlite(pool))
    }

    /// Create a new in-memory SQLite database pool and run migrations. Useful for testing.
    pub async fn new_sqlite_memory() -> Result<Self> {
        let pool = SqlitePool::connect(":memory:").await?;
        Self::run_migrations(&pool).await?;
        Ok(DatabasePool::Sqlite(pool))
    }

    /// Default per-tenant Postgres pool size. Hosted multi-tenant runs hold
    /// one pool per cached tenant, so this must stay small to avoid blowing
    /// past Postgres' `max_connections` (default 100). The OSS single-tenant
    /// path opens exactly one pool, so the smaller default is fine there too.
    pub const DEFAULT_POSTGRES_MAX_CONNECTIONS: u32 = 3;

    /// Create a new PostgreSQL database pool. Sets `search_path` to the provided
    /// schema so all subsequent queries are scoped to that schema.
    ///
    /// `schema` MUST satisfy `is_valid_pg_schema` — callers should validate first
    /// (config validation ensures this for the OSS path). Passing an invalid
    /// schema returns an error rather than allowing SQL injection via DDL.
    pub async fn new_postgres(url: &str, schema: &str) -> Result<Self> {
        Self::new_postgres_with_max_connections(url, schema, Self::DEFAULT_POSTGRES_MAX_CONNECTIONS)
            .await
    }

    /// Same as [`new_postgres`] but with an explicit `max_connections` cap,
    /// for callers (e.g. the hosted multi-tenant runtime) that need to size
    /// per-tenant pools relative to a configured budget.
    pub async fn new_postgres_with_max_connections(
        url: &str,
        schema: &str,
        max_connections: u32,
    ) -> Result<Self> {
        if !is_valid_pg_schema(schema) {
            return Err(ChalkError::Config(format!(
                "invalid postgres schema name: {schema}"
            )));
        }
        let opts = PgConnectOptions::from_str(url)
            .map_err(|e| ChalkError::Config(format!("invalid postgres url: {e}")))?
            .options([("search_path", schema)]);
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect_with(opts)
            .await?;
        Ok(DatabasePool::Postgres(pool))
    }

    /// Run Postgres migrations into the provided schema. Creates the schema if
    /// it doesn't exist, then applies each migration file in order. Tracks
    /// applied versions in `_meta_schema_migrations` to avoid re-running.
    pub async fn run_migrations_postgres(&self, schema: &str) -> Result<()> {
        let pool = match self {
            DatabasePool::Postgres(p) => p,
            _ => {
                return Err(ChalkError::Config(
                    "run_migrations_postgres called on non-Postgres pool".into(),
                ))
            }
        };
        if !is_valid_pg_schema(schema) {
            return Err(ChalkError::Config(format!(
                "invalid postgres schema name: {schema}"
            )));
        }

        // Create the schema if it doesn't exist (idempotent; outside the lock).
        sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS \"{schema}\""))
            .execute(pool)
            .await?;

        // Race safety for concurrent `migrate-all` / `provision` invocations
        // is provided by `INSERT ... ON CONFLICT DO NOTHING RETURNING` below
        // (only one claimer wins the version; losers skip). We deliberately
        // do NOT hold an advisory lock across awaits because that requires
        // pinning a single connection (`pool.begin()` / `pool.acquire()`),
        // which trips an sqlx HRTB and makes the future non-`Send` — unusable
        // from axum handlers. The pool's `search_path` is already pinned at
        // pool creation; per-statement `pool.execute` re-applies it implicitly.
        sqlx::query(&format!("SET search_path TO \"{schema}\""))
            .execute(pool)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS _meta_schema_migrations (\
                version TEXT PRIMARY KEY, \
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()\
            )",
        )
        .execute(pool)
        .await?;

        let migrations = POSTGRES_MIGRATIONS;

        for (version, sql) in migrations {
            // Atomic claim: INSERT wins for exactly one racer. Losers skip.
            // The winner then applies the SQL. Note that if the winner's
            // process dies after INSERT but before applying the SQL, the
            // migration will be silently incomplete — operators should not
            // SIGKILL `migrate-all` mid-run. (A retry mechanism would track
            // applied_at IS NULL; we keep the schema simple for now.)
            let claimed: Option<(String,)> = sqlx::query_as(
                "INSERT INTO _meta_schema_migrations (version) VALUES ($1) \
                 ON CONFLICT DO NOTHING RETURNING version",
            )
            .bind(version)
            .fetch_optional(pool)
            .await?;
            if claimed.is_none() {
                continue;
            }
            sqlx::raw_sql(sql).execute(pool).await?;
        }

        Ok(())
    }

    async fn run_migrations(pool: &SqlitePool) -> Result<()> {
        // Enable foreign keys
        sqlx::query("PRAGMA foreign_keys = ON;")
            .execute(pool)
            .await?;

        // NOTE: there is no version table here — every file re-runs on every
        // call, and the split below is a naive character split with no SQL
        // parsing. See the `SQLITE_MIGRATIONS` doc comment.
        for (file, migration_sql) in SQLITE_MIGRATIONS {
            for statement in migration_sql.split(';') {
                let trimmed = statement.trim();
                if !trimmed.is_empty() && !trimmed.starts_with("PRAGMA") {
                    // Ignore errors from ALTER TABLE if column already exists
                    let result = sqlx::query(trimmed).execute(pool).await;
                    if let Err(e) = &result {
                        let msg = e.to_string();
                        if msg.contains("duplicate column") || msg.contains("already exists") {
                            continue;
                        }
                        // Name the file: a bare syntax error on a fragment is
                        // otherwise almost impossible to trace back to a
                        // migration, which is exactly how a stray semicolon in
                        // a comment hides.
                        return Err(ChalkError::Config(format!(
                            "sqlite migration {file} failed: {msg}"
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repository::AssetRepository;
    use crate::db::sqlite::SqliteRepository;
    use crate::models::asset::{Asset, AssetFilter};
    use crate::models::page::PageRequest;

    /// Strip `--` line comments, returning what SQLite would actually parse.
    fn strip_line_comments(sql: &str) -> String {
        sql.lines()
            .map(|line| match line.find("--") {
                Some(idx) => &line[..idx],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn sqlite_migration_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../migrations/sqlite")
            .canonicalize()
            .expect("migrations/sqlite must exist")
    }

    fn postgres_migration_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../migrations/postgres")
            .canonicalize()
            .expect("migrations/postgres must exist")
    }

    fn sql_files_in(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("readable migration dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".sql"))
            .collect();
        names.sort();
        names
    }

    /// Timestamps that SQL *compares* must never take a `DEFAULT
    /// (datetime('now'))`.
    ///
    /// Comparison on a TEXT timestamp is lexicographic, and the two formats in
    /// play do not sort against each other: SQLite's `datetime()` emits
    /// `2026-07-27 01:00:00` while every writer in `sqlite.rs` emits RFC 3339
    /// `2026-07-27T01:00:00+00:00`. A space is 0x20 and `T` is 0x54, so a
    /// default-written value always sorts *below* a code-written one — and
    /// `WHERE started_at < :cutoff` then matches rows it should not.
    ///
    /// That is not hypothetical. It produced a wrong result twice while this
    /// module was being built: once making history render out of order, and
    /// once making startup recovery sweep a job whose worker was still alive.
    /// Both times the malformed rows were hand-written SQL rather than
    /// application writes — but a `DEFAULT` would make the application produce
    /// them, which is why this guards the schema rather than the callers.
    ///
    /// `created_at` is exempt: it is displayed and ordered within one format,
    /// never compared against a code-generated bound.
    #[test]
    fn compared_timestamp_columns_have_no_sqlite_default() {
        // Columns some query compares against a bound the code generates.
        const COMPARED: [&str; 3] = ["started_at", "run_after", "finished_at"];

        for (file, sql) in SQLITE_MIGRATIONS {
            for (lineno, line) in sql.lines().enumerate() {
                let code = line.split("--").next().unwrap_or("");
                let Some(col) = COMPARED.iter().find(|c| code.trim_start().starts_with(**c)) else {
                    continue;
                };
                assert!(
                    !code.to_ascii_lowercase().contains("datetime('now')"),
                    "{file}:{}: `{col}` defaults to SQLite's datetime('now'), which \
                     does not sort against the RFC 3339 the code writes. A row \
                     taking this default would compare wrongly in every \
                     `{col} < ?` query:\n  {line}",
                    lineno + 1
                );
            }
        }
    }

    /// The trap this whole suite exists for: a semicolon inside a comment
    /// splits the following statement in half, and the resulting syntax error
    /// is neither "duplicate column" nor "already exists", so it propagates and
    /// fails every boot.
    #[test]
    fn sqlite_migrations_have_no_semicolons_in_comments() {
        for (file, sql) in SQLITE_MIGRATIONS {
            for (lineno, line) in sql.lines().enumerate() {
                if let Some(idx) = line.find("--") {
                    assert!(
                        !line[idx..].contains(';'),
                        "{file}:{}: semicolon inside a comment. The SQLite \
                         migration runner splits on ';' with no SQL parsing, so \
                         this cuts the next statement in half:\n  {line}",
                        lineno + 1
                    );
                }
            }
        }
    }

    /// A fragment containing only comments is still non-empty after `trim()`,
    /// so the runner would hand it to SQLite as a statement. That happens when
    /// a file ends with a trailing comment after its last semicolon.
    #[test]
    fn sqlite_migrations_have_no_comment_only_statements() {
        for (file, sql) in SQLITE_MIGRATIONS {
            for (idx, fragment) in sql.split(';').enumerate() {
                if fragment.trim().is_empty() {
                    continue;
                }
                assert!(
                    !strip_line_comments(fragment).trim().is_empty(),
                    "{file}: fragment {idx} is comments only. The runner would \
                     execute it as a statement — move the comment above the \
                     preceding statement's terminator."
                );
            }
        }
    }

    /// Every registered file must be re-runnable, which rules out `CREATE
    /// TABLE` without `IF NOT EXISTS` and any seed DML or backfill.
    #[test]
    fn sqlite_migrations_are_create_if_not_exists_only() {
        for (file, sql) in SQLITE_MIGRATIONS {
            let bare = strip_line_comments(sql);
            let upper = bare.to_uppercase();
            for forbidden in ["DROP TABLE", "DROP INDEX", "CREATE TRIGGER", "DELETE FROM"] {
                assert!(
                    !upper.contains(forbidden),
                    "{file}: contains `{forbidden}`, which re-runs on every boot"
                );
            }
            for statement in bare.split(';') {
                let s = statement.trim().to_uppercase();
                if s.starts_with("CREATE TABLE") {
                    assert!(
                        s.starts_with("CREATE TABLE IF NOT EXISTS"),
                        "{file}: CREATE TABLE without IF NOT EXISTS"
                    );
                }
                if s.starts_with("CREATE INDEX") || s.starts_with("CREATE UNIQUE INDEX") {
                    assert!(
                        s.contains("IF NOT EXISTS"),
                        "{file}: CREATE INDEX without IF NOT EXISTS"
                    );
                }
            }
        }
    }

    /// Registration trap: both `include_str!` lists are hand-maintained, so a
    /// new file silently does nothing until it is added.
    #[test]
    fn every_sqlite_migration_file_is_registered() {
        let registered: Vec<String> = SQLITE_MIGRATIONS
            .iter()
            .map(|(f, _)| (*f).to_string())
            .collect();
        for file in sql_files_in(&sqlite_migration_dir()) {
            assert!(
                registered.contains(&file),
                "migrations/sqlite/{file} is not in SQLITE_MIGRATIONS — it will never run"
            );
        }
    }

    #[test]
    fn every_postgres_migration_file_is_registered() {
        let registered: Vec<String> = POSTGRES_MIGRATIONS
            .iter()
            .map(|(v, _)| format!("{v}.sql"))
            .collect();
        for file in sql_files_in(&postgres_migration_dir()) {
            assert!(
                registered.contains(&file),
                "migrations/postgres/{file} is not in POSTGRES_MIGRATIONS — it will never run"
            );
        }
    }

    /// The two dialects must stay in lockstep, or a tenant migrated on one
    /// backend has a schema the other cannot read.
    #[test]
    fn sqlite_and_postgres_migration_sets_are_paired() {
        let sqlite: Vec<&str> = SQLITE_MIGRATIONS
            .iter()
            .map(|(f, _)| f.trim_end_matches(".sql"))
            .collect();
        let postgres: Vec<&str> = POSTGRES_MIGRATIONS.iter().map(|(v, _)| *v).collect();
        assert_eq!(sqlite, postgres, "migration lists diverged");
    }

    /// **The guard.** SQLite has no migration version table, so a second
    /// process start re-executes every statement. This opens the same database
    /// file twice in one process and asserts the second run is clean and the
    /// schema still works.
    #[tokio::test]
    async fn sqlite_migrations_are_re_runnable_across_process_starts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rerun.db");
        let url = format!("sqlite://{}?mode=rwc", path.display());

        // First "process start".
        let first = DatabasePool::new_sqlite(&url).await.expect("first migrate");
        drop(first);

        // Second "process start" against the already-migrated file. Every
        // statement in every file runs again. This must not error.
        let second = DatabasePool::new_sqlite(&url)
            .await
            .expect("second migrate must be clean — a stray ';' in a comment fails here");

        let pool = match &second {
            DatabasePool::Sqlite(p) => p.clone(),
            DatabasePool::Postgres(_) => unreachable!(),
        };

        // A third run on the live pool, for good measure.
        DatabasePool::run_migrations(&pool)
            .await
            .expect("third migrate must be clean");

        // The schema still works after three passes: the 019/021/022 tables
        // exist exactly once and accept writes.
        for table in [
            "assets",
            "asset_events",
            "google_device_sync_cursors",
            "google_device_sync_runs",
            "change_sets",
            "change_set_items",
        ] {
            let count: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            )
            .bind(table)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(count.0, 1, "table {table} missing or duplicated");
        }

        let repo = SqliteRepository::new(pool);
        let asset = Asset::new("asset-rerun");
        repo.create_asset(&asset).await.unwrap();
        let page = repo
            .list_assets(&AssetFilter::default(), PageRequest::default())
            .await
            .unwrap();
        assert_eq!(page.total, 1);
    }

    /// Cursor rows must come from code, never from a migration: a seed INSERT
    /// would re-run on every boot and clobber a live `page_token`.
    #[tokio::test]
    async fn device_sync_cursors_are_not_seeded_by_the_migration() {
        let pool = match DatabasePool::new_sqlite_memory().await.unwrap() {
            DatabasePool::Sqlite(p) => p,
            DatabasePool::Postgres(_) => unreachable!(),
        };
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM google_device_sync_cursors")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0);
    }

    /// Every migration file on disk is registered in the `include_str!` array.
    ///
    /// The arrays are hand-maintained, which makes a forgotten entry the
    /// obvious failure mode — and a silent one: the file sits in the directory
    /// looking applied, while the column it adds simply does not exist. The
    /// symptom arrives much later as "no such column" from a query nobody
    /// touched. This turns that into a failing test the moment the file is
    /// added.
    #[test]
    fn every_migration_file_on_disk_is_registered() {
        for (dialect, registered) in [
            ("sqlite", SQLITE_MIGRATIONS),
            ("postgres", POSTGRES_MIGRATIONS),
        ] {
            let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../migrations")
                .join(dialect);
            let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".sql"))
                .collect();
            on_disk.sort();

            for file in &on_disk {
                // The two arrays name their entries differently — SQLite keeps
                // the `.sql` suffix, Postgres does not — so compare on the
                // stem, which is the part that actually identifies a migration.
                let stem = file.trim_end_matches(".sql");
                assert!(
                    registered
                        .iter()
                        .any(|(name, _)| name.trim_end_matches(".sql") == stem),
                    "migrations/{dialect}/{file} exists but is not in {}_MIGRATIONS — \
                     it will never run, and the column it adds will be missing at runtime",
                    dialect.to_uppercase()
                );
            }
            assert_eq!(
                registered.len(),
                on_disk.len(),
                "{dialect}: {} registered vs {} on disk",
                registered.len(),
                on_disk.len()
            );
        }
    }

    /// The two dialects must stay in step. A migration added to one and not the
    /// other is a schema that silently diverges by backend — and the parity
    /// suite only runs with Docker, so it can go unnoticed for a long time.
    #[test]
    fn the_two_dialects_have_the_same_migrations() {
        let sqlite: Vec<&str> = SQLITE_MIGRATIONS
            .iter()
            .map(|(n, _)| n.trim_end_matches(".sql"))
            .collect();
        let postgres: Vec<&str> = POSTGRES_MIGRATIONS
            .iter()
            .map(|(n, _)| n.trim_end_matches(".sql"))
            .collect();
        assert_eq!(sqlite, postgres);
    }
}
