pub mod postgres;
pub mod repository;
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

        let migrations: &[(&str, &str)] = &[
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
        ];

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

        let migrations: &[&str] = &[
            include_str!("../../../../migrations/sqlite/001_initial_schema.sql"),
            include_str!("../../../../migrations/sqlite/002_idp_google_sync.sql"),
            include_str!("../../../../migrations/sqlite/003_admin_audit.sql"),
            include_str!("../../../../migrations/sqlite/004_config_overrides.sql"),
            include_str!("../../../../migrations/sqlite/005_webhooks.sql"),
            include_str!("../../../../migrations/sqlite/006_sso_partners.sql"),
            include_str!("../../../../migrations/sqlite/007_sso_compat.sql"),
            include_str!("../../../../migrations/sqlite/008_access_tokens.sql"),
            include_str!("../../../../migrations/sqlite/009_ad_sync_groups.sql"),
            include_str!("../../../../migrations/sqlite/010_password_reset_tokens.sql"),
            include_str!("../../../../migrations/sqlite/011_junction_indexes.sql"),
            include_str!("../../../../migrations/sqlite/012_api_tokens.sql"),
            include_str!("../../../../migrations/sqlite/013_tenant_config.sql"),
            include_str!("../../../../migrations/sqlite/014_webhook_deliveries_cascade.sql"),
            include_str!("../../../../migrations/sqlite/015_api_token_scope.sql"),
            include_str!("../../../../migrations/sqlite/016_magic_login_tokens.sql"),
            include_str!("../../../../migrations/sqlite/017_sso_partner_audience.sql"),
            include_str!("../../../../migrations/sqlite/018_sso_partner_launch_url.sql"),
        ];

        for migration_sql in migrations {
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
                        result?;
                    }
                }
            }
        }
        Ok(())
    }
}
