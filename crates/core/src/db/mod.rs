pub mod repository;
pub mod sqlite;

use sqlx::SqlitePool;

use crate::error::Result;

pub enum DatabasePool {
    Sqlite(SqlitePool),
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
