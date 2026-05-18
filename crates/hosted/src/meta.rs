//! `_meta` schema migrations for the hosted control plane.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// SQL for the `_meta` schema bootstrap migration.
const META_MIGRATION: &str = include_str!("../migrations/postgres/000_meta.sql");

/// Phase 5a: add a nullable `sis_provider` column to `_meta.signup_pending`
/// so the signup form can carry the operator's SIS choice through to
/// `activate_tenant`. Idempotent via `ADD COLUMN IF NOT EXISTS`.
const META_MIGRATION_001_SIGNUP_SIS: &str =
    include_str!("../migrations/postgres/001_signup_sis_provider.sql");

/// Default max-connections cap for short-lived admin pools (CLI subcommands,
/// signup state, etc.). The hosted `serve` path overrides this to 5.
const ADMIN_POOL_MAX_CONNECTIONS: u32 = 2;

/// Run the `_meta` schema migrations on the provided pool.
///
/// Idempotent: uses `CREATE ... IF NOT EXISTS` throughout.
pub async fn run_migrations(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(META_MIGRATION).execute(pool).await?;
    sqlx::raw_sql(META_MIGRATION_001_SIGNUP_SIS)
        .execute(pool)
        .await?;
    Ok(())
}

/// Open a small admin pool against the control-plane Postgres URL and apply
/// the `_meta` migrations. Used by every CLI subcommand that needs to talk
/// to the registry.
pub async fn connect_meta(url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(ADMIN_POOL_MAX_CONNECTIONS)
        .connect(url)
        .await?;
    run_migrations(&pool).await?;
    Ok(pool)
}
