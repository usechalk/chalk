-- Postgres parity of sqlite/021_google_device_sync.sql. Type mapping per the
-- 013 header: TEXT timestamps -> TIMESTAMPTZ, INTEGER counters -> BIGINT,
-- INTEGER flags -> BOOLEAN, AUTOINCREMENT -> BIGSERIAL.
--
-- This file is applied exactly once, tracked in _meta_schema_migrations, via
-- whole-file sqlx::raw_sql. It is therefore unconstrained -- but the SQLite
-- side is NOT (see the header of sqlite/021_google_device_sync.sql: every
-- statement there re-runs on every boot, split naively on the semicolon
-- character). Do not add a backfill, trigger, or seed DML here and mirror it
-- back to SQLite. In particular google_device_sync_cursors rows are NOT
-- seeded in either dialect -- the sync engine upserts them in code.
--
-- NOTE: device sync deliberately does not reuse google_sync_state (002),
-- which is the per-user Workspace provisioning table. Do not touch 002.

CREATE TABLE IF NOT EXISTS google_device_sync_cursors (
    resource_type TEXT PRIMARY KEY,                   -- chromeosdevices|orgunits|directory_users
    page_token TEXT,                                  -- mid-pagination resume point
    last_full_sync_at TIMESTAMPTZ,
    last_delta_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'idle',              -- idle|running|error
    error_message TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Mirrors google_sync_runs (002), but every counter is BIGINT and bound as
-- i64. The `as i32` counter binds in postgres.rs update_google_sync_run
-- silently truncate above 2^31 -- do not copy that pattern here.
CREATE TABLE IF NOT EXISTS google_device_sync_runs (
    id BIGSERIAL PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'running',           -- running|succeeded|failed|cancelled
    mode TEXT NOT NULL DEFAULT 'full',                -- full|delta|writeback
    devices_seen BIGINT NOT NULL DEFAULT 0,
    devices_created BIGINT NOT NULL DEFAULT 0,
    devices_updated BIGINT NOT NULL DEFAULT 0,
    devices_matched BIGINT NOT NULL DEFAULT 0,
    devices_unmatched BIGINT NOT NULL DEFAULT 0,
    api_calls BIGINT NOT NULL DEFAULT 0,
    throttle_events BIGINT NOT NULL DEFAULT 0,
    dry_run BOOLEAN NOT NULL DEFAULT FALSE,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_gdev_sync_runs_status ON google_device_sync_runs(status);
CREATE INDEX IF NOT EXISTS idx_gdev_sync_runs_started ON google_device_sync_runs(started_at);
