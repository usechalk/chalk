-- Google ChromeOS device sync bookkeeping.
--
-- NOTE: the PRD's name `google_sync_state` for device sync collides with the
-- existing per-user google_sync_state table (migration 002, keyed by
-- user_sourced_id, powers Workspace user provisioning). Device sync gets its
-- own tables here. Do not touch 002.
--
-- SQLITE-ONLY CONSTRAINT -- READ BEFORE EDITING THIS FILE:
-- SQLite has no migration version table. core/src/db/mod.rs re-executes every
-- migration file on every process start, splitting the file on the semicolon
-- character with no SQL parsing, and swallowing only errors containing
-- "duplicate column" or "already exists". Therefore, in this file:
--   1. No semicolon anywhere except as a statement terminator -- INCLUDING
--      inside comments. A semicolon in a comment cuts the following statement
--      in half and fails the migration at boot, on every boot.
--   2. CREATE TABLE / CREATE INDEX IF NOT EXISTS only. No triggers, no seed
--      DML, no backfills, no DROP.
--   3. Specifically: google_device_sync_cursors rows are NOT seeded here.
--      The sync engine upserts them in code -- an INSERT here would re-run
--      forever and clobber a live cursor mid-pagination.
--   4. The file must not end with a trailing comment after the final
--      semicolon -- that fragment would be executed as a statement.
-- The Postgres parity file is unconstrained (real version table, whole-file
-- raw_sql, applied once). Do not add a Postgres backfill and mirror it back.

CREATE TABLE IF NOT EXISTS google_device_sync_cursors (
    resource_type TEXT PRIMARY KEY,                   -- chromeosdevices|orgunits|directory_users
    page_token TEXT,                                  -- mid-pagination resume point
    last_full_sync_at TEXT,
    last_delta_at TEXT,
    status TEXT NOT NULL DEFAULT 'idle',              -- idle|running|error
    error_message TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Mirrors google_sync_runs (002). Counters are 64-bit: SQLite INTEGER is
-- already i64, and the Postgres parity file declares BIGINT for the same
-- columns. Bind i64, never `as i32` -- see the truncating binds at
-- postgres.rs update_google_sync_run, which this table deliberately does not
-- copy.
CREATE TABLE IF NOT EXISTS google_device_sync_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,             -- BIGSERIAL in postgres
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',           -- running|succeeded|failed|cancelled
    mode TEXT NOT NULL DEFAULT 'full',                -- full|delta|writeback
    devices_seen INTEGER NOT NULL DEFAULT 0,
    devices_created INTEGER NOT NULL DEFAULT 0,
    devices_updated INTEGER NOT NULL DEFAULT 0,
    devices_matched INTEGER NOT NULL DEFAULT 0,
    devices_unmatched INTEGER NOT NULL DEFAULT 0,
    api_calls INTEGER NOT NULL DEFAULT 0,
    throttle_events INTEGER NOT NULL DEFAULT 0,
    dry_run INTEGER NOT NULL DEFAULT 0,               -- BOOLEAN in postgres
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_gdev_sync_runs_status ON google_device_sync_runs(status);
CREATE INDEX IF NOT EXISTS idx_gdev_sync_runs_started ON google_device_sync_runs(started_at);
