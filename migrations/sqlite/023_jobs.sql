-- Background jobs (ARCHITECTURE.md §4.7, §6).
--
-- One in-process worker claims rows here and runs them. There is no Redis and
-- no external queue: a district's whole install is one binary, and the job
-- table is the queue.
--
-- ARCHITECTURE names this file `022_jobs_change_sets.sql`, holding `jobs` plus
-- the change-set tables. Those shipped separately as 022 during WS-1, so `jobs`
-- takes its own number here. There is no FK between them in either direction —
-- a change-set commit job carries its change-set id inside `payload` — so the
-- split is clean and purely additive.
--
-- SQLITE-ONLY CONSTRAINT -- READ BEFORE EDITING THIS FILE:
-- SQLite has no migration version table. core/src/db/mod.rs re-executes every
-- migration file on every process start, splitting the file on the semicolon
-- character with no SQL parsing, and swallowing only errors containing
-- "duplicate column" or "already exists". Therefore, in this file:
--   1. No semicolon anywhere except as a statement terminator -- INCLUDING
--      inside comments. A semicolon in a comment cuts the following statement
--      in half and hands SQLite a fragment. That errors as neither "duplicate
--      column" nor "already exists", so it propagates and fails the migration
--      at boot, on every boot.
--   2. CREATE TABLE / CREATE INDEX IF NOT EXISTS only. No triggers, no seed
--      DML, no backfills, no DROP.
--   3. The file must not end with a trailing comment after the final
--      semicolon -- that fragment would be executed as a statement.
-- The Postgres parity file is unconstrained (real version table, whole-file
-- raw_sql, applied once). Do not add a Postgres backfill and mirror it back.

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,                              -- UUID
    kind TEXT NOT NULL,                               -- google_device_sync|change_set_commit|
                                                      -- imap_poll|csv_import_commit|sla_scan|
                                                      -- notify_flush
    status TEXT NOT NULL DEFAULT 'queued',            -- queued|running|succeeded|failed|cancelled
    payload TEXT NOT NULL DEFAULT '{}',               -- JSON, job-kind specific
    run_after TEXT,                                   -- NULL = as soon as a worker is free
    attempt INTEGER NOT NULL DEFAULT 0,
    -- 1 for every job kind that writes to Google. At-most-once matters more
    -- than at-least-once when a retry could re-apply a fleet-wide mutation, so
    -- a failed Google job is re-armed by a human rather than by the runner.
    max_attempts INTEGER NOT NULL DEFAULT 1,
    started_at TEXT,
    finished_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- The worker's own query: queued rows whose run_after has passed.
CREATE INDEX IF NOT EXISTS idx_jobs_status_run_after ON jobs(status, run_after);
CREATE INDEX IF NOT EXISTS idx_jobs_kind ON jobs(kind);
-- Startup recovery scans running rows by age.
CREATE INDEX IF NOT EXISTS idx_jobs_status_started ON jobs(status, started_at);
