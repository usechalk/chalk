-- Postgres parity of sqlite/023_jobs.sql. Type mapping per the 013 header:
-- TEXT timestamps -> TIMESTAMPTZ, INTEGER -> BIGINT.
--
-- This file is applied exactly once, tracked in _meta_schema_migrations, via
-- whole-file sqlx::raw_sql. It is therefore unconstrained -- but the SQLite
-- side is NOT (see the header of sqlite/023_jobs.sql: every statement there
-- re-runs on every boot, split naively on the semicolon character). Do not add
-- a backfill, trigger, or seed DML here and mirror it back to SQLite.
--
-- 022's header notes `jobs` was deferred to a later number and links to change
-- sets by a UUID inside jobs.payload rather than an FK. This is that number.
-- The absence of an FK is deliberate: a commit job outlives the set it commits
-- in the audit sense, and neither table should cascade into the other.

-- STATUS SEMANTICS -- read before adding a status value:
--   queued     waiting for a worker
--   running    a worker has claimed it (see the claim protocol below)
--   succeeded  the handler returned Ok
--   failed     the handler errored and no attempts remain, OR the job was
--              found `running` past the liveness window after a restart
--   cancelled  withdrawn before it ran
--
-- CLAIMING is a conditional UPDATE, not SELECT-then-UPDATE:
--
--   UPDATE jobs SET status='running', ... WHERE id=$1 AND status='queued'
--
-- and the worker proceeds only when exactly one row was affected. That is
-- correct on both drivers without SKIP LOCKED, which matters because SQLite
-- has no such thing. Two workers racing the same row means one of them sees
-- zero rows affected and moves on.
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    payload TEXT NOT NULL DEFAULT '{}',
    run_after TIMESTAMPTZ,
    attempt BIGINT NOT NULL DEFAULT 0,
    -- 1 for every job kind that writes to Google: at-most-once matters more
    -- than at-least-once when a retry could re-apply a fleet-wide mutation.
    max_attempts BIGINT NOT NULL DEFAULT 1,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_jobs_status_run_after ON jobs(status, run_after);
CREATE INDEX IF NOT EXISTS idx_jobs_kind ON jobs(kind);
CREATE INDEX IF NOT EXISTS idx_jobs_status_started ON jobs(status, started_at);
