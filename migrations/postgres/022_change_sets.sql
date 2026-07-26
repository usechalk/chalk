-- Postgres parity of sqlite/022_change_sets.sql. Type mapping per the 013
-- header: TEXT timestamps -> TIMESTAMPTZ, INTEGER -> BIGINT, AUTOINCREMENT ->
-- BIGSERIAL.
--
-- This file is applied exactly once, tracked in _meta_schema_migrations, via
-- whole-file sqlx::raw_sql. It is therefore unconstrained -- but the SQLite
-- side is NOT (see the header of sqlite/022_change_sets.sql: every statement
-- there re-runs on every boot, split naively on the semicolon character). Do
-- not add a backfill, trigger, or seed DML here and mirror it back to SQLite.
--
-- `jobs` is deliberately NOT in this file -- it takes a later number in WS-3
-- and links to change sets by a UUID inside jobs.payload, not an FK.

-- STATUS SEMANTICS -- read before adding a status value:
--   planned    the plan exists, nothing has been touched
--   committing a commit has claimed this set
--   committed  the commit loop ran to completion (items may still be
--              individually failed or indeterminate -- see below)
--   discarded  abandoned without committing
--
-- There is deliberately NO `partial` value. ARCHITECTURE 6.3 assumed a crashed
-- process would write one, but nothing can. Display status is DERIVED at read
-- time from change_set_items counts, and a `committing` row whose committed_at
-- is still NULL past a liveness window is reported as INTERRUPTED. Interrupted
-- sets are never auto-resumed -- retry is an explicit human re-arm over items
-- still in ('pending','failed','indeterminate').
--
-- plan_hash and expected_item_count are COLUMNS, not summary JSON keys,
-- because the commit path compares them to the live plan to implement the
-- plan -> commit staleness guard. They must be queryable.
CREATE TABLE IF NOT EXISTS change_sets (
    id TEXT PRIMARY KEY,                              -- UUID
    kind TEXT NOT NULL,                               -- google_writeback|csv_import|bulk_edit
    status TEXT NOT NULL DEFAULT 'planned',           -- planned|committing|committed|discarded
    created_by TEXT NOT NULL,                         -- actor (users.sourced_id or token prefix)
    plan_hash TEXT NOT NULL,                          -- staleness guard, hash over the planned items
    expected_item_count BIGINT NOT NULL DEFAULT 0,    -- staleness guard, item count at plan time
    summary TEXT NOT NULL DEFAULT '{}',               -- JSON, counts per op type, source file hash, etc.
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    committed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_change_sets_status ON change_sets(status);
CREATE INDEX IF NOT EXISTS idx_change_sets_kind ON change_sets(kind);
CREATE INDEX IF NOT EXISTS idx_change_sets_created ON change_sets(created_at);

-- ITEM STATUS -- four values, not two:
--   pending       not yet attempted
--   applied       confirmed applied, applied_at is set
--   failed        confirmed NOT applied, safe to retry
--   indeterminate the remote call's outcome is unknown -- the UI says
--                 "may have applied, verify" rather than "failed". This
--                 exists because moveDevicesToOu is chunk-granular: 50 items
--                 share one outcome.
--   skipped       excluded by the operator at preview time
--
-- target_ref and google_device_id are DENORMALIZED on purpose. asset_id is
-- ON DELETE SET NULL, which would otherwise destroy the audit truth of an
-- already-applied item.
CREATE TABLE IF NOT EXISTS change_set_items (
    id BIGSERIAL PRIMARY KEY,
    change_set_id TEXT NOT NULL REFERENCES change_sets(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    target_ref TEXT,                                  -- denormalized asset identity (serial or tag)
    google_device_id TEXT,                            -- denormalized Directory API deviceId
    op TEXT NOT NULL,                                 -- update_field|move_ou|change_status|create|assign|unassign
    field TEXT,
    old_value TEXT,
    new_value TEXT,
    remote_target TEXT NOT NULL DEFAULT 'local',      -- google when the op writes to Admin SDK, else local
    status TEXT NOT NULL DEFAULT 'pending',           -- pending|applied|failed|indeterminate|skipped
    error TEXT,
    applied_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_change_set_items_set ON change_set_items(change_set_id);
CREATE INDEX IF NOT EXISTS idx_change_set_items_status ON change_set_items(change_set_id, status);
CREATE INDEX IF NOT EXISTS idx_change_set_items_asset ON change_set_items(asset_id);
