-- Diff-preview-then-commit staging (Google write-backs, CSV re-import, bulk
-- edits). ARCHITECTURE 6.4: plan -> preview -> commit, one two-phase object
-- with three entry points.
--
-- `jobs` is deliberately NOT in this file. It takes a later number in WS-3 and
-- has no FK to change_sets (the link is a UUID inside jobs.payload), so the
-- split is clean and 022 lands independently.
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
--   3. The file must not end with a trailing comment after the final
--      semicolon -- that fragment would be executed as a statement.
-- The Postgres parity file is unconstrained (real version table, whole-file
-- raw_sql, applied once). Do not add a Postgres backfill and mirror it back.

-- STATUS SEMANTICS -- read before adding a status value:
--   planned    the plan exists, nothing has been touched
--   committing a commit has claimed this set
--   committed  the commit loop ran to completion (items may still be
--              individually failed or indeterminate -- see below)
--   discarded  abandoned without committing
--
-- There is deliberately NO `partial` value. ARCHITECTURE 6.3 assumed a crashed
-- process would write one, but nothing can: a crashed process writes nothing,
-- and there is no sweeper to do it for them. Display status is DERIVED at read
-- time from change_set_items counts (ChangeSetRepository::item_status_counts),
-- and a `committing` row whose committed_at is still NULL past a liveness
-- window is reported as INTERRUPTED. Interrupted sets are never auto-resumed:
-- per-item truth already records exactly which items landed, and a retry is an
-- explicit human re-arm over items still in ('pending','failed','indeterminate').
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
    expected_item_count INTEGER NOT NULL DEFAULT 0,   -- staleness guard, item count at plan time
    summary TEXT NOT NULL DEFAULT '{}',               -- JSON, counts per op type, source file hash, etc.
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    committed_at TEXT
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
--                 share one outcome, and a chunk timeout tells us nothing
--                 about any individual device.
--   skipped       excluded by the operator at preview time
--
-- target_ref and google_device_id are DENORMALIZED on purpose. asset_id is
-- ON DELETE SET NULL, which would otherwise destroy the audit truth of an
-- already-applied item. These two columns preserve what was targeted even if
-- the asset row goes away.
CREATE TABLE IF NOT EXISTS change_set_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,             -- BIGSERIAL in postgres
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
    applied_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_change_set_items_set ON change_set_items(change_set_id);
CREATE INDEX IF NOT EXISTS idx_change_set_items_status ON change_set_items(change_set_id, status);
CREATE INDEX IF NOT EXISTS idx_change_set_items_asset ON change_set_items(asset_id);
