-- Custody records — the 1:1 circulation loop (WS-12).
--
-- The asset's `assigned_user_sourced_id` says who holds a device NOW. A
-- custody record says when they took it, when it is due back, what condition
-- it left in, whether the device agreement was acknowledged, and — once
-- checked in — when it returned and in what shape. That history is what a
-- district needs at year-end and the single FK cannot carry it.
--
-- At most one OPEN record (checked_in_at IS NULL) per asset, enforced by the
-- partial unique index. Closed records accumulate as history.
--
-- Re-runnable via IF NOT EXISTS. No semicolons inside comments.

CREATE TABLE IF NOT EXISTS custody_records (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    checked_out_at TEXT NOT NULL,
    due_at TEXT,
    checked_in_at TEXT,
    condition_out TEXT,
    condition_in TEXT,
    agreement_acknowledged INTEGER NOT NULL DEFAULT 0,
    actor TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_custody_one_open
    ON custody_records(asset_id) WHERE checked_in_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_custody_user ON custody_records(user_sourced_id);
