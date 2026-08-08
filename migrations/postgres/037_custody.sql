-- Custody records — the 1:1 circulation loop (WS-12). See the SQLite copy.
-- At most one open record per asset, via the partial unique index.

CREATE TABLE IF NOT EXISTS custody_records (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    checked_out_at TIMESTAMPTZ NOT NULL,
    due_at TIMESTAMPTZ,
    checked_in_at TIMESTAMPTZ,
    condition_out TEXT,
    condition_in TEXT,
    agreement_acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    actor TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_custody_one_open
    ON custody_records(asset_id) WHERE checked_in_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_custody_user ON custody_records(user_sourced_id);
