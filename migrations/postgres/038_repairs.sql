-- Repair records (WS-12). See the SQLite copy: the story behind the "repair"
-- status, with the cost a fee can be assessed from.

CREATE TABLE IF NOT EXISTS repair_records (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ticket_id TEXT REFERENCES tickets(id) ON DELETE SET NULL,
    description TEXT NOT NULL,
    vendor TEXT,
    opened_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ,
    cost_cents BIGINT,
    actor TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_repairs_asset ON repair_records(asset_id);
