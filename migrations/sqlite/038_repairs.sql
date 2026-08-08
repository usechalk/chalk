-- Repair records (WS-12).
--
-- "repair" was only an asset status. A repair record is the story: what broke,
-- who is fixing it, when it went out and came back, and what it cost — linked
-- to the ticket that reported it when there is one. The cost is what a district
-- reports on and what a fee can be assessed from.
--
-- Re-runnable via IF NOT EXISTS. No semicolons inside comments.

CREATE TABLE IF NOT EXISTS repair_records (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ticket_id TEXT REFERENCES tickets(id) ON DELETE SET NULL,
    description TEXT NOT NULL,
    vendor TEXT,
    opened_at TEXT NOT NULL,
    closed_at TEXT,
    cost_cents INTEGER,
    actor TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_repairs_asset ON repair_records(asset_id);
