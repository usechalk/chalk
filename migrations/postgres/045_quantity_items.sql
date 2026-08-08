-- Quantity item classes (SS-4): accessories and consumables
-- An accessory is returnable (chargers, hotspots) and a consumable is
-- consumed at issue (styluses, screen protectors) — one table, two rules

CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    item_type TEXT NOT NULL DEFAULT 'accessory',
    notes TEXT,
    quantity_total INTEGER NOT NULL DEFAULT 0,
    school_org_sourced_id TEXT REFERENCES orgs(sourced_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS item_holdings (
    id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    quantity INTEGER NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    returned_at TIMESTAMPTZ,
    actor TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_holdings_item ON item_holdings(item_id, returned_at);
CREATE INDEX IF NOT EXISTS idx_holdings_user ON item_holdings(user_sourced_id);
