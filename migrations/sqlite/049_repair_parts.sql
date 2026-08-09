-- Parts consumed by repairs (GP-4)
-- Parts ARE items -- no second inventory namespace -- a repair consumes from
-- the same consumables stock the give-out flow uses which is what makes bulk
-- import and counting come for free
-- item_name is denormalized so a repair's parts list survives item deletion
-- unit_cost_cents is captured at consumption time because catalog prices move

ALTER TABLE items ADD COLUMN unit_cost_cents INTEGER;
ALTER TABLE items ADD COLUMN low_stock_threshold INTEGER;

CREATE TABLE IF NOT EXISTS repair_parts (
    id TEXT PRIMARY KEY,
    repair_id TEXT NOT NULL REFERENCES repair_records(id),
    item_id TEXT NOT NULL,
    item_name TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    unit_cost_cents INTEGER,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_repair_parts_repair ON repair_parts(repair_id);
