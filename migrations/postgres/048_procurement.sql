-- Procurement fields and records (GP-3)
-- vendor and po_number join the existing purchase_date purchase_cost_cents
-- funding_source warranty_expires block on assets
-- funding_sources promotes the free-text column to a managed list which the
-- edit form offers as choices -- the column itself stays text so history and
-- CSV imports keep working unchanged
-- purchase_orders is a light record an asset row can name by po_number --
-- receiving happens through the existing CSV import diff preview

ALTER TABLE assets ADD COLUMN IF NOT EXISTS vendor TEXT;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS po_number TEXT;

CREATE TABLE IF NOT EXISTS funding_sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS purchase_orders (
    id TEXT PRIMARY KEY,
    po_number TEXT NOT NULL UNIQUE,
    vendor TEXT,
    funding_source TEXT,
    po_date DATE,
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_po_number ON assets(po_number);
CREATE INDEX IF NOT EXISTS idx_assets_warranty ON assets(warranty_expires);
