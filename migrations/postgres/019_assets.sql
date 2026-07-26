-- Postgres parity of sqlite/019_assets.sql. Type mapping per the 013 header:
-- TEXT timestamps -> TIMESTAMPTZ, TEXT dates -> DATE, INTEGER -> BIGINT,
-- AUTOINCREMENT -> BIGSERIAL, BOOLEAN native.
--
-- This file is applied exactly once, tracked in _meta_schema_migrations, via
-- whole-file sqlx::raw_sql. It is therefore unconstrained -- but the SQLite
-- side is NOT (see the header of sqlite/019_assets.sql: every statement there
-- re-runs on every boot, split naively on the semicolon character). Do not add
-- a backfill, trigger, or seed DML here and mirror it back to SQLite.
--
-- The asset <-> users join is the product wedge: assigned_user_sourced_id
-- references users(sourced_id) from 001, so roster context is one JOIN away.

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,                              -- UUID
    asset_tag TEXT,
    serial_number TEXT,
    asset_type TEXT NOT NULL DEFAULT 'chromebook',    -- chromebook|laptop|tablet|projector|hotspot|other
    make TEXT,
    model TEXT,
    status TEXT NOT NULL DEFAULT 'active',            -- active|repair|storage|retired|deprovisioned|lost
    school_org_sourced_id TEXT REFERENCES orgs(sourced_id) ON DELETE SET NULL,
    assigned_user_sourced_id TEXT REFERENCES users(sourced_id) ON DELETE SET NULL,
    org_unit_path TEXT,
    source TEXT NOT NULL DEFAULT 'manual',            -- google|csv|manual|api
    match_state TEXT NOT NULL DEFAULT 'manual',       -- matched|unmatched|manual|ignored
    google_device_id TEXT UNIQUE,                     -- Directory API deviceId, NULL for non-Google assets
    annotated_user TEXT,                              -- raw Google annotatedUser (max 100 enforced in code)
    annotated_asset_id TEXT,                          -- raw Google annotatedAssetId
    aue_date DATE,                                    -- autoUpdateExpiration / supportEndDate
    os_version TEXT,
    last_sync_at TIMESTAMPTZ,
    last_known_ip TEXT,
    purchase_date DATE,
    purchase_cost_cents BIGINT,                       -- integer cents, no floats for money
    funding_source TEXT,
    warranty_expires DATE,
    location TEXT,                                    -- Google annotatedLocation (max 200 enforced in code)
    notes TEXT,                                       -- (max 500 enforced in code when pushed to Google)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_serial
    ON assets(serial_number) WHERE serial_number IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_assigned_user ON assets(assigned_user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_assets_school ON assets(school_org_sourced_id);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_ou ON assets(org_unit_path);
CREATE INDEX IF NOT EXISTS idx_assets_aue ON assets(aue_date);
CREATE INDEX IF NOT EXISTS idx_assets_match_state ON assets(match_state);
CREATE INDEX IF NOT EXISTS idx_assets_updated ON assets(updated_at);

-- Immutable audit trail. Append and read only: AssetEventRepository exposes
-- append_event/list_events and nothing else. Assets are never hard-deleted
-- (retirement is a status change), so RESTRICT is belt-and-suspenders.
CREATE TABLE IF NOT EXISTS asset_events (
    id BIGSERIAL PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    actor TEXT NOT NULL,                              -- users.sourced_id, api token prefix, or 'system:google-sync'
    actor_kind TEXT NOT NULL,                         -- admin|technician|api_token|system
    event_type TEXT NOT NULL,                         -- assigned|unassigned|moved_ou|status_changed|
                                                      -- deprovisioned|repaired|imported|field_changed
    payload TEXT,                                     -- JSON, {"field":..,"old":..,"new":..} or op detail
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asset_events_asset ON asset_events(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_events_created ON asset_events(created_at);
CREATE INDEX IF NOT EXISTS idx_asset_events_type ON asset_events(event_type);
