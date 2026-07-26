-- Asset inventory: devices tracked by the chalk-devices module.
--
-- The asset <-> users join is the product wedge: assets.assigned_user_sourced_id
-- references users(sourced_id) from 001, so school, grade, homeroom and guardian
-- context are one JOIN away from the roster the SIS sync already populates.
-- FKs target orgs(sourced_id) / users(sourced_id) from 001, so this file lands
-- without needing 020.
--
-- SQLITE-ONLY CONSTRAINT -- READ BEFORE EDITING THIS FILE:
-- SQLite has no migration version table. core/src/db/mod.rs re-executes every
-- migration file on every process start, splitting the file on the semicolon
-- character with no SQL parsing, and swallowing only errors containing
-- "duplicate column" or "already exists". Therefore, in this file:
--   1. No semicolon anywhere except as a statement terminator -- INCLUDING
--      inside comments. A semicolon in a comment cuts the following statement
--      in half and hands SQLite a fragment. That errors as neither "duplicate
--      column" nor "already exists", so it propagates and fails the migration
--      at boot, on every boot.
--   2. CREATE TABLE / CREATE INDEX IF NOT EXISTS only. No triggers, no seed
--      DML, no backfills, no DROP.
--   3. The file must not end with a trailing comment after the final
--      semicolon -- that fragment would be executed as a statement.
-- The Postgres parity file is unconstrained (real version table, whole-file
-- raw_sql, applied once). Do not add a Postgres backfill and mirror it back.

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
    aue_date TEXT,                                    -- autoUpdateExpiration / supportEndDate, ISO 8601 date
    os_version TEXT,
    last_sync_at TEXT,
    last_known_ip TEXT,
    purchase_date TEXT,
    purchase_cost_cents INTEGER,                      -- integer cents, no floats for money
    funding_source TEXT,
    warranty_expires TEXT,
    location TEXT,                                    -- Google annotatedLocation (max 200 enforced in code)
    notes TEXT,                                       -- (max 500 enforced in code when pushed to Google)
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
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
    id INTEGER PRIMARY KEY AUTOINCREMENT,             -- BIGSERIAL in postgres
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    actor TEXT NOT NULL,                              -- users.sourced_id, api token prefix, or 'system:google-sync'
    actor_kind TEXT NOT NULL,                         -- admin|technician|api_token|system
    event_type TEXT NOT NULL,                         -- assigned|unassigned|moved_ou|status_changed|
                                                      -- deprovisioned|repaired|imported|field_changed
    payload TEXT,                                     -- JSON, {"field":..,"old":..,"new":..} or op detail
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_asset_events_asset ON asset_events(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_events_created ON asset_events(created_at);
CREATE INDEX IF NOT EXISTS idx_asset_events_type ON asset_events(event_type);
