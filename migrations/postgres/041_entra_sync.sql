-- Entra ID (Azure AD) provisioning state and run history (WS-15b)
-- Mirrors the ad_sync tables one-for-one so the two directory syncs share
-- their operational shape

CREATE TABLE IF NOT EXISTS entra_sync_state (
    user_sourced_id TEXT PRIMARY KEY,
    entra_object_id TEXT NOT NULL,
    upn TEXT NOT NULL,
    field_hash TEXT NOT NULL,
    sync_status TEXT NOT NULL DEFAULT 'pending',
    last_synced_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS entra_sync_runs (
    id TEXT PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'running',
    users_created INTEGER NOT NULL DEFAULT 0,
    users_updated INTEGER NOT NULL DEFAULT 0,
    users_disabled INTEGER NOT NULL DEFAULT 0,
    users_skipped INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    error_details TEXT,
    dry_run BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_entra_sync_state_status ON entra_sync_state(sync_status);
CREATE INDEX IF NOT EXISTS idx_entra_sync_runs_status ON entra_sync_runs(status);
