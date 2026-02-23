-- SSO compatibility (Clever/ClassLink) and AD Sync support

-- Add external IDs column to users for Clever/ClassLink ID mapping
-- Stores JSON map like {"clever": "5f1a2b3c4d5e6f7a8b9c0d1e", "classlink": 12345}
ALTER TABLE users ADD COLUMN external_ids TEXT NOT NULL DEFAULT '{}';

-- AD Sync state: tracks which roster users have been provisioned to AD
CREATE TABLE IF NOT EXISTS ad_sync_state (
    user_sourced_id TEXT PRIMARY KEY,
    ad_dn TEXT NOT NULL,
    ad_sam_account_name TEXT NOT NULL,
    ad_upn TEXT,
    ad_ou TEXT NOT NULL,
    field_hash TEXT NOT NULL,
    sync_status TEXT NOT NULL DEFAULT 'pending',
    initial_password TEXT,
    last_synced_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- AD Sync run history
CREATE TABLE IF NOT EXISTS ad_sync_runs (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    users_created INTEGER NOT NULL DEFAULT 0,
    users_updated INTEGER NOT NULL DEFAULT 0,
    users_disabled INTEGER NOT NULL DEFAULT 0,
    users_skipped INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    error_details TEXT,
    dry_run INTEGER NOT NULL DEFAULT 0
);

-- Indices for AD sync lookups
CREATE INDEX IF NOT EXISTS idx_ad_sync_state_status ON ad_sync_state(sync_status);
CREATE INDEX IF NOT EXISTS idx_ad_sync_state_ou ON ad_sync_state(ad_ou);
CREATE INDEX IF NOT EXISTS idx_ad_sync_runs_status ON ad_sync_runs(status);
CREATE INDEX IF NOT EXISTS idx_ad_sync_runs_started ON ad_sync_runs(started_at);
