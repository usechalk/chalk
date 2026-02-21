-- IDP Sessions
CREATE TABLE IF NOT EXISTS idp_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    auth_method TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    saml_request_id TEXT,
    relay_state TEXT
);

CREATE INDEX IF NOT EXISTS idx_idp_sessions_user ON idp_sessions(user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_idp_sessions_expires ON idp_sessions(expires_at);

-- QR Badges
CREATE TABLE IF NOT EXISTS qr_badges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    badge_token TEXT NOT NULL UNIQUE,
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_qr_badges_token ON qr_badges(badge_token);
CREATE INDEX IF NOT EXISTS idx_qr_badges_user ON qr_badges(user_sourced_id);

-- Picture Passwords
CREATE TABLE IF NOT EXISTS picture_passwords (
    user_sourced_id TEXT PRIMARY KEY NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    image_sequence TEXT NOT NULL
);

-- IDP Auth Log
CREATE TABLE IF NOT EXISTS idp_auth_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_sourced_id TEXT,
    username TEXT,
    auth_method TEXT NOT NULL,
    success INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_idp_auth_log_user ON idp_auth_log(user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_idp_auth_log_created ON idp_auth_log(created_at);

-- Google Sync State (per-user sync tracking)
CREATE TABLE IF NOT EXISTS google_sync_state (
    user_sourced_id TEXT PRIMARY KEY NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    google_id TEXT,
    google_email TEXT,
    google_ou TEXT,
    field_hash TEXT NOT NULL,
    sync_status TEXT NOT NULL DEFAULT 'pending',
    last_synced_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_google_sync_state_status ON google_sync_state(sync_status);

-- Google Sync Runs
CREATE TABLE IF NOT EXISTS google_sync_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    users_created INTEGER NOT NULL DEFAULT 0,
    users_updated INTEGER NOT NULL DEFAULT 0,
    users_suspended INTEGER NOT NULL DEFAULT 0,
    ous_created INTEGER NOT NULL DEFAULT 0,
    dry_run INTEGER NOT NULL DEFAULT 0,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_google_sync_runs_status ON google_sync_runs(status);

-- Add password_hash column to users table for IDP password auth
ALTER TABLE users ADD COLUMN password_hash TEXT;
