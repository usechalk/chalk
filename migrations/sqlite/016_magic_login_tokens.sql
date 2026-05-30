-- One-time, single-use magic-link login tokens (passwordless login). Only the
-- SHA-256 hash is stored, never the raw token, which travels in the emailed
-- link. SQLite stores timestamps as TEXT (ISO-8601) like the other tables.
CREATE TABLE IF NOT EXISTS magic_login_tokens (
    token_hash TEXT PRIMARY KEY,
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS magic_login_tokens_user ON magic_login_tokens(user_sourced_id);
CREATE INDEX IF NOT EXISTS magic_login_tokens_expires ON magic_login_tokens(expires_at);
