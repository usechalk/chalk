CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash TEXT PRIMARY KEY,
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS password_reset_tokens_user ON password_reset_tokens(user_sourced_id);
CREATE INDEX IF NOT EXISTS password_reset_tokens_expires ON password_reset_tokens(expires_at);
