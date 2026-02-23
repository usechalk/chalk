CREATE TABLE IF NOT EXISTS access_tokens (
    token TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_sourced_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user_sourced_id ON access_tokens(user_sourced_id);
