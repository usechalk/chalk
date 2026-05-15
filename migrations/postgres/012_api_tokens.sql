-- API tokens for authenticating external clients against the OneRoster REST
-- API. Tokens are tenant-scoped (live in the tenant schema in hosted mode),
-- 32 random bytes hex-encoded with a `chk_` prefix shown as plaintext to the
-- admin exactly once at creation; only the SHA-256 hash is stored.
CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_revoked_at ON api_tokens(revoked_at);
