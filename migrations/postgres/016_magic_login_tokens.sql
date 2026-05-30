-- One-time, single-use magic-link login tokens (passwordless login for the
-- admin console and the IDP portal in hosted mode). Only the SHA-256 hash is
-- stored; the raw token travels in the emailed link. Mirrors
-- password_reset_tokens but creates a session on redemption rather than
-- setting a password.
CREATE TABLE IF NOT EXISTS magic_login_tokens (
    token_hash TEXT PRIMARY KEY,
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS magic_login_tokens_user ON magic_login_tokens(user_sourced_id);
CREATE INDEX IF NOT EXISTS magic_login_tokens_expires ON magic_login_tokens(expires_at);
