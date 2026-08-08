-- TOTP two-factor auth for console users (SS-3)
-- The secret is the base32 otpauth secret and recovery is a JSON array of
-- SHA-256 hex digests of one-time recovery codes

ALTER TABLE console_users ADD COLUMN totp_secret TEXT;
ALTER TABLE console_users ADD COLUMN totp_confirmed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE console_users ADD COLUMN totp_recovery TEXT;

CREATE TABLE IF NOT EXISTS totp_challenges (
    token TEXT PRIMARY KEY,
    console_user_id TEXT NOT NULL REFERENCES console_users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
