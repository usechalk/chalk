-- Per-person console accounts, and identity on the session. See the SQLite
-- copy of this migration for the full rationale.
--
-- console_users is a namespace separate from the SIS roster on purpose: IT
-- technicians are often not in PowerSchool, so console identity cannot depend
-- on `users`. This resolves ARCHITECTURE §12's technician-identity question.

CREATE TABLE IF NOT EXISTS console_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'technician',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_console_users_email ON console_users (email);

ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS actor_id TEXT;
ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS actor_label TEXT;
ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS actor_role TEXT;
