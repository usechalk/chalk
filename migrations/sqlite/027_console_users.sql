-- Per-person console accounts, and identity on the session.
--
-- The console authenticated one shared district password and every session was
-- anonymous, so every audit event and every ticket comment was attributed to
-- the literal string "console:admin". A district cannot see which technician
-- resolved a ticket, assign one to a person, or hold anyone accountable in the
-- log. This is the F1 foundation: real per-person identity.
--
-- console_users is a namespace SEPARATE from the SIS roster on purpose. A
-- district's IT technicians are frequently not students or staff in PowerSchool
-- — they are contractors, department staff, or a help-desk vendor — so tying
-- console identity to the roster (`users`) would lock them out. This resolves
-- ARCHITECTURE §12's open question about technician identity.
--
-- Re-runnable per the SQLITE_MIGRATIONS contract: CREATE ... IF NOT EXISTS, and
-- the ALTER ADD COLUMN statements raise "duplicate column" on a second run,
-- which the migration runner swallows. No semicolons inside comments.

CREATE TABLE IF NOT EXISTS console_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    -- Nullable: a magic-link-only technician has no password. NULL means "this
    -- account cannot sign in with a password", not "empty password".
    password_hash TEXT,
    -- admin | technician | read_only
    role TEXT NOT NULL DEFAULT 'technician',
    -- active | disabled
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One account per email. Case-folding is done in code before lookup/insert so
-- this stays a simple unique index.
CREATE UNIQUE INDEX IF NOT EXISTS idx_console_users_email ON console_users (email);

-- Identity carried on the session, captured at login so attribution needs no
-- join. A shared-password login leaves these NULL and resolves to the honest
-- "Administrator" fallback — we genuinely do not know who it was.
ALTER TABLE admin_sessions ADD COLUMN actor_id TEXT;
ALTER TABLE admin_sessions ADD COLUMN actor_label TEXT;
ALTER TABLE admin_sessions ADD COLUMN actor_role TEXT;
