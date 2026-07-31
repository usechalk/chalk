-- Per-tenant device-sync configuration, with the service-account key sealed.
--
-- Mirrors `tenant_config_google_sync` deliberately: same one-row shape, same
-- `*_sealed BLOB` convention, same updated_at/updated_by audit columns. The
-- device module has its own row rather than borrowing the google_sync one
-- because the two are independently enabled — a district can provision users
-- without syncing devices, and the reverse — and because their credentials may
-- differ (device sync needs only the ChromeOS read scopes).
--
-- WHY SEALED BYTES RATHER THAN A PATH:
-- `[device_sync] service_account_key_path` in chalk.toml is a filesystem path.
-- That works for a self-hoster editing TOML and does not work for anything
-- else: hosted has no filesystem the operator controls, and an OAuth refresh
-- token -- the next credential this module will hold -- is not a path at all.
-- Storing the key material sealed from the start is what stops that from
-- becoming a retrofit. The TOML path stays supported as a fallback.
--
-- SQLITE-ONLY CONSTRAINT -- READ BEFORE EDITING THIS FILE:
-- SQLite has no migration version table. core/src/db/mod.rs re-executes every
-- migration file on every process start, splitting the file on the semicolon
-- character with no SQL parsing, and swallowing only errors containing
-- "duplicate column" or "already exists". Therefore, in this file:
--   1. No semicolon anywhere except as a statement terminator -- INCLUDING
--      inside comments.
--   2. CREATE TABLE / CREATE INDEX IF NOT EXISTS only. No triggers, no seed
--      DML, no backfills, no DROP.
--   3. The file must not end with a trailing comment after the final
--      semicolon.

CREATE TABLE IF NOT EXISTS tenant_config_devices (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    -- Directory API customer. "my_customer" resolves to the impersonated
    -- admin's own domain and is right for every self-hosted install.
    customer_id TEXT,
    -- The super-admin the service account impersonates. Domain-wide delegation
    -- is authorised against this person in the district's own Admin console.
    admin_email TEXT,
    -- AES-256-GCM sealed service-account JSON. Never returned to a browser --
    -- the console shows a fingerprint and offers replacement.
    service_account_key_sealed BLOB,
    page_size INTEGER,
    requests_per_minute INTEGER,
    sync_schedule TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by TEXT NOT NULL
);
