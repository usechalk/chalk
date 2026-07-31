-- Postgres parity of sqlite/024_tenant_config_devices.sql. Type mapping per
-- the 013 header: BLOB -> BYTEA, INTEGER -> BIGINT/BOOLEAN, TEXT timestamps ->
-- TIMESTAMPTZ, and the singleton `id BOOLEAN PRIMARY KEY DEFAULT TRUE
-- CHECK (id)` pattern rather than SQLite's `id INTEGER ... CHECK (id = 1)`.
--
-- This file is applied exactly once, tracked in _meta_schema_migrations, via
-- whole-file sqlx::raw_sql. It is therefore unconstrained -- but the SQLite
-- side is NOT (every statement there re-runs on every boot, split naively on
-- the semicolon character). Do not add a backfill, trigger, or seed DML here
-- and mirror it back.
--
-- The device module has its own row rather than borrowing google_sync's
-- because the two are independently enabled -- a district can provision users
-- without syncing devices, and the reverse -- and because their credentials may
-- differ (device sync needs only the ChromeOS read scopes).
CREATE TABLE IF NOT EXISTS tenant_config_devices (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    -- Directory API customer. "my_customer" resolves to the impersonated
    -- admin's own domain.
    customer_id TEXT,
    -- The super-admin the service account impersonates. Domain-wide delegation
    -- is authorised against this person in the district's own Admin console.
    admin_email TEXT,
    -- AES-256-GCM sealed service-account JSON. Never returned to a browser --
    -- the console shows a fingerprint and offers replacement.
    service_account_key_sealed BYTEA,
    page_size BIGINT,
    requests_per_minute BIGINT,
    sync_schedule TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL
);
