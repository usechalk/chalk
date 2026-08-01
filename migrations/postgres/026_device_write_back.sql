-- Per-tenant opt-in for Google write-back. See the SQLite file of the same
-- number for why this is separate from `enabled`.
--
-- Postgres has a real migration version table and runs each file once as a
-- whole statement, so `IF NOT EXISTS` is belt-and-braces rather than the load-
-- bearing guard it is on the SQLite side.

ALTER TABLE tenant_config_devices
    ADD COLUMN IF NOT EXISTS write_back_enabled BOOLEAN NOT NULL DEFAULT FALSE;
