-- Multi-platform MDM groundwork (WS-14).
--
-- assets.google_device_id keys a row to Google. Intune and Jamf devices need
-- the same stable join to their own consoles, so this adds a generic
-- external_id — the device id in whatever MDM the row came from. The source
-- column already says which system that is. Google rows keep using
-- google_device_id untouched.
--
-- Re-runnable: ALTER ADD COLUMN raises "duplicate column" on a second run,
-- which the migration runner swallows. No semicolons inside comments.

ALTER TABLE assets ADD COLUMN external_id TEXT;

CREATE INDEX IF NOT EXISTS idx_assets_external ON assets(source, external_id);
