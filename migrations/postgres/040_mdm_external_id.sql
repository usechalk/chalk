-- Multi-platform MDM groundwork (WS-14). See the SQLite copy: a generic
-- MDM device id beside the Google-specific one.

ALTER TABLE assets ADD COLUMN IF NOT EXISTS external_id TEXT;

CREATE INDEX IF NOT EXISTS idx_assets_external ON assets(source, external_id);
