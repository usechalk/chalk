-- E-signature on checkout (SS-1)
-- The drawn signature is stored as a base64 PNG data URL with the custody
-- record it belongs to, so the agreement and the mark that accepted it are
-- one row

ALTER TABLE custody_records ADD COLUMN signature_png TEXT;
ALTER TABLE custody_records ADD COLUMN signed_at TEXT;
