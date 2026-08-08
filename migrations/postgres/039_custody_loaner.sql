-- Loaner flag on custody (WS-12). See the SQLite copy.

ALTER TABLE custody_records ADD COLUMN IF NOT EXISTS loaner BOOLEAN NOT NULL DEFAULT FALSE;
