-- Loaner flag on custody (WS-12).
--
-- A loaner is a temporary swap — the student keeps their primary device
-- assignment on the broken machine while carrying this one. The flag marks the
-- loan as temporary so the circulation list can say so, and year-end knows
-- which devices come back first.
--
-- Re-runnable: ALTER ADD COLUMN raises "duplicate column" on a second run,
-- which the migration runner swallows.

ALTER TABLE custody_records ADD COLUMN loaner INTEGER NOT NULL DEFAULT 0;
