-- Assign a ticket to a technician (WS-11).
--
-- The ticket model shipped with `assignee_user_sourced_id`, a roster FK — but a
-- technician who works the help desk is a console_user (F1), not a student or
-- teacher in the SIS, so the roster column can never name them and the console
-- never had a way to set it. This adds the column that can.
--
-- The old roster column stays: it is harmless, and removing a column from a
-- naively re-run SQLite migration set is not worth the risk. New assignment
-- uses this one.
--
-- Re-runnable: ALTER ADD COLUMN raises "duplicate column" on a second run,
-- which the migration runner swallows. No semicolons inside comments.

ALTER TABLE tickets ADD COLUMN assignee_console_user_id TEXT REFERENCES console_users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_tickets_assignee_console ON tickets(assignee_console_user_id);
