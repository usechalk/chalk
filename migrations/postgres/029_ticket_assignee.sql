-- Assign a ticket to a technician (WS-11). See the SQLite copy for rationale:
-- a technician is a console_user (F1), not a roster user, so the original
-- roster assignee column could never name them.

ALTER TABLE tickets ADD COLUMN IF NOT EXISTS assignee_console_user_id TEXT
    REFERENCES console_users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_tickets_assignee_console ON tickets(assignee_console_user_id);
