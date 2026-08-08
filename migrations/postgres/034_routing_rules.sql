-- Routing rules — auto-assignment at ticket creation (WS-11). See the SQLite
-- copy: NULL category/school is a wildcard, most specific match wins.

CREATE TABLE IF NOT EXISTS routing_rules (
    id TEXT PRIMARY KEY,
    category TEXT,
    school_org_sourced_id TEXT,
    assignee_console_user_id TEXT NOT NULL REFERENCES console_users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL
);
