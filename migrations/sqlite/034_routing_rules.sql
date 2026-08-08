-- Routing rules — auto-assignment at ticket creation (WS-11).
--
-- "Hardware tickets go to Ana, anything from Beta Middle goes to Ravi." A rule
-- matches on category and/or school (NULL is a wildcard) and names the
-- technician who gets the ticket. The most specific matching rule wins, so a
-- category+school rule beats a category-only one. Applied inside the ticket
-- service, so a ticket routed from email gets the same owner as one typed into
-- the console.
--
-- Re-runnable via IF NOT EXISTS. No semicolons inside comments.

CREATE TABLE IF NOT EXISTS routing_rules (
    id TEXT PRIMARY KEY,
    category TEXT,
    school_org_sourced_id TEXT,
    assignee_console_user_id TEXT NOT NULL REFERENCES console_users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);
