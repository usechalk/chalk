-- Saved queue views (WS-11).
--
-- A named bookmark over the ticket queue's filter parameters — "Unassigned
-- urgent", "Beta Middle wifi" — saved from the queue itself and offered back
-- as one-click links. The stored value is the queue's own query string, which
-- is already the canonical serialization of a view. District-wide, like canned
-- responses: the value is a shared triage vocabulary.
--
-- Re-runnable via IF NOT EXISTS. No semicolons inside comments.

CREATE TABLE IF NOT EXISTS saved_views (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    query_string TEXT NOT NULL,
    created_at TEXT NOT NULL
);
