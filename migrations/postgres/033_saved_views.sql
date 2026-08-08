-- Saved queue views (WS-11). See the SQLite copy: named bookmarks over the
-- ticket queue's own query string.

CREATE TABLE IF NOT EXISTS saved_views (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    query_string TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
