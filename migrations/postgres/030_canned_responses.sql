-- Canned responses (reply macros) for the help desk (WS-11). See the SQLite
-- copy for rationale: shared, district-wide reply templates.

CREATE TABLE IF NOT EXISTS canned_responses (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
