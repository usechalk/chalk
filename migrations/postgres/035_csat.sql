-- CSAT — one satisfaction survey per resolved ticket (WS-11). See the SQLite
-- copy: tokened one-click rating links, first response only.

CREATE TABLE IF NOT EXISTS csat_responses (
    id TEXT PRIMARY KEY,
    ticket_id TEXT NOT NULL UNIQUE REFERENCES tickets(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    score INTEGER,
    sent_at TIMESTAMPTZ NOT NULL,
    responded_at TIMESTAMPTZ
);
