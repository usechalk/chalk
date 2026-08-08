-- CSAT — one satisfaction survey per resolved ticket (WS-11).
--
-- When a ticket is resolved, the requester is emailed one-click rating links
-- carrying an unguessable token. One row per ticket (the UNIQUE), created at
-- send time so the token exists before the email does. Only the first response
-- is recorded — a survey is not a poll.
--
-- Re-runnable via IF NOT EXISTS. No semicolons inside comments.

CREATE TABLE IF NOT EXISTS csat_responses (
    id TEXT PRIMARY KEY,
    ticket_id TEXT NOT NULL UNIQUE REFERENCES tickets(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    score INTEGER,
    sent_at TEXT NOT NULL,
    responded_at TEXT
);
