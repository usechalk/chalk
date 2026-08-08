-- Ticket tags (WS-11). See the SQLite copy for rationale: a join table so the
-- tag filter is SQL, not string surgery.

CREATE TABLE IF NOT EXISTS ticket_tags (
    ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (ticket_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_ticket_tags_tag ON ticket_tags(tag);
