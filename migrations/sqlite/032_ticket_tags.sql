-- Ticket tags (WS-11).
--
-- Free-form labels a technician puts on tickets — "printer", "wifi",
-- "chromebook-cart" — so a queue can be narrowed to a theme that category is
-- too coarse for. A join table rather than a delimited text column, so the tag
-- filter is an EXISTS in SQL and a rename does not need string surgery.
--
-- Re-runnable via IF NOT EXISTS. No semicolons inside comments.

CREATE TABLE IF NOT EXISTS ticket_tags (
    ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (ticket_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_ticket_tags_tag ON ticket_tags(tag);
