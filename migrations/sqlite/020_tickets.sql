-- Helpdesk: tickets, their comments and their attachments (WS-4).
--
-- WHY A COUNTER TABLE RATHER THAN AUTOINCREMENT:
-- The human-facing ticket number has to mean the same thing on both drivers,
-- and SQLite AUTOINCREMENT and a Postgres sequence do not agree about gaps
-- after a rollback. Incrementing a row inside the insert transaction gives
-- identical semantics on both. Never MAX(number)+1, which races two
-- simultaneous submissions into the same number.
--
-- WHY THE MESSAGE-ID INDEXES ARE UNIQUE AND PARTIAL:
-- Email dedup IS the insert conflict. A read-then-write check would lose to a
-- mail loop delivering the same message twice in the same second, which is the
-- normal failure mode of email ingestion rather than an exotic one. Partial,
-- because most tickets have no Message-ID and NULLs must not collide.
--
-- SQLITE-ONLY CONSTRAINT -- READ BEFORE EDITING THIS FILE:
-- SQLite has no migration version table. core/src/db/mod.rs re-executes every
-- migration file on every process start, splitting the file on the semicolon
-- character with no SQL parsing, and swallowing only errors containing
-- "duplicate column" or "already exists". Therefore, in this file:
--   1. No semicolon anywhere except as a statement terminator -- INCLUDING
--      inside comments.
--   2. CREATE TABLE / CREATE INDEX IF NOT EXISTS only.
--   3. The one INSERT is the documented exception: INSERT OR IGNORE against a
--      single-row table whose primary key is pinned by a CHECK cannot clobber
--      a live counter on re-run. Seeding it in code instead would mean every
--      caller checking first.

CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,
    number INTEGER NOT NULL UNIQUE,
    requester_user_sourced_id TEXT REFERENCES users(sourced_id) ON DELETE SET NULL,
    -- Kept for email-sourced tickets whose sender matches no roster user. A
    -- ticket from a parent or a substitute is still a ticket.
    requester_email TEXT,
    -- Auto-attached from the requester's assignment. THE wedge for helpdesk:
    -- the device module already knows who holds what, so a teacher never types
    -- an asset tag.
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    school_org_sourced_id TEXT REFERENCES orgs(sourced_id) ON DELETE SET NULL,
    assignee_user_sourced_id TEXT REFERENCES users(sourced_id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'open',
    priority TEXT NOT NULL DEFAULT 'normal',
    category TEXT,
    subject TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'portal',
    -- RFC 5322 Message-ID of the originating mail. The unique index below is
    -- what makes email dedup an insert conflict rather than a read-then-write
    -- race against a mail loop.
    email_message_id TEXT,
    sla_due_at TEXT,
    first_response_at TEXT,
    resolved_at TEXT,
    closed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tickets_email_msgid
    ON tickets(email_message_id) WHERE email_message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_assignee ON tickets(assignee_user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_tickets_requester ON tickets(requester_user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_tickets_asset ON tickets(asset_id);
CREATE INDEX IF NOT EXISTS idx_tickets_school ON tickets(school_org_sourced_id);
CREATE INDEX IF NOT EXISTS idx_tickets_sla_due ON tickets(sla_due_at);

CREATE TABLE IF NOT EXISTS ticket_counters (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    next_number INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ticket_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_user_sourced_id TEXT REFERENCES users(sourced_id) ON DELETE SET NULL,
    author_email TEXT,
    body TEXT NOT NULL,
    -- Internal notes never reach the requester portal or an email reply.
    is_internal INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'portal',
    email_message_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ticket_comments_ticket ON ticket_comments(ticket_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ticket_comments_msgid
    ON ticket_comments(email_message_id) WHERE email_message_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ticket_attachments (
    id TEXT PRIMARY KEY,
    ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    comment_id INTEGER REFERENCES ticket_comments(id) ON DELETE SET NULL,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ticket_attachments_ticket ON ticket_attachments(ticket_id);

INSERT OR IGNORE INTO ticket_counters (id, next_number) VALUES (1, 1);
