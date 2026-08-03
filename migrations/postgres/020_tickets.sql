-- Helpdesk: tickets, their comments and their attachments (WS-4).
--
-- Postgres parity of the SQLite file of the same number. See that file for why
-- ticket numbers come from a counter row rather than a sequence, and why the
-- Message-ID indexes are unique and partial.
--
-- Postgres has a real migration version table and runs each file once as a
-- whole statement, so this file is unconstrained -- but it deliberately stays a
-- straight translation. A backfill here and not there is a schema that diverges
-- by backend, and the parity suite only runs with Docker.

CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,
    number BIGINT NOT NULL UNIQUE,
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
    sla_due_at TIMESTAMPTZ,
    first_response_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
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
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    next_number BIGINT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ticket_comments (
    id BIGSERIAL PRIMARY KEY,
    ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_user_sourced_id TEXT REFERENCES users(sourced_id) ON DELETE SET NULL,
    author_email TEXT,
    body TEXT NOT NULL,
    -- Internal notes never reach the requester portal or an email reply.
    is_internal BOOLEAN NOT NULL DEFAULT FALSE,
    source TEXT NOT NULL DEFAULT 'portal',
    email_message_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ticket_comments_ticket ON ticket_comments(ticket_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ticket_comments_msgid
    ON ticket_comments(email_message_id) WHERE email_message_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ticket_attachments (
    id TEXT PRIMARY KEY,
    ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    comment_id BIGINT REFERENCES ticket_comments(id) ON DELETE SET NULL,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    sha256 TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ticket_attachments_ticket ON ticket_attachments(ticket_id);

INSERT INTO ticket_counters (id, next_number) VALUES (TRUE, 1)
    ON CONFLICT (id) DO NOTHING;
