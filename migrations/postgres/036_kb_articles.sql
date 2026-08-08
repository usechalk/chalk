-- Knowledge base (WS-11). See the SQLite copy: drafts console-only, published
-- articles readable on the help portal without sign-in.

CREATE TABLE IF NOT EXISTS kb_articles (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    published BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
