-- Knowledge base (WS-11).
--
-- Articles IT writes once instead of answering the same question forever —
-- "how to join the wifi", "projector will not pair". Drafts are visible only
-- in the console. Published articles appear on the staff help portal, where
-- reading them needs no sign-in because nothing in them is personal.
--
-- Re-runnable via IF NOT EXISTS. No semicolons inside comments.

CREATE TABLE IF NOT EXISTS kb_articles (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    published INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
