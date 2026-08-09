-- Tokened read-only dashboard share links (GP-5)
-- A row is a live link -- revocation deletes it -- tokens are random and
-- carry no session so the page they open renders counts only

CREATE TABLE IF NOT EXISTS dashboard_shares (
    token TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);
