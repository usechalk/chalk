-- Report-builder-lite (SS-5): saved asset reports
-- A report is a saved filter (the inventory's own query string) plus one
-- group-by dimension — the URL-as-saved-view idea given a name and a page

CREATE TABLE IF NOT EXISTS asset_reports (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    query TEXT NOT NULL DEFAULT '',
    group_by TEXT NOT NULL DEFAULT 'status',
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL
);
