-- Granular permission sets and per-user site scoping (GP-2)
-- Built-in role presets are computed in code from the Permission enum so no
-- permission list is stored here and none can drift from the code
-- A console user with a NULL permission_set_id falls back to their role
-- which is how every existing user keeps working the moment this lands

CREATE TABLE IF NOT EXISTS permission_sets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    permissions TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

ALTER TABLE console_users ADD COLUMN permission_set_id TEXT REFERENCES permission_sets(id);

-- A user with rows here is building-scoped and sees only these schools
-- A user with no rows is district-wide which is also the pre-047 behavior
CREATE TABLE IF NOT EXISTS console_user_sites (
    console_user_id TEXT NOT NULL REFERENCES console_users(id) ON DELETE CASCADE,
    school_org_sourced_id TEXT NOT NULL,
    PRIMARY KEY (console_user_id, school_org_sourced_id)
);

-- Whether a scoped user also sees rows with no school at all such as
-- unassigned devices fresh from a sync -- hidden by default
ALTER TABLE console_users ADD COLUMN include_unscoped INTEGER NOT NULL DEFAULT 0;
