-- Mirror of postgres/011_junction_indexes.sql. SQLite list_ methods use
-- per-parent SELECTs and these indexes help keep schemas aligned.
CREATE INDEX IF NOT EXISTS idx_user_identifiers_user
    ON user_identifiers(user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_orgs_parent
    ON orgs(parent_sourced_id);
CREATE INDEX IF NOT EXISTS idx_academic_sessions_parent
    ON academic_sessions(parent_sourced_id);
