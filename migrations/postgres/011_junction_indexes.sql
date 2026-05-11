-- Indexes supporting batched FK lookups in list_* methods.
--
-- Most junction tables have a composite PK with the parent FK first, so
-- the PK already covers prefix lookups. The exceptions are:
--   * user_identifiers: PK is on the BIGSERIAL `id`, not user_sourced_id.
--   * orgs.parent_sourced_id / academic_sessions.parent_sourced_id: not
--     junctions, but used for child fan-out which list_orgs and
--     list_academic_sessions now batch via WHERE parent_sourced_id = ANY(...).
CREATE INDEX IF NOT EXISTS idx_user_identifiers_user
    ON user_identifiers(user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_orgs_parent
    ON orgs(parent_sourced_id);
CREATE INDEX IF NOT EXISTS idx_academic_sessions_parent
    ON academic_sessions(parent_sourced_id);
