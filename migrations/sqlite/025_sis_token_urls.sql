-- Per-provider OAuth token endpoints for Infinite Campus and Skyward.
--
-- Their token URL is not derivable from base_url, so `InfiniteCampusConnector::new`
-- and `SkywardConnector::new` hard-fail without one. `tenant_config_sis` shipped
-- with only `powerschool_token_url`, so a hosted tenant on either provider had
-- nowhere to store the value and its sync could never succeed.
--
-- Re-runnable: SQLite has no IF NOT EXISTS for columns, but the second run
-- raises "duplicate column", which the migration runner swallows. See the
-- SQLITE_MIGRATIONS doc comment in crates/core/src/db/mod.rs.
ALTER TABLE tenant_config_sis ADD COLUMN infinite_campus_token_url TEXT;
ALTER TABLE tenant_config_sis ADD COLUMN skyward_token_url TEXT;
