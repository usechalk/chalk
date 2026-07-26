-- Per-provider OAuth token endpoints for Infinite Campus and Skyward.
--
-- Their token URL is not derivable from base_url, so `InfiniteCampusConnector::new`
-- and `SkywardConnector::new` hard-fail without one. `tenant_config_sis` shipped
-- with only `powerschool_token_url`, so a hosted tenant on either provider had
-- nowhere to store the value and its sync could never succeed.
ALTER TABLE tenant_config_sis ADD COLUMN IF NOT EXISTS infinite_campus_token_url TEXT;
ALTER TABLE tenant_config_sis ADD COLUMN IF NOT EXISTS skyward_token_url TEXT;
