-- Optional audience scope for an SSO partner stored as a JSON string in
-- audience_json (classes/orgs whose members may see and launch the app in the
-- portal). NULL means unrestricted, i.e. visible to all in an allowed role,
-- which preserves existing behavior for TOML and database partners. The hosted
-- marketplace install path populates it from the install data-sharing scope so
-- a section- or school-scoped install only surfaces its app to covered users.
ALTER TABLE sso_partners ADD COLUMN audience_json TEXT;
