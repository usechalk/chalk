-- Optional audience scope for an SSO partner: the classes/orgs whose members
-- may see and launch it in the portal. NULL = unrestricted (visible to all in
-- an allowed role), preserving existing behavior for TOML/database partners.
-- Marketplace installs populate it from the install's data-sharing scope so a
-- section- or school-scoped install only surfaces its app to covered users.
ALTER TABLE sso_partners ADD COLUMN IF NOT EXISTS audience_json TEXT;
