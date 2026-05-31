-- Destination URL for launcher-tile SSO partners (protocol = 'link'). Launching
-- such a tile redirects here instead of performing SSO. NULL for SSO protocols.
-- Used by hosted Google Workspace built-ins and self-hosted bookmark tiles.
ALTER TABLE sso_partners ADD COLUMN IF NOT EXISTS launch_url TEXT;

-- Allow the new 'link' protocol on existing tables (the original CHECK from 006
-- predates it). Drop the auto-named inline constraint and re-add it widened.
ALTER TABLE sso_partners DROP CONSTRAINT IF EXISTS sso_partners_protocol_check;
ALTER TABLE sso_partners ADD CONSTRAINT sso_partners_protocol_check
    CHECK (protocol IN ('saml', 'oidc', 'clever_compat', 'classlink_compat', 'link'));
