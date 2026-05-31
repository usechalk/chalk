-- Destination URL for launcher-tile SSO partners (protocol is link). Launching
-- such a tile redirects to this URL instead of performing SSO, and it is NULL
-- for the SSO protocols. Used by hosted Google Workspace built-ins and by
-- self-hosted bookmark tiles configured through the console.
ALTER TABLE sso_partners ADD COLUMN launch_url TEXT;
