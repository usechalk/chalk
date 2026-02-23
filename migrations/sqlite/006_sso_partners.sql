-- SSO Partners table
CREATE TABLE IF NOT EXISTS sso_partners (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    logo_url TEXT,
    protocol TEXT NOT NULL CHECK (protocol IN ('saml', 'oidc', 'clever_compat', 'classlink_compat')),
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'database' CHECK (source IN ('toml', 'database', 'marketplace')),
    tenant_id TEXT,
    roles_json TEXT NOT NULL DEFAULT '[]',
    saml_entity_id TEXT,
    saml_acs_url TEXT,
    oidc_client_id TEXT,
    oidc_client_secret TEXT,
    oidc_redirect_uris_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sso_partners_protocol ON sso_partners(protocol);
CREATE INDEX IF NOT EXISTS idx_sso_partners_enabled ON sso_partners(enabled);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sso_partners_entity_id ON sso_partners(saml_entity_id) WHERE saml_entity_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_sso_partners_client_id ON sso_partners(oidc_client_id) WHERE oidc_client_id IS NOT NULL;

-- OIDC Authorization Codes table
CREATE TABLE IF NOT EXISTS oidc_authorization_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_sourced_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'openid',
    nonce TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oidc_codes_client_id ON oidc_authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_codes_expires ON oidc_authorization_codes(expires_at);

-- Portal Sessions table
CREATE TABLE IF NOT EXISTS portal_sessions (
    id TEXT PRIMARY KEY,
    user_sourced_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_portal_sessions_user ON portal_sessions(user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_portal_sessions_expires ON portal_sessions(expires_at);
