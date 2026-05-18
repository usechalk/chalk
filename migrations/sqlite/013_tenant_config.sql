-- SQLite parity of postgres/013_tenant_config.sql. Used by `cargo test` against
-- in-memory SQLite. BYTEA -> BLOB, JSONB -> TEXT, BOOLEAN -> INTEGER,
-- TIMESTAMPTZ -> TEXT. See SSO/webhook migrations for the established mapping.

CREATE TABLE IF NOT EXISTS tenant_config_sis (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    provider TEXT,
    powerschool_base_url TEXT,
    powerschool_token_url TEXT,
    powerschool_client_id TEXT,
    powerschool_client_secret_sealed BLOB,
    infinite_campus_base_url TEXT,
    infinite_campus_client_id TEXT,
    infinite_campus_client_secret_sealed BLOB,
    skyward_base_url TEXT,
    skyward_client_id TEXT,
    skyward_client_secret_sealed BLOB,
    oneroster_csv_dir TEXT,
    sync_schedule TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_config_google_sync (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    workspace_domain TEXT,
    admin_email TEXT,
    service_account_key_sealed BLOB,
    provision_users INTEGER NOT NULL DEFAULT 0,
    manage_ous INTEGER NOT NULL DEFAULT 0,
    suspend_inactive INTEGER NOT NULL DEFAULT 0,
    sync_schedule TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_config_idp (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    qr_badge_login INTEGER NOT NULL DEFAULT 0,
    picture_passwords INTEGER NOT NULL DEFAULT 0,
    session_timeout_minutes INTEGER,
    default_password_pattern TEXT,
    default_password_roles TEXT,
    saml_cert_sealed BLOB,
    saml_signing_key_sealed BLOB,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_config_ad_sync (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    host TEXT,
    port INTEGER,
    bind_dn TEXT,
    bind_password_sealed BLOB,
    base_dn TEXT,
    user_filter TEXT,
    use_tls INTEGER NOT NULL DEFAULT 1,
    tls_ca_cert_sealed BLOB,
    sync_schedule TEXT,
    ou_mapping TEXT,
    groups TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by TEXT NOT NULL
);
