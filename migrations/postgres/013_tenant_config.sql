-- Per-tenant config tables (Wave B): move TOML-based per-tenant configuration
-- into the database so hosted tenants can self-serve via the webui.
--
-- All four tables are singletons (one row per tenant schema). The
-- `id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id)` pattern enforces this at
-- the database layer — only the value TRUE is permitted, so INSERTs after the
-- first either UPSERT or fail.
--
-- Secret columns suffixed `_sealed` hold AES-256-GCM ciphertext produced by
-- `crates/hosted/src/keys.rs::seal`. The format is `nonce(12) || ct || tag(16)`.

CREATE TABLE IF NOT EXISTS tenant_config_sis (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    provider TEXT,
    powerschool_base_url TEXT,
    powerschool_token_url TEXT,
    powerschool_client_id TEXT,
    powerschool_client_secret_sealed BYTEA,
    infinite_campus_base_url TEXT,
    infinite_campus_client_id TEXT,
    infinite_campus_client_secret_sealed BYTEA,
    skyward_base_url TEXT,
    skyward_client_id TEXT,
    skyward_client_secret_sealed BYTEA,
    oneroster_csv_dir TEXT,
    sync_schedule TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_config_google_sync (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    workspace_domain TEXT,
    admin_email TEXT,
    service_account_key_sealed BYTEA,
    provision_users BOOLEAN NOT NULL DEFAULT FALSE,
    manage_ous BOOLEAN NOT NULL DEFAULT FALSE,
    suspend_inactive BOOLEAN NOT NULL DEFAULT FALSE,
    sync_schedule TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_config_idp (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    qr_badge_login BOOLEAN NOT NULL DEFAULT FALSE,
    picture_passwords BOOLEAN NOT NULL DEFAULT FALSE,
    session_timeout_minutes INTEGER,
    default_password_pattern TEXT,
    default_password_roles JSONB,
    saml_cert_sealed BYTEA,
    saml_signing_key_sealed BYTEA,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_config_ad_sync (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    host TEXT,
    port INTEGER,
    bind_dn TEXT,
    bind_password_sealed BYTEA,
    base_dn TEXT,
    user_filter TEXT,
    use_tls BOOLEAN NOT NULL DEFAULT TRUE,
    tls_ca_cert_sealed BYTEA,
    sync_schedule TEXT,
    ou_mapping JSONB,
    groups JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL
);
