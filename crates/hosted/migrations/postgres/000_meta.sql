CREATE SCHEMA IF NOT EXISTS _meta;

CREATE TABLE IF NOT EXISTS _meta.tenants (
    slug TEXT PRIMARY KEY,
    db_schema TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    display_name TEXT NOT NULL,
    admin_email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    saml_keypair BYTEA,
    oidc_signing_jwk JSONB
);

CREATE TABLE IF NOT EXISTS _meta.signup_pending (
    token TEXT PRIMARY KEY,
    slug TEXT NOT NULL,
    admin_email TEXT NOT NULL,
    admin_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS signup_pending_expires ON _meta.signup_pending (expires_at);
