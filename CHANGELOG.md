# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.2.2] - 2026-02-23

### Added
- Clever-compatible SSO endpoints (`/oauth/authorize`, `/oauth/tokens`, `/v3.0/me`, `/v3.0/users/{id}`, etc.) for drop-in Clever API replacement
- ClassLink-compatible SSO endpoints (`/oauth2/v2/auth`, `/oauth2/v2/token`, `/v2/my/info`) for drop-in ClassLink API replacement
- Active Directory sync via LDAP with delta sync engine, OU management, and username/password generation
- `chalk ad-sync` CLI command with `--dry-run`, `--status`, `--test-connection`, `--full`, and `--export-passwords` flags
- `CleverCompat` and `ClassLinkCompat` SSO protocol types for partner configuration
- Student portal auto-redirect for Clever and ClassLink compatible partners (instant SSO)
- External IDs column on users for Clever/ClassLink ID mapping
- AD sync state tracking tables (ad_sync_state, ad_sync_runs) with database migration 007
- Password generation with template patterns (`{firstName}`, `{lastName}`, `{grade}`, `{random4}`)
- Documentation for all three new features

## [1.2.1] - 2026-02-22

### Fixed
- GitHub API URL pointing to wrong organization (`anthropics/chalk` → `usechalk/chalk`)
- git clone URL in README (`chalk-education/chalk` → `usechalk/chalk`)

### Added
- Self-update capability to `chalk update` command (downloads and replaces binary)
- `--check` flag to `chalk update` for check-only behavior
- Install section to README with download links for all platforms

## [1.2.0] - 2026-02-22

### Added
- Universal SSO partner support with both SAML 2.0 and OIDC Authorization Code flow
- Multi-SP SAML with RSA-SHA256 signed assertions and SP-initiated/IDP-initiated flows
- OIDC provider with discovery, JWKS, authorization, token exchange, and userinfo endpoints
- Student/teacher launch portal at `/portal` with role-based app tiles and auto-login
- Portal session system (`chalk_portal` cookie) — separate from admin sessions for security
- SSO partner management in admin console (list, add, edit, toggle, detail views)
- TOML-based `[[sso_partners]]` configuration for SAML and OIDC partners
- Database-managed SSO partners with admin console CRUD
- Role-based app visibility (restrict which apps students vs teachers see)
- Backward-compatible `[idp.google]` config synthesis as an SSO partner
- AuthnRequest parsing with DEFLATE decompression for SP-initiated SAML
- Partner integration guide (`docs/sso-partner-guide.md`)
- School setup guide (`docs/sso-school-setup.md`)
- Database migration 006 for sso_partners, oidc_authorization_codes, and portal_sessions tables

## [1.1.0] - 2026-02-22

### Added
- Webhook delivery system for pushing OneRoster data to external partners
- TOML-based `[[webhooks]]` configuration for self-service partner integrations
- Two security modes: HMAC-SHA256 signing (`sign_only`) and AES-256-GCM payload encryption (`encrypted`) with HKDF key derivation
- Scoping engine with entity type, org, role, and field-level filtering
- Automatic change detection during sync (created/updated/deleted entity tracking)
- Batched and per-entity delivery modes
- Exponential backoff retry strategy (5 attempts: 1min, 5min, 30min, 2hr, 12hr)
- Webhook delivery audit log in database
- Marketplace webhook endpoint injection support (Phase 2 ready)
- Partner documentation with signature verification and decryption code samples in Python, Node.js, Ruby, Go, and Java

## [1.0.0] - 2026-02-22

### Added
- SIS connectors for PowerSchool, Infinite Campus, and Skyward via OneRoster 1.1
- Identity provider with SAML 2.0 SSO, QR badge login, and picture passwords
- Google Workspace sync with automated user provisioning and OU management
- Admin console with dashboard, user directory, sync management, and settings
- OneRoster 1.1 REST API for third-party integrations
- Migration tools for Clever and ClassLink platform transitions
- CLI with init, sync, serve, import, export, migrate, and google-sync commands
- Session authentication with CSRF protection and AES-256-GCM encryption at rest
- Admin audit logging
- SQLite database with automatic migrations
