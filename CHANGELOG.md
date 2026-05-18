# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Breaking
- `sis.provider` is now optional in TOML (`Option<SisProvider>`). Previously, a
  missing `provider` key under `[sis]` silently meant `"powerschool"`; that
  implicit default has been removed. Self-hosters who relied on the implicit
  default and have `enabled = true` under `[sis]` **must** now add
  `provider = "powerschool"` (or the appropriate provider) explicitly. At
  startup the binary logs a `warn!` when `sis.enabled = true && provider`
  is unset, and the `chalk sync` subcommand / admin-console "Trigger Sync"
  button refuse to run rather than guessing PowerSchool. Existing configs
  that already specify `provider = "..."` are unaffected.

### Added
- Hosted signup form now lets new tenants pick their SIS (or "I'll set this up
  later") at signup time. The choice is persisted on the
  `_meta.signup_pending` row and logged at tenant-activation time; Phase 3/4
  work in Wave B will wire it through to the per-tenant `tenant_config_sis`
  table the parallel agent is creating.

## [1.3.0] - 2026-05-09

Major release: Postgres support, multi-tenant hosted runtime, security hardening.

### Added — Postgres support (OSS)
- `PostgresRepository` implementing `ChalkRepository` against `sqlx::PgPool` (~1400 LOC, parity with SQLite impl)
- 9 ported migrations under `migrations/postgres/` (BOOLEAN/TIMESTAMPTZ/JSONB/BIGSERIAL types)
- `DatabasePool::new_postgres(url, schema)` with per-pool `search_path` pinning
- `run_migrations_postgres` with PL/pgSQL-aware SQL splitter, `_meta_schema_migrations` tracking, and `pg_advisory_xact_lock` per-schema serialization
- `[chalk.database] schema = "..."` config field with regex validation
- `chalk serve` Postgres branch wired (CLI subcommands other than `serve` remain SQLite-only with a uniform helpful error)

### Added — Hosted multi-tenant runtime (`crates/hosted/`)
- New private workspace crate; excluded from `default-members` so OSS self-hosters' `cargo build` is unchanged
- `_meta` schema with `tenants` and `signup_pending` tables
- Tenant resolver middleware: `Host` header → tenant lookup with LRU pool cache (`parking_lot::Mutex`, single-flight on miss)
- `TenantContext` per-tenant: pinned Postgres pool, OSS state structs (`AppState`, `IdpState`, `OidcState`), per-tenant SAML keypair + OIDC JWK sealed at rest with master key (AES-256-GCM)
- Defense-in-depth: `task_local!` `CURRENT_TENANT_SCHEMA` asserted on every `ChalkRepository` method via `TenantScopedRepository` wrapper
- Multi-tenant scheduler: per-tick iteration over active tenants with bounded concurrency, per-tenant SyncEngine dispatch in scoped tenant context
- Per-tenant `tokio::sync::Semaphore` (default 32 permits) and global 30 s `tower_http::timeout::TimeoutLayer` for noisy-neighbor protection
- `SIGHUP` handler clears the state cache so `tenant suspend/unsuspend` takes effect without restart

### Added — `chalk-hosted` CLI
- `serve`, `provision`, `deprovision`, `migrate-all`, `rotate-master-key`, `tenant suspend/unsuspend`
- Shared `meta::connect_meta(url)` helper consolidating admin pool boilerplate across subcommands
- `provision` shares the `activate_tenant` path with the signup verify callback

### Added — Self-serve signup
- Apex `POST /api/signup` and `GET /api/signup/verify` on the hosted binary
- Cloudflare Turnstile validation, per-IP `governor` rate limiting (3/hour), Postmark verification email (spawned off the request path)
- Reserved-slug blocklist + slug regex `^[a-z][a-z0-9-]{2,30}$` shared with manual provisioning
- Verify callback activates tenant, bootstraps admin user, redirects with single-use reset token

### Added — Password reset tokens (OSS)
- New `password_reset_tokens` table (sqlite + postgres migrations) with SHA-256 indexed lookup, atomic single-use consumption, 24 h expiry, GC method
- `PasswordResetTokenRepository` sub-trait on `ChalkRepository`
- `/set-password` route in console consumes a reset token and sets the user's password
- Replaces previous reset-token-stored-as-password-hash anti-pattern

### Added — Marketing site
- New repo `chalk-marketing` (Astro static): landing, pricing, docs, signup pages
- Dev-only `/api/signup` mock with `prerender = false` (production routes via Caddy)

### Added — Operator infra (`infra/`)
- `Caddyfile` with DNS-01 wildcard via Cloudflare module, security headers (HSTS, CSP, frame/content-type/referrer policies)
- `chalk-hosted.service` systemd unit
- `bootstrap.sh` idempotent Ubuntu 24.04 droplet provisioner
- `env.example`, `runbook.md` operator runbook

### Added — CI hygiene
- `cargo audit` GitHub Actions workflow (PR + weekly)
- Dependabot configs for cargo + github-actions (chalk repo) and npm + github-actions (chalk-marketing)

### Security
- Cookies set `Secure` flag when `public_url` is `https://` (5 cookie sites, both console and idp); plain-HTTP self-host deployments unaffected
- All argon2 verify call sites wrapped in `tokio::task::spawn_blocking` to keep the runtime worker pool free
- Audit log events emitted on tenant activation: `tenant_provisioned` and `admin_bootstrapped`
- Per-tenant SAML keypair + OIDC JWK sealed with master key; `rotate-master-key` re-seals all rows in a single transaction
- Reset tokens are single-use, expire in 24 h, cannot be replayed
- Defense-in-depth: every per-tenant repository call asserts the active schema matches the request context

### Performance
- `list_users` 4001 queries → 5 (junction batching via `WHERE x = ANY($1::text[])`); same pattern applied to `list_orgs`, `list_classes`, `list_courses`, `list_academic_sessions`
- Per-tenant Postgres pool default `max_connections` reduced from 10 → 3 (manageable footprint at LRU cap × pool size)
- New junction-table indexes (migration 011) for postgres + sqlite
- StateCache moved to `parking_lot::Mutex` (sync critical section) with single-flight build on cache miss

### Refactoring (DRY)
- New `chalk_core::auth` (`hash_password`, `verify_password`) replaces duplicated argon2 wrappers in console + idp
- New `chalk_core::cookies` (`set_cookie`, `clear_cookie`, `SameSite`, `CookieAttrs`) replaces 5 inline cookie-format sites
- New `chalk_cli::commands::common::{assert_sqlite_only, unwrap_sqlite_pool}` replaces 16 drift-prone Postgres bail arms across 8 CLI subcommand files
- `ChalkRepository` consumers across the workspace migrated from `Arc<SqliteRepository>` to `Arc<dyn ChalkRepository>`; state struct constructors made `pub`
- `TenantStatus` enum bound everywhere (5 raw SQL/JSON status literals eliminated)

## [1.2.4] - 2026-02-27

### Added
- Teacher Dashboard: "My Classes" view at `/portal/my-classes` where teachers can see their enrolled classes with student counts
- Class roster view at `/portal/my-classes/:class_id` showing students enrolled in each class
- Teacher-initiated password reset for students in their classes (auto-generate or set custom password)
- Teacher-initiated QR badge generation for students in their classes
- HTMX-powered inline password reset and badge generation with no page reloads
- `list_enrollments_for_user` and `list_enrollments_for_class` repository methods for efficient enrollment queries
- "My Classes" navigation link in portal header for teacher users
- Audit logging for teacher password resets and badge generation actions (includes student name in badge audit)
- Shared `chalk_core::http::extract_client_ip` utility with security documentation (replaces duplicated helpers)
- SRI integrity hash on HTMX CDN script tag to prevent CDN compromise

### Fixed
- `error_html` now HTML-escapes messages to prevent XSS if user-controlled data flows into error pages
- Class roster `onclick` handler uses `data-student-id` attribute instead of injecting IDs into JS string context (XSS hardening)
- `extract_client_ip` returns `None` for empty X-Forwarded-For headers instead of `Some("")`
- Deduplicated enrollment row-mapping in SQLite repository (4 copies → shared `enrollment_from_row` helper)
- Deduplicated teacher-class authorization into `validate_teacher_for_class` helper (used by 3 handlers)
- Deduplicated student-in-class validation into `validate_student_in_class` helper (used by 2 handlers)
- Console `client_ip` now delegates to shared `extract_client_ip` from chalk-core
- Portal "My Classes" link uses consistent `.nav-link` CSS class instead of inline styles

### Security
- Teacher actions strictly scoped: teachers can only manage students in classes where they have a teacher enrollment
- Cross-class access denied for all teacher dashboard operations
- All teacher dashboard endpoints require valid portal session and teacher role verification

## [1.2.3] - 2026-02-23

### Fixed
- ClassLink `sourced_id_to_integer` now uses SHA-256 instead of `DefaultHasher` for deterministic, cross-platform hashing
- Clever `role_to_clever_type` uses exhaustive match instead of catch-all wildcard; `Aide`, `Proctor`, `Guardian`, `Parent` now map to `"staff"` instead of `"student"`
- Replaced O(n) user lookup loop in Clever SSO with indexed `find_user_by_external_id` query using `json_extract`
- Access tokens now stored in dedicated `access_tokens` table instead of reusing OIDC authorization codes with scope prefix hack

### Added
- `compat_common` module in IDP crate with shared `extract_cookie`, `generate_random_hex`, and `extract_client_credentials` helpers (deduplicated from 5 files)
- `AccessTokenRepository` trait and SQLite implementation with migration 008
- AD Sync group management: automatic creation and membership sync of role-based groups (Students, Teachers, Staff) with migration 009
- `find_user_by_external_id` repository method for efficient external ID lookups

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
