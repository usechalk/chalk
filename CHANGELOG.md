# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.6.1] - 2026-05-30

Audience-scoped SSO partners — the launch portal now hides an app from users
outside its data-sharing scope, not just outside its allowed roles. This is the
generic primitive hosted marketplace installs use so a section- or
school-scoped install only surfaces its app to the students/teachers actually
covered (closing a tile over-exposure where a teacher's classroom app, or a
grade-scoped district install, appeared to every student tenant-wide).

### Added
- **`SsoPartner.audience` (`Option<SsoAudience>`).** A marketplace-agnostic
  audience scope of allowed classes, orgs (schools), and grades. Each populated
  dimension is a constraint (empty = wildcard) and the dimensions are AND-ed, so
  an install scoped to "school A, grade 9" reaches only grade-9 students at
  school A. `None`/unrestricted = visible to everyone in an allowed role —
  preserving existing behavior for TOML/database partners and OSS self-hosters.
  Persisted in the new nullable `sso_partners.audience_json` column (migration
  `017`). New `SsoPartner::is_within_audience(classes, orgs, grades)`.

### Security
- **The launch portal enforces audience scope at both tile-render and launch.**
  `portal_home` filters tiles by the user's enrollments/orgs/grades, and
  `portal/launch/:id` re-checks audience so an out-of-scope user can't reach an
  app by guessing its launch URL (defense in depth alongside the existing role
  check).

## [1.6.0] - 2026-05-30

Optional passwordless admin login — the building block hosted/cloud
deployments use to drop admin passwords entirely. Off by default; OSS
self-hosters keep the password flow unless they opt in.

### Added
- **Magic-link admin login (opt-in).** A binary can now enable passwordless
  console login by injecting a `chalk_core::mail::MagicLinkMailer` via
  `AppState::with_magic_login(...)`. When enabled, `/login` emails a one-time
  link (15-min, single-use, hashed at rest in the new `magic_login_tokens`
  table; migration `016`) and `/login/verify` redeems it into an admin
  session. Only `Administrator`-role users with a matching email may log in,
  and the response is uniform regardless of whether the email matches (no
  account enumeration). The mailer abstraction keeps email-provider code out
  of the core/console crates; a `LoggingMailer` is provided for dev.

### Security
- **`auth_middleware` enforces the session whenever magic-link login is
  enabled.** Previously the console skipped authentication entirely when no
  `admin_password_hash` was configured (an OSS "run-open-in-dev" shortcut).
  That shortcut now applies *only* when both no password is set **and**
  magic-link is disabled — so any deployment using magic-link (e.g. hosted
  multi-tenant) always requires a valid session on protected paths.

## [1.5.0] - 2026-05-28

Foundation for scoped third-party data access — the generic primitive the
hosted marketplace builds on, kept fully marketplace-agnostic so OSS installs
are unaffected.

### Added
- **API tokens can carry an optional read scope.** A new `TokenScope`
  (`chalk_core::models::token_scope`) narrows what a single OneRoster API token
  may read along five dimensions — orgs (schools/districts), grades, subjects,
  sections (class sourcedIds), and per-resource allow/deny — plus a
  `redact_fields` list that strips sensitive fields (e.g. `birthDate`) from
  serialized `users`/`demographics` payloads. The scope is persisted on
  `api_tokens.scope` (JSONB on Postgres, JSON text on SQLite; migration `015`)
  and is **nullable**: a `NULL` scope means unrestricted, so every existing
  token and self-hosted deployment behaves exactly as before.
- **OneRoster API enforces token scope.** `oneroster_bearer_middleware` now
  loads the authenticated token's scope into the request, and every
  `/api/oneroster/v1p1` list/get handler filters rows, gates resources
  (`403` for denied families), and redacts fields accordingly. Out-of-scope
  `get` lookups return `404` so a scoped token can't probe for records it
  can't see. Section/subject scopes resolve a user's enrollments to decide
  visibility ("share students in math sections").

## [1.4.5] - 2026-05-28

Three bugs surfaced by a user trying to get their first hosted tenant
configured from the webui:

### Fixed
- **SIS / Google / AD dashboards now link to their settings pages.**
  The `/sync`, `/google-sync`, and `/ad-sync` dashboards rendered the
  current config and a "Trigger Sync" button but offered no path to the
  matching `/<dashboard>/settings` editor — the only way to find it was
  to know the URL. Each dashboard now has a "Configure …" call-to-action
  next to its Actions section. The Google and SIS dashboards also dropped
  the stale "(manual trigger only — scheduled syncs coming soon)"
  annotation; scheduled syncs shipped earlier this wave.
- **`chalk serve` auto-discovers `chalk.toml` after `chalk init`.**
  On Windows (and any platform where the data directory isn't the cwd),
  `chalk init` wrote `chalk.toml` under the platform's data directory
  (`%LOCALAPPDATA%\chalk` on Windows, `~/Library/Application Support/chalk`
  on macOS, `/var/lib/chalk` on Linux), but `chalk serve` defaulted
  `--config` to `chalk.toml` in the cwd and failed with a confusing
  "file not found." `--config` is now optional; when omitted, chalk
  probes the cwd first, then the platform data directory, and reports
  every path it tried if none exist.
- **API Tokens page is now reachable from the sidebar.** `/settings/api-tokens`
  was only discoverable by reading source. Added a sidebar entry with
  its own active-page highlight.

## [1.4.4] - 2026-05-28

### Fixed
- **Hosted OIDC `/authorize` now finds manually-created SSO partners.**
  A user created an OIDC SSO Partner via `/sso-partners/new`, got a
  `client_id` back from the console, then hit
  `/idp/oidc/authorize?client_id=…` and was rejected with
  `{"error":"invalid_request","error_description":"unknown client_id"}`
  — even though the partner showed `Enabled` in the admin console.
  Root cause: hosted `TenantContext::build` constructed `OidcState`
  with `Vec::new()` (empty partners) and only loaded the real partner
  list afterward for the Clever / ClassLink compat-router gates. The
  OSS `chalk serve` path (cli/serve.rs) already did this correctly.
  Hosted now loads partners up front and passes the same list into
  `OidcState::new`. The existing SSO-invalidator hook already evicts
  the cached `TenantContext` on partner CRUD, so a freshly-created
  partner is queryable on the next request.

## [1.4.3] - 2026-05-27

Same-day follow-up to 1.4.2. The SAML download button shipped in 1.4.2
only resolved certs from `idp.saml_cert_path` (a filesystem path) — but
on hosted tenants the cert lives sealed in `_meta.tenants.saml_keypair`
and is only unsealed into memory at context build, never written to
disk. A brand-new hosted tenant clicking Download therefore got a
404 ("SAML certificate not configured…") even though their cert was
already generated at signup and reachable via `/idp/saml/metadata` XML.

### Fixed
- `/identity/saml-cert.pem` now falls back to the in-memory provisioned
  SAML cert when no on-disk path is set. Resolution order:
  1. `AppState::saml_signing_cert_pem` — populated by the hosted
     context from the unsealed `_meta.tenants.saml_keypair`.
  2. `state.config.idp.saml_cert_path` — used by self-hosted OSS
     installs and hosted tenants who've uploaded a custom cert.
- New `AppState::with_saml_signing_cert(pem)` builder so hosted code
  can pass through the provisioned cert without exposing
  `IdpState`'s internals to the console crate.

## [1.4.2] - 2026-05-27

Two bugs caught by an early user during local self-hosted setup. Patch
release.

### Fixed
- **`chalk init` now picks a platform-appropriate default `--data-dir`.**
  The CLI hard-coded `/var/lib/chalk` regardless of platform, so on Windows
  the printed init summary (Database / SAML cert / SAML key / Master key
  paths) showed `/var/lib/chalk/…` while files were actually being written
  somewhere else on the C: or D: drive — the summary didn't match what
  the filesystem had. New `chalk_core::config::default_data_dir()` picks:
  - Windows → `%LOCALAPPDATA%\chalk` (e.g. `C:\Users\<user>\AppData\Local\chalk`).
    Falls back to `%USERPROFILE%\chalk` then `C:\ProgramData\chalk`.
  - macOS → `$HOME/Library/Application Support/chalk`.
  - Linux / other Unix → `/var/lib/chalk` (unchanged for existing installs).
  Pass `--data-dir <path>` to override on any platform. The same helper
  now also drives `ChalkConfig::generate_default()`.
- **`/identity/saml-setup` shows a download button for the SAML
  certificate** instead of just a server filesystem path. The page told
  admins to "Upload the SAML certificate from `/var/lib/chalk/saml.crt`"
  — a path their browser can't reach when they're configuring Google
  Workspace from a different machine. New `GET /identity/saml-cert.pem`
  route streams the cert as `application/x-pem-file` with
  `Content-Disposition: attachment; filename="chalk-saml-cert.pem"`.
  The server path is still surfaced behind a collapsed `<details>` for
  self-hosters who want to back up or inspect it.

## [1.4.1] - 2026-05-27

Pre-launch hardening pass. Wave B's webui shipped a real bug list on first
production smoke-test — multipart submissions died on CSRF, settings saves
didn't propagate to the running engines, the LDAP-URI round-trip was
broken, the OneRoster API had no pagination, and the cron scheduler logged
ticks but never dispatched. This release fixes those and adds the missing
ops escape hatches schools need to actually run the service.

### Fixed
- **Multipart settings forms now pass CSRF.** The CSRF middleware only
  validated `csrf_token` on `application/x-www-form-urlencoded` bodies, so
  every save on `/google-sync/settings`, `/identity/settings`, and
  `/ad-sync/settings` (all multipart for file uploads) returned `403 CSRF
  token missing`. Middleware now scans the multipart body for the token
  part, with case-preserving boundary parsing.
- **Settings saves immediately invalidate the cached `TenantContext`.**
  Previously a save persisted the row but the running engines kept their
  old config until the LRU evicted naturally — materialized secret files
  never appeared on disk, schedule changes were ignored. The four
  settings POST handlers now call `notify_tenant_config_changed()` so the
  next request rebuilds the context with the fresh row.
- **AD `connection.server` round-trips cleanly.** `import-toml` used to
  store the full `ldaps://host:port` URI in the `host` column with
  `port = NULL`; the loader then re-prefixed the scheme, emitting
  `ldap://ldaps://host:port:port`. Importer now parses the URI into
  `(use_tls, host, port)` triples; `use_tls` is derived from the scheme
  (not the unrelated `tls_verify` cert-validation flag). New
  `chalk_core::ldap::{parse_ldap_uri, build_ldap_uri}` helpers shared by
  the importer, loader, and the AD settings form (which now auto-parses
  pasted full URIs in the Host field).
- **Webhook delete no longer fails with FK violation.** The
  `webhook_deliveries → webhook_endpoints` foreign key now has `ON DELETE
  CASCADE` (migration 014 for existing tenants + corrected DDL in
  migration 005 for fresh ones).
- **Webhook form accepts checkbox-group submissions.** Selecting any
  combination of `entity_types` previously returned `400 invalid type:
  string, expected a sequence` because `axum::Form` collapses repeated
  keys. A hand-written `FromRequest` impl now aggregates repeated keys
  into the `Vec<String>` field.
- **Google sync init failures surface in the History table.** Previously
  a pre-engine failure (bad service-account JSON, missing admin email)
  only logged `tracing::error` server-side — the user got "background
  sync started" and then the history list stayed empty. We now record a
  `google_sync_runs` row up front and update its status to Failed with
  the error message.
- **Malformed JSON in settings forms redirects with an actionable
  message** instead of silently wiping the prior row or coercing to
  `Value::String` (which later broke `apply_idp` on every cache miss).
  Applies to `default_password_roles`, `ou_mapping`, and `groups`.
- **`SealingTenantConfigRepo` treats `Some(empty)` as unset** on both
  seal and unseal, so empty secret submissions can't blank a field via a
  non-`None` sealed blob.
- **`/settings/api-tokens` form includes a `csrf_token` hidden input** —
  previously only the `hx-headers` attribute was set, so non-htmx submits
  hit `CSRF token missing`.
- **CSP allows Google Fonts.** The Caddy CSP blocked `fonts.googleapis.com`
  + `fonts.gstatic.com`, falling back to system fonts and (on
  chrome-in-chrome) tripping a "Security error" tab title. Added
  explicit `style-src` + `font-src` entries.
- **SIS "provider not set" error message points at the SIS Settings
  page** instead of `chalk.toml` (which doesn't exist in hosted mode).
- **CI no longer fails with "No space left on device."** The
  `ubuntu-latest` runner's ~14 GB free space couldn't fit the grown
  cargo cache during restore. Added the `jlumbroso/free-disk-space`
  prelude and dropped `target/` from the cache key.
- **`/identity` no longer blocks browser debuggers from attaching.**
  Changed `hx-trigger="load"` → `hx-trigger="revealed"` on the auth-log
  panel so the htmx XHR doesn't race the page load.
- **Signup form accepts both JSON and `application/x-www-form-urlencoded`.**
  Previously rejected non-JSON submissions with `415` — users with JS
  disabled (or curl) got an unrecoverable error.

### Added — Pre-launch features
- **`chalk-hosted reset-admin-password --tenant <slug>`** — ops escape
  hatch for customers who forget their admin password. Generates a 24h
  one-time reset URL, audits the issuance, prints to stdout. Self-serve
  forgot-password flow is post-launch scope.
- **OneRoster 1.1 pagination.** All seven list endpoints accept
  `?limit=N&offset=N` (default 100 / 0, cap 1000), and emit
  `X-Total-Count` + RFC 5988 `Link` headers (`rel="next"`, `"prev"`,
  `"first"`, `"last"`). Real Clever / ClassLink / vendor integrations
  paginate by default and would otherwise re-ingest the full collection
  on every page.
- **Multi-tenant cron scheduler now dispatches sync engines.** The
  scheduler tick previously read schedules and did nothing. It now runs
  the SIS, Google Sync, and AD Sync engines per tenant on their cron
  schedules. Uses a new `cron_due` helper with a 24h lookback so a
  paused tenant catches up with one run, not hundreds; accepts both
  POSIX 5-field (`min hour dom mon dow`) and `cron`-crate 6-field
  (`sec min hour dom mon dow`) expressions.
- **Hosted signup seeds `tenant_config_sis` with the operator's
  chooser pick.** Previously the choice was logged at activation but
  never written to the per-tenant row — first-login operators saw
  "Provider: Not configured" even though they'd picked PowerSchool.
- **`/webhooks` admin section wired into the router.** The handlers had
  existed in `crates/console/src/webhooks.rs` since Phase 3.1 but were
  never registered. List / new / detail / edit / delete / test routes
  all exposed; sidebar nav entry added.
- **Self-hosted htmx** at `/static/htmx-2.0.4.min.js`. Pinned bundle
  embedded via `include_str!`, served with long cache headers, exempt
  from auth + CSRF. CSP no longer needs a unpkg.com exception (it
  didn't have one and silently broke other htmx pages).

### Changed
- Settings-page source badge says `"defaults"` (was `"toml"`) when no
  DB row exists yet — hosted tenants have no TOML file.
- Dashboard surfaces `Hosting: managed` for Postgres tenants instead of
  leaking the per-tenant schema name.
- `AdSyncEngine` repo bound loosened to `R: ChalkRepository + ?Sized`
  so callers can pass an `Arc<dyn ChalkRepository>` (matches the
  existing `GoogleSyncEngine`).
- Schedule fields on `/sync` and `/google-sync` previously annotated
  "manual trigger only — scheduled syncs coming soon"; now that the
  cron scheduler dispatches, the annotation is stale and should be
  removed in 1.4.2.

## [1.4.0] - 2026-05-18

Hosted tenant config moves out of TOML and into the database. Hosted operators
no longer need to edit server-side files to configure SIS, Google Sync, IDP,
or AD sync — every setting is editable from the admin console settings pages.
Secrets (OAuth client secrets, Google service-account JSON, SAML cert/key,
AD bind password, TLS CA) are sealed with the master key at rest.

### Breaking
- `sis.provider` is now optional in TOML (`Option<SisProvider>`). Previously
  a missing `provider` key under `[sis]` silently meant `"powerschool"`; that
  implicit default has been removed. Self-hosters who relied on the implicit
  default and have `enabled = true` under `[sis]` **must** now add
  `provider = "powerschool"` (or the appropriate provider) explicitly. At
  startup the binary logs a `warn!` when `sis.enabled = true && provider`
  is unset, and `chalk sync` / the admin-console "Trigger Sync" button
  refuse to run rather than guessing PowerSchool.

### Added — Hosted tenant config in the database
- New per-tenant tables (`migrations/postgres/013_tenant_config.sql` +
  sqlite parity): `tenant_config_sis`, `tenant_config_google_sync`,
  `tenant_config_idp`, `tenant_config_ad_sync` (singleton rows). All
  secret-bearing columns are sealed `BYTEA` (AES-256-GCM under
  `MASTER_ENCRYPTION_KEY`).
- `TenantConfigRepo` trait with paired `get_*`/`put_*` methods; Postgres and
  SQLite implementations. Hosted code accesses the trait through
  `SealingTenantConfigRepo`, which seals/unseals at the boundary.
- `TenantContext::build` folds the four DB sections onto the synthesized
  `ChalkConfig` per cache miss. Independent gets fan out via `tokio::try_join!`.
- Console settings pages: `/sync/settings`, `/google-sync/settings`,
  `/identity/settings`, `/ad-sync`, `/ad-sync/settings`. Multipart uploads for
  Google SA JSON, SAML cert/key, and AD TLS CA. Each page shows a
  `source: toml | database` badge; secrets render as `(set)` placeholders
  with an explicit Replace affordance — values are never re-rendered to HTML.
- `chalk-hosted import-toml --tenant <slug> --file <path>`: one-shot migration
  tool that imports a legacy TOML into the per-tenant tables, sealing secrets.
  Idempotent on retry.
- Hosted signup form lets new tenants pick their SIS provider (or "I'll set
  this up later"); the choice seeds the `tenant_config_sis` row.
- `rotate-master-key` re-seals the 8 new tenant-config sealed columns across
  every tenant in a single transaction.
- Materialized secret files under `<data_dir>/tenants/<slug>/` are cleaned up
  by `TenantContext`'s `Drop` impl on LRU eviction.

### Fixed
- AD `connection.server` round-trips correctly through `import-toml` → loader.
  Previously the importer stored the full `ldaps://host:port` URI in the
  `host` column with `port = NULL`, and the loader re-prefixed the scheme,
  producing `ldap://ldaps://host:port`. The importer now parses the URI into
  `(use_tls, host, port)` and the loader rebuilds it via `build_ldap_uri`.
- AD `use_tls` is now derived from the URI scheme on import (was incorrectly
  populated from `tls_verify`, which controls cert validation, not transport).
- Console settings forms surface a `?err=…` redirect when `default_password_roles`,
  `ou_mapping`, or `groups` JSON fails to parse. Previously a malformed value
  silently wiped the prior row (or, worse, coerced to `Value::String`, which
  later broke `apply_idp` at every cache miss).
- `SealingTenantConfigRepo` treats `Some(empty)` plaintext as `None`, so
  empty secret submissions cannot blank out a field via a non-`None` sealed blob.

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
