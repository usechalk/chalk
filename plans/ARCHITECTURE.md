# Chalk ARCHITECTURE.md

**Status:** Draft for review · July 2026
**Scope:** Target architecture for Chalk v1.0 hosted launch (Devices + Helpdesk), per PRD v1.0 §5–§7 as amended by the Gate A memo (CANON: strangler pattern, no AssetRemix rewrite or sidecar, native Rust Devices/Helpdesk modules).
**Sources:** Direct inspection of `chalk`, `chalk-hosted-crate`, `asset-getter-backend`, `Chromebook-Getter` repos. All file paths below are real paths in those repos.

---

## 1. System context

```
                                K-12 DISTRICT ESTATE (post-Gate-A)
                                ==================================

  ┌────────────────┐   SIS REST/OneRoster   ┌─────────────────────────────────────────────┐
  │ PowerSchool /  │───────────────────────▶│                CHALK BINARY                 │
  │ InfiniteCampus │                        │  (one Rust binary; self-host AND hosted)    │
  │ / Skyward      │                        │                                             │
  └────────────────┘                        │  core ── roster (OneRoster), SyncEngine,    │
                                            │          crypto, mail, webhooks, repos      │
  ┌────────────────┐  Admin SDK (directory, │  console ─ HTMX admin UI + REST API         │
  │ Google         │  chromeosdevices, OUs, │  idp ───── SAML 2.0 / QR / picture pwd      │
  │ Workspace      │◀──────────────────────▶│  google-sync ─ user provisioning + NEW      │
  │ (customer's)   │  users, issueCommand)  │               ChromeOS device sync (WS-1)   │
  └────────────────┘                        │  ad-sync ── LDAP provisioning               │
                                            │  chalk-devices ── NEW (WS-3)                │
  ┌────────────────┐  LDAPS                 │  chalk-helpdesk ─ NEW (WS-4)                │
  │ Active         │◀──────────────────────▶│                                             │
  │ Directory      │                        │  SQLite (self-host) / Postgres schema       │
  └────────────────┘                        │  (hosted, per tenant)                       │
                                            └─────────────┬───────────────▲───────────────┘
  ┌────────────────┐  IMAP poll (self-host)               │               │
  │ District mail /│─────────────────────────────────────▶│               │ module flags,
  │ Postmark       │  inbound webhook (hosted)            │               │ provisioning,
  │ inbound        │                                      │               │ cron dispatch
  └────────────────┘                                      │               │
                                            ┌─────────────▼───────────────┴───────────────┐
  ┌────────────────┐   signup / pricing     │        CHALK-HOSTED CONTROL PLANE           │
  │ Marketing site │──────────────────────▶ │  (private crate, v1.5.x)                    │
  │ chalk-marketing│   CTA links            │  _meta.tenants registry · per-tenant PG     │
  │ (Astro/Caddy)  │                        │  schema · Scheduler/cron_due · Postmark     │
  └───────▲────────┘                        │  mailer · admin/platform_admin · signup     │
          │                                 │  [marketplace/vendor portal: DORMANT, D4]   │
          │  CTA panel                      └─────────────────────────────────────────────┘
          │  ("Your fleet, synced free →")
  ┌───────┴────────┐
  │ Chromebook     │   FROZEN. 1.8k LOC Apps Script. Two reliability bugs fixed (WS-0.4),
  │ Getter add-on  │   then feature-freeze. Its ONLY job: verified listing + install base
  │ (Marketplace)  │   as a funnel. Scopes/identity NEVER change (D6). No data flow to Chalk.
  └────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │ ASSETREMIX (maintenance island — serves Llano ISD, Malakoff ISD, KIPP Indy)          │
  │ TS/Express/Apollo · Sequelize/Postgres · Redis+BullMQ · PubSub/CloudRun/GCS ·        │
  │ Firebase · Chargify · BoxyHQ · WorkOS · Postmark. 5 deployed processes.              │
  │                                                                                      │
  │ DELIBERATELY DOES NOT INTEGRATE WITH CHALK. Not a sidecar, not a module, no shared   │
  │ DB, no API bridge. Chalk reads its CODE as a reference spec (consumers/, migrations) │
  │ — never its runtime. Eventual `chalk import assetremix` is a one-way offline export, │
  │ deadline driven by district readiness, not launch.                                   │
  └─────────────────────────────────────────────────────────────────────────────────────┘
```

What deliberately does **not** integrate:

| Pair | Why not |
|---|---|
| Chalk ↔ AssetRemix runtime | Strangler pattern (Gate A §2). AssetRemix's dependency stack (PubSub, Redis, Firebase, Chargify…) cannot be self-hosted; federation is a fiction. |
| Chromebook Getter ↔ Chalk data | D6: never touch the verified listing's scopes/identity. CTA is a hyperlink, nothing more. |
| chalk-hosted marketplace/vendor portal ↔ anything | D4: code stays (`vendor.rs`, `tenant_marketplace.rs`, `portal_ui.rs`), routes not surfaced. |
| Chalk ↔ Chargify | Hosted billing is annual PO/invoice, mostly manual (§8). Chargify remains AssetRemix-only. |

---

## 2. Current state per crate (verified July 2026)

Workspace: `chalk/` — Cargo workspace, Axum 0.7, sqlx 0.8 (`sqlite` + `postgres` features), Askama, Tokio. Migrations at `chalk/migrations/sqlite/` (001–018) with Postgres parity files in `chalk/migrations/postgres/` (mapping documented in `013_tenant_config.sql`: BYTEA→BLOB, JSONB→TEXT, BOOLEAN→INTEGER, TIMESTAMPTZ→TEXT). Migrations embedded via `include_str!`, run at startup.

| Crate | LOC | What exists today |
|---|---|---|
| `core` | ~25k | OneRoster 1.1 models (`src/models/`); `DatabasePool` enum over SQLite + Postgres (`src/db/mod.rs`, with schema-scoped `search_path` for Postgres); 30+ repository traits in `src/db/repository.rs` (one `#[async_trait] pub trait XRepository: Send + Sync` per entity, aggregated in the `ChalkRepository` supertrait), implemented twice in `src/db/sqlite.rs` (6.3k) and `src/db/postgres.rs` (3.6k); SIS connectors PowerSchool/InfiniteCampus/Skyward (`src/connectors/`); `SyncEngine` (`src/sync.rs`); OneRoster CSV import/export; Clever/ClassLink migration parsers; AES-256-GCM sealing (`src/crypto.rs`, "sealed BLOB" columns); LDAP (`src/ldap.rs`); `MagicLinkMailer` trait (`src/mail.rs`, 30 lines — trait + `LoggingMailer`); webhooks with retry/delivery tracking (`src/webhooks/`); typed config (`src/config.rs`: `ChalkConfig` → `SisConfig`, `IdpConfig`, `GoogleSyncConfig`, `AdSyncConfig`, …). |
| `cli` | ~2.6k | Binary entry point. Subcommands (verified in `src/main.rs`): `init`, `sync`, `status`, `update`, `serve`, `google-sync`, `import`, `export`, `passwords`, `migrate`, `webhook`, `ad-sync` — all with `--dry-run` where mutation is involved. |
| `console` | ~9.7k | Askama+HTMX admin UI (`templates/` per feature area: `google_sync/`, `identity/`, `migration/`, `sso/`, `sync/`, `users/`, `webhooks/`, `settings/`), static assets embedded (`static/htmx-2.0.4.min.js`, font). Session auth: login authenticates **roster `users` with `RoleType::Administrator`** against `PasswordRepository` hashes; `admin_sessions` table; magic-link login; login rate limiter; CSRF (`src/csrf.rs`). Read-only OneRoster REST API at `src/api/oneroster.rs`, bearer-token auth via `oneroster_bearer_middleware` + `api_tokens` (hashed, prefixed, revocable, optional JSON `TokenScope`). |
| `idp` | ~8.5k | SAML 2.0 IdP, QR badge login, picture passwords, portal sessions, auth log. Act 2 — built, not touched by this plan. |
| `google-sync` | ~2.7k | Workspace **user** provisioning + OU management. `src/auth.rs`: `GoogleAuth::from_service_account` — service-account JWT (RS256) with domain-wide delegation, impersonating `admin_email`. `src/client.rs`: hand-rolled reqwest Directory client (users CRUD, suspend, OU list/create). **No ChromeOS device calls, no backoff/retry yet.** `google_sync_state` table (002) is per-**user** provisioning state — name collision with PRD §6, see §4.3. |
| `ad-sync` | ~2.9k | LDAP provisioning from roster. Act 2, done. |
| `agent` | ~0.4k | AI diagnostics stub. |
| `marketplace` | stub | Disabled by default (`[marketplace] enabled = false`). |
| `telemetry` | ~0.6k | Opt-in anonymous usage. |

### 2.1 Verified corrections — READ BEFORE BUILDING (added July 25 2026)

Direct inspection during WS-0 found three load-bearing assumptions in this document and its companions to be **false about the current codebase**. Anything built on them will not work.

| Assumption | Reality | Consequence |
|---|---|---|
| **Assets are embedded via `rust-embed`** (PRD D9; §10 below; `DESIGN_SYSTEM.md` §6 AG Grid note) | **`rust-embed` is not a dependency anywhere in the workspace.** Assets are two hand-rolled handlers using `include_str!`/`include_bytes!`: `console/src/lib.rs:315-333` serves htmx, `:335-355` serves the brand font. Both set `Cache-Control: immutable`. `tower-http` is present but `ServeDir` is unused. | The single-binary property (D9) still holds — it's just achieved differently. But there is **no content-hashed filename mechanism** and no asset manifest. `DESIGN_SYSTEM.md` §10.1's `tokens.9f3a.css` scheme has to be built, not merely used. Adding rust-embed is a reasonable WS-2 task; just don't assume it's already there. |
| **CSS lives in files** (`DESIGN_SYSTEM.md` §10.1's `assets/css/{tokens,base,components,console,portal}.css` tree) | **There are no `.css` files in the repo.** All styling is one inline `<style>` block at `console/templates/base.html:8-164`, with the `:root` token block at `:15-44`. That block is **copy-pasted** into 10 `crates/idp/templates/*.html` files and again into `chalk-hosted-crate/src/portal_ui.rs:14-124` as a Rust string constant. Three copies, no shared source. | WS-2's first task is **extraction**, not authoring: create the file tree, serve it, and collapse three divergent copies into one source of truth. Until that lands, any token change must be made in three places or the surfaces drift. This is also why D17's "keep indigo" is cheap and a re-theme would not have been. |
| **SQLite migrations are versioned** (§4.1's conventions imply normal migration semantics) | **SQLite has no migration version table at all.** `core/src/db/mod.rs:243-256` re-runs *every* statement on every boot, naïvely splitting the file on `;` and swallowing "duplicate column"/"already exists" errors. (Postgres is fine — it tracks `_meta_schema_migrations` with an atomic claim, `db/mod.rs:107-114`.) Both drivers' file lists are hardcoded `include_str!` arrays (`db/mod.rs:116-190` and `:222-241`) that must be hand-edited per migration. | **Migrations 019–024 must be written to survive re-execution:** no `;` inside string literals, trigger bodies, or `CHECK` constraints (the splitter will cut them mid-statement); `CREATE TABLE/INDEX IF NOT EXISTS` only; **no non-idempotent DML** — note that `020_tickets.sql`'s `INSERT OR IGNORE INTO ticket_counters` is correctly idempotent, but any seed data added later must be too. Every new migration also means editing both `include_str!` arrays. |

Two smaller facts worth having: `ChalkRepository` (`core/src/db/repository.rs:500`) is a 29-trait supertrait with two full implementations (`sqlite.rs` 6.3k lines, `postgres.rs` 3.6k) — **every new entity costs edits in five places** (repository.rs, both impls, both migration dirs) plus the two `include_str!` arrays, which is the real per-entity cost of §4.2's six migrations. And there is **no jobs/scheduler module in core today** (§6 describes something to be built); the only cron code is `cron_due.rs` in the hosted crate, which is pure `chrono`+`cron` and moves cleanly — but `scheduler.rs` is welded to hosted's `StateCache`/`TenantRegistry`/`TenantContext` and does *not* move without genericizing over a tenant-provider trait.

---

`chalk-hosted-crate` (private, v1.5.10, ~13k LOC): multi-tenant control plane. **Tenancy = one shared Postgres, one schema per tenant** (`_meta.tenants` registry with `slug`, `db_schema` via `schema_for_slug`, `status` provisioning/active/suspended, sealed key material; `tenant_migrations.rs::apply(pool, schema)`). `scheduler.rs`: `Scheduler` struct, `tokio::time::interval` with `MissedTickBehavior::Skip`, ~60s tick, spawns per-tenant engine runs. `cron_due.rs`: pure `cron_due(expr, last_run, now)` — 5-field POSIX cron normalized to 6-field, missed ticks coalesced into one run, malformed expressions never fire, 24h lookback cap. Also: signup, mailer (Postmark), notify, admin, platform_admin, state_cache, keys, and dormant marketplace/vendor-portal modules.

`asset-getter-backend` (AssetRemix, maintenance island): ~54k LOC TS, 76 Sequelize models, 148 migrations, 5 deployed processes. Reference implementations for edge cases: `src/consumers/chromebookInitialSync.ts` (device ingest), `src/consumers/emailToTickets.ts` (inbound mail parsing, loop guards), `src/consumers/ticketAssignBot.ts` (auto-assign rules), `src/consumers/snipeItSync.ts` (external-inventory reconciliation). Port lessons, never code.

`Chromebook-Getter`: 1.8k LOC Apps Script. Frozen after WS-0.4 bug fixes.

---

## 3. Target state: `chalk-devices` and `chalk-helpdesk`

### 3.1 Crate shape — follow the established split

Observed convention: **models + repository traits + migrations live in `core`; behavior lives in the feature crate; UI lives in `console`.** (`idp` and `google-sync` both work this way: `IdpSessionRepository`/`GoogleSyncStateRepository` are in `core/src/db/repository.rs`, the crates hold logic, and their templates live in `console/templates/identity/` and `console/templates/google_sync/`.) Every feature crate depends only on `chalk-core` (`chalk-core = { path = "../core" }`). Do the same — do **not** invent self-contained crates with private repo traits; that would fork the `DatabasePool`/`ChalkRepository` pattern and duplicate the sqlite/postgres impl plumbing.

```
crates/core/src/models/asset.rs          Asset, AssetStatus, AssetType, AssetEvent, AssetEventType, MatchState
crates/core/src/models/ticket.rs         Ticket, TicketStatus, TicketPriority, TicketComment, TicketAttachment
crates/core/src/db/repository.rs         + AssetRepository, AssetEventRepository, TicketRepository,
                                           TicketCommentRepository, TicketAttachmentRepository,
                                           GoogleDeviceSyncRepository, JobRepository, ChangeSetRepository
                                           (added to the ChalkRepository supertrait)
crates/core/src/db/sqlite.rs, postgres.rs   impls for both drivers
crates/core/src/attachments.rs           AttachmentStore trait + FsAttachmentStore (§4.5)
crates/core/src/jobs/                    Scheduler + cron_due + JobRunner (ported from hosted, §6)

crates/devices/        (package `chalk-devices`)
  src/lib.rs           module wiring
  src/service.rs       AssetService: CRUD-with-events, assignment, bulk ops, guarded deprovision
  src/matching.rs      device→roster matching (§5.6)
  src/sync.rs          Google device sync orchestration: full/delta, diff-plan builder
  src/csv.rs           CSV/Sheets round-trip with diff preview (reuses core::oneroster_csv patterns)
  src/reports.rs       AUE planning, OS distribution, unassigned, by-school

crates/helpdesk/       (package `chalk-helpdesk`)
  src/lib.rs
  src/service.rs       TicketService: lifecycle, numbering, SLA timers, first-response tracking
  src/assign.rs        auto-assign rules (reference: ticketAssignBot.ts — keep v1 to round-robin + category→assignee map)
  src/email_ingest.rs  inbound mail → ticket/comment (§7)
  src/notify.rs        outbound notifications via core Mailer (§7.3)

crates/google-sync/src/chromeos.rs       Admin SDK ChromeOS client (§5) — extends the existing crate per Gate A §4
crates/console/src/devices/  + templates/devices/    UI: inventory table, device detail, unmatched queue, bulk ops, diff preview
crates/console/src/helpdesk/ + templates/helpdesk/   UI: technician queue, ticket detail, teacher portal (own minimal layout)
crates/console/src/api/devices.rs, api/tickets.rs    REST API (§3.3)
```

`cli` grows: `chalk devices sync [--dry-run]`, `chalk devices import <csv> [--dry-run]`, `chalk devices export`, `chalk mail-poll` (one-shot IMAP ingest for cron-style self-hosters). `serve` starts the in-process scheduler (§6).

### 3.2 Module enablement — config flags + nav gating (no plugin runtime)

Extend `core/src/config.rs` with a `ModulesConfig` section, defaulting Act-2 modules per existing `enabled` flags:

```toml
[modules]
devices  = true
helpdesk = true
roster   = true    # roster/SSO surfaces; maps onto existing [idp]/[sso] enablement
sso      = false
```

- All modules compile into the one binary; flags gate **routing and navigation only**. `console` builds its Axum `Router` conditionally (`if config.modules.devices { router = router.nest("/devices", …) }`) and `templates/base.html` gates nav items. Disabled module routes 404.
- Self-host: `chalk.toml`. Nothing feature-gated in the OSS build (D2/D8 — the gate is asset *type* on the hosted free tier, enforced by the control plane, never by compile-time features).
- Hosted: control plane writes a `tenant_config_modules` singleton row (same pattern as `tenant_config_sis` etc. in migration 013: `id CHECK (id = 1)`, `updated_at`, `updated_by`) into the tenant schema; `tenant_config_loader` merges it over file config exactly as it does for SIS/Google/IdP config today. Entitlement flow: §8.

### 3.3 REST API for assets/tickets

Extend `console/src/api/` (today: `mod.rs` + `oneroster.rs`) — same crate, same middleware, new modules:

- `GET/POST /api/v1/devices`, `GET/PATCH /api/v1/devices/{id}`, `GET /api/v1/devices/{id}/events`, `POST /api/v1/devices/import` (CSV, returns a change-set id for diff preview), `GET /api/v1/devices/export.csv`
- `GET/POST /api/v1/tickets`, `GET/PATCH /api/v1/tickets/{id}`, `POST /api/v1/tickets/{id}/comments`
- Auth: existing `api_tokens` (hashed token, prefix, revocation) + `scope` JSON (migration 015). Extend `TokenScope` with module scopes: `devices:read`, `devices:write`, `tickets:read`, `tickets:write`. `NULL` scope stays "unrestricted" (preserves current OSS semantics).
- **Deprovision and `issueCommand` are console-only in v1** — not exposed through the API. Irreversible, license-audited operations stay behind interactive typed confirmation (§9.2). Revisit if an integrator asks.
- This API is also WS-5's Sheets bridge surface (5.1 kept, 5.2 killed): token + `export.csv` + import-with-diff is the whole spreadsheet story.

---

## 4. Data model

### 4.1 Conventions (read off `001_initial_schema.sql` … `018`)

- SQLite-first; each migration gets a Postgres parity file under `migrations/postgres/` (mapping per 013 header comment).
- `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS idx_<table>_<col>`; snake_case.
- IDs: roster entities use OneRoster `sourced_id TEXT PRIMARY KEY`; app-owned entities use `id TEXT PRIMARY KEY` holding a UUID (`webhook_endpoints`, `api_tokens`); append-only logs use `INTEGER PRIMARY KEY AUTOINCREMENT` (`admin_audit_log`, `idp_auth_log`, `google_sync_runs`) → `BIGSERIAL` in Postgres.
- Timestamps: `TEXT` RFC3339, `DEFAULT (datetime('now'))` where sensible → `TIMESTAMPTZ DEFAULT now()`.
- FKs inline `REFERENCES t(c) ON DELETE …`; junctions get composite PKs.
- Secrets: `*_sealed BLOB` (AES-256-GCM via `core::crypto`).
- **No `tenant_id` columns.** PRD §6 lists `tenant_id` on every table; drop it. Chalk's tenancy is schema-level (hosted: one Postgres schema per tenant; self-host: one SQLite file). Adding row-level tenancy would contradict every existing table and buy nothing.
- PRD's `school_id→schools.id` / `assigned_user_id→users.id` become `…→orgs(sourced_id)` / `…→users(sourced_id)` — there is no `schools` table; schools are `orgs` with `org_type='school'`.

### 4.2 Migration files to add

| File (sqlite + postgres pair) | Contents |
|---|---|
| `019_assets.sql` | `assets`, `asset_events` |
| `020_tickets.sql` | `tickets`, `ticket_counters`, `ticket_comments`, `ticket_attachments` |
| `021_google_device_sync.sql` | `google_device_sync_cursors`, `google_device_sync_runs` |
| `022_jobs_change_sets.sql` | `jobs`, `change_sets`, `change_set_items` |
| `023_module_config.sql` | `tenant_config_modules`, `tenant_config_devices`, `tenant_config_helpdesk` (013-style singletons; sealed Google OAuth/IMAP credentials) |
| `024_console_roles.sql` | `console_roles` (§9.1) |

### 4.3 DDL — `019_assets.sql`

The **asset ↔ users join is the product wedge** ("the only asset tracker that already knows your students"): `assets.assigned_user_sourced_id → users(sourced_id)` means school, grade, homeroom, and guardian context are one JOIN away from the roster the SIS sync already populated. Nothing about a device's owner is ever re-entered.

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,                              -- UUID
    asset_tag TEXT,
    serial_number TEXT,
    asset_type TEXT NOT NULL DEFAULT 'chromebook',    -- chromebook|laptop|tablet|projector|hotspot|other
    make TEXT,
    model TEXT,
    status TEXT NOT NULL DEFAULT 'active',            -- active|repair|storage|retired|deprovisioned|lost
    school_org_sourced_id TEXT REFERENCES orgs(sourced_id) ON DELETE SET NULL,
    assigned_user_sourced_id TEXT REFERENCES users(sourced_id) ON DELETE SET NULL,
    org_unit_path TEXT,
    source TEXT NOT NULL DEFAULT 'manual',            -- google|csv|manual|api
    match_state TEXT NOT NULL DEFAULT 'manual',       -- matched|unmatched|manual|ignored   (§5.6)
    google_device_id TEXT UNIQUE,                     -- Directory API deviceId; NULL for non-Google assets
    annotated_user TEXT,                              -- raw Google annotatedUser (≤100 enforced in code)
    annotated_asset_id TEXT,                          -- raw Google annotatedAssetId
    aue_date TEXT,                                    -- autoUpdateExpiration / supportEndDate
    os_version TEXT,
    last_sync_at TEXT,
    last_known_ip TEXT,
    purchase_date TEXT,
    purchase_cost_cents INTEGER,                      -- integer cents; no floats for money
    funding_source TEXT,
    warranty_expires TEXT,
    location TEXT,                                    -- Google annotatedLocation (≤200 enforced in code)
    notes TEXT,                                       -- (≤500 enforced in code when pushed to Google)
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_serial
    ON assets(serial_number) WHERE serial_number IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_assigned_user ON assets(assigned_user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_assets_school ON assets(school_org_sourced_id);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_ou ON assets(org_unit_path);
CREATE INDEX IF NOT EXISTS idx_assets_aue ON assets(aue_date);
CREATE INDEX IF NOT EXISTS idx_assets_match_state ON assets(match_state);

-- Immutable audit trail. Append + read only: AssetEventRepository exposes
-- append_event/list_events and nothing else. Assets are never hard-deleted
-- (retirement is a status change), so RESTRICT is belt-and-suspenders.
--
-- NOTE: no semicolons anywhere in this file except as statement terminators,
-- including inside comments. The SQLite migration runner
-- (core/src/db/mod.rs:241-256) splits the file on the semicolon character with
-- no SQL parsing, so one inside a comment cuts the next statement in half and
-- hands SQLite a fragment. That errors as neither "duplicate column" nor
-- "already exists", so it propagates and fails the migration at boot.
CREATE TABLE IF NOT EXISTS asset_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,             -- BIGSERIAL in postgres
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    actor TEXT NOT NULL,                              -- users.sourced_id, api token prefix, or 'system:google-sync'
    actor_kind TEXT NOT NULL,                         -- admin|technician|api_token|system
    event_type TEXT NOT NULL,                         -- assigned|unassigned|moved_ou|status_changed|
                                                      -- deprovisioned|repaired|imported|field_changed
    payload TEXT,                                     -- JSON: {"field":…, "old":…, "new":…} or op detail
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_asset_events_asset ON asset_events(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_events_created ON asset_events(created_at);
CREATE INDEX IF NOT EXISTS idx_asset_events_type ON asset_events(event_type);
```

Note: the PRD's name `google_sync_state` for device sync **collides with the existing per-user `google_sync_state` table** (migration 002, keyed by `user_sourced_id`, powers Workspace user provisioning). Device sync bookkeeping gets its own tables (§4.6). Do not touch 002.

### 4.4 DDL — `020_tickets.sql`

```sql
CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,                              -- UUID
    number INTEGER NOT NULL UNIQUE,                   -- human-facing, monotonic (see ticket_counters)
    requester_user_sourced_id TEXT REFERENCES users(sourced_id) ON DELETE SET NULL,
    requester_email TEXT,                             -- retained for email-sourced tickets from unmatched senders
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,   -- auto-attached from requester's assignment
    school_org_sourced_id TEXT REFERENCES orgs(sourced_id) ON DELETE SET NULL,
    assignee_user_sourced_id TEXT REFERENCES users(sourced_id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'open',              -- open|in_progress|waiting|resolved|closed
    priority TEXT NOT NULL DEFAULT 'normal',          -- low|normal|high|urgent
    category TEXT,
    subject TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'portal',            -- portal|email|api|agent
    email_message_id TEXT,                            -- RFC 5322 Message-ID of the originating mail (dedup/threading)
    sla_due_at TEXT,
    first_response_at TEXT,
    resolved_at TEXT,
    closed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tickets_email_msgid
    ON tickets(email_message_id) WHERE email_message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_assignee ON tickets(assignee_user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_tickets_requester ON tickets(requester_user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_tickets_asset ON tickets(asset_id);
CREATE INDEX IF NOT EXISTS idx_tickets_school ON tickets(school_org_sourced_id);
CREATE INDEX IF NOT EXISTS idx_tickets_sla_due ON tickets(sla_due_at);

-- Monotonic ticket numbers, identical semantics on both drivers (avoids
-- SQLite-AUTOINCREMENT-vs-Postgres-sequence divergence): increment inside the
-- insert transaction. SQLite's serialized writer makes this race-free. On
-- Postgres use UPDATE … RETURNING. (No semicolons in comments — see 019.)
CREATE TABLE IF NOT EXISTS ticket_counters (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    next_number INTEGER NOT NULL DEFAULT 1
);
INSERT OR IGNORE INTO ticket_counters (id, next_number) VALUES (1, 1);

CREATE TABLE IF NOT EXISTS ticket_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_user_sourced_id TEXT REFERENCES users(sourced_id) ON DELETE SET NULL,
    author_email TEXT,                                -- for email replies from unmatched senders
    body TEXT NOT NULL,
    is_internal INTEGER NOT NULL DEFAULT 0,           -- internal notes hidden from requester portal + email
    source TEXT NOT NULL DEFAULT 'portal',            -- portal|email|api
    email_message_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ticket_comments_ticket ON ticket_comments(ticket_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ticket_comments_msgid
    ON ticket_comments(email_message_id) WHERE email_message_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ticket_attachments (
    id TEXT PRIMARY KEY,                              -- UUID; doubles as the storage key stem
    ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    comment_id INTEGER REFERENCES ticket_comments(id) ON DELETE SET NULL,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    storage_key TEXT NOT NULL,                        -- opaque; interpreted by AttachmentStore
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ticket_attachments_ticket ON ticket_attachments(ticket_id);
```

### 4.5 Attachment storage — one trait, two backends

```rust
// core/src/attachments.rs
#[async_trait]
pub trait AttachmentStore: Send + Sync {
    async fn put(&self, key: &str, content_type: &str, bytes: Bytes) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<Bytes>>;
    async fn delete(&self, key: &str) -> Result<()>;
}
```

- **Self-host (default): `FsAttachmentStore`** rooted at `<data_dir>/attachments/` (config already has `data_dir = "/var/lib/chalk"`). Key layout `attachments/<yyyy>/<mm>/<uuid>` — flat, fanned by month, no metadata in the path (metadata lives in `ticket_attachments`). Backup story = "back up the data dir", same as the SQLite file. No new deps.
- **Hosted: `S3AttachmentStore`** (S3-compatible API → GCS via interoperability mode or any S3 store; one `aws-sdk-s3`-or-`object_store` impl covers both), bucket per environment, key prefix per tenant schema. Lives in `chalk-hosted-crate`, injected the same way Postmark's mailer is (the `MagicLinkMailer` precedent: core defines the trait, the runtime injects the impl).
- v1 limits enforced in `TicketService`: 10 MB/file, 5 files/comment, content-type allowlist (images, PDF, txt/log, office docs). `storage_key` is opaque so backends can be swapped without a data migration.

### 4.6 DDL — `021_google_device_sync.sql`

```sql
CREATE TABLE IF NOT EXISTS google_device_sync_cursors (
    resource_type TEXT PRIMARY KEY,                   -- 'chromeosdevices' | 'orgunits' | 'directory_users'
    page_token TEXT,                                  -- mid-pagination resume point
    last_full_sync_at TEXT,
    last_delta_at TEXT,
    status TEXT NOT NULL DEFAULT 'idle',              -- idle|running|error
    error_message TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS google_device_sync_runs (   -- mirrors google_sync_runs (002)
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',           -- running|succeeded|failed|cancelled
    mode TEXT NOT NULL DEFAULT 'full',                -- full|delta|writeback
    devices_seen INTEGER NOT NULL DEFAULT 0,
    devices_created INTEGER NOT NULL DEFAULT 0,
    devices_updated INTEGER NOT NULL DEFAULT 0,
    devices_matched INTEGER NOT NULL DEFAULT 0,
    devices_unmatched INTEGER NOT NULL DEFAULT 0,
    api_calls INTEGER NOT NULL DEFAULT 0,
    throttle_events INTEGER NOT NULL DEFAULT 0,
    dry_run INTEGER NOT NULL DEFAULT 0,
    error_message TEXT
);
CREATE INDEX IF NOT EXISTS idx_gdev_sync_runs_status ON google_device_sync_runs(status);
```

### 4.7 DDL — `022_jobs_change_sets.sql` (see §6 for semantics)

```sql
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,                              -- UUID
    kind TEXT NOT NULL,                               -- google_device_sync|change_set_commit|imap_poll|
                                                      -- csv_import_commit|sla_scan|notify_flush
    status TEXT NOT NULL DEFAULT 'queued',            -- queued|running|succeeded|failed|cancelled
    payload TEXT NOT NULL DEFAULT '{}',
    run_after TEXT,                                   -- NULL = ASAP
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 1,          -- 1 for Google-writing jobs (at-most-once)
    started_at TEXT,
    finished_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_jobs_status_run_after ON jobs(status, run_after);
CREATE INDEX IF NOT EXISTS idx_jobs_kind ON jobs(kind);

-- Diff-preview-then-commit staging (Google write-backs, CSV re-import, bulk ops)
CREATE TABLE IF NOT EXISTS change_sets (
    id TEXT PRIMARY KEY,                              -- UUID
    kind TEXT NOT NULL,                               -- google_writeback|csv_import|bulk_edit
    status TEXT NOT NULL DEFAULT 'planned',           -- planned|committing|committed|partial|discarded
    created_by TEXT NOT NULL,                         -- actor (users.sourced_id or token prefix)
    summary TEXT NOT NULL DEFAULT '{}',               -- JSON: counts per op type, source file hash, etc.
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    committed_at TEXT
);

CREATE TABLE IF NOT EXISTS change_set_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    change_set_id TEXT NOT NULL REFERENCES change_sets(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    op TEXT NOT NULL,                                 -- update_field|move_ou|change_status|create|assign|unassign
    field TEXT,
    old_value TEXT,
    new_value TEXT,
    remote_target TEXT,                               -- 'google' when the op writes to Admin SDK, else 'local'
    status TEXT NOT NULL DEFAULT 'pending',           -- pending|applied|failed|skipped
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_change_set_items_set ON change_set_items(change_set_id);
CREATE INDEX IF NOT EXISTS idx_change_set_items_status ON change_set_items(change_set_id, status);
```

---

## 5. Google Admin SDK integration (extends `crates/google-sync`)

Per Gate A §4: WS-1 extends `google-sync` rather than starting cold. `auth.rs` (service-account JWT with domain-wide delegation) and the reqwest client skeleton are reused; new module `src/chromeos.rs` plus a shared `src/backoff.rs`.

### 5.1 Auth per deployment mode

| Mode | Mechanism | Why |
|---|---|---|
| **Self-host (recommended: service account)** | Customer creates a service account in **their own** Cloud project, enables Admin SDK, grants domain-wide delegation for the exact scopes, points `[modules.devices]`/`tenant_config_devices` at the JSON key (`service_account_key_path`, or sealed blob when entered via console) + `admin_email` to impersonate. Identical to today's `[google_sync] service_account_key_path` flow and `GoogleAuth::from_service_account`. | No Google verification/CASA applies — restricted-scope review binds to *Chalk's* OAuth clients, not to a customer's own project. Headless (no browser dance on a server), documented pattern admins already follow for GAM/Gopher-class tools. Offer OAuth-client-in-their-project as a documented fallback only. |
| **Hosted (WS-6)** | Chalk's verified Cloud project; standard OAuth 2.0 web flow (admin consents in browser), offline access, refresh token sealed (AES-GCM) into `tenant_config_devices.google_oauth_refresh_token_sealed`. Minimal restricted scopes; CASA Tier 2 assessment; new Marketplace listing after verification. | Hosted Chalk is a third-party server storing restricted-scope data — this is the schedule-critical external review (start first). |

Scopes (both modes, request `.readonly` variants until the tenant enables write-back — one function, `token::device_sync_scopes(write_enabled)`, so the delegation panel, the token exchange and the CLI cannot drift; enabling write-back widens **only** the device scope, since moving a device is a device write and a granted scope is usable by anything holding the key):
`admin.directory.device.chromeos[.readonly]`, `admin.directory.orgunit[.readonly]`, `admin.directory.user.readonly`, and optionally `chrome.management.telemetry.readonly` (§5.5).

`GoogleAuth` gains a second constructor, `from_oauth_refresh_token(...)`; `ChromeOsClient` takes `Box<dyn TokenProvider>` so sync code is mode-agnostic.

> **§5 corrections from the Chromebook Getter study** (July 25 2026 — full detail and file:line evidence in `CHROMEBOOK_GETTER_STUDY.md`). A production add-on with a large district install base has been running this exact ingestion path for years. Its evidence corrects §5's *constants*; it validates §5's *architecture* nearly everywhere.
>
> 1. **`maxResults=200`, not 100.** §5.2's `maxResults=100 (hard max)` comment is wrong, and §5.4's "20k devices = 200 requests" follows from it. Production uses 200 in both its server and Apps Script paths. Verify against current docs, then halve the fleet-walk call count.
> 2. **`moveDevicesToOu` chunks at 50, not 20.** Production carries the comment `// can only push 50 changes at a time`. Resolve before the `ChromeOsClient` signature hardens — 20 is the safe fallback, 50 is 2.5× fewer calls on the bulk path.
> 3. **Dispatch on the JSON error `reason`, never the HTTP status.** The Directory API returns **403** for rate limiting (`rateLimitExceeded`), and 403 is *also* genuine permission failure. The incumbent cannot tell them apart and guesses in its error text; this is its single most expensive ambiguity. §5.3's retry policy must branch on `reason`.
> 4. **Bound the OU fan-out.** §5.3 specifies a request-rate token bucket but is silent on per-OU parallelism. The incumbent's unbounded `Promise.all` over the whole OU tree is the likely root cause of its 403 storms. Better still: list at root with `orgUnitPath=/` and filter locally — it only fans out because it needs per-OU counts, which Chalk does not.
> 5. **Handle 412 Precondition Failed** — it means "device is already in that state". `batchChangeStatus` inherits this. Port the incumbent's pre-flight status check, but into the change-set **plan** phase (§6.4) so it surfaces as a per-item exclusion rather than aborting the batch.
> 6. **§5.6's matching ladder is NOT validated by that study** — the incumbent does no device→user matching at all. §5.6 rests on `chromebookInitialSync.ts` alone. Its rule 1 is still the right first rule: districts demonstrably do put meaningful data in `annotatedUser` by hand.
>
> **Resolved against Google's live documentation (Aug 1 2026), during the WS-1 write-back build.** The study was directionally right and specifically incomplete:
>
> - **`maxResults`: the documented maximum is 300, not 100 or 200.** Chalk sends **200** by default anyway — a `projection=FULL` page is large and 200 has years of field evidence at district scale, while 300 buys 67 requests instead of 100 on a 20k fleet. Configurable via `[device_sync] page_size`, clamped to 300.
> - **Both write endpoints cap at 50.** Confirmed for `moveDevicesToOu` ("You can move up to 50 devices at once") and `batchChangeStatus` ("Maximum 50"). Item 2's fallback of 20 was unnecessary.
> - **`orgUnitPath` on `moveDevicesToOu` is a QUERY parameter, not a body field.** The body carries only `deviceIds`. Putting the path in the body is the shape that looks right and returns 400.
> - **`batchChangeStatus` is colon-transcoded**: `.../devices/chromeos:batchChangeStatus`. A slash 404s.
> - **`deprovisionReason` is required if and only if the action is deprovision**, and only four of its eleven values are selectable by a district. Four are deprecated (`UPGRADE`, `DOMAIN_MOVE`, `SERVICE_EXPIRATION`, `OTHER`), plus `UNSPECIFIED`, `NOT_REQUIRED`, and `REPAIR_CENTER` — the last settable only by a repair centre during an RMA. Chalk models the four, and carries the reason *inside* the `Deprovision` variant so a deprovision without one is unrepresentable.
>
> Items 3, 4 and 5 shipped as specified: dispatch is on `reason`, the fan-out was rejected outright in favour of a single root listing, and 412 is read as already-applied.
>
> Confirmed correct and worth keeping as written: at-most-once writes with no auto-retry after ambiguous failure (§5.3), the mid-pagination cursor (§5.4 — genuinely novel; the incumbent restarts a 20k walk on failure), typed `AnnotatedFields` length validation (§5.2 — the incumbent has none, and its users hit opaque Google errors), and per-item `pending → applied|failed` (§6.3), which is the direct fix for the limitation the incumbent's own authors documented as unfixable.

### 5.2 Client design (`google-sync/src/chromeos.rs`)

```rust
pub struct ChromeOsClient { http: reqwest::Client, base_url: String, customer_id: String, /* "my_customer" */ auth: Box<dyn TokenProvider>, limiter: RateLimiter }

impl ChromeOsClient {
    pub async fn list_devices(&self, page_token: Option<&str>, query: Option<&str>)
        -> Result<ChromeOsDevicePage>;                 // GET chromeosdevices; maxResults=200 (300 is the
                                                       // documented max; 200 is the default -- see below),
                                                       // projection=FULL (needed for autoUpdateExpiration/
                                                       // supportEndDate, lastSync, recentUsers, activeTimeRanges)
    pub async fn list_org_units(&self) -> Result<Vec<OrgUnit>>;      // orgunits.list, type=all
    pub async fn list_directory_users(&self, page_token: Option<&str>) -> Result<UserPage>;
    pub async fn patch_device(&self, device_id: &str, patch: &AnnotatedFields) -> Result<()>;
                                                       // annotatedUser ≤100, annotatedLocation ≤200,
                                                       // notes ≤500 — validated BEFORE the call; typed
                                                       // AnnotatedFields constructor rejects oversize input
    pub async fn batch_change_status(&self, action: ChangeStatusAction, device_ids: &[String])
        -> BatchOutcome;                               // POST .../devices/chromeos:batchChangeStatus -- a
                                                       // COLON, not a slash (gRPC transcoding).
                                                       // NEVER chromeosdevices.action (deprecated).
                                                       // Chunks at 50. Deprovision carries its reason in
                                                       // the enum variant, so it cannot be omitted.
    pub async fn move_devices_to_ou(&self, org_unit_path: &str, device_ids: &[String])
        -> BatchOutcome;                               // chunks at 50 INSIDE the client, serially, with
                                                       // per-chunk outcome capture. orgUnitPath is a QUERY
                                                       // parameter; the body carries only deviceIds.
    pub async fn issue_command(&self, device_id: &str, cmd: DeviceCommand) -> Result<CommandId>;
                                                       // REBOOT | REMOTE_POWERWASH | WIPE_USERS — console-only, guarded
}
```

### 5.3 Rate limiting & backoff (`google-sync/src/backoff.rs`)

- Budget: 2,400 queries/min/user/project (raiseable) **plus** a per-Workspace-account ceiling that is *not* raiseable. Design to the unraiseable one: client-side token bucket defaulting well under quota (default 500 req/min, configurable), because a district's other tooling (GAM scripts, Gopher) shares the same per-account ceiling.
- On 429/403 `rateLimitExceeded`/5xx: exponential backoff with **full jitter**, base 1s, cap **32s**, honor `Retry-After` when present. Reads retry up to 8 attempts inside the client. **Writes never auto-retry after an ambiguous failure** (timeout/5xx-after-send) — they surface to the job layer, which is at-most-once (§6.3).
- Every throttle event increments `google_device_sync_runs.throttle_events` — visible in the sync history UI so "why was sync slow" is answerable.

### 5.4 Sync state

Full sync: page through `list_devices` (200/page by default, `projection=FULL`), persisting `page_token` into `google_device_sync_cursors` after each page — a crashed sync resumes mid-pagination instead of restarting a 20k-device fleet walk. Delta: Directory API has no true changes feed for ChromeOS devices, so "delta" = full re-list on schedule (cheap: 20k devices = 100 requests at the default page size) diffed against local state by `google_device_id`; `orderBy=lastSync` short-circuit is an optimization to add later, not a correctness feature. Upsert rule: Google is authoritative for hardware/OS/OU/AUE fields; Chalk is authoritative for assignment, status (except `deprovisioned` observed from Google), purchase/warranty/funding fields. Field-level merge, never row clobber.

### 5.5 Telemetry API

Licence-gated (Chrome Enterprise Premium / telemetry entitlement). Treat as **optional enrichment**: attempt one probe call when the tenant enables it; on 403, record "not licensed" in `tenant_config_devices` and hide telemetry UI panels. Never promise telemetry dashboards in marketing without the licensing caveat (PRD 1.8).

### 5.6 Device → roster matching (`chalk-devices/src/matching.rs`)

Order, per PRD 1.10, informed by `chromebookInitialSync.ts`:

1. `annotatedUser` parsed as email → exact match on `users.email` (case-insensitive).
2. Else most recent `recentUsers[].email` (skip non-domain/service accounts) → `users.email`.
3. Else `serial_number`, then `annotatedAssetId` vs `assets.asset_tag`, against pre-existing (CSV/manual) asset rows — this *merges* a Google device into an already-tracked asset rather than duplicating it.
4. Else `match_state='unmatched'` → the **unmatched queue** console view (filter, bulk-resolve, "ignore" for carts/kiosks/loaners; `ignored` devices stay synced but leave the queue).

Every automatic match writes an `asset_events` row (`event_type='assigned'`, `actor='system:google-sync'`, payload records the rule that fired) so mismatches are diagnosable and reversible. Matching is idempotent: it never overwrites a manual assignment (`match_state='manual'` wins over rules).

Wedge acceptance (PRD §6): fresh install + SIS + Google → populated inventory with students attached in <30 min, zero CSV. The 30-minute budget is dominated by SIS full sync; device list+match for 5k devices is ~50 API calls + one in-memory pass.

---

## 6. Background jobs without Redis/queues (single binary)

> **BUILT** (migration 023, `core::jobs`). Two things differ from the sketch
> below and are the shipped behaviour:
>
> - **Handlers are registered by the binary**, not matched inside the runner.
> `chalk-core` is the leaf crate and cannot depend on `chalk-devices`; a
> `JobHandler` trait keeps the loop and the claim protocol in core while the
> binary supplies the work. The payoff is that `chalk-console` enqueues jobs
> through `JobRepository` and never learns `chalk-devices` exists.
> - **`jobs` took migration 023, not 022.** The change-set tables shipped as 022
> during WS-1. There is no FK between them in either direction, so the split is
> purely additive.
>
> The claim protocol, at-most-once for Google writes, and startup recovery are
> as described and are covered by mutation-checked tests on both backends.


### 6.1 Pattern: port the hosted scheduler into core

`chalk-hosted-crate/src/scheduler.rs` + `cron_due.rs` already solve this shape correctly: a `tokio::time::interval` ticker (60s, `MissedTickBehavior::Skip`), and a pure `cron_due(expression, last_run, now)` that normalizes 5-field POSIX cron, coalesces missed ticks into one run, and never fires on malformed expressions. **Move both into `chalk-core/src/jobs/`** (the hosted crate then depends on core's copy — one implementation, two consumers). `chalk serve` spawns:

- **Cron loop**: each tick, for every enabled schedule (`[sis] sync_schedule`, `[google_sync] sync_schedule`, `[modules.devices] google_sync_schedule`, helpdesk `sla_scan` every 5 min, `imap_poll` per config), `cron_due(...)` against the last run recorded in the relevant `*_runs`/`jobs` row → enqueue a `jobs` row.
- **Worker loop**: single in-process worker (v1: concurrency 1 — SQLite has one writer anyway and it keeps Google-write ordering trivial) polls `jobs WHERE status='queued' AND (run_after IS NULL OR run_after <= now)` every few seconds.

Hosted mode: the control plane's scheduler keeps doing tenant fan-out exactly as today; the per-tenant work items land in that tenant schema's `jobs` table and are executed by the same core `JobRunner`.

### 6.2 Claiming (correct on both drivers, no SKIP LOCKED needed at n=1)

```sql
UPDATE jobs SET status='running', started_at=?, attempt=attempt+1, updated_at=?
WHERE id=? AND status='queued';   -- proceed only if rows_affected = 1
```

Startup recovery: any `running` job older than a liveness window (30 min) → `failed` with `last_error='abandoned (process restart)'`; never silently re-queued if it writes to Google.

### 6.3 At-most-once for Google writes

`max_attempts=1` for every job kind that mutates Google (`change_set_commit` with `remote_target='google'`). Inside a commit, each `change_set_items` row transitions `pending → applied|failed` **individually, persisted before the next remote call**. A crash mid-commit leaves per-item truth: the UI shows exactly which 37 of 500 OU moves applied, and "retry failed items" re-arms only the unresolved ones — explicit human re-arm, not automatic redelivery. This is how we get at-most-once per item without idempotency tokens Google doesn't offer.

> **AS BUILT — three corrections to the paragraph above.**
>
> 1. **`pending → applied|failed` is two-valued and loses the case that actually matters.** `moveDevicesToOu` and `batchChangeStatus` are **chunk-granular**: up to fifty devices share one verdict, and a timeout says nothing about any individual device in that chunk. There is a third state, `indeterminate`, and the UI says *"may have applied — verify"* rather than picking one of the two lies available. `failed` is reserved for a refusal Google issued *before* touching anything, which is therefore safe to re-arm.
> 2. **Nothing writes `partial`.** It is not a value the `status` column can hold — see §4.7. Display status is *derived* at read time from item counts, so a committed set with unresolved items reads as `partial` and a `committing` set past the liveness window reads as `interrupted`. Neither is stored, and nothing auto-resumes.
> 3. **The near-idempotence is now load-bearing, and deliberately so.** `retry-failed` re-arms indeterminate items too, which may repeat a write that already landed. Both operations tolerate that — re-moving a device to its current OU is a no-op, and a redundant status change returns 412, which the commit path reads as already-applied. The CLI states how many outcomes are unknown *before* acting, because this is a property of today's two operations rather than a general law.
>
> The atom is `ChangeSetRepository::mark_item_applied` — asset write, audit event and item status in one transaction — plus `mark_item_created` for the CSV-import case, where the row does not exist yet and the item's `asset_id` cannot be set until it does.

### 6.4 Diff-preview-then-commit (one flow, three entry points)

> **BUILT for local changes** — `core::change_plan` (plan), `console::preview`
> (preview), `core::change_commit` (commit), driven by the
> `change_set_commit` job. Bulk edits from the inventory are its first
> consumer; CSV import and sync dry-run reuse the same preview unchanged.
>
> **Google write-back is BUILT** (Aug 1 2026). The planner emits `MoveOu` and
> `ChangeStatus` items marked `remote_target='google'`; the commit path applies
> local items first, then groups the remote ones by exactly what will be sent,
> so five hundred devices bound for one OU is one call and two destinations can
> never share a request.
>
> `core::remote_write::RemoteWriter` is the seam: `chalk-core` stays a leaf and
> never learns the Directory API exists, while `chalk-devices` implements the
> trait over `ChromeOsClient`. The writer answers **per device**, not per
> request — chunking is the implementation's business, and the commit loop
> cannot record what happened to each device if it is handed one verdict for
> fifty.
>
> Write-back is a **separate per-tenant opt-in** (`write_back_enabled`,
> migration 026), off by default, because reading a district's fleet and
> changing it are different levels of trust. It also selects the scope set:
> domain-wide delegation matches the literal scope string, so the Connect page's
> delegation panel and the token exchange both read the same flag. A deployment
> without it gets a writer that refuses every device *with the reason*, so the
> change set records why rather than appearing to succeed.
>
> Three entry points now exist as promised: bulk edits from the inventory, CSV
> import (`core::csv_import`), and Google write-back — all rendering the same
> preview. A deprovision additionally passes DESIGN_SYSTEM §5.11's typed
> confirmation, checked on the **server** and recounted from the stored items,
> so striking a row out changes the number that confirms.


Google write-back, CSV re-import, and bulk edits all compile to the same two-phase object:

1. **Plan**: pure read — compute per-field diffs → insert `change_sets` + `change_set_items` (`status='planned'`). Nothing touched.
2. **Preview**: console renders the change set (adds / field changes / OU moves / status changes / deletes-as-retire), with per-item exclusion checkboxes. The AG Grid island (WS-2.4) is this same preview for spreadsheet-shaped edits.
3. **Commit**: CSRF-protected POST enqueues `change_set_commit`; worker applies local items in a transaction, remote items per §6.3, appending `asset_events` for every applied item.

`--dry-run` on `chalk devices sync`/`import` = plan + print + discard, matching the existing CLI convention.

---

## 7. Email-to-ticket ingestion (`chalk-helpdesk/src/email_ingest.rs`)

One parser, two transports. Both normalize into `InboundEmail { message_id, in_reply_to, references, from, to, subject, text_body, html_body, headers, attachments }` and feed the same pipeline.

### 7.1 Transports

- **Hosted: Postmark inbound webhook** (AdminRemix already runs Postmark for AssetRemix; the JSON shape is field-tested via `emailToTickets.ts`). Tenant gets `support@<slug>.usechalk.com` (or CNAMEs their own `helpdesk@district.org` at Postmark). Webhook endpoint lives in `console` (`POST /hooks/email/postmark`), authenticated by a per-tenant secret in the URL path + Postmark signature check. Handler does *only* store-and-enqueue (`jobs.kind='email_ingest'`) — parsing happens in the worker.
- **Self-host, option A (default): IMAP polling.** `[modules.helpdesk.imap] host/port/username/password(sealed via console)/folder/poll_schedule`. Job fetches UNSEEN, processes, marks seen (moves to `Chalk/Processed` on success, `Chalk/Failed` on parse errors — nothing is deleted). Crate: `async-imap` + `mail-parser`. Fits districts pointing a Google Group or shared mailbox at it.
- **Self-host, option B: generic inbound webhook** — same endpoint as hosted with provider adapters (Postmark, Mailgun) for self-hosters who already have a provider and hate polling.

### 7.2 Pipeline (lessons ported from `emailToTickets.ts`)

1. **Dedup**: `Message-ID` already in `tickets.email_message_id` or `ticket_comments.email_message_id` → drop (both have partial unique indexes; the insert conflict *is* the dedup).
2. **Loop/auto-reply guard**: drop if `Auto-Submitted != no`, `Precedence: bulk|junk|list`, `X-Autoreply`/`X-Autorespond` present, or From is a known mailer-daemon pattern. Additionally: never send a notification to the address a ticket just arrived from within a short window, and cap notifications per ticket per hour (circuit breaker). This is the #1 field-tested failure mode (OOO ↔ helpdesk ping-pong).
3. **Thread**: `In-Reply-To`/`References` → existing ticket (via stored message-ids) → append as `ticket_comments` (source `email`). Fallback: `[Ticket #123]` token in subject.
4. **Sender resolution**: From → `users.email`. Match → `requester_user_sourced_id`, auto-attach their assigned asset (`assets.assigned_user_sourced_id`) and school. No match → policy per config: `create_unmatched` (default: ticket with `requester_email` only) or `reject` (for spam-averse districts; sender gets one polite bounce, rate-limited).
5. **Spam honesty**: Chalk does **no** content spam-filtering in v1 and the docs must say so. Hosted inherits Postmark's inbound spam scoring (threshold configurable); IMAP self-hosters are told to point Chalk at a mailbox *behind* their existing filter (Google/M365 already filter). Unmatched-sender tickets land in a separate "triage" queue view so a spam burst never buries real teacher tickets.
6. Attachments → `AttachmentStore` (same limits as §4.5; oversize attachments dropped with a note appended to the ticket body, not a hard reject).

### 7.3 Outbound side

Generalize `core/src/mail.rs` alongside the existing trait (which stays for magic links):

```rust
#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, msg: OutboundMail) -> anyhow::Result<()>;  // to, subject, text, html, headers
}
```

Impls: `SmtpMailer` (lettre; self-host `[mail] smtp_*` config — most districts have a relay), `PostmarkMailer` (hosted crate, already exists for magic links), `LoggingMailer` (dev). `chalk-helpdesk/src/notify.rs` renders notifications (ticket created / comment added / assigned / resolved) with `References` headers so replies thread back in, and threads all sends through the §7.2 loop guards.

---

## 8. Multi-tenancy & billing (hosted)

### 8.1 Tenancy today (verified) — unchanged by this plan

One shared Postgres cluster; `_meta.tenants` registry (`slug`, `db_schema` = `schema_for_slug(slug)`, `status ∈ provisioning|active|suspended`, sealed key material); `tenant_migrations.rs::apply(pool, schema)` runs chalk's `migrations/postgres/*` plus hosted-private per-tenant tables into that schema. Chalk core natively supports `driver = "postgres"` + `schema = "…"` with schema-scoped `search_path` (see `chalk.example.toml`), which is exactly how a tenant's Chalk instance runs. Signup (`signup.rs`) → create tenant row (`provisioning`) → apply migrations → seed → `activate()`. New module migrations 019–024 flow through this path with zero new mechanism.

### 8.2 Module entitlement flow

```
plan (control plane)  →  tenant_config_modules row in tenant schema  →  tenant_config_loader merge  →  ModulesConfig  →  router/nav gating
```

> **Verified July 25 2026:** the hosted control plane has **zero billing/plan substrate today** — no plans table, no entitlement column, no tier field, no billing code of any kind. `_meta.tenants` carries only `status ∈ {provisioning, active, suspended}`. The `_meta.tenant_plans` DDL below is therefore entirely greenfield, which is good news: nothing to migrate, no legacy tier semantics to honor. The natural enforcement point is `TenantContext` (already built per-tenant and LRU-cached), and the natural home for the row is the existing `_meta` schema whose migrations run via `meta::run_migrations`.
>
> **Tier names must match the published D16 ladder** (PRD §7), not the free/devices_helpdesk/full sketch below: the sold products are *Devices + Helpdesk* and *Full stack*, each at four fleet-size rungs (≤1,000 / ≤5,000 / ≤20,000 / 20,000+). Model the rung as data (a device-count band) rather than baking four tier names per product into an enum — the bands will move, the products won't. `asset_types_allowed` keeps its D8 meaning unchanged and remains the *only* thing gating the free hosted tier: `["chromebook"]` for free, the full set for any paid rung. It is enforced in `AssetService::create/import` as hosted config and **never compiled out** (D2).

`023_module_config.sql` adds to hosted-private tables a control-plane `plans` record per tenant:

```sql
-- control plane, _meta schema (hosted-private migration)
CREATE TABLE IF NOT EXISTS _meta.tenant_plans (
    tenant_slug TEXT PRIMARY KEY REFERENCES _meta.tenants(slug),
    plan TEXT NOT NULL DEFAULT 'free',            -- free|devices_helpdesk|full
    devices_enabled BOOLEAN NOT NULL DEFAULT true,
    helpdesk_enabled BOOLEAN NOT NULL DEFAULT true,
    roster_sso_enabled BOOLEAN NOT NULL DEFAULT false,
    asset_types_allowed TEXT NOT NULL DEFAULT '["chromebook"]',  -- D8: free tier = Chromebooks only; JSON array
    grandfathered BOOLEAN NOT NULL DEFAULT false, -- the 3 AssetRemix-era districts / CG payers, $99-flat honor flag
    enrollment_count_reported INTEGER,            -- latest measured (8.3)
    enrollment_count_billed INTEGER,              -- what the current PO was cut against
    po_reference TEXT, invoice_notes TEXT,
    renews_at DATE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

`platform_admin` UI edits this row; a control-plane sync writes the derived `tenant_config_modules` (+ `asset_types_allowed`) into the tenant schema on change. The free-tier gate (D8) is the `asset_types_allowed` check in `AssetService::create/import` — **hosted-config enforced, never compiled out**; self-host ignores it entirely (D2).

### 8.3 Enrollment-count billing dimension

Source of truth the district already gave us: the roster. Nightly control-plane job (existing `Scheduler`) runs per active tenant: `SELECT COUNT(*) FROM <schema>.users WHERE role = 'student' AND status = 'active'` → `enrollment_count_reported` + a small history table (`_meta.tenant_enrollment_snapshots(tenant_slug, count, measured_at)`) so renewal conversations use a season-aware number (October count, not July's near-zero). **No automated billing.** Annual PO/invoice workflow is manual by design (D3, WS-7): platform_admin shows reported vs billed count with a drift flag at renewal; invoices are cut by a human; `grandfathered=true` short-circuits all of it. No Chargify, no card processing, no dunning — that machinery stays on AssetRemix's island.

---

## 9. Security & compliance architecture

### 9.1 Existing base (keep) + role model (extend)

Existing: session auth against roster users with `RoleType::Administrator` + Argon2-hashed passwords (`PasswordRepository`), `admin_sessions`, login rate limiting, magic-link login (anti-enumeration neutral responses), CSRF middleware, AES-256-GCM sealed secrets at rest, `admin_audit_log`, hashed+prefixed+scoped+revocable `api_tokens`.

New (`024_console_roles.sql`): console access today is binary (OneRoster `Administrator`). Devices/Helpdesk need three grades:

```sql
CREATE TABLE IF NOT EXISTS console_roles (
    user_sourced_id TEXT PRIMARY KEY REFERENCES users(sourced_id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'technician',      -- admin|technician
    granted_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

- **admin**: everything, incl. settings, tokens, deprovision, `issueCommand`.
- **technician**: asset/ticket read-write, bulk OU/status/annotated ops, no deprovision, no wipe/powerwash, no settings/token management.
- **teacher (requester)**: no console role row. The teacher portal authenticates via the existing idp session (`PortalSession`) — SSO'd, zero account creation (WS-2.5) — and can only create tickets + view own tickets/comments (`is_internal` filtered).
- Backward compat: OneRoster `Administrator` with no `console_roles` row = `admin` (today's behavior preserved).

### 9.2 Destructive-operation guard (PRD WS-1 safety)

Deprovision (and powerwash/wipe) is irreversible and license-audited, so, enforced **in `AssetService`, not just the UI**: (1) actor's `console_roles.role='admin'`; (2) typed confirmation — the handler requires the literal device count typed back (`"deprovision 37"`), carried through the CSRF-protected form as proof-of-intent; (3) `asset_events` row per device (`event_type='deprovisioned'`, payload: reason + change_set id) written in the same flow that calls `batch_change_status`; (4) console-only — no API token can reach it in v1 (§3.3); (5) `admin_audit_log` entry for the batch.

### 9.3 Audit coverage

Three ledgers, one story: `asset_events` (immutable device history — append-only repo trait, RESTRICT FK), `ticket_comments` + status timestamps (ticket history), `admin_audit_log` (console/settings actions incl. token issuance, role grants, module toggles, change-set commits). Every mutation path — UI, API token, sync job — writes actor + `actor_kind`. API-token actions record the token *prefix* (never the token).

### 9.4 FERPA-ish data minimization

- Devices/Helpdesk join *against* the roster; they copy nothing from it. Asset and ticket rows hold `sourced_id` references, not student names/grades — deleting or redacting a student in the roster leaves no PII shadow in module tables (FKs are `ON DELETE SET NULL`).
- `recentUsers` from Google are used transiently for matching and not persisted per-device beyond `annotated_user` (data the district itself wrote into Google).
- Demographics tables are never read by devices/helpdesk code paths.
- Attachments are the loosest surface (teachers photograph screens); retention setting (`[modules.helpdesk] attachment_retention_days`, default keep) + closed-ticket purge job.
- Telemetry (chalk `telemetry` crate) stays opt-in and roster-blind.

### 9.5 What the NDPA / security whitepaper points at

Concrete, inspectable claims: AGPL source; single binary + local SQLite = data residency in the district (self-host); per-tenant Postgres schema isolation (hosted); AES-256-GCM for stored credentials/keys; TLS everywhere; scoped revocable API tokens; immutable asset audit; role-gated destructive ops with typed confirmation; magic-link anti-enumeration; roster data minimization (§9.4); Google access limited to enumerated scopes with read-only-until-enabled write-back; no third-party trackers in console; subprocessor list for hosted = Postmark + cloud provider + object storage, full stop. SOC 2 deferred (PRD §9); VPAT via WS-2.7; SDPC NDPA v2 pre-signed per PRD §11.

---

## 10. What explicitly does NOT change

- **AssetRemix — maintenance mode**, meaning technically: dependency/security patches (`npm audit`-driven) and data-loss/billing bug fixes only; no new features, no new models/migrations except fixes; **no Vue 3 port** (explicitly rejected in Gate A risk table); the 5 deployed processes, Chargify billing, and all integrations keep running as-is; ~2 hrs/wk budget; no shared infrastructure with Chalk, ever; per-district DB usage audit each semester feeds the strangle checklist; `chalk import assetremix` is built against district readiness, not launch.
- **Chromebook Getter — frozen**: two WS-0.4 reliability fixes shipped, then no code changes. Listing identity/scopes untouched forever (D6). Only in-app change permitted: the CTA panel. No data path to Chalk.
- **idp / ad-sync / google-sync user provisioning — Act 2, already built.** No rework; WS-1 only *adds* `chromeos.rs` + backoff to `google-sync`. Marketing order ≠ build order.
- **No SPA.** HTMX + Askama for ~95% of surfaces; the only client-side island is AG Grid Community (MIT), mounted inside an HTMX page via rust-embed (D9/WS-2). No Datastar.
- **Single binary preserved** (D9): new crates compile in; assets embed at compile time; SQLite remains the zero-dependency default; no Redis, no external queue, no sidecar processes.
- **chalk-hosted marketplace/vendor code** stays dormant (D4): not deleted, not routed.

---

## 11. Build sequencing (WS-1 → WS-9, 10–15 hr/wk, heavy AI-agent leverage)

Estimates are calendar weeks at 10–15 solo hr/wk with agents writing first drafts of code+tests; the binding constraints are **review bandwidth and external clocks**, so parallelism below means "agent lanes running while you review," not more hours.

**Critical path: WS-6 (CASA/OAuth verification) — start week 0, everything hosted-launch-shaped queues behind it.** Self-host ships regardless of WS-6 (service-account mode needs no Google review), which is the schedule hedge.

| WS | Crate-level tasks | Est. | Depends on |
|---|---|---|---|
| **WS-6** OAuth/CASA (external clock) | New Cloud project + OAuth client; scope enumeration doc; CASA Tier 2 assessor engagement (~$500–1k/yr); Marketplace listing after verification. Mostly waiting + paperwork. | ~2 wk active work spread over **8–16 wk elapsed** | — |
| **WS-1** Google device ingestion | `google-sync/src/chromeos.rs` client + typed `AnnotatedFields` validation; `backoff.rs` limiter; `GoogleAuth::from_oauth_refresh_token`; migrations 021; `GoogleDeviceSyncRepository`; `chalk-devices/src/sync.rs` full/resumable sync + `matching.rs`; `cli devices sync --dry-run`; mock-server tests (existing google-sync test style). | 3–4 wk | — (service-account mode; hosted OAuth slots in when WS-6 lands) |
| **WS-2** UI architecture | `[modules]` config + router/nav gating; `console_roles` (024) + role middleware; technician table pattern (dense rows, keyboard nav, saved filters, form-wrapped bulk select); AG Grid island + rust-embed verify; teacher portal shell on `PortalSession`; a11y pass + VPAT draft. | 3 wk | overlaps WS-1 |
| **WS-3** Devices module | Migrations 019, 022; `AssetRepository`/`AssetEventRepository`/`ChangeSetRepository` (sqlite+postgres); `AssetService` CRUD-with-events; core jobs port (Scheduler/cron_due → `core::jobs`) + `JobRunner`; diff-preview-commit flow; CSV round-trip; bulk ops incl. guarded deprovision (§9.2); reports; `api/devices.rs` + scopes; inventory/detail/unmatched-queue templates. | 4–5 wk | WS-1, WS-2 |
| **WS-4** Helpdesk module | Migration 020; ticket repos + `TicketService` (numbering, SLA scan job, first-response); `AttachmentStore` + `FsAttachmentStore`; teacher portal (<60s ticket, auto-attached device); technician queue; `email_ingest.rs` (Postmark webhook + IMAP job) with loop guards; `Mailer` trait + `SmtpMailer`; `notify.rs`; `api/tickets.rs`. | 4–5 wk | WS-2 (portal shell); parallel with WS-3 after core jobs land |
| **WS-5** Sheets bridge (as amended) | Nothing beyond WS-3's API/CSV except: `export to Sheets/CSV` button (5.4) and the CG CTA panel (5.3, copy + one dialog in the frozen add-on). 5.2 killed. | 2–3 days | WS-3 |
| **WS-7** Pricing/tenancy/billing | `_meta.tenant_plans` + platform_admin screens; entitlement → `tenant_config_modules` writer; enrollment snapshot job; grandfather flag; migrations 023 wired into `tenant_migrations::apply`. | 1–2 wk | WS-3 (flags exist to gate) |
| **WS-8** Strangle plan | Per-district AssetRemix DB usage audit query + semester checklist doc; `chalk import assetremix` **deferred** until a district's checklist clears. | 2–3 days now | — |
| **WS-9** Distribution | Dockerfile exists; add compose, Proxmox helper script, one-clicks (DO/Railway/Render/Coolify), Cloudron/YunoHost/CasaOS/TrueNAS/Unraid manifests, Homebrew tap, awesome-selfhosted PR. Agent-heavy, review-light. | 2 wk, fully parallel | a tagged release |

**Parallelism picture:** Week 0: WS-6 filings + WS-0 hygiene. Weeks 1–4: WS-1 (agent lane A) ∥ WS-2 (agent lane B). Weeks 5–9: WS-3 ∥ WS-4 (both consume WS-1/WS-2 output; core-jobs port lands first inside WS-3). Weeks 10–12: WS-5 + WS-7 + hardening + a11y/VPAT ∥ WS-9. Self-host beta ≈ week 10–12; hosted GA gated on WS-6's external clock. Total ≈ Aug–Dec 2026 build window, matching PRD §8, with quotes ready for Jan–Mar 2027.

Per-crate release discipline: version bumps across all crate `Cargo.toml`s + `CHANGELOG.md` + tag per the repo's release process (now 11 crates once devices/helpdesk land — update the release checklist in `CLAUDE.md`).

---

## 12. Open architecture questions

1. **Hosted runtime topology:** does one chalk process serve all tenant schemas (router resolves slug → schema-scoped pool), or one process per tenant? The control plane's registry supports either; memory footprint, blast radius, and the in-process `JobRunner`'s tenant fan-out differ materially. Needs a decision before WS-7 (recommend: single multi-tenant process with per-schema pools, matching the existing scheduler's fan-out — but confirm against current hosted deploy reality).
2. **Technician identity when technicians aren't in the SIS:** `console_roles` assumes techs exist as roster `users`. Contractors/aides often don't. Do we allow manually-created local users (a `source='manual'` user row), or a separate `console_accounts` table? Leaning manual roster rows (keeps FKs uniform), but it slightly pollutes OneRoster exports — needs a filter rule.
3. **Postgres parity timing for 019–024:** parity files must exist before hosted GA, but do we CI-test both drivers from day one (slower iteration) or SQLite-only until WS-7? Repo precedent (013's paired files + in-memory SQLite tests) suggests day-one parity; confirm the CI cost is acceptable.
4. **Telemetry entitlement detection:** is a 403-probe on the Chrome Management Telemetry API a reliable licence signal across Education SKUs, or do we need an explicit per-tenant toggle plus documentation? Affects whether telemetry panels can be auto-discovered or must be opt-in config.
5. **Hosted attachment storage + scanning:** GCS-via-S3-interop vs native GCS client (`object_store` abstracts both, but pick one for the whitepaper's subprocessor list), and do district security questionnaires force AV scanning on upload (ClamAV sidecar breaks single-binary purity on self-host — likely hosted-only scanning, self-host documented as "behind your filter", mirroring §7.2's mail stance)?
