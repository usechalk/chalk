# Architecture

Chalk is a Rust workspace monorepo that compiles into a single binary. The architecture follows a layered design with clear separation of concerns.

## Crate Overview

```
chalk (workspace)
├── crates/
│   ├── core/          # Data models, DB, connectors, sync engine
│   ├── cli/           # Binary entry point and CLI commands
│   ├── console/       # Web admin UI (Askama + HTMX)
│   ├── idp/           # SAML 2.0 identity provider
│   ├── google-sync/   # Google Workspace provisioning
│   ├── agent/         # AI diagnostic agent
│   ├── marketplace/   # App marketplace integrations
│   └── telemetry/     # Anonymous usage telemetry
├── migrations/
│   └── sqlite/        # SQL migration scripts
└── docs/              # Documentation
```

## Core Crate (`chalk-core`)

The foundation crate with no dependencies on other Chalk crates.

### Models (`models/`)

OneRoster 1.1 compliant data models:

| Model | Description |
|-------|-------------|
| `User` | Students, teachers, administrators |
| `Org` | Schools, districts, departments |
| `Course` | Course catalog entries |
| `Class` | Scheduled class sections |
| `Enrollment` | User-to-class assignments |
| `AcademicSession` | Terms and grading periods |
| `Demographics` | Student demographic data |

All models use `#[serde(rename_all = "camelCase")]` for OneRoster JSON/CSV compatibility.

### Database Layer (`db/`)

- **`DatabasePool`** — Enum abstracting over SQLite (and future PostgreSQL)
- **Repository traits** — 15+ async traits defining CRUD operations
- **`SqliteRepository`** — SQLite implementation of all repository traits
- **`ChalkRepository`** — Supertrait combining all repository traits

Migrations are embedded via `include_str!` and run at startup.

### Connectors (`connectors/`)

SIS connector trait and implementations:

```rust
#[async_trait]
pub trait SisConnector: Send + Sync {
    async fn full_sync(&self) -> Result<SyncPayload>;
    async fn test_connection(&self) -> Result<()>;
    fn provider_name(&self) -> &str;
}
```

Implementations: PowerSchool, Infinite Campus, Skyward.

### Sync Engine (`sync.rs`)

`SyncEngine<R: ChalkRepository>` orchestrates full data syncs:
1. Fetches `SyncPayload` from connector
2. Persists entities in dependency order (orgs → sessions → users → courses → classes → enrollments → demographics)
3. Records sync run metadata

### OneRoster CSV (`oneroster_csv/`)

Read and write OneRoster 1.1 bulk CSV format:
- `reader.rs` — Parses CSV directory into `SyncPayload`
- `writer.rs` — Writes `SyncPayload` to CSV files
- `manifest.rs` — Parses `manifest.csv` metadata

### Migration (`migration/`)

Parsers for Clever and ClassLink export formats, producing `MigrationPlan` structs with roster data and cutover steps.

### Crypto (`crypto.rs`)

AES-256-GCM encryption for sensitive data at rest (SIS credentials, API tokens).

## CLI Crate (`chalk-cli`)

Single binary with subcommands:

| Command | Description |
|---------|-------------|
| `chalk init` | Initialize data directory and database |
| `chalk sync` | Run SIS data sync |
| `chalk serve` | Start admin console web server |
| `chalk status` | Show instance status |
| `chalk update` | Check for updates |
| `chalk import` | Import OneRoster CSV data |
| `chalk export` | Export data to OneRoster CSV |
| `chalk migrate` | Migrate from Clever or ClassLink |
| `chalk google-sync` | Run Google Workspace sync |

## Console Crate (`chalk-console`)

HTMX-powered admin web UI served by the binary:

- **Askama templates** — Compile-time checked Jinja2 templates
- **HTMX** — Partial page updates without JavaScript frameworks
- **Auth middleware** — Session-based admin authentication
- **CSRF protection** — Token validation on POST requests
- **OneRoster REST API** — Read-only API at `/api/oneroster/v1p1/`

## IDP Crate (`chalk-idp`)

SAML 2.0 identity provider with:
- Password authentication
- QR badge login (for young students)
- Picture password login
- SAML SSO for Google Workspace

## Data Flow

```
SIS (PowerSchool/IC/Skyward)
    │
    ▼
SIS Connector (full_sync)
    │
    ▼
SyncPayload
    │
    ▼
SyncEngine → SQLite Database
    │              │
    ▼              ▼
Google Sync    Admin Console
    │              │
    ▼              ▼
Google        OneRoster API
Workspace     (REST/CSV)
```

## Security

- Admin console requires authentication
- CSRF tokens on all POST requests
- Security headers (X-Frame-Options, X-Content-Type-Options, etc.)
- AES-256-GCM encryption for sensitive data at rest
- Argon2 password hashing
- Admin audit logging
