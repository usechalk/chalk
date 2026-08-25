[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

# Chalk

Chalk is the open-source K-12 IT stack: device tracking, help desk, rostering, SSO, and Workspace sync in one binary. Self-host it free, or we host it.

## Run it

From an empty directory:

```sh
mkdir chalk && cd chalk
curl -fsSLO https://raw.githubusercontent.com/usechalk/chalk/main/docker-compose.yml
docker compose up -d
docker compose logs chalk | grep "Admin password"
```

Then open <http://localhost:8080>. One container, SQLite on a volume, no
external services — background jobs run in-process, so there is no Redis and no
worker to deploy.

Already have this repo cloned? Skip the `curl` and run the same two
`docker compose` commands from the checkout.

Everything Chalk keeps lives in one directory (`/var/lib/chalk`): the database,
the master encryption key, the SAML keypair and `chalk.toml`. Back up that
directory and you have backed up the install — including the key every stored
credential is sealed with, without which the database cannot be read.

## Why Chalk?

District IT runs on a pile of disconnected tools, and the data that ties them together — who your students are, what class they're in, what device they carry — lives in your SIS. Chalk pulls that roster once and reuses it everywhere: identity, provisioning, vendor data feeds, your asset inventory, and your ticket queue.

You own the data and the infrastructure. It's a single static binary with a SQLite database, licensed [AGPL-3.0](LICENSE), with no per-student fees and no seat counting. Chalk works with PowerSchool, Infinite Campus, Skyward, and any SIS that supports OneRoster CSV or API exports.

Don't want to run it yourself? We offer a hosted Chalk — see [usechalk.xyz/pricing](https://usechalk.xyz/pricing). Self-hosting stays free forever.

## Features

**Devices — a mixed-fleet inventory built on your roster**

- Google Admin ChromeOS sync with students already attached, matched by roster email
- Microsoft Intune (Windows) and Jamf Pro (iPad) connectors, so the whole fleet lives in one inventory
- Write-back to Google: OU moves, disable/re-enable/deprovision, and pushing Chalk's assignment and asset tag into `annotatedUser`/`annotatedAssetId` — every write goes through a diff preview an operator approves first
- Circulation desk: check-out/check-in with due dates and agreement acknowledgement, a loaner pool, and family email notifications
- Repairs with costs, a fees/fines ledger (assessment and waive/settle records only — Chalk never touches payment cards), lost/stolen with police-report capture
- Barcode/QR: scan lookup, printable QR label sheets, and a scan-to-reconcile physical audit mode — all keyboard-wedge, no special hardware
- CSV import/export through the same diff preview, fleet reports, per-device history

*The Intune, Jamf, and Entra connectors are new and validated against mocked APIs so far — field reports from real tenants are very welcome.*

**Helpdesk — a real ticket queue that emails people**

- Technician queue with assignment, priority/category, tags, and saved views
- First-response and resolution SLAs, routing/auto-assignment rules, canned responses
- Staff portal with magic-link sign-in, inbound email, outbound reply/resolve notifications, CSAT
- Knowledge base (console and public portal), ticket analytics, device↔ticket links, read-only REST API

**Identity & rostering**

- SIS connectors: PowerSchool, Infinite Campus, Skyward — plus OneRoster CSV/API for everything else
- SAML 2.0 / OIDC identity provider with a launcher portal, QR badge and picture-password login for young students
- Clever- and ClassLink-shaped OAuth 2.0 compatibility endpoints, plus migration importers for both
- OneRoster 1.1 REST API with `filter`, `sort`/`orderBy`, and `fields` query parameters
- Provisioning: Google Workspace users/OUs, Active Directory via LDAP, and Entra ID (Azure AD) via the Graph API
- Webhooks for real-time data-change events

**Platform**

- Admin console with per-person accounts (admin / technician / read-only) and honest audit attribution
- Session auth, CSRF protection, AES-256-GCM encryption at rest, audit logging
- One static binary, SQLite, in-process background jobs — no Redis, no worker fleet

## Requirements

- **Operating System** — Linux or macOS (Windows supported for development)
- **SQLite** — Version 3.35 or later
- **Network Access** — Connectivity to your SIS instance (PowerSchool, Infinite Campus, or Skyward)

## Install

Use the installer to pick the right release asset for your OS/CPU and install it
as `chalk`:

```bash
curl -fsSL https://raw.githubusercontent.com/usechalk/chalk/main/install.sh | sh
```

Set `INSTALL_DIR` if you want somewhere other than `/usr/local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/usechalk/chalk/main/install.sh | INSTALL_DIR="$HOME/.local/bin" sh
```

Or download the latest binary for your platform directly:

| Platform | Download |
|----------|----------|
| Linux (x86_64) | [chalk-x86_64-unknown-linux-gnu](https://github.com/usechalk/chalk/releases/latest/download/chalk-x86_64-unknown-linux-gnu) |
| macOS (Apple Silicon) | [chalk-aarch64-apple-darwin](https://github.com/usechalk/chalk/releases/latest/download/chalk-aarch64-apple-darwin) |
| macOS (Intel) | [chalk-x86_64-apple-darwin](https://github.com/usechalk/chalk/releases/latest/download/chalk-x86_64-apple-darwin) |
| Windows (x86_64) | [chalk-x86_64-pc-windows-msvc.exe](https://github.com/usechalk/chalk/releases/latest/download/chalk-x86_64-pc-windows-msvc.exe) |

After installing, run `chalk update` to stay current with future releases.

## Quick Start

```bash
# Initialize
chalk init --data-dir /var/lib/chalk --provider powerschool

# Configure your SIS credentials in chalk.toml, then sync
chalk sync --config /var/lib/chalk/chalk.toml

# Start the admin console
chalk serve --config /var/lib/chalk/chalk.toml --port 8080
```

See [chalk.example.toml](chalk.example.toml) for a fully commented configuration template.

## Build from Source

```bash
git clone https://github.com/usechalk/chalk.git
cd chalk
cargo build --release
# Binary at target/release/chalk
```

If you want Docker Compose to build from this checkout instead of pulling GHCR:

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

Requires Rust stable and SQLite3. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## Documentation

- [Getting Started](docs/getting-started.md) — Installation, initialization, and first sync
- [Configuration](docs/configuration.md) — TOML configuration reference
- [Architecture](docs/architecture.md) — System design and crate overview
- [Identity Provider](docs/idp-setup.md) — SAML SSO, QR badges, and picture passwords
- [Google Workspace Sync](docs/google-sync.md) — User provisioning and OU management
- [OneRoster API](docs/oneroster-api.md) — REST API for OneRoster 1.1 data access
- [Migration: Clever](docs/migration-clever.md) — Importing a Clever export bundle
- [Migration: ClassLink](docs/migration-classlink.md) — Importing a ClassLink export bundle
- [Clever-Compatible SSO](docs/clever-sso.md) — Clever-shaped OAuth 2.0 compatibility endpoints
- [ClassLink-Compatible SSO](docs/classlink-sso.md) — ClassLink-shaped OAuth 2.0 compatibility endpoints
- [Active Directory Sync](docs/ad-sync.md) — LDAP user provisioning and OU management
- [SSO Partner Guide](docs/sso-partner-guide.md) — Integrating apps via SAML 2.0 and OIDC
- [SSO School Setup](docs/sso-school-setup.md) — Configuring SSO for your school
- [Webhooks](docs/webhooks.md) — Real-time event notifications for data changes
- [Security](docs/security.md) — Authentication, encryption, and security hardening
- [Deployment](docs/deployment.md) — Production deployment with reverse proxy and systemd

## CLI Commands

| Command | Description |
|---------|-------------|
| `chalk init` | Initialize data directory and database |
| `chalk sync` | Run SIS data sync |
| `chalk serve` | Start admin console web server |
| `chalk status` | Show instance status |
| `chalk update` | Self-update to the latest release |
| `chalk update --check` | Check for updates without installing |
| `chalk import` | Import OneRoster CSV data |
| `chalk export` | Export data to OneRoster CSV |
| `chalk migrate` | Import a Clever or ClassLink export bundle |
| `chalk google-sync` | Run Google Workspace sync |
| `chalk ad-sync` | Sync roster data to Active Directory via LDAP |
| `chalk entra-sync` | Provision roster users into Entra ID (Azure AD) |
| `chalk devices` | ChromeOS device inventory: sync, change sets, push |
| `chalk mdm sync` | Pull the Intune / Jamf fleets into the inventory |
| `chalk jobs` | Inspect the background job queue, re-arm failures |
| `chalk console-users` | Manage per-person console accounts |
| `chalk passwords` | Generate default passwords for users |
| `chalk webhook` | Webhook operator subcommands |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Chalk is licensed under the [GNU Affero General Public License v3.0](LICENSE).
