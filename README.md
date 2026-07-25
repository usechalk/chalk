[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

# Chalk

Chalk is the open-source K-12 IT stack: device tracking, help desk, rostering, SSO, and Workspace sync in one binary. Self-host it free, or we host it.

## Why Chalk?

District IT runs on a pile of disconnected tools, and the data that ties them together — who your students are, what class they're in, what device they carry — lives in your SIS. Chalk pulls that roster once and reuses it everywhere: identity, provisioning, vendor data feeds, and (soon) your asset inventory and ticket queue.

You own the data and the infrastructure. It's a single static binary with a SQLite database, licensed [AGPL-3.0](LICENSE), with no per-student fees and no seat counting. Chalk works with PowerSchool, Infinite Campus, Skyward, and any SIS that supports OneRoster CSV or API exports.

Don't want to run it yourself? We offer a hosted Chalk — see [usechalk.xyz/pricing](https://usechalk.xyz/pricing). Self-hosting stays free forever.

## Status

**Shipping today:**

- SIS sync — PowerSchool, Infinite Campus, Skyward
- OneRoster 1.1 models, CSV import/export, and a read-only REST API
- SAML 2.0 identity provider
- QR badge and picture-password login for young students
- Google Workspace user provisioning and OU management
- Active Directory sync via LDAP
- Webhooks for real-time data-change events
- Admin console

**In build for SY2027-28:**

- **Devices** — Chromebook and asset tracking, with the inventory populated from your SIS roster
- **Helpdesk** — ticketing plus a teacher-facing portal

## Features

- **SIS Connectors** — PowerSchool, Infinite Campus, Skyward
- **Identity Provider** — SAML 2.0 SSO with QR badge and picture password login
- **Google Workspace Sync** — Automated user provisioning and OU management
- **OneRoster 1.1** — CSV import/export and REST API
- **OAuth 2.0 Compatibility Endpoints** — Clever- and ClassLink-shaped OAuth 2.0 endpoints for districts migrating off those providers, so already-integrated vendor apps can point at Chalk
- **Active Directory Sync** — Automated AD user provisioning via LDAP
- **Migration Tools** — Import a Clever or ClassLink export bundle into Chalk
- **Admin Console** — HTMX-powered web UI with dashboard, user directory, and settings
- **Security** — Session auth, CSRF protection, AES-256-GCM encryption at rest, audit logging

## Requirements

- **Operating System** — Linux or macOS (Windows supported for development)
- **SQLite** — Version 3.35 or later
- **Network Access** — Connectivity to your SIS instance (PowerSchool, Infinite Campus, or Skyward)

## Install

Download the latest binary for your platform:

| Platform | Download |
|----------|----------|
| Linux (x86_64) | [chalk-x86_64-unknown-linux-gnu](https://github.com/usechalk/chalk/releases/latest/download/chalk-x86_64-unknown-linux-gnu) |
| macOS (Apple Silicon) | [chalk-aarch64-apple-darwin](https://github.com/usechalk/chalk/releases/latest/download/chalk-aarch64-apple-darwin) |
| macOS (Intel) | [chalk-x86_64-apple-darwin](https://github.com/usechalk/chalk/releases/latest/download/chalk-x86_64-apple-darwin) |
| Windows (x86_64) | [chalk-x86_64-pc-windows-msvc.exe](https://github.com/usechalk/chalk/releases/latest/download/chalk-x86_64-pc-windows-msvc.exe) |

**Linux / macOS one-liner:**

```bash
curl -fsSL https://github.com/usechalk/chalk/releases/latest/download/chalk-$(uname -m)-$(case "$(uname -s)" in Linux*) echo unknown-linux-gnu;; Darwin*) echo apple-darwin;; esac) -o chalk && chmod +x chalk && sudo mv chalk /usr/local/bin/
```

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
| `chalk ad-sync` | Sync roster data to Active Directory |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Chalk is licensed under the [GNU Affero General Public License v3.0](LICENSE).
