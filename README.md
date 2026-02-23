[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

# Chalk

Chalk is a unified K-12 data platform that connects your Student Information System (SIS) to identity, sync, and classroom tools — all from a single binary.

## Features

- **SIS Connectors** — PowerSchool, Infinite Campus, Skyward
- **Identity Provider** — SAML 2.0 SSO with QR badge and picture password login
- **Google Workspace Sync** — Automated user provisioning and OU management
- **OneRoster 1.1** — CSV import/export and REST API
- **Migration Tools** — Switch from Clever or ClassLink with guided migration
- **Admin Console** — HTMX-powered web UI with dashboard, user directory, and settings
- **Security** — Session auth, CSRF protection, AES-256-GCM encryption at rest, audit logging

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
- [Migration: Clever](docs/migration-clever.md) — Migrating from Clever
- [Migration: ClassLink](docs/migration-classlink.md) — Migrating from ClassLink
- [SSO Partner Guide](docs/sso-partner-guide.md) — Integrating apps via SAML 2.0 and OIDC
- [SSO School Setup](docs/sso-school-setup.md) — Configuring SSO for your school
- [Webhooks](docs/webhooks.md) — Real-time event notifications for data changes
- [Security](docs/security.md) — Authentication, encryption, and security hardening

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
| `chalk migrate` | Migrate from Clever or ClassLink |
| `chalk google-sync` | Run Google Workspace sync |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Chalk is licensed under the [GNU Affero General Public License v3.0](LICENSE).
