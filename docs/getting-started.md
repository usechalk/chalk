# Getting Started

## Prerequisites

- A supported operating system (Linux, macOS, or Windows)
- Network access to your SIS (PowerSchool, Infinite Campus, or Skyward)
- Admin credentials for your SIS instance

## Installation

Download the latest release binary for your platform from the [Releases](https://github.com/usechalk/chalk/releases) page.

```bash
# Linux / macOS
chmod +x chalk
sudo mv chalk /usr/local/bin/

# Verify installation
chalk --version
```

## Initialization

Initialize Chalk with your SIS provider:

```bash
chalk init --data-dir /var/lib/chalk --provider powerschool
```

Supported providers: `powerschool`, `infinite_campus`, `skyward`

This creates:
- Configuration file (`chalk.toml`)
- SQLite database (`chalk.db`)
- SAML certificate and key for identity provider

## Configuration

Edit the generated `chalk.toml` to add your SIS credentials:

```toml
[sis]
enabled = true
base_url = "https://your-powerschool.example.com"
client_id = "your-client-id"
client_secret = "your-client-secret"
```

See [Configuration Reference](configuration.md) for all options.

## First Sync

Test your connection:

```bash
chalk sync --dry-run --config /var/lib/chalk/chalk.toml
```

Run the first sync:

```bash
chalk sync --config /var/lib/chalk/chalk.toml
```

## Admin Console

Start the web-based admin console:

```bash
chalk serve --config /var/lib/chalk/chalk.toml --port 8080
```

Open `http://localhost:8080` in your browser. Log in with the admin password set during initialization.

## Data Import/Export

Import OneRoster CSV data:

```bash
chalk import --format oneroster-csv --path /path/to/csv/dir --config chalk.toml
```

Export data to OneRoster CSV:

```bash
chalk export --format oneroster-csv --output /path/to/output --config chalk.toml
```

## Migration from Clever or ClassLink

```bash
chalk migrate --from clever --path /path/to/clever/export --config chalk.toml
chalk migrate --from classlink --path /path/to/classlink/export --config chalk.toml
```

See [Clever Migration](migration-clever.md) or [ClassLink Migration](migration-classlink.md) for details.

## Next Steps

- Enable the [Identity Provider](idp-setup.md) for SAML SSO, password management, and QR badge login
- Configure [Google Workspace Sync](configuration.md#google-sync) for user provisioning
- Set up the [OneRoster API](oneroster-api.md) for third-party integrations
