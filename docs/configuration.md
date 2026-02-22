# Configuration Reference

Chalk uses a TOML configuration file (`chalk.toml`). Generate a default configuration with `chalk init`.

## Sections

### `[chalk]` — Core Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `instance_name` | String | `"My School District"` | Display name for this Chalk instance |
| `data_dir` | String | `/var/lib/chalk` | Directory for database, keys, and certificates |
| `public_url` | String? | — | Public URL for SAML metadata and SSO callbacks |

### `[chalk.database]` — Database

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `driver` | `"sqlite"` \| `"postgres"` | `"sqlite"` | Database driver |
| `path` | String? | — | SQLite file path (required for sqlite driver) |
| `url` | String? | — | PostgreSQL connection URL (required for postgres driver) |

### `[chalk.telemetry]` — Telemetry

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable anonymous usage telemetry |

### `[sis]` — Student Information System

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable SIS sync |
| `provider` | `"PowerSchool"` \| `"InfiniteCampus"` \| `"Skyward"` | `"PowerSchool"` | SIS provider |
| `base_url` | String | — | SIS API base URL |
| `token_url` | String? | — | OAuth token endpoint (required for IC/Skyward) |
| `client_id` | String | — | OAuth client ID |
| `client_secret` | String | — | OAuth client secret |
| `sync_schedule` | String | `"0 2 * * *"` | Cron expression for automatic sync |

### `[idp]` — Identity Provider

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable identity provider |
| `qr_badge_login` | bool | `true` | Enable QR badge authentication |
| `picture_passwords` | bool | `true` | Enable picture password authentication |
| `saml_cert_path` | String? | — | Path to SAML signing certificate |
| `saml_key_path` | String? | — | Path to SAML signing private key |
| `session_timeout_minutes` | u32 | `480` | IDP session timeout in minutes |
| `default_password_pattern` | String? | — | Pattern for generating default passwords (e.g., `"{lastName}{birthYear}"`) |
| `default_password_roles` | String[] | `[]` | Roles to generate passwords for (e.g., `["student", "teacher"]`) |

### `[idp.google]` — Google SAML Integration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `entity_id` | String? | — | SAML entity ID |
| `acs_url` | String? | — | Assertion Consumer Service URL |
| `workspace_domain` | String? | — | Google Workspace domain |

### `[google_sync]` — Google Workspace Sync

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable Google Workspace sync |
| `provision_users` | bool | `true` | Auto-create Google accounts |
| `manage_ous` | bool | `true` | Auto-manage organizational units |
| `suspend_inactive` | bool | `false` | Suspend inactive users |
| `sync_schedule` | String | `"0 3 * * *"` | Cron expression for sync |
| `service_account_key_path` | String? | — | Path to Google service account JSON key |
| `admin_email` | String? | — | Google Workspace admin email |
| `workspace_domain` | String? | — | Google Workspace domain |

### `[agent]` — AI Agent

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable AI diagnostic agent |

### `[marketplace]` — Marketplace

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable marketplace integrations |

## Example Configuration

```toml
[chalk]
instance_name = "Springfield School District"
data_dir = "/var/lib/chalk"
public_url = "https://chalk.springfield.k12.us"

[chalk.database]
driver = "sqlite"
path = "/var/lib/chalk/chalk.db"

[chalk.telemetry]
enabled = false

[sis]
enabled = true
provider = "PowerSchool"
base_url = "https://powerschool.springfield.k12.us"
client_id = "abc123"
client_secret = "secret456"
sync_schedule = "0 2 * * *"

[idp]
enabled = true
qr_badge_login = true
picture_passwords = true
saml_cert_path = "/var/lib/chalk/saml_cert.pem"
saml_key_path = "/var/lib/chalk/saml_key.pem"
session_timeout_minutes = 480

[google_sync]
enabled = false

[agent]
enabled = false

[marketplace]
enabled = false
```
