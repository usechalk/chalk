# Active Directory Sync

## Overview

Chalk's AD Sync provisions and manages Active Directory user accounts from your SIS roster data via LDAP. It can:

- **Create accounts** for new students and staff in Active Directory
- **Update accounts** when roster data changes (name, role, school, grade)
- **Manage Organizational Units (OUs)** to organize users by school, grade, and role
- **Generate usernames** using configurable patterns (e.g., first initial + last name)
- **Generate passwords** using templates or random generation
- **Disable or remove accounts** when users leave the roster

Sync uses a delta approach: only users whose data has changed since the last run are created or updated, keeping LDAP operations efficient.

## Prerequisites

1. Chalk initialized and users synced from your SIS (`chalk init` and `chalk sync`)
2. An Active Directory domain controller accessible via LDAP or LDAPS
3. A service account with permissions to create/modify/disable users and manage OUs
4. Network connectivity from the Chalk server to the domain controller (port 636 for LDAPS or 389 for LDAP)

## Configuration

Add the `[ad_sync]` section to your `chalk.toml`:

```toml
[ad_sync]
enabled = true
sync_schedule = "0 3 * * *"

[ad_sync.connection]
server = "ldaps://dc01.example.com:636"
bind_dn = "CN=chalk-svc,OU=Service Accounts,DC=school,DC=edu"
bind_password = "secure-password"
base_dn = "DC=school,DC=edu"
tls_verify = true

[ad_sync.ou_mapping]
students = "/Students/{school}/{grade}"
teachers = "/Teachers/{school}"
staff = "/Staff/{school}"

[ad_sync.options]
provision_users = true
deprovision_action = "disable"
manage_ous = true
dry_run = false
```

### Connection Settings

| Key | Description |
|-----|-------------|
| `server` | LDAP(S) URI of the domain controller |
| `bind_dn` | Distinguished name of the service account |
| `bind_password` | Password for the service account |
| `base_dn` | Base DN for the AD domain |
| `tls_verify` | Verify TLS certificates (recommended: `true`) |

### Options

| Key | Description |
|-----|-------------|
| `provision_users` | Automatically create AD accounts for new roster users |
| `deprovision_action` | Action for removed users: `"disable"`, `"move_to_ou"`, or `"delete"` |
| `manage_ous` | Automatically create OUs that do not exist |
| `dry_run` | Preview changes without modifying AD |

## OU Mapping

OU mapping controls where users are placed in the AD hierarchy:

```toml
[ad_sync.ou_mapping]
students = "/Students/{school}/{grade}"
teachers = "/Teachers/{school}"
staff = "/Staff/{school}"
```

### Placeholders

| Placeholder | Source | Example |
|---|---|---|
| `{school}` | User's first organization from roster data | `Lincoln HS` |
| `{grade}` | User's first grade level from roster data | `09` |

With the configuration above, a 9th-grade student at Lincoln HS would be placed in:

```
OU=09,OU=Lincoln HS,OU=Students,DC=school,DC=edu
```

If `manage_ous` is enabled, Chalk creates any OUs that do not exist in Active Directory.

## Username Generation

Chalk generates AD usernames using a configurable pattern. The default is first initial + last name (e.g., `jsmith` for Jane Smith).

Collisions are handled automatically by appending a number (e.g., `jsmith2`).

## Password Generation

Chalk supports two password generation modes:

### Template Passwords

Use a template pattern to generate predictable passwords for initial distribution:

```toml
[ad_sync.password]
mode = "template"
template = "{firstName}{grade}{random4}"
```

| Placeholder | Description | Example |
|---|---|---|
| `{firstName}` | User's first name | `Jane` |
| `{lastName}` | User's last name | `Smith` |
| `{grade}` | User's grade level | `09` |
| `{random4}` | Four random digits | `3847` |

With the template above, Jane Smith in 9th grade might get: `Jane093847`

### Random Passwords

Generate fully random passwords:

```toml
[ad_sync.password]
mode = "random"
length = 16
```

### Exporting Passwords

After sync, export generated passwords for distribution:

```bash
chalk ad-sync --export-passwords
```

This outputs a CSV with username and initial password for newly created accounts.

## CLI Commands

| Command | Description |
|---------|-------------|
| `chalk ad-sync` | Run AD sync (delta -- only changed users) |
| `chalk ad-sync --full` | Run a full sync (all users, not just changes) |
| `chalk ad-sync --dry-run` | Preview changes without modifying AD |
| `chalk ad-sync --status` | Show the last sync run status |
| `chalk ad-sync --test-connection` | Test LDAP connectivity and authentication |
| `chalk ad-sync --export-passwords` | Export initial passwords for new accounts |

## Dry Run

Before running a live sync, use dry run mode to preview what changes would be made without modifying Active Directory:

```bash
chalk ad-sync --dry-run
```

Dry run output shows the number of users that would be created, updated, or disabled, along with any OUs that would be created. No changes are made to AD.

## Run Sync

To run a delta sync (only changed users):

```bash
chalk ad-sync
```

To run a full sync (all users):

```bash
chalk ad-sync --full
```

This will:

1. Load all active, enabled users from the roster database
2. Compare each user against the last known sync state
3. Create new AD accounts for users not yet provisioned
4. Update accounts where roster data has changed
5. Disable, move, or delete accounts for users no longer in the roster (based on `deprovision_action`)
6. Create any missing OUs (if `manage_ous` is enabled)

## Schedule Automatic Sync

Automatic sync runs on the schedule defined by `sync_schedule` in your configuration:

```toml
[ad_sync]
sync_schedule = "0 3 * * *"   # Every day at 3:00 AM
```

Common schedules:

| Cron Expression | Description |
|---|---|
| `0 3 * * *` | Daily at 3:00 AM |
| `0 */6 * * *` | Every 6 hours |
| `0 3 * * 1-5` | Weekdays at 3:00 AM |

## Monitoring

### CLI

View the latest sync run from the command line:

```bash
chalk ad-sync --status
```

### Console Dashboard

The Chalk admin console provides an AD Sync section showing:

- **Last sync status** -- success or failure with timestamp
- **Sync history** -- a log of recent sync runs with user counts
- **User status** -- per-user sync state (synced, pending, disabled)

## Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| "connection refused" | DC not reachable | Verify network connectivity and `server` URI |
| "invalid credentials" | Wrong bind DN or password | Check `bind_dn` and `bind_password` |
| "TLS handshake failed" | Certificate issue | Set `tls_verify = false` to test, then fix certificates |
| Users created in wrong OU | Incorrect `ou_mapping` | Check `{school}` and `{grade}` placeholders match your roster data |
| Username collisions | Duplicate names | Chalk appends a number automatically; no action needed |
| Sync runs but no users created | No active users in roster | Run `chalk sync` first to populate roster data from your SIS |
