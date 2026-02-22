# Google Workspace Sync

## Overview

Chalk's Google Sync provisions and manages Google Workspace user accounts from your SIS roster data. It can:

- **Create accounts** for new students and staff in Google Workspace
- **Update accounts** when roster data changes (name, role, school, grade)
- **Manage Organizational Units (OUs)** to organize users by school, grade, and role
- **Suspend inactive accounts** when users leave the roster

Sync uses a delta approach: only users whose data has changed since the last run are created or updated, keeping API usage efficient.

## Prerequisites

Before configuring Google Sync, ensure you have:

1. A [Google Workspace for Education](https://workspace.google.com/products/education/) subscription
2. **Super Admin** access to the Google Admin Console
3. A Google Cloud project with the [Admin SDK API](https://console.cloud.google.com/apis/library/admin.googleapis.com) enabled
4. A service account with domain-wide delegation (see below)
5. Chalk initialized and users synced from your SIS (`chalk init` and `chalk sync`)

## Create a Service Account

Google Sync authenticates using a service account with a JSON key file. Follow these steps:

1. Open the [Google Cloud Console](https://console.cloud.google.com/)
2. Select or create a project for Chalk
3. Navigate to **IAM & Admin > Service Accounts**
4. Click **Create Service Account** and give it a descriptive name (e.g., `chalk-sync`)
5. No roles are required at the project level -- click **Done**
6. Click the new service account, go to the **Keys** tab, and click **Add Key > Create new key**
7. Select **JSON** and download the key file
8. Store the key file securely on the Chalk server (e.g., `/var/lib/chalk/google-sa.json`)

For detailed instructions, see:
- [Creating a service account](https://cloud.google.com/iam/docs/service-accounts-create)
- [Creating service account keys](https://cloud.google.com/iam/docs/keys-create-delete)

## Enable Domain-Wide Delegation

The service account needs domain-wide delegation to manage users on behalf of a Workspace admin.

1. In the Google Cloud Console, go to **IAM & Admin > Service Accounts**
2. Click the service account, then **Show advanced settings**
3. Copy the **Client ID** (a numeric value)
4. Sign in to the [Google Admin Console](https://admin.google.com)
5. Navigate to **Security > Access and data control > API controls > Manage Domain Wide Delegation**
6. Click **Add new** and enter the Client ID from step 3
7. Add the following OAuth scopes (comma-separated):

```
https://www.googleapis.com/auth/admin.directory.user,https://www.googleapis.com/auth/admin.directory.orgunit
```

8. Click **Authorize**

For more details, see [Domain-wide delegation overview](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority).

## Configure Chalk

Add the `[google_sync]` section to your `chalk.toml`:

```toml
[google_sync]
enabled = true
provision_users = true
manage_ous = true
suspend_inactive = false
sync_schedule = "0 3 * * *"
service_account_key_path = "/var/lib/chalk/google-sa.json"
admin_email = "admin@springfield.k12.us"
workspace_domain = "springfield.k12.us"
```

| Key | Description |
|-----|-------------|
| `enabled` | Enable or disable Google Sync |
| `provision_users` | Automatically create Google accounts for new roster users |
| `manage_ous` | Automatically create and assign Organizational Units |
| `suspend_inactive` | Suspend Google accounts for users no longer in the active roster |
| `sync_schedule` | Cron expression controlling when automatic sync runs |
| `service_account_key_path` | Absolute path to the service account JSON key file |
| `admin_email` | A Google Workspace super admin email the service account impersonates |
| `workspace_domain` | Your Google Workspace domain (e.g., `springfield.k12.us`) |

## OU Mapping

OU mapping lets you control where users are placed in your Google Workspace OU hierarchy. Add the `[google_sync.ou_mapping]` section:

```toml
[google_sync.ou_mapping]
students = "/Students/{school}/{grade}"
teachers = "/Teachers/{school}"
staff = "/Staff/{school}"
```

### Placeholders

| Placeholder | Source | Example |
|---|---|---|
| `{school}` | User's first organization from roster data | `Lincoln HS` |
| `{grade}` | User's first grade level from roster data | `09` |

### Examples

With the configuration above, a 9th-grade student at Lincoln HS would be placed in:

```
/Students/Lincoln HS/09
```

A teacher at Lincoln HS would be placed in:

```
/Teachers/Lincoln HS
```

If `manage_ous` is enabled, Chalk creates any OUs that do not already exist in Google Workspace.

## Dry Run

Before running a live sync, use dry run mode to preview what changes would be made without calling the Google API:

```bash
chalk google-sync --dry-run
```

Dry run output shows the number of users that would be created, updated, or suspended, along with any OUs that would be created. No changes are made to Google Workspace.

## Run Sync

To run a live sync:

```bash
chalk google-sync
```

This will:

1. Load all active, enabled users from the roster database
2. Compare each user against the last known sync state (using a field hash)
3. Create new Google accounts for users not yet provisioned
4. Update accounts where roster data has changed
5. Suspend accounts for users no longer in the active roster (if `suspend_inactive` is enabled)
6. Create any missing OUs (if `manage_ous` is enabled)

New accounts are created with a random password and `changePasswordAtNextLogin` set to `true`.

## Schedule Automatic Sync

Automatic sync runs on the schedule defined by `sync_schedule` in your configuration. The value is a standard cron expression:

```toml
[google_sync]
sync_schedule = "0 3 * * *"   # Every day at 3:00 AM
```

You can also configure the schedule through the Chalk admin console under **Settings > Google Sync > Schedule**.

Common schedules:

| Cron Expression | Description |
|---|---|
| `0 3 * * *` | Daily at 3:00 AM |
| `0 */6 * * *` | Every 6 hours |
| `0 3 * * 1-5` | Weekdays at 3:00 AM |
| `30 2 * * *` | Daily at 2:30 AM |

## Monitoring

### Console Dashboard

The Chalk admin console provides a Google Sync dashboard showing:

- **Last sync status** -- success or failure with timestamp
- **Sync history** -- a log of recent sync runs with user counts
- **User status** -- per-user sync state (synced, pending, suspended)

Access the dashboard at **Google Sync** in the admin console sidebar.

### CLI

View the latest sync run from the command line:

```bash
chalk google-sync --status
```

## Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| "workspace_domain not configured" | Missing `workspace_domain` in config | Add `workspace_domain` to `[google_sync]` |
| 401 Unauthorized | Invalid or expired service account key | Re-download the JSON key and update `service_account_key_path` |
| 403 Forbidden | Domain-wide delegation not configured | Verify the OAuth scopes and Client ID in Google Admin Console |
| "cannot suspend user without google_email" | Sync state missing email | Delete the sync state and re-run to re-provision |
| Users created in wrong OU | Incorrect `ou_mapping` templates | Check `{school}` and `{grade}` placeholders match your roster data |
| Sync runs but no users created | No active, enabled users in roster | Run `chalk sync` first to populate roster data from your SIS |
| Rate limit errors | Too many API calls | Reduce sync frequency or contact Google to increase quotas |

## Google Reference Links

- [Google Cloud Console](https://console.cloud.google.com/)
- [Creating a service account](https://cloud.google.com/iam/docs/service-accounts-create)
- [Creating service account keys](https://cloud.google.com/iam/docs/keys-create-delete)
- [Domain-wide delegation](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority)
- [Admin SDK Directory API](https://developers.google.com/admin-sdk/directory/v1/guides)
- [Google Admin Console](https://admin.google.com)
- [API controls and domain-wide delegation](https://support.google.com/a/answer/162106)
