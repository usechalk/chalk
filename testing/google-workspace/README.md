# Google Workspace sync

**No docker container. No `run.sh`.** This one needs a real Google
Workspace tenant with admin access — not something we can stand up
locally.

## Prerequisites

1. A **Google Workspace tenant** you control. A free
   [Google Workspace dev account](https://developers.google.com/workspace/marketplace/programs)
   works fine for testing, or a paid Workspace tenant with a test OU.

2. A **service account** in that Workspace tenant's GCP project, with:
   - The Admin SDK API enabled.
   - **Domain-wide delegation** authorized for the scopes
     `https://www.googleapis.com/auth/admin.directory.user`,
     `.../admin.directory.orgunit`, `.../admin.directory.group` (only
     the scopes chalk actually uses — see `crates/google-sync/`).
   - The service-account JSON key downloaded.

3. An **impersonation subject** — the email of a real super-admin in the
   Workspace tenant. Service-account calls to the Directory API require
   delegated impersonation; chalk uses this principal for every
   provisioning call.

4. A target OU in Workspace where chalk can safely create test users
   (don't point this at your production user OU until you're confident).

## chalk.toml fragment

```toml
[google_sync]
enabled = true
service_account_key = "/path/to/service-account.json"
impersonation_subject = "admin@yourdomain.example"
domain = "yourdomain.example"

[google_sync.ou_mapping]
students = "/Chalk Test/Students/{school}/{grade}"
teachers = "/Chalk Test/Teachers/{school}"
staff = "/Chalk Test/Staff"

[google_sync.options]
suspend_inactive = true
sync_schedule = "0 3 * * *"
```

## How to run

```bash
# Always start with --dry-run on a real tenant.
chalk --config /path/to/chalk.toml google-sync --dry-run

# Review the planned diff. If it looks right:
chalk --config /path/to/chalk.toml google-sync
```

## What to look for

- `--dry-run` output enumerates **create / update / suspend** counts that
  match what you expect for the synced cohort.
- Real run completes with no API errors. (Common gotcha: Workspace
  rate-limits at ~1500 requests / 100 seconds per project — large initial
  syncs may need throttling.)
- Workspace admin console (admin.google.com → Directory → Users) shows
  the synced users in the right OUs.
- `chalk-marketing` admin console at `/google-sync` shows a successful
  run in the history.

## What we can fake locally instead

Nothing — Google Directory has no offline emulator we can credibly stand
up in docker. The closest is unit-testing the request shapes against
`wiremock`, which the `chalk-google-sync` crate already does in its own
test suite.
