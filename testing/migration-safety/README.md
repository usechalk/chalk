# Migration safety scenario

Exercises `chalk-hosted migrate-all` against a tenant that already has
data, to confirm that re-applying migrations is a no-op against the data
and doesn't lock out in-flight requests.

## What this proves

✅ `migrate-all` on a tenant already at head is a clean no-op — no
   tables dropped, no rows lost.

✅ Per-schema `pg_advisory_xact_lock` serialization works — concurrent
   `migrate-all` invocations don't race each other or corrupt the
   `_meta_schema_migrations` table.

✅ A `migrate-all` run completes while in-flight requests against the
   tenant still get served (no global outage).

## What this does NOT prove

⚠️ Roll-forward through a new migration. We don't add a synthetic
   migration mid-test; this would require a much bigger rig. We're
   only verifying the existing migration set re-applies safely, which
   is what real operators do after a chalk-hosted version bump.

⚠️ Roll-back. There is no down-migration story in this codebase. The
   advice is "test in staging, snapshot before".

## Prerequisites

- chalk-marketing docker stack running.
- `/usr/bin/curl` on PATH.

## Run

```bash
./run.sh
```

The script:
1. Provisions a fresh tenant.
2. Pushes a synthetic OneRoster CSV bundle in via `chalk sync` so the
   tenant has real rows (orgs, users, classes, enrollments).
3. Captures pre-migration counts via the (authenticated) OneRoster REST API.
4. Kicks off `chalk-hosted migrate-all` and a stream of `/api/oneroster/v1p1/users`
   GETs in parallel. Confirms the GETs all return 200 (no lockout).
5. Captures post-migration counts. Asserts identical.
6. Runs a second `migrate-all` simultaneously with the first via
   `&` to exercise the advisory-lock serialization. Both should
   succeed and the migrations table should report each version once.
7. Deprovisions the test tenant.

## Layout

```
migration-safety/
├── README.md
└── run.sh
```
