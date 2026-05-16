# Backup and restore

How to back up a hosted chalk deployment and how to restore from a
snapshot. Self-hosted users on SQLite can copy `chalk.db` while the
process is stopped, or use `chalk export` for a OneRoster CSV bundle.

## What needs to be in the backup

Two things, with very different operational properties:

1. **The Postgres database.** Contains every tenant's `_meta` registry
   row, sealed SAML keypairs, sealed OIDC signing keys, and the per-tenant
   schema with users, classes, enrollments, audit logs, etc.

2. **The master encryption key.** A 32-byte base64 string held in the
   `MASTER_ENCRYPTION_KEY` environment variable. Without it the
   contents of `_meta.tenants.saml_keypair` and `oidc_signing_jwk` are
   unrecoverable — they're sealed at rest with AES-256-GCM under this
   key. **Losing the master key permanently invalidates every tenant's
   identity provider.**

Treat the two as separate backups stored in separate locations. A
single-source-of-failure backup that contains both defeats the purpose
of envelope encryption.

## Postgres: nightly logical backup with pg_dump

Recommended for tenants up to ~100 schemas / a few GB of roster data:

```sh
#!/usr/bin/env bash
# /usr/local/bin/chalk-backup.sh
set -euo pipefail

PGURL="${PGURL:-postgres://chalk:chalk@localhost:5432/chalk}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/chalk}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

mkdir -p "$BACKUP_DIR"
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$BACKUP_DIR/chalk-$TS.sql.gz"

pg_dump --format=custom --no-owner --no-acl "$PGURL" | gzip > "$OUT"
sha256sum "$OUT" > "$OUT.sha256"

# Ship to off-host storage (S3, GCS, Backblaze B2 — whatever you trust).
# aws s3 cp "$OUT"        s3://chalk-backups/$(date -u +%Y/%m)/
# aws s3 cp "$OUT.sha256" s3://chalk-backups/$(date -u +%Y/%m)/

# Prune local copies older than RETENTION_DAYS.
find "$BACKUP_DIR" -name "chalk-*.sql.gz" -mtime "+$RETENTION_DAYS" -delete
find "$BACKUP_DIR" -name "chalk-*.sql.gz.sha256" -mtime "+$RETENTION_DAYS" -delete
```

Add to root's crontab (or your scheduler of choice):

```cron
17 3 * * * /usr/local/bin/chalk-backup.sh > /var/log/chalk-backup.log 2>&1
```

Why 3:17am: the multi-tenant sync scheduler fires at 02:00 (`0 2 * * *`)
across tenants by default. Running backups after the sync wave avoids
locking the same rows the sync engine is upserting against.

For larger deployments, switch to managed snapshots (RDS, Cloud SQL,
Aurora, Crunchy Bridge, Neon) on a 15-minute or 1-hour cadence with
point-in-time recovery enabled.

## Master key: store separately, in two locations

The 32-byte master key is the smallest thing in the system but the most
valuable. Recommended:

- **Primary**: live in your secrets manager (AWS Secrets Manager, GCP
  Secret Manager, HashiCorp Vault) referenced by the application via
  IAM. Rotated through `chalk-hosted rotate-master-key` (see
  `testing/key-rotation/` for the e2e flow).
- **Secondary**: printed, signed, sealed in an envelope, in a
  physically-secured cabinet. Updated whenever the key rotates. This is
  the "the cloud caught fire" plan.

`MASTER_ENCRYPTION_KEY` should never appear in a Postgres backup. If you
extract environment variables into your monitoring system, scrub this one.

## Restore

### Postgres: pg_restore from the latest snapshot

```sh
# Verify checksum first.
sha256sum -c chalk-$TS.sql.gz.sha256

# Restore into a fresh database. NEVER restore on top of a populated DB
# — pg_restore --clean is destructive.
createdb chalk_restored
gunzip -c chalk-$TS.sql.gz | pg_restore --no-owner --no-acl -d chalk_restored
```

Then point a staging `chalk-hosted` at `postgres://…/chalk_restored`
with the matching `MASTER_ENCRYPTION_KEY` env var. Verify a known tenant
can sign in before cutting production traffic over.

### Master key recovery

Set the recovered key in the environment, restart `chalk-hosted`, and
exercise:

```sh
chalk-hosted serve --config /etc/chalk/hosted.toml
# In another shell — verify a tenant's SAML metadata renders with a non-empty cert:
curl -s http://acme.localhost:8080/idp/saml/metadata | grep -c '<ds:X509Certificate>[^<]\+'
# Expect: 1
```

If the cert element is empty (zero matches), the key in the env does not
match the key the secrets were sealed with — stop and pick the right
key.

## Test the restore quarterly

A backup you've never restored is a hope, not a backup. Schedule a
quarterly restore drill into a staging environment:

1. Pick a recent snapshot.
2. Restore into a throwaway Postgres.
3. Start `chalk-hosted` against it with the matching master key.
4. Run `testing/tenant-lifecycle/run.sh` against the restored stack.
5. Note the elapsed time end-to-end and any rough edges in the runbook.

## What's NOT in scope

- **In-flight sync runs.** A backup taken mid-sync may not include the
  most recent run. The sync engine is idempotent, so the next scheduled
  run picks up where it left off — no data loss, just up to one tick of
  latency.
- **Webhook delivery state.** Pending deliveries in `webhook_deliveries`
  are included in the Postgres backup, but a restored deployment will
  re-attempt them on its next retry tick. Downstream receivers should
  be idempotent on `X-Chalk-Event-Id`.
- **`/var/log/chalk-hosted/*` access logs.** Not in the DB, not in the
  backup. Ship to a log aggregator separately.
