# Chalk Hosted - Operator Runbook

Internal runbook for the team operating the chalk hosted service. Pair with
`infra/bootstrap.sh`, `infra/caddy/Caddyfile`, `infra/systemd/chalk-hosted.service`,
and `infra/env.example`.

All commands assume Ubuntu 24.04 on a Digital Ocean droplet, run as root unless
otherwise noted.

---

## 1. Initial deploy checklist

1. Provision the DO droplet (Ubuntu 24.04, 2 vCPU / 4 GB minimum) on the same
   VPC as the DO Managed Postgres cluster.
2. Point the apex `<apex>` and wildcard `*.<apex>` DNS records at the droplet
   in Cloudflare. Set both to **DNS only** (grey cloud) - Caddy terminates TLS.
3. SSH in and run `bash bootstrap.sh`.
4. Copy artifacts and configure per the "next steps" the script prints:
   - `/usr/local/bin/chalk-hosted` (binary)
   - `/var/www/chalk-marketing/dist/` (marketing static assets)
   - `/etc/caddy/Caddyfile` (substitute `<apex>` for the real apex)
   - `/etc/systemd/system/chalk-hosted.service`
   - `/etc/chalk-hosted/secrets.env` (mode 0640, root:chalk-hosted)
   - `/etc/chalk-hosted/config.toml`
5. `systemctl enable --now chalk-hosted caddy`
6. Smoke test:
   - `curl -fsS https://<apex>/` -> marketing site
   - `curl -fsS https://app.<apex>/health` -> 200 OK from chalk-hosted
   - `journalctl -u chalk-hosted -n 100 --no-pager` -> no panics
7. Sign up the first internal tenant via the marketing site to confirm the full
   loop (verification email, tenant slug provisioning, login).

---

## 2. Master encryption key

The master key wraps every per-tenant SAML/OIDC private key in the database.
**Loss is unrecoverable**: all tenants would have to re-issue and re-upload
their identity provider credentials.

### 2.1 Generation

```bash
openssl rand -base64 32
```

Paste into `MASTER_ENCRYPTION_KEY` inside `/etc/chalk-hosted/secrets.env`.
Verify the file is `0640 root:chalk-hosted`.

### 2.2 Backup procedure

Keep two independent copies, both encrypted at rest:

1. **1Password**, "Chalk Hosted - prod" vault, item "MASTER_ENCRYPTION_KEY".
   Tag with the rotation timestamp.
2. **age-encrypted file** committed to the private `chalk-ops` repo at
   `secrets/master-key-<YYYYMMDD>.age`. Encrypt to the team's age recipients:

   ```bash
   echo -n "$MASTER_ENCRYPTION_KEY" \
     | age -R ops-recipients.txt -o secrets/master-key-$(date +%Y%m%d).age
   ```

Never commit the plaintext. Never paste into chat. Never leave on a laptop
outside an encrypted volume.

### 2.3 Rotation

`rotate-master-key` re-wraps every per-tenant sealed secret (`saml_keypair`
and `oidc_signing_jwk` in `_meta.tenants`) under a new master key inside a
single Postgres transaction. The operation is idempotent: a row that was
already rotated by a previous (interrupted) run is detected and skipped.

```bash
# 1. Take a fresh manual snapshot (section 5).
# 2. Run the rotation. Omit --new-key to have one generated and printed.
sudo -u chalk-hosted /usr/local/bin/chalk-hosted rotate-master-key \
    --postgres-url "$POSTGRES_URL" \
    --old-key "$OLD_MASTER_ENCRYPTION_KEY" \
    --new-key "$NEW_MASTER_ENCRYPTION_KEY"
# 3. On success, update /etc/chalk-hosted/secrets.env with the new key.
# 4. Restart so the in-memory key matches what the DB was just rewrapped to:
systemctl restart chalk-hosted
```

If you omit `--old-key`, the binary falls back to the value of
`MASTER_ENCRYPTION_KEY` already in the operator's environment — which is the
common case when running the command on the chalk-hosted host. If you omit
`--new-key`, the binary generates a fresh 32-byte key, prints it once to
stdout (`MASTER_ENCRYPTION_KEY=...`), and uses it for the rotation. **Capture
that output before the process exits** — there is no second chance.

Back up the new key per section 2.2 *before* discarding the old one. Keep the
previous key archived for 30 days in case rollback is required.

If a tenant's sealed material can be opened with neither the old nor the new
key, rotation aborts and the transaction rolls back; the error names the slug
so you can investigate that tenant in isolation.

---

## 3. Tenant lifecycle

The `chalk-hosted` binary supports the following tenant subcommands:
`provision`, `tenant suspend`, `tenant unsuspend`, `deprovision`, and
`migrate-all`.

### 3.1 Provision a new tenant

```bash
sudo -u chalk-hosted /usr/local/bin/chalk-hosted provision \
    --slug <tenant-slug> \
    --admin-email <admin@example.com> \
    --display-name "<District Name>" \
    --postgres-url "$POSTGRES_URL"
```

### 3.2 Suspend a tenant (blocks logins, retains data)

```bash
sudo -u chalk-hosted /usr/local/bin/chalk-hosted tenant suspend \
    --slug <tenant-slug> \
    --postgres-url "$POSTGRES_URL"
```

Tenants are routed via the resolver's `StateCache`; the running `serve`
process will continue serving this tenant from cache until LRU eviction
(~10 min idle). For immediate effect, send `SIGHUP` to flush the cache
without dropping in-flight connections:

```bash
sudo systemctl kill -s HUP chalk-hosted
```

The serve process catches `SIGHUP` and calls `StateCache::clear()`, so the
next request for any tenant re-queries `_meta.tenants` and rebuilds its
context. A suspended tenant will then resolve to `None` and be 404'd.
Use the same signal after `tenant unsuspend` if you want the reactivated
tenant to be available immediately rather than waiting for the previous
(suspended) cache entry to expire. As a heavier hammer,
`systemctl restart chalk-hosted` still works.

### 3.3 Reactivate

```bash
sudo -u chalk-hosted /usr/local/bin/chalk-hosted tenant unsuspend \
    --slug <tenant-slug> \
    --postgres-url "$POSTGRES_URL"
```

### 3.4 Deprovision (hard delete, irreversible)

```bash
sudo -u chalk-hosted /usr/local/bin/chalk-hosted deprovision \
    --slug <tenant-slug> \
    --postgres-url "$POSTGRES_URL" \
    --purge-data
```

This drops the tenant's schema and cascades to all per-tenant data. Take a
fresh DB backup first (section 5). Omit `--purge-data` to retain the schema
while removing the registry row.

### 3.5 Re-run OSS migrations across all tenants

```bash
sudo -u chalk-hosted /usr/local/bin/chalk-hosted migrate-all \
    --postgres-url "$POSTGRES_URL" \
    --concurrency 4
```

---

## 4. Logs

All chalk-hosted output goes to journald.

```bash
# Live tail
journalctl -u chalk-hosted -f

# Filter by tenant (logs are JSON; tenant_slug is a top-level field)
journalctl -u chalk-hosted -f --output=cat | grep '"tenant_slug":"acme"'

# Last hour, errors only
journalctl -u chalk-hosted --since "1 hour ago" -p err

# Caddy
journalctl -u caddy -f
```

Retention is whatever journald is configured for (default ~1 month). Forward
to a long-term store (e.g. Better Stack, Loki) once we cross ~50 tenants.

---

## 5. Database backup & restore

We use **DO Managed Postgres**, so the heavy lifting is handled by DO:

- **Daily automated backups**: retained 7 days on the standard plan.
- **Point-in-time recovery (PITR)**: 7-day window. Restore via the DO control
  panel ("Forks & restore") to a new cluster, then point chalk-hosted at the
  new endpoint and restart.
- **Manual snapshot** before risky operations (master-key rotation, schema
  migrations, tenant deprovision):

  ```bash
  PGPASSWORD=... pg_dump \
    "$POSTGRES_URL" \
    --format=custom \
    --file=/var/lib/chalk-hosted/backups/chalk-$(date +%Y%m%dT%H%M%S).dump
  ```

  Copy off-droplet (DO Spaces or S3) immediately; do not rely on droplet disk
  alone.

**Restore drill**: practice on staging quarterly. Document RTO/RPO once we
have real customer load.

---

## 6. Incident response

### 6.1 Caddy is down (no TLS, site unreachable)

```bash
systemctl status caddy
journalctl -u caddy -n 200 --no-pager
```

Common causes:

- **Cloudflare API token expired/revoked** -> DNS-01 wildcard fails. Rotate
  `CF_API_TOKEN`, restart caddy.
- **Caddyfile syntax error after edit** -> `caddy validate --config /etc/caddy/Caddyfile`.
- **Port 80/443 blocked by ufw** -> `ufw status` and re-allow if needed.

Mitigation while debugging: nothing graceful - chalk-hosted is HTTP-only on
loopback, so without Caddy there is no public path. Communicate via status
page.

### 6.2 chalk-hosted panicking / restart loop

```bash
systemctl status chalk-hosted
journalctl -u chalk-hosted -n 500 --no-pager
```

Triage:

1. Capture the panic backtrace and the last successful request from the log.
2. If a recent deploy is the cause, roll back the binary:

   ```bash
   cp /usr/local/bin/chalk-hosted.prev /usr/local/bin/chalk-hosted
   systemctl restart chalk-hosted
   ```

   (We always keep the previous binary as `.prev`.)
3. If it is data-driven (e.g. one tenant's row triggers it), suspend that
   tenant via the offline subcommand:

   ```bash
   sudo -u chalk-hosted /usr/local/bin/chalk-hosted tenant suspend \
       --slug <tenant-slug> --reason "incident-<id>"
   ```
4. File an incident, attach logs, page on-call.

### 6.3 Database unreachable

```bash
psql "$POSTGRES_URL" -c 'select 1'
```

- **DO control panel**: check cluster health, ongoing maintenance, failover
  state.
- **Connection limit exhausted**: chalk-hosted should be using a bounded pool
  (see config). If exhausted, restart chalk-hosted, then investigate leaks.
- **Private network blip**: confirm droplet still has the VPC interface up
  (`ip a`). Open a DO support ticket.

While the DB is down, chalk-hosted will fail health checks and Caddy will
return 502. Post a status-page incident immediately; do not silently retry.

---

## 7. Routine maintenance

- Apply OS security updates monthly: `unattended-upgrades` is enabled by
  default on DO Ubuntu images; verify with `apt list --upgradable`.
- Rebuild Caddy quarterly to pick up upstream patches:
  `CADDY_VERSION=v2.x.y bash bootstrap.sh` (re-runnable; only the build step
  executes if version differs).
- Audit `/etc/chalk-hosted/secrets.env` permissions monthly: must be
  `0640 root:chalk-hosted`.
- Review `journalctl -u chalk-hosted -p warning --since "7 days ago"` weekly
  and triage anything unfamiliar.

---

## 8. Cookie scoping audit

Audited 2026-05-08 against `crates/console/` and `crates/idp/`. Result: **no
parent-domain cookie leakage**. All `Set-Cookie` headers in the OSS code paths
omit the `Domain` attribute, which means browsers scope each cookie to the
exact host that issued it (e.g. `alpha.<apex>` cookies are not visible to
`bravo.<apex>` or `<apex>`). This is the correct posture for the wildcard
`*.<apex>` deployment.

Cookies inventoried:

| Cookie | Issuer | Flags | Notes |
|---|---|---|---|
| `chalk_session` | `crates/console/src/auth.rs` | `Path=/; HttpOnly; SameSite=Strict; Secure (https); Max-Age=…` | No `Domain`. `Secure` set when `chalk.public_url` starts with `https://`. |
| `chalk_session` (clear) | `crates/console/src/auth.rs` | `Path=/; HttpOnly; SameSite=Strict; Secure (https); Max-Age=0` | No `Domain`. |
| `chalk_csrf` | `crates/console/src/csrf.rs` | `Path=/; SameSite=Strict; Secure (https); Max-Age=86400` | No `Domain`. Intentionally not `HttpOnly` (double-submit pattern). |
| `chalk_portal` | `crates/idp/src/routes.rs` | `Path=/; HttpOnly; SameSite=Lax; Secure (https); Max-Age=28800` | No `Domain`. `SameSite=Lax` is correct for an SSO flow that completes after a cross-site redirect. |
| `chalk_portal` (clear) | `crates/idp/src/portal.rs` | `Path=/; HttpOnly; SameSite=Lax; Secure (https); Max-Age=0` | No `Domain`. |

The `Secure` flag is now set automatically when `chalk.public_url` begins with
`https://` (controlled by `ChalkSection::cookies_secure()` in
`crates/core/src/config.rs`). Hosted deployments behind Caddy have HTTPS
public URLs and therefore receive `Secure` cookies; OSS self-hosters running
plain HTTP on a LAN keep working without it (forcing `Secure` on plain HTTP
would cause browsers to drop the cookie entirely).

---

## 9. Logging hygiene audit

Audited 2026-05-08 across `crates/`. Searched for `tracing::{info,debug,warn,
error}!`, `info!`, `debug!`, `warn!`, `error!`, `println!`, and `eprintln!`,
filtered for occurrences whose context mentions tokens, secrets, passwords,
bearer/authorization, SAML assertions, OIDC ID tokens, or DB DSNs.

Findings:

- **Server-side logs (chalk-core / chalk-idp / chalk-console / chalk-hosted):
  clean.** No bearer tokens, access tokens, SAML assertion bodies, OIDC ID
  tokens, reset/verification tokens, password fields, or DSN strings are
  emitted. The single sensitive-looking match —
  `crates/core/src/connectors/oneroster_client.rs:63` — logs only the
  `token_url` (the OAuth endpoint), not the credential. Acceptable.
- **CLI tooling intentionally prints secrets to the operator's terminal:**
  - `crates/cli/src/commands/init.rs:124` — prints the generated default
    admin password once during `chalk init`. Intended; documented in the
    "Next steps" output that follows. Operator is expected to capture and
    rotate.
  - `crates/cli/src/commands/ad_sync.rs:102-108` — emits a CSV of
    `(sourced_id, sam_account_name, password)` only when the operator passes
    `--export-passwords`. Intentional admin export; should be redirected to
    a file with restrictive perms.
  - `crates/cli/src/commands/passwords.rs` — prints the password generation
    pattern (not the passwords themselves) and counts. Acceptable.

No follow-up tasks filed: the OSS code paths do not leak secrets to journald.

---

## 10. Deferred features (not yet implemented)

These features are referenced elsewhere in this runbook or in product docs
but are **not yet shipped** in the `chalk-hosted` binary. Treat with manual
workarounds until they land:

_(none currently)_
