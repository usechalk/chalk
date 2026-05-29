# Production deployment

How to deploy chalk-hosted in production. This is the "you've decided on
a domain and have credentials" runbook. For local development see
`../../chalk-marketing/docker-compose.yml`; for backup/restore see
`../backup/README.md`.

## Architecture in one diagram

```
       *.chalk.school (wildcard A record)
                 │
                 ▼
            ┌────────┐
            │  Caddy │  TLS termination, HTTP→HTTPS, host-based routing
            └───┬────┘
                │
        ┌───────┴───────────┐
        │                   │
        ▼                   ▼
  apex (chalk.school)   *.chalk.school
  ─→ marketing dist/    ─→ chalk-hosted:9000
                              │
                              ▼
                       postgres (RDS / Cloud SQL / managed)
```

The hosted chalk binary speaks plain HTTP on port 9000. TLS lives in
Caddy. Postgres should be a managed service in production — running
your own database for a multi-tenant SIS platform is a side quest you
don't want.

## Prerequisites

- A real domain (the marketing site reads `PUBLIC_SITE_DOMAIN` from
  `.env`; chalk-hosted reads `CHALK_APEX` from its config).
- A wildcard DNS record `*.<your-domain>` pointing at the host
  running Caddy.
- Managed Postgres 14+ with at least 4 GB RAM, point-in-time recovery
  enabled, and an IAM-controlled secret holding the connection string.
- A 32-byte master encryption key generated with `openssl rand -base64 32`,
  stored in your secrets manager (see `../backup/README.md`).
- A Postmark account (or whatever transactional email provider you
  pick) with DKIM + SPF configured for your domain.
- Optional but recommended: a Cloudflare Turnstile site key + secret
  for signup bot defense.

## Step 1: DNS

Point an `A` record at the host running Caddy:

```
chalk.school.        A    198.51.100.10
*.chalk.school.      A    198.51.100.10
```

Verify with `dig +short demo.chalk.school` — should return your host IP.

## Step 2: Production Caddyfile

Replace the local-only `chalk-marketing/docker/Caddyfile.local` with
something like:

```caddy
# /etc/caddy/Caddyfile

# Apex domain — marketing static site, plus the apex API surface
# (signup, contact, marketplace lead capture). Caddy auto-issues a
# Let's Encrypt cert.
chalk.school {
    encode gzip zstd

    # Apex API endpoints handled by chalk-hosted directly.
    handle /api/signup* {
        reverse_proxy chalk-hosted:9000 {
            header_up Host {host}
        }
    }
    handle /api/contact {
        reverse_proxy chalk-hosted:9000 {
            header_up Host {host}
        }
    }
    handle /api/marketplace/apply {
        reverse_proxy chalk-hosted:9000 {
            header_up Host {host}
        }
    }
    handle /health {
        reverse_proxy chalk-hosted:9000
    }

    # Everything else is the static marketing site.
    handle {
        root * /var/www/chalk-marketing/dist
        try_files {path} {path}/ {path}.html /index.html
        file_server
    }

    # Strong HTTPS posture. HSTS preload requires you to have served
    # this header for 30+ days before submitting to hstspreload.org.
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        # CSP starts strict — relax per-route only as needed.
        Content-Security-Policy "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors 'none'"
    }
}

# Per-tenant subdomains — every request goes to chalk-hosted, which
# resolves the tenant from the Host header.
*.chalk.school {
    encode gzip zstd
    reverse_proxy chalk-hosted:9000 {
        header_up Host {host}
    }
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
    }
}
```

For ACME wildcard certs Caddy needs a DNS provider plugin
(`caddy-dns/cloudflare`, `caddy-dns/route53`, etc.) compiled in.

## Step 3: chalk-hosted config

```toml
# /etc/chalk/hosted.toml

# Required.
postgres_url = "postgres://chalk:<secret>@db.internal:5432/chalk?sslmode=require"
apex         = "chalk.school"

# Required: 32-byte base64 master key. The example value here is a
# placeholder — generate your own and store in your secrets manager.
master_encryption_key = "REPLACE_WITH_OPENSSL_RAND_BASE64_32"

# External URL components — used to build per-tenant URLs (OIDC issuer,
# SAML entity ID, signup verification email links).
public_scheme = "https"
public_port   = 443

# Bind address inside the container or host. Caddy reverse-proxies to
# this; do not expose it directly to the internet.
bind = "0.0.0.0:9000"

# Per-tenant pool sizing. 6 connections × N active tenants is a fair
# starting point; tune based on your Postgres `max_connections`.
[state_cache]
capacity            = 256
pool_max_connections = 6

# Background sync scheduler tick. Keep at 60s unless you have hundreds
# of tenants and want to spread the load.
scheduler_tick_secs   = 60
scheduler_concurrency = 4
```

Pass secret values via env vars rather than committing them:

```sh
# /etc/chalk/hosted.env
MASTER_ENCRYPTION_KEY=<from secrets manager>
POSTGRES_URL=<from secrets manager>
POSTMARK_TOKEN=<for signup verification emails>
TURNSTILE_SECRET=<optional, see signup.rs>
```

## Step 3b: obtain the chalk-hosted binary

The `chalk-hosted` runtime is **not** part of this open-source repo — it lives in
the private `usechalk/chalk-hosted-crate` repo, which depends on this repo's
`chalk-core`/`chalk-console`/`chalk-idp` crates pinned to a release tag. Its CI
builds an `x86_64-unknown-linux-gnu` binary and attaches it to each release, so
the host does not need a Rust toolchain or the source.

Pull the prebuilt binary onto the host (authenticated to the private repo via a
`gh` token or deploy key) and keep the previous one for rollback:

```sh
cp /usr/local/bin/chalk-hosted /usr/local/bin/chalk-hosted.prev 2>/dev/null || true
gh release download -R usechalk/chalk-hosted-crate <tag> \
    -p chalk-hosted -O /usr/local/bin/chalk-hosted
chmod 0755 /usr/local/bin/chalk-hosted
```

(Operators with access can instead build it themselves: `git clone` the private
repo and `cargo build --release --locked`.)

## Step 4: systemd unit (or your runtime of choice)

```ini
# /etc/systemd/system/chalk-hosted.service
[Unit]
Description=chalk-hosted multi-tenant SIS sync runtime
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=chalk
Group=chalk
WorkingDirectory=/var/lib/chalk
EnvironmentFile=/etc/chalk/hosted.env
ExecStart=/usr/local/bin/chalk-hosted serve --config /etc/chalk/hosted.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Tighten the sandbox.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/chalk

[Install]
WantedBy=multi-user.target
```

Then:

```sh
systemctl daemon-reload
systemctl enable --now chalk-hosted
journalctl -u chalk-hosted -f
```

## Step 5: deploy the marketing site

The marketing site is a static Astro build. CI should:

```sh
cd chalk-marketing
pnpm install
PUBLIC_SITE_DOMAIN=chalk.school pnpm build
rsync -a dist/client/ deploy@chalk.school:/var/www/chalk-marketing/dist/
```

Caddy serves it directly from disk — no node process required.

## Step 6: provision the first tenant

```sh
chalk-hosted provision \
    --postgres-url "$POSTGRES_URL" \
    --slug demo \
    --admin-email admin@demo.example \
    --admin-name "Demo Admin" \
    --display-name "Demo District"
```

The command prints a one-time reset token. Email it to the admin (or
hand it over directly the first time you provision your own internal
tenant). The admin visits `https://demo.chalk.school/login?reset_token=...`
to set a password.

## Step 7: post-deploy verification checklist

In order, against the production deployment:

- [ ] `curl -fsS https://chalk.school/health` returns `ok`.
- [ ] `curl -fsS https://chalk.school/` returns the marketing site.
- [ ] `dig +short demo.chalk.school` returns the host IP.
- [ ] `curl -fsS https://demo.chalk.school/health` returns `ok demo`.
- [ ] `curl -s https://demo.chalk.school/idp/saml/metadata | grep -q '<ds:X509Certificate>[^<]\+'`
      (non-empty cert in metadata).
- [ ] Submit the signup form on `https://chalk.school/signup` and
      confirm the verification email lands in your inbox.
- [ ] HSTS header present:
      `curl -sI https://chalk.school | grep -i strict-transport-security`.
- [ ] `chalk-hosted rotate-master-key --new-key <fresh>` on a staging
      copy of the DB succeeds + you can recover. (Don't rotate production
      keys until you've practiced once.)

## Step 8: schedule maintenance jobs

Per `../backup/README.md`:

- Nightly `pg_dump` shipped off-host.
- Quarterly restore drill on a throwaway environment.

Per `../../testing/key-rotation/README.md`:

- Master key rotation cadence is up to you. Annual is a reasonable
  default unless your threat model says faster.

## Known operational gaps

The following exist as documented gaps; see the parent `testing/`
scenarios for the current state:

- **Live SIS sync** (`testing/sis-live/`) — every district connector
  needs real OAuth credentials.
- **Google Workspace sync** (`testing/google-workspace/`) — needs a
  Workspace tenant + service-account JSON.
- **Marketplace** — backend is currently a stub. The marketing site
  collects lead-capture forms; vendor onboarding is manual until the
  marketplace product ships.
