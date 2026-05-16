# Console Security Audit — Snapshot

Light XSS / SQL-injection sweep of `crates/console/` and the SQL surface in
`crates/core/` and `crates/hosted/`. Not a full pentest; this is the
"obvious foot-guns" pass.

## Scope and method

1. **XSS via Askama `|safe` filter**
   - `grep -rn "{{.*|safe" crates/console/templates/`
   - `grep -rn "safe" crates/console/templates/`
2. **XSS regression test**
   - Create an SSO partner with `<script>alert(1)</script>` as its name
     via the live repo + router; assert rendered HTML escapes it.
3. **SQL injection via `format!`-built queries**
   - `grep -rnE "format!\(.*(SELECT|INSERT|UPDATE|DELETE)" crates/`
   - Followed each hit and checked whether interpolated values are
     bound parameters vs. raw user input.

## Findings

### 1. Askama `|safe` usage — none found

No template in `crates/console/templates/**` uses the `|safe` filter.
The only `safe` matches in the tree are the literal English word "safe"
in user-facing copy:

- `templates/settings/api_tokens.html:10` — "save it somewhere safe."
- `templates/sso/detail.html:85` — "store it somewhere safe."

**Result:** every interpolated value is HTML-escaped by Askama's default
escaper. No changes required.

### 2. XSS regression test — added

`crates/console/src/lib.rs::sso_partner_detail_escapes_script_payload_in_name`

The test inserts an SSO partner with `name = "<script>alert(1)</script>"`
through the real repo (`upsert_sso_partner`), then `GET /sso-partners/<id>`
against the live `router`, and asserts:

- The rendered HTML contains `&lt;script&gt;alert(1)&lt;/script&gt;`.
- The rendered HTML does **not** contain raw `<script>alert(1)</script>`.

This is a regression guard: any future template that adds `|safe` to a
user-controlled field on this page will now fail the suite loudly rather
than silently shipping a stored-XSS bug.

### 3. `format!`-built SQL — two hits, both safe

```
crates/core/src/db/postgres.rs:1368   DELETE FROM {table} WHERE class_sourced_id = $1
crates/core/src/db/postgres.rs:1373   INSERT INTO {table} (class_sourced_id, {col}) VALUES ($1, $2)
crates/hosted/src/commands/deprovision.rs:48   DROP SCHEMA IF EXISTS "{schema}" CASCADE
```

For each:

- **`postgres.rs:1368` / `:1373`** — `{table}` and `{col}` come from a
  hard-coded `[(table, col), ...]` array (`class_terms`, `class_grades`,
  `class_subjects`, `class_periods`). No user input reaches the SQL
  string; values are bound with `$1`/`$2`. **Safe by construction.**
- **`deprovision.rs:48`** — `{schema}` is `schema_for_slug(&args.slug)`
  where `args.slug` is gated by `is_valid_slug` (lowercase ASCII letter
  start, `[a-z0-9-]+` tail, length 3–63, not in a reserved list).
  `schema_for_slug` then maps `-` to `_`, producing a strict
  `tenant_[a-z0-9_]+` identifier — wrapped in `"…"` for quoting.
  No user-controllable injection vector. **Safe by validator.**

`schema_for_slug` itself has unit tests (`crates/hosted/src/lib.rs`)
covering both slug validation and the schema-name mapping. The injection
risk reduces to "is `is_valid_slug` correct?" — and that surface is
covered by `slug_validation`.

## What was changed

- Added per-IP token-bucket rate limit on `POST /login`
  (`crates/console/src/auth.rs`): 5 attempts / 60s, `429 Too Many Requests`
  with `Retry-After: 60` on exceed. GET `/login` is unaffected by design
  (form render only).
- Added XSS regression test for the SSO partner detail page.
- Added integration test for the login rate limiter (5 OK, 6th = 429).

## What is intentional

- `chalk_session` is `HttpOnly`, `Strict`, and `Secure` on HTTPS
  deployments (see `login_cookie_includes_secure_on_https` test). On
  plain HTTP installs (OSS self-host on `http://localhost`) the `Secure`
  flag is intentionally omitted so the cookie actually round-trips.
- `/api/oneroster/*` bypasses session auth and is gated by
  `oneroster_bearer_middleware`. This is intentional, documented in
  `PUBLIC_PATHS`, and covered by `is_public_path_returns_true_for_oneroster_prefix`.
- The rate limiter is in-memory and per-process. Hosted runs with
  multiple replicas, so the per-replica budget is best-effort defense in
  depth; the real backstop is the argon2 work factor and (future)
  account-level lockout. Documented inline in `auth.rs`.

## Out of scope (for a future pass)

- CSRF: every form-POST route already requires `x-csrf-token` +
  `chalk_csrf` cookie (see `csrf.rs`); the audit did not re-validate the
  middleware.
- SAML/OIDC IdP signature validation in `crates/idp/` — not touched.
- Tenant isolation in `crates/hosted/` beyond the slug validator.
- DoS via large request bodies (login body is already capped at 16 KiB).
- Per-account lockout (separate from per-IP rate limit).
