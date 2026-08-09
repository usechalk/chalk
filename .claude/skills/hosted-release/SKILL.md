---
name: hosted-release
description: Ship and prod-verify the hosted (multi-tenant) build — pins, tenant wrappers, deploy, plan-flip verification
---

# Hosted release + prod verification

The hosted crate (separate private repo) pins chalk by git tag and deploys
to the droplet automatically on tag push.

## Ship

1. Bump the three pins in `Cargo.toml` (`chalk-core`, `chalk-console`,
   `chalk-idp` → `tag = "vX.Y.Z"`) and the crate `version`.
2. `cargo update -p chalk-core -p chalk-console -p chalk-idp`, build, test.
3. **New repository trait since last pin?** It needs a `TenantScoped*`
   wrapper in `src/tenant_assert.rs` (the `scoped_wrapper!` macro + forward
   every method through `self.check()?`) and a `.with_*` call in
   `src/context.rs`'s console block. This is the hosted twin of the
   serve-wiring rule: the public repo's guard can't see this repo.
4. Commit, push, watch CI **pinned by commit SHA**, tag, push the tag. The
   release workflow builds and SSH-deploys with health-check/rollback.
   Confirm: `ssh root@143.198.104.245 'chalk-hosted --version'`.

## Prod verification (the standing choreography)

- Postgres DB on the droplet is named **`chalk`** (not chalk_hosted).
  Tenants meta: `_meta.tenants (slug, db_schema, plan, status)`.
- Migrations apply per tenant schema on deploy — verify with one query
  across `information_schema` joined from `_meta.tenants`.
- Tenant contexts are LRU-cached with NO TTL: after ANY `_meta.tenants`
  change, `NOTIFY chalk_tenant_invalidate, '<slug>'` on the same DB or the
  change does nothing.
- Plan gating check: flip `test-123` to `full_stack` + NOTIFY, probe the
  gated routes (auth-gated routes 303 to /login; plan-gated 404 on free),
  then **revert + NOTIFY** and confirm the gate closes. Leave the tenant as
  found.
- Functional store check: INSERT/SELECT/DELETE a probe row directly in the
  tenant schema (e.g. `tenant_test_123.permission_sets`) — proves the
  migration works against real Postgres, then clean up.
- Hosted tenants use the **magic-link** login template, not the password
  one; `WIRED_DEVICES` still holds the devices module back regardless of
  plan. A /devices 404 on full_stack is that flag, not a bug.
