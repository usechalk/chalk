# Tenant lifecycle scenario

End-to-end exercise of the `chalk-hosted tenant suspend`,
`chalk-hosted tenant unsuspend`, and `chalk-hosted deprovision --purge-data`
commands.

## What this proves

✅ A freshly-provisioned tenant accepts requests on its subdomain.
✅ `tenant suspend` flips the `_meta.tenants.status` row to `suspended`
   and the StateCache evicts the cached `TenantContext` so the next
   request rebuilds against the new status.
✅ Suspended tenants stop serving — requests against
   `<slug>.localhost:8080/health` return 404 (the resolver treats
   non-active tenants as unknown).
✅ `tenant unsuspend` restores the tenant; the next request goes through.
✅ `deprovision --purge-data` removes the registry row AND drops the
   per-tenant schema. Subsequent requests on the subdomain 404, and the
   `tenant_<slug>` schema is gone from Postgres.

## What this does NOT prove

⚠️ Hot-eviction during an in-flight request. We invalidate the cache,
   but an existing request in flight when suspend lands continues to
   serve. That's by design (no surprise terminations) but means
   "suspend = drop traffic immediately" is not literally true.

⚠️ Recovery from a partial deprovision. If `deprovision --purge-data`
   crashes between dropping the schema and removing the registry row,
   we'd have a "ghost" registry row pointing at nothing. Not tested.

## How invalidation reaches the running process

The first version of this scenario surfaced a real security gap: the
CLI updated `_meta.tenants` but didn't signal running `chalk-hosted`
processes, so a suspended tenant could keep serving requests for up to
~10 min from the LRU.

Fixed by adding a Postgres `LISTEN`/`NOTIFY` channel
(`chalk_tenant_invalidate`):

- `tenant suspend / unsuspend / deprovision` fires
  `NOTIFY chalk_tenant_invalidate, '<slug>'` after each successful DB
  write (see `crates/hosted/src/notify.rs`).
- Every running `chalk-hosted serve` process holds a `PgListener` on
  that channel (`spawn_listener` in `serve.rs`) and calls
  `StateCache::invalidate(slug)` on receipt — surgical per-slug
  eviction, no global cache flush.
- The existing `SIGHUP → StateCache::clear` path stays as a coarse
  escape hatch (covers dropped notify connections + bulk operations).

This scenario verifies the notify path works in practice; the
sub-second sleep between command + assertion is for the notify
round-trip and is the only timing dependency.

## Prerequisites

- chalk-marketing docker stack running (run `../_common/precheck.sh`).
- `python3` and `/usr/bin/curl` on PATH.

## Run

```bash
./run.sh
```

The script:
1. Provisions a test tenant via `chalk-hosted provision` (no signup
   rate-limit issues since this is the operator path).
2. Confirms `http://<slug>.localhost:8080/health` returns 200.
3. Runs `chalk-hosted tenant suspend --slug <slug>`.
4. Confirms `<slug>.localhost:8080/health` now 404s.
5. Confirms the Postgres `_meta.tenants` row shows `status = suspended`.
6. Runs `chalk-hosted tenant unsuspend --slug <slug>`.
7. Confirms `<slug>.localhost:8080/health` is back to 200.
8. Confirms the row shows `status = active`.
9. Runs `chalk-hosted deprovision --slug <slug> --purge-data`.
10. Confirms the subdomain 404s.
11. Confirms the `_meta.tenants` row is gone.
12. Confirms the `tenant_<slug>` schema is dropped from Postgres.

Single PASS/FAIL banner at the end, container state untouched.

## Layout

```
tenant-lifecycle/
├── README.md
└── run.sh
```
