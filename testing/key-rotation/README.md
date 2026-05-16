# Master key rotation scenario

End-to-end exercise of `chalk-hosted rotate-master-key` against a live
docker stack with multiple active tenants.

## What this proves

✅ `rotate-master-key` re-wraps every tenant's sealed SAML keypair and
   OIDC signing key in a single transaction.

✅ After rotating + restarting `chalk-hosted` with the new master key,
   every tenant still:
   - Serves valid SAML metadata (cert unchanged, signed by the same
     keypair — just re-wrapped at rest).
   - Returns a valid OIDC JWKS document.
   - Accepts admin login (session creation still works).

✅ The rotation is idempotent: running it a second time with the same
   "new key" reports rows as already-rotated and changes nothing.

## What this does NOT prove

⚠️ Hot-reload of the master key in the running process. The current
   architecture requires a `chalk-hosted` restart after rotation — the
   in-process `MasterKey` is fixed at startup. Rotation is therefore an
   operator-driven maintenance-window task. If you need zero-downtime
   rotation, that's a feature gap to track separately.

⚠️ Recovery from a partial-rotation failure. The code path
   (`rotate_master_key.rs::rotate_all`) wraps the entire rotation in a
   single Postgres transaction with row-level FOR UPDATE locks, so a
   crash mid-rotation rolls back cleanly — but we don't simulate a
   crash here.

## Prerequisites

- chalk-marketing docker stack running (run `../_common/precheck.sh`).
- `python3` and `/usr/bin/curl` on PATH.

## Run

```bash
./run.sh
```

The script:
1. Reads the current `MASTER_ENCRYPTION_KEY` from `chalk-marketing/.env`.
2. Provisions two test tenants via the apex `/api/signup` flow.
3. Activates both via the dev verification URL (logged to stdout) and
   sets admin passwords.
4. Captures each tenant's SAML metadata + OIDC JWKS as a "before" snapshot.
5. Runs `chalk-hosted rotate-master-key` inside the chalk-hosted
   container, generating a fresh key (`--new-key` omitted on purpose).
6. Captures the new key from stdout, writes it back to `.env`, restarts
   the chalk-hosted container.
7. Captures each tenant's SAML metadata + OIDC JWKS as an "after"
   snapshot. Asserts they match the "before" (same certs, same JWKS keys
   — only the at-rest envelope changes).
8. Re-logs in to each tenant. Asserts 200.
9. Runs the rotation a second time. Asserts both tenants report
   "already on new key, skipped" — proves idempotency.
10. Restores the original `.env`, restarts `chalk-hosted` so the
    docker stack returns to its baseline state, deprovisions the test
    tenants (purge-data).

The script cleans up on any exit path via `trap`.

## Layout

```
key-rotation/
├── README.md
└── run.sh
```
