# Webhook receiver scenario

End-to-end exercise of the chalk webhook delivery contract: HMAC-SHA256
signing with `X-Chalk-Signature: sha256=<hex>`, plus the standard
`X-Chalk-Event-Id` / `X-Chalk-Webhook-Id` / `X-Chalk-Timestamp` headers.

## What this proves

✅ A vendor receiver implementing the documented HMAC verification works
   against a payload generated with the same secret + algorithm chalk uses.

✅ The signing scheme in `crates/core/src/webhooks/delivery.rs:65`
   (`sign_payload(&secret, &body) → hex(HMAC-SHA256(secret, body))`) is
   reproducible from outside the binary.

## What this does NOT prove

⚠️ That a sync triggered from `/sync/trigger` actually fires a webhook.
   **As of 2026-05-15 the engine has no production caller.** The
   `WebhookDeliveryEngine::deliver_all` function is unit-tested in
   `crates/core/src/webhooks/delivery.rs:630+` but no sync, identity, or
   admin handler invokes it. The webhook admin UI under `/webhooks` lets
   you store endpoints; nothing currently reads them at runtime.

   **Follow-up:** wire `deliver_all` into the sync completion path (the
   right place is probably the end of `sync_engine.run()` — fire an event
   for `sync.completed` with run metadata, then drain
   `webhook_endpoints` matching that event scope).

## Run

```bash
./run.sh
```

Brings up the Python receiver on `localhost:9911`, posts a chalk-shaped
event to it from the bundled sender (uses the same HMAC scheme), prints
PASS/FAIL, and tears the container down on exit (including on error or
Ctrl+C).

## Layout

```
webhook-receiver/
├── README.md
├── docker-compose.yml      # python:3.12-alpine receiver bound to :9911
├── receiver.py             # serves POST /webhook, verifies signature
├── sender.py               # mimics chalk: builds payload, signs, POSTs
└── run.sh                  # up → send → assert → down
```
