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

✅ The production sync paths **do** invoke `WebhookDeliveryEngine::deliver_all`:
   - OSS CLI: `crates/cli/src/commands/sync.rs:113-134` fires endpoints
     after a successful `chalk sync`.
   - Admin console: `crates/console/src/lib.rs` `sync_trigger` (called by
     the "Trigger Sync Now" button) runs the connector, persists the
     payload, and fires endpoints on success.

   This `run.sh` exercises the wire-format end of that chain (sender →
   receiver). For a true end-to-end demo, run `chalk sync` with an
   endpoint configured in `chalk.toml` pointed at the receiver in this
   scenario.

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
