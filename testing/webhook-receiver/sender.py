"""Mimics chalk's WebhookDeliveryEngine.deliver: builds a sample event,
signs the body with HMAC-SHA256, POSTs with the documented headers."""

import datetime
import hashlib
import hmac
import json
import os
import sys
import urllib.request
import uuid

URL = os.environ.get("RECEIVER_URL", "http://localhost:9911/webhook")
SECRET = os.environ.get("CHALK_WEBHOOK_SECRET", "test-secret-do-not-ship")

event = {
    "event_id": str(uuid.uuid4()),
    "event_type": "sync.completed",
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "tenant_slug": "test-tenant",
    "sync_run_id": 42,
    "data": {
        "users_synced": 3,
        "orgs_synced": 1,
        "classes_synced": 2,
    },
}
body = json.dumps(event, separators=(",", ":")).encode()
signature = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()

req = urllib.request.Request(
    URL,
    data=body,
    method="POST",
    headers={
        "Content-Type": "application/json",
        "X-Chalk-Event-Id": event["event_id"],
        "X-Chalk-Webhook-Id": "wh-test-0001",
        "X-Chalk-Timestamp": event["timestamp"],
        "X-Chalk-Security-Mode": "sign_only",
        "X-Chalk-Signature": f"sha256={signature}",
    },
)

try:
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(f"sender: receiver returned {resp.status}", flush=True)
        sys.exit(0 if resp.status == 200 else 1)
except urllib.error.HTTPError as e:
    print(f"sender: receiver returned {e.code} ({e.read().decode()})", flush=True)
    sys.exit(1)
except urllib.error.URLError as e:
    print(f"sender: cannot reach receiver: {e}", flush=True)
    sys.exit(2)
