"""Tiny webhook sink that verifies chalk's X-Chalk-Signature header.

Mirrors the production verification path a vendor would implement.

Flaky-mode (used by run-retry.sh): when FAIL_FIRST_N is set, the first N
signed POSTs return HTTP 500 (with an `X-Receiver-Attempt: <i>/<N>`
header). Subsequent POSTs return 200 as usual. This proves chalk's
WebhookDeliveryEngine retry/backoff machinery hands off the same event
multiple times until success.
"""

import hmac
import hashlib
import http.server
import os
import sys
import threading

SECRET = os.environ.get("CHALK_WEBHOOK_SECRET", "test-secret-do-not-ship")
PORT = int(os.environ.get("PORT", "9911"))
# 0 (the default) disables flaky mode.
FAIL_FIRST_N = int(os.environ.get("FAIL_FIRST_N", "0"))

# Shared, thread-safe attempt counter. http.server spawns a thread per
# request via its default ThreadingHTTPServer.
_attempt_lock = threading.Lock()
_attempt_counter = 0


def _next_attempt() -> int:
    global _attempt_counter
    with _attempt_lock:
        _attempt_counter += 1
        return _attempt_counter


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 — http.server convention
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)

        sig_header = self.headers.get("X-Chalk-Signature", "")
        event_id = self.headers.get("X-Chalk-Event-Id", "")
        webhook_id = self.headers.get("X-Chalk-Webhook-Id", "")

        # Header format: "sha256=<hex>".
        prefix = "sha256="
        if not sig_header.startswith(prefix):
            self._reject("malformed X-Chalk-Signature header")
            return
        provided = sig_header[len(prefix):]

        expected = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(provided, expected):
            print(
                f"  ✗ signature mismatch  expected={expected[:12]}…  got={provided[:12]}…",
                flush=True,
            )
            self._reject("invalid signature")
            return

        attempt = _next_attempt()
        if FAIL_FIRST_N > 0 and attempt <= FAIL_FIRST_N:
            print(
                f"  ✗ flaky-mode fail  event_id={event_id}  webhook_id={webhook_id}  "
                f"attempt={attempt}/{FAIL_FIRST_N}",
                flush=True,
            )
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Receiver-Attempt", f"{attempt}/{FAIL_FIRST_N}")
            self.end_headers()
            self.wfile.write(b'{"error":"flaky-mode injected failure"}')
            return

        print(
            f"  ✓ verified  event_id={event_id}  webhook_id={webhook_id}  "
            f"bytes={len(body)}  attempt={attempt}",
            flush=True,
        )
        # Surface the body for human inspection.
        sys.stdout.write("    body: " + body.decode("utf-8", errors="replace") + "\n")
        sys.stdout.flush()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Receiver-Attempt", str(attempt))
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def _reject(self, reason: str) -> None:
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(f'{{"error":"{reason}"}}'.encode())

    def log_message(self, fmt, *args):  # silence the default access log
        return


if __name__ == "__main__":
    mode = "flaky" if FAIL_FIRST_N > 0 else "normal"
    print(
        f"webhook-receiver listening on :{PORT} (secret prefix={SECRET[:4]}…, "
        f"mode={mode}, fail_first_n={FAIL_FIRST_N})",
        flush=True,
    )
    # ThreadingHTTPServer keeps each request handler off the accept loop,
    # which matters here because chalk's retry driver fires several
    # requests in rapid succession.
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
