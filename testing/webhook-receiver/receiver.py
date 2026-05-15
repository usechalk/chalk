"""Tiny webhook sink that verifies chalk's X-Chalk-Signature header.

Mirrors the production verification path a vendor would implement.
"""

import hmac
import hashlib
import http.server
import os
import sys

SECRET = os.environ.get("CHALK_WEBHOOK_SECRET", "test-secret-do-not-ship")
PORT = int(os.environ.get("PORT", "9911"))


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

        print(
            f"  ✓ verified  event_id={event_id}  webhook_id={webhook_id}  "
            f"bytes={len(body)}",
            flush=True,
        )
        # Surface the body for human inspection.
        sys.stdout.write("    body: " + body.decode("utf-8", errors="replace") + "\n")
        sys.stdout.flush()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
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
    print(f"webhook-receiver listening on :{PORT} (secret prefix={SECRET[:4]}…)", flush=True)
    http.server.HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
