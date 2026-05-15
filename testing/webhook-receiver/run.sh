#!/usr/bin/env bash
# webhook-receiver scenario:
#   1. up the Python sink on :9911
#   2. send a chalk-shaped HMAC-signed payload from sender.py
#   3. assert the receiver verified it
#   4. tear down (always — even on failure or interrupt)

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

cleanup() {
    echo
    echo "tearing down receiver…"
    docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "==> bringing up receiver"
docker compose up -d --wait-timeout 10 >/dev/null 2>&1 || docker compose up -d >/dev/null

# Wait for port 9911 to actually accept connections (image healthcheck on a
# non-existent path means the container won't go "healthy" — poll directly).
for i in 1 2 3 4 5 6 7 8 9 10; do
    if /usr/bin/curl -fsS -o /dev/null --connect-timeout 1 -X POST \
        -H 'Content-Type: application/json' \
        -d '{}' \
        http://localhost:9911/health 2>/dev/null; then
        break
    fi
    sleep 0.5
done

echo "==> sending signed event"
LOG=$(mktemp)
if ! python3 sender.py 2>&1 | tee "$LOG"; then
    echo
    echo "FAIL — sender exited non-zero"
    echo
    echo "receiver logs:"
    docker compose logs receiver | tail -20
    exit 1
fi

# Confirm the receiver actually verified by inspecting its stdout.
sleep 0.3
if docker compose logs receiver 2>&1 | grep -q "✓ verified"; then
    echo
    echo "PASS — receiver verified the HMAC signature"
    exit 0
else
    echo
    echo "FAIL — receiver did not log a verified delivery"
    echo
    echo "receiver logs:"
    docker compose logs receiver | tail -20
    exit 1
fi
