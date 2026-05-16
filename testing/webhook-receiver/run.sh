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

# Confirm the receiver actually verified the wire-format probe.
sleep 0.3
if ! docker compose logs receiver 2>&1 | grep -q "verified  event_id"; then
    echo
    echo "FAIL — receiver did not log a verified delivery for the wire-format probe"
    echo
    echo "receiver logs:"
    docker compose logs receiver | tail -20
    exit 1
fi
echo "  ✓ wire-format probe verified"

echo
echo "==> phase 2: end-to-end via real chalk sync (CSV connector → webhook)"
ROOT=$(cd "$HERE/../.." && pwd)
( cd "$ROOT" && cargo build -p chalk-cli --release --quiet )
CHALK="$ROOT/target/release/chalk"
WORK=$(mktemp -d)
phase_two_cleanup() { rm -rf "$WORK"; }
trap 'phase_two_cleanup; cleanup' EXIT INT TERM

cat > "$WORK/chalk.toml" <<EOF
[chalk]
instance_name = "webhook-e2e-test"
data_dir = "$WORK"

[chalk.database]
driver = "sqlite"
path = "$WORK/chalk.db"

[chalk.telemetry]
enabled = false

[sis]
enabled = true
provider = "oneroster_csv"
csv_dir = "$HERE/../oneroster-csv/data"
client_id = "unused"
client_secret = "unused"

[idp]
enabled = false

[[webhooks]]
name = "test-receiver"
url = "http://host.docker.internal:9911/webhook"
secret = "${CHALK_WEBHOOK_SECRET:-test-secret-do-not-ship}"
security = "sign_only"
mode = "batched"
enabled = true
EOF

# host.docker.internal in chalk → host port 9911. We're running chalk
# OUTSIDE docker but the receiver is INSIDE; address the receiver via
# localhost from chalk's perspective.
sed -i '' 's#http://host.docker.internal:9911#http://localhost:9911#' "$WORK/chalk.toml"

# Reset receiver verification counter so we only count the new delivery.
docker compose restart receiver >/dev/null
sleep 1

set +e
SYNC=$("$CHALK" --config "$WORK/chalk.toml" sync 2>&1)
SYNC_RC=$?
set -e
echo "$SYNC" | tail -15
if [ "$SYNC_RC" -ne 0 ]; then
    echo
    echo "FAIL — chalk sync exited $SYNC_RC"
    exit 1
fi

# Give the async webhook delivery a beat to land.
sleep 1
if docker compose logs receiver 2>&1 | grep -q "✓ verified.*event_id"; then
    echo
    echo "PASS — chalk sync delivered a signed webhook end-to-end"
    exit 0
else
    echo
    echo "FAIL — chalk sync did not deliver a signed webhook"
    echo
    echo "receiver logs:"
    docker compose logs receiver | tail -30
    exit 1
fi
