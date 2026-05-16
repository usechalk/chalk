#!/usr/bin/env bash
# webhook-receiver retry-machinery scenario:
#   1. up the Python sink on :9911 in flaky mode (FAIL_FIRST_N=3 → first 3
#      POSTs return 500, then it returns 200).
#   2. run `chalk sync` against the CSV bundle; the first delivery should
#      land in webhook_deliveries with status='retrying'.
#   3. drive `chalk webhook retry-pending` repeatedly with a shortened
#      backoff (CHALK_WEBHOOK_BACKOFF_SECS=1,1,1) until the receiver flips
#      to 200 and the row turns 'delivered'.
#   4. assert: ≥3 attempts in webhook_deliveries, final status delivered,
#      receiver logs show 3 "flaky-mode fail" entries.
#   5. tear down (always — even on failure or interrupt).

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

cleanup() {
    echo
    echo "tearing down receiver…"
    docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    if [ -n "${WORK:-}" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT INT TERM

# --- bring up receiver in flaky mode --------------------------------------
echo "==> bringing up receiver in flaky mode (FAIL_FIRST_N=3)"
FAIL_FIRST_N=3 docker compose up -d --force-recreate >/dev/null

for i in 1 2 3 4 5 6 7 8 9 10; do
    if /usr/bin/curl -fsS -o /dev/null --connect-timeout 1 -X POST \
        -H 'Content-Type: application/json' \
        -d '{}' \
        http://localhost:9911/health 2>/dev/null; then
        break
    fi
    sleep 0.5
done

# --- build chalk + config -------------------------------------------------
echo "==> building chalk binary"
ROOT=$(cd "$HERE/../.." && pwd)
( cd "$ROOT" && cargo build -p chalk-cli --release --quiet )
CHALK="$ROOT/target/release/chalk"
WORK=$(mktemp -d)

cat > "$WORK/chalk.toml" <<EOF
[chalk]
instance_name = "webhook-retry-e2e-test"
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
name = "test-retry-receiver"
url = "http://localhost:9911/webhook"
secret = "${CHALK_WEBHOOK_SECRET:-test-secret-do-not-ship}"
security = "sign_only"
mode = "batched"
enabled = true
EOF

# Use a 1s/1s/1s backoff so the e2e check completes in seconds, not hours.
export CHALK_WEBHOOK_BACKOFF_SECS=1,1,1

# --- phase 1: initial sync should leave the delivery in 'retrying' --------
echo "==> phase 1: chalk sync (first delivery expected to 500)"
set +e
SYNC=$("$CHALK" --config "$WORK/chalk.toml" sync 2>&1)
SYNC_RC=$?
set -e
echo "$SYNC" | tail -10
if [ "$SYNC_RC" -ne 0 ]; then
    echo
    echo "FAIL — chalk sync exited $SYNC_RC"
    exit 1
fi

sleep 1
INITIAL=$(sqlite3 "$WORK/chalk.db" "SELECT status, http_status, attempt_count FROM webhook_deliveries ORDER BY id;")
echo "  initial deliveries: $INITIAL"
if ! echo "$INITIAL" | grep -q "^retrying|500|1$"; then
    echo
    echo "FAIL — expected first delivery to be retrying|500|1, got: $INITIAL"
    docker compose logs receiver | tail -20
    exit 1
fi
echo "  ✓ first attempt 500'd and was queued for retry"

# --- phase 2: drive retries until success ---------------------------------
echo "==> phase 2: draining the retry queue"
for tick in 1 2 3 4 5 6; do
    sleep 1.2
    "$CHALK" --config "$WORK/chalk.toml" webhook retry-pending --iterations 1 --interval-secs 1 \
        2>&1 | tail -3
    STATUS=$(sqlite3 "$WORK/chalk.db" "SELECT status FROM webhook_deliveries ORDER BY id LIMIT 1;")
    ATTEMPTS=$(sqlite3 "$WORK/chalk.db" "SELECT attempt_count FROM webhook_deliveries ORDER BY id LIMIT 1;")
    echo "  tick $tick: status=$STATUS attempts=$ATTEMPTS"
    if [ "$STATUS" = "delivered" ]; then
        break
    fi
done

# --- assertions -----------------------------------------------------------
FINAL=$(sqlite3 "$WORK/chalk.db" "SELECT status, http_status, attempt_count FROM webhook_deliveries ORDER BY id;")
echo
echo "==> final deliveries:"
echo "$FINAL"

FINAL_STATUS=$(sqlite3 "$WORK/chalk.db" "SELECT status FROM webhook_deliveries ORDER BY id LIMIT 1;")
FINAL_ATTEMPTS=$(sqlite3 "$WORK/chalk.db" "SELECT attempt_count FROM webhook_deliveries ORDER BY id LIMIT 1;")
RECEIVER_FAILS=$(docker compose logs receiver 2>&1 | grep -c "flaky-mode fail" || true)
RECEIVER_OKS=$(docker compose logs receiver 2>&1 | grep -c "✓ verified" || true)

echo
echo "==> receiver attempts: fails=$RECEIVER_FAILS oks=$RECEIVER_OKS"

OK=1
if [ "$FINAL_STATUS" != "delivered" ]; then
    echo "FAIL — final status is '$FINAL_STATUS', expected 'delivered'"
    OK=0
fi
if [ "$FINAL_ATTEMPTS" -lt 3 ]; then
    echo "FAIL — attempt_count=$FINAL_ATTEMPTS, expected ≥3 (3 failures + 1 success)"
    OK=0
fi
if [ "$RECEIVER_FAILS" -lt 3 ]; then
    echo "FAIL — receiver logged $RECEIVER_FAILS flaky-mode failures, expected ≥3"
    OK=0
fi
if [ "$RECEIVER_OKS" -lt 1 ]; then
    echo "FAIL — receiver never reached the 200 path"
    OK=0
fi

if [ "$OK" -eq 1 ]; then
    echo
    echo "PASS — chalk webhook retry/backoff machinery survived 3 receiver 500s and delivered"
    exit 0
else
    echo
    echo "receiver logs (last 40 lines):"
    docker compose logs receiver | tail -40
    exit 1
fi
