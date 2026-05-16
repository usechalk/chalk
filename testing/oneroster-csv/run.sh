#!/usr/bin/env bash
# oneroster-csv scenario:
#   1. build the chalk CLI (cached after first run)
#   2. generate a temp config with provider = "oneroster_csv"
#   3. `chalk sync` exercises the new OneRosterCsvConnector end-to-end
#   4. assert the printed counts match the CSV contents
#   5. `chalk status` confirms the synced rows landed in SQLite
#   6. clean up temp files

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
cd "$HERE"

WORK=$(mktemp -d)
cleanup() {
    echo
    echo "tearing down: $WORK"
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

echo "==> building chalk CLI (target/release; cargo cache reused after first run)"
( cd "$ROOT" && cargo build -p chalk-cli --release --quiet )
CHALK="$ROOT/target/release/chalk"
"$CHALK" --version

echo
echo "==> generating temp config"
cat > "$WORK/chalk.toml" <<EOF
[chalk]
instance_name = "csv-test"
data_dir = "$WORK"

[chalk.database]
driver = "sqlite"
path = "$WORK/chalk.db"

[chalk.telemetry]
enabled = false

[sis]
enabled = true
provider = "oneroster_csv"
csv_dir = "$HERE/data"
client_id = "unused"
client_secret = "unused"

[idp]
enabled = false
EOF

echo
echo "==> chalk sync"
set +e
SYNC=$("$CHALK" --config "$WORK/chalk.toml" sync 2>&1)
SYNC_RC=$?
set -e
echo "$SYNC"
if [ "$SYNC_RC" -ne 0 ]; then
    echo
    echo "FAIL — chalk sync exited $SYNC_RC"
    exit 1
fi

# Expected counts from data/*.csv (header rows excluded):
EXPECTED_USERS=5
EXPECTED_ORGS=1
EXPECTED_ENROLL=5
EXPECTED_CLASSES=2

assert_count() {
    local label="$1" expected="$2"
    local got
    got=$(echo "$SYNC" | grep -E "^\s+${label}:" | head -1 | awk '{print $NF}')
    if [ "$got" = "$expected" ]; then
        echo "  ✓ $label = $expected"
    else
        echo "  ✗ $label expected=$expected got=$got"
        return 1
    fi
}

echo
echo "==> asserting sync counts"
assert_count "Users" "$EXPECTED_USERS"
assert_count "Orgs" "$EXPECTED_ORGS"
assert_count "Classes" "$EXPECTED_CLASSES"
assert_count "Enrollments" "$EXPECTED_ENROLL"

echo
echo "==> chalk status (confirm DB has the rows)"
STATUS=$("$CHALK" --config "$WORK/chalk.toml" status 2>&1)
echo "$STATUS"

# Status output formatting varies by version; assert the user total is present.
if echo "$STATUS" | grep -qE "Total:\s+${EXPECTED_USERS}"; then
    echo
    echo "PASS — chalk sync via OneRosterCsvConnector populated SQLite ($EXPECTED_USERS users)"
else
    echo
    echo "FAIL — chalk status did not show expected user total $EXPECTED_USERS"
    exit 1
fi
