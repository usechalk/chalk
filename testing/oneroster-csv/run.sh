#!/usr/bin/env bash
# oneroster-csv scenario:
#   1. build the chalk CLI (cached after first run)
#   2. run `chalk import --dry-run` against the synthetic data/ bundle
#   3. assert the parsed counts match what's in the CSV files
#   4. real import into a temp SQLite DB
#   5. `chalk status` confirms the synced user count
#   6. clean up temp files (the SQLite DB + chalk.toml)

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
enabled = false
provider = "powerschool"
base_url = "https://unused.example"
client_id = "unused"
client_secret = "unused"

[idp]
enabled = false
EOF

echo
echo "==> chalk import --dry-run"
set +e
DRY=$("$CHALK" --config "$WORK/chalk.toml" import --dir "$HERE/data" --dry-run 2>&1)
DRY_RC=$?
set -e
echo "$DRY"
if [ "$DRY_RC" -ne 0 ]; then
    echo
    echo "FAIL — chalk import dry-run exited $DRY_RC"
    exit 1
fi

# Expected counts from data/*.csv (sans header rows):
EXPECTED_USERS=5
EXPECTED_ORGS=1
EXPECTED_ENROLL=5
EXPECTED_CLASSES=2

assert_count() {
    local label="$1" expected="$2"
    local got
    got=$(echo "$DRY" | grep -E "^\s+${label}:" | head -1 | awk '{print $NF}')
    if [ "$got" = "$expected" ]; then
        echo "  ✓ $label = $expected"
    else
        echo "  ✗ $label expected=$expected got=$got"
        return 1
    fi
}

echo
echo "==> asserting parsed counts"
assert_count "Users" "$EXPECTED_USERS"
assert_count "Orgs" "$EXPECTED_ORGS"
assert_count "Classes" "$EXPECTED_CLASSES"
assert_count "Enrollments" "$EXPECTED_ENROLL"

echo
echo "==> chalk import (real, into $WORK/chalk.db)"
"$CHALK" --config "$WORK/chalk.toml" import --dir "$HERE/data" >/dev/null

echo "==> chalk status (confirm DB has the synced rows)"
STATUS=$("$CHALK" --config "$WORK/chalk.toml" status 2>&1)
echo "$STATUS"

# Status output formatting varies; just make sure the user count we expect
# is somewhere in the output.
if echo "$STATUS" | grep -qE "(\b${EXPECTED_USERS}\b)"; then
    echo
    echo "PASS — CSV parser + import + status round-trip works ($EXPECTED_USERS users in DB)"
else
    echo
    echo "FAIL — chalk status did not show expected user count $EXPECTED_USERS"
    exit 1
fi
