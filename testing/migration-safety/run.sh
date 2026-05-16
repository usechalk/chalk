#!/usr/bin/env bash
# migration-safety scenario:
#   1. provision tenant
#   2. populate with CSV sync
#   3. snapshot counts
#   4. migrate-all + parallel GETs → no lockout, no data loss
#   5. concurrent migrate-all invocations → advisory lock serializes
#   6. cleanup

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
MARKETING=$(cd "$ROOT/../chalk-marketing" && pwd)
cd "$MARKETING"

CURL=/usr/bin/curl
SLUG="mig$(date +%s)"
PG_URL="postgres://chalk:chalk@postgres:5432/chalk"

. "$HERE/../_common/precheck.sh"

PASS=true
cleanup() {
    echo
    echo "==> cleanup: deprovisioning test tenant"
    docker compose exec -T chalk-hosted chalk-hosted deprovision \
        --slug "$SLUG" --postgres-url "$PG_URL" --purge-data \
        >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

count_users_in_schema() {
    docker compose exec -T postgres psql -U chalk -d chalk -tA \
        -c "SELECT count(*) FROM tenant_$SLUG.users" 2>/dev/null \
        | tr -d '[:space:]'
}

count_migrations_in_schema() {
    docker compose exec -T postgres psql -U chalk -d chalk -tA \
        -c "SELECT count(*) FROM tenant_$SLUG._meta_schema_migrations" 2>/dev/null \
        | tr -d '[:space:]'
}

distinct_migrations_in_schema() {
    docker compose exec -T postgres psql -U chalk -d chalk -tA \
        -c "SELECT count(DISTINCT version) FROM tenant_$SLUG._meta_schema_migrations" 2>/dev/null \
        | tr -d '[:space:]'
}

assert() {
    local label=$1 expected=$2 actual=$3
    if [ "$expected" = "$actual" ]; then
        echo "    ✓ $label: $actual"
    else
        echo "    ✗ $label: expected=$expected got=$actual"
        PASS=false
    fi
}

echo
echo "==> provisioning tenant $SLUG"
docker compose exec -T chalk-hosted chalk-hosted provision \
    --slug "$SLUG" \
    --admin-email "migration@test.example" \
    --admin-name "Mig Admin" \
    --display-name "Migration Test" \
    --postgres-url "$PG_URL" \
    >/dev/null
docker compose kill -s SIGHUP chalk-hosted >/dev/null 2>&1
sleep 1

# We can't easily run `chalk sync` against the hosted Postgres from the
# host (the connector wants SqliteRepository per the OSS CLI). Instead,
# seed users directly via psql so the tenant has real rows to protect.
echo
echo "==> seeding tenant_$SLUG.users with 5 rows"
docker compose exec -T postgres psql -U chalk -d chalk >/dev/null <<SQL
INSERT INTO tenant_$SLUG.users
  (sourced_id, status, date_last_modified, username, enabled_user,
   given_name, family_name, role)
VALUES
  ('u-1', 'active', NOW(), 'alpha',   true, 'Alpha',   'One',   'student'),
  ('u-2', 'active', NOW(), 'bravo',   true, 'Bravo',   'Two',   'student'),
  ('u-3', 'active', NOW(), 'charlie', true, 'Charlie', 'Three', 'teacher'),
  ('u-4', 'active', NOW(), 'delta',   true, 'Delta',   'Four',  'teacher'),
  ('u-5', 'active', NOW(), 'echo',    true, 'Echo',    'Five',  'student')
ON CONFLICT (sourced_id) DO NOTHING;
SQL
echo "    seeded $(count_users_in_schema) users"

BEFORE_USERS=$(count_users_in_schema)
BEFORE_MIGRATIONS=$(count_migrations_in_schema)

echo
echo "==> running migrate-all + parallel /health GETs to verify no lockout"
# Start a background flood of GETs against the tenant's health endpoint.
# A migration that takes a global lock or an exclusive table lock on a
# critical path would cause some of these to time out / 500.
(
    for _ in $(seq 1 30); do
        $CURL -s -o /dev/null -w "%{http_code}\n" \
            --max-time 5 \
            "http://$SLUG.localhost:8080/health"
    done
) > /tmp/migration-safety-codes.txt &
FLOOD_PID=$!

docker compose exec -T chalk-hosted chalk-hosted migrate-all \
    --postgres-url "$PG_URL" 2>&1 | tail -3 | sed 's/^/    /'

wait $FLOOD_PID
NON_200=$(grep -cv "^200$" /tmp/migration-safety-codes.txt || true)
TOTAL=$(wc -l </tmp/migration-safety-codes.txt | tr -d ' ')
assert "all parallel GETs returned 200 (no lockout)" "0" "$NON_200"
echo "    (saw $TOTAL responses total)"

AFTER_USERS=$(count_users_in_schema)
AFTER_MIGRATIONS=$(count_migrations_in_schema)
assert "user count preserved across migrate-all" "$BEFORE_USERS" "$AFTER_USERS"
assert "migrations row count unchanged (no duplicate rows)" "$BEFORE_MIGRATIONS" "$AFTER_MIGRATIONS"

echo
echo "==> running two migrate-all invocations concurrently to exercise advisory lock"
(
    docker compose exec -T chalk-hosted chalk-hosted migrate-all \
        --postgres-url "$PG_URL" >/tmp/migration-safety-concurrent-1.log 2>&1
) &
PID1=$!
(
    docker compose exec -T chalk-hosted chalk-hosted migrate-all \
        --postgres-url "$PG_URL" >/tmp/migration-safety-concurrent-2.log 2>&1
) &
PID2=$!
wait $PID1; RC1=$?
wait $PID2; RC2=$?
assert "concurrent migrate-all #1 exited 0" "0" "$RC1"
assert "concurrent migrate-all #2 exited 0" "0" "$RC2"

DISTINCT_VERSIONS=$(distinct_migrations_in_schema)
TOTAL_ROWS=$(count_migrations_in_schema)
assert "no duplicate migration rows (distinct == total)" "$DISTINCT_VERSIONS" "$TOTAL_ROWS"

echo
if [ "$PASS" = true ]; then
    echo "PASS — migrate-all is safe on populated tenant + serializes concurrent runs"
    exit 0
else
    echo "FAIL"
    exit 1
fi
