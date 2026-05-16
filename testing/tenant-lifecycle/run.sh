#!/usr/bin/env bash
# tenant-lifecycle scenario:
#   1. provision tenant via chalk-hosted CLI
#   2. confirm subdomain serves
#   3. suspend → confirm 404 + status=suspended in DB
#   4. unsuspend → confirm 200 + status=active
#   5. deprovision --purge-data → confirm 404 + row gone + schema dropped

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MARKETING=$(cd "$HERE/../../../chalk-marketing" && pwd)
cd "$MARKETING"

CURL=/usr/bin/curl
SLUG="lc$(date +%s)"
PG_URL="postgres://chalk:chalk@postgres:5432/chalk"

. "$HERE/../_common/precheck.sh"

PASS=true
cleanup() {
    echo
    echo "==> cleanup: ensuring test tenant is gone"
    docker compose exec -T chalk-hosted chalk-hosted deprovision \
        --slug "$SLUG" --postgres-url "$PG_URL" --purge-data \
        >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# --- helpers ---------------------------------------------------------------

http_code() {
    $CURL -s -o /dev/null -w "%{http_code}" "$1"
}

tenant_status_in_db() {
    docker compose exec -T postgres psql -U chalk -d chalk -tA \
        -c "SELECT status FROM _meta.tenants WHERE slug = '$SLUG'" 2>/dev/null \
        | tr -d '[:space:]'
}

schema_exists_in_db() {
    docker compose exec -T postgres psql -U chalk -d chalk -tA \
        -c "SELECT 1 FROM information_schema.schemata WHERE schema_name = 'tenant_$SLUG'" \
        2>/dev/null | tr -d '[:space:]'
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

# --- scenario --------------------------------------------------------------

echo
echo "==> provisioning tenant $SLUG"
docker compose exec -T chalk-hosted chalk-hosted provision \
    --slug "$SLUG" \
    --admin-email "lifecycle@test.example" \
    --admin-name "LC Admin" \
    --display-name "Lifecycle Test" \
    --postgres-url "$PG_URL" \
    >/dev/null 2>&1
sleep 1
assert "active tenant serves health" 200 "$(http_code http://$SLUG.localhost:8080/health)"
assert "status row in DB" "active" "$(tenant_status_in_db)"
assert "schema exists in DB" "1" "$(schema_exists_in_db)"

# The `tenant suspend/unsuspend/deprovision` CLI updates the registry but
# does NOT invalidate the running chalk-hosted process's per-tenant LRU
# (`StateCache`). The CLI explicitly tells the operator to restart or
# SIGHUP for immediate effect — we do SIGHUP here, which is cheaper and
# matches `crates/hosted/src/commands/serve.rs`'s `spawn_sighup_listener`.
# (Follow-up: tenant CLI ideally sends SIGHUP automatically. See README.)
sighup_chalk_hosted() {
    docker compose kill -s SIGHUP chalk-hosted >/dev/null 2>&1
    sleep 0.5
}

echo
echo "==> suspending tenant"
docker compose exec -T chalk-hosted chalk-hosted tenant suspend \
    --slug "$SLUG" --postgres-url "$PG_URL" 2>&1 | sed 's/^/    /'
sighup_chalk_hosted
assert "suspended tenant 404s" 404 "$(http_code http://$SLUG.localhost:8080/health)"
assert "status row updated" "suspended" "$(tenant_status_in_db)"
assert "schema preserved across suspend" "1" "$(schema_exists_in_db)"

echo
echo "==> unsuspending tenant"
docker compose exec -T chalk-hosted chalk-hosted tenant unsuspend \
    --slug "$SLUG" --postgres-url "$PG_URL" 2>&1 | sed 's/^/    /'
sighup_chalk_hosted
assert "unsuspended tenant serves again" 200 "$(http_code http://$SLUG.localhost:8080/health)"
assert "status row back to active" "active" "$(tenant_status_in_db)"

echo
echo "==> deprovisioning tenant (--purge-data)"
docker compose exec -T chalk-hosted chalk-hosted deprovision \
    --slug "$SLUG" --postgres-url "$PG_URL" --purge-data 2>&1 | sed 's/^/    /'
sighup_chalk_hosted
assert "deprovisioned tenant 404s" 404 "$(http_code http://$SLUG.localhost:8080/health)"
assert "tenant row gone" "" "$(tenant_status_in_db)"
assert "tenant schema dropped" "" "$(schema_exists_in_db)"

echo
if [ "$PASS" = true ]; then
    echo "PASS — tenant lifecycle: provision → suspend → unsuspend → deprovision verified"
    exit 0
else
    echo "FAIL — one or more assertions above failed"
    exit 1
fi
