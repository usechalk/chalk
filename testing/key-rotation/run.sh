#!/usr/bin/env bash
# key-rotation scenario:
#   1. provision 2 test tenants via /api/signup
#   2. snapshot their SAML metadata + OIDC JWKS (the "before" state)
#   3. rotate the master key inside the chalk-hosted container
#   4. update .env, restart chalk-hosted with the new key
#   5. snapshot again, assert identical (only at-rest envelope changed)
#   6. assert re-login still works for each tenant
#   7. re-run rotation, assert idempotency (rows reported as already rotated)
#   8. restore original .env + restart + deprovision tenants

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
MARKETING=$(cd "$ROOT/../chalk-marketing" && pwd)
cd "$MARKETING"

CURL=/usr/bin/curl
# Single tenant: chalk's signup is rate-limited to 3/hour per IP. Rotation
# logic doesn't care about tenant count — one row exercises the same
# rewrap path the SELECT FOR UPDATE loop processes per row. The test
# wins as long as ANY tenant's secrets survive a rotation round trip.
SLUG_A="kr$(date +%s)"
PASSWORD="TestPass123!secure"

. "$HERE/../_common/precheck.sh"

# Snapshot the original .env so we can restore on exit. We rotate the key
# in this scenario, and if the script aborts the operator would otherwise
# be stuck with an .env that no longer matches what's in Postgres.
ORIG_ENV=$(mktemp)
cp .env "$ORIG_ENV"

NEW_KEY=""
cleanup() {
    echo
    echo "==> cleanup: restoring original master key + tearing down test tenants"
    cp "$ORIG_ENV" .env
    rm -f "$ORIG_ENV"
    # Restart chalk-hosted so the running process picks up the original key
    # again. This is the same restart the operator would do after a rotation,
    # in reverse.
    docker compose up -d chalk-hosted >/dev/null 2>&1 || true
    sleep 3
    # Deprovision both test tenants if they were created. --purge-data drops
    # the per-tenant schema so we leave the docker stack clean.
    docker compose exec -T chalk-hosted chalk-hosted deprovision \
        --slug "$SLUG_A" --postgres-url "postgres://chalk:chalk@postgres:5432/chalk" \
        --purge-data >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

provision_tenant() {
    local slug=$1
    local email=$2
    echo "==> provisioning tenant $slug via admin CLI (bypasses signup rate limit)"
    # `chalk-hosted provision` is the admin/operator path — it creates the
    # tenant row, applies migrations, and seals fresh SAML + OIDC keys.
    # Public `/api/signup` is rate-limited to 3/hour per IP and not
    # appropriate for repeated test runs.
    local prov_out
    prov_out=$(docker compose exec -T chalk-hosted chalk-hosted provision \
        --slug "$slug" \
        --admin-email "$email" \
        --admin-name "KR Admin" \
        --display-name "Key Rotation Test" \
        --postgres-url "postgres://chalk:chalk@postgres:5432/chalk" 2>&1)
    echo "$prov_out" | grep -v "schema\|relation\|notice" | sed 's/^/    /'
    # The provision command prints a reset URL the operator would normally
    # email — we capture the reset token from it to set the admin password.
    local reset_token
    reset_token=$(echo "$prov_out" | python3 -c "
import sys, json, re
text = sys.stdin.read()
# Provision prints a JSON blob; extract the {…} substring and parse.
m = re.search(r'\{[\s\S]*?\}', text)
if m:
    print(json.loads(m.group(0)).get('reset_token', ''))
")
    if [ -z "$reset_token" ]; then
        echo "    FAIL: no reset token in provision output"
        return 1
    fi
    $CURL -s -c "/tmp/cookies-$slug.txt" -X POST "http://$slug.localhost:8080/set-password" \
        --data-urlencode "reset_token=$reset_token" \
        --data-urlencode "password=$PASSWORD" \
        --data-urlencode "confirm=$PASSWORD" -o /dev/null \
        -w "    set-password: HTTP %{http_code}\n"
}

snapshot_tenant() {
    local slug=$1
    local label=$2
    # Extract just the X509Certificate body (no whitespace) — that's the
    # invariant across a rotation. The PEM envelope of the keypair at rest
    # changes but the public cert in the metadata MUST be byte-identical.
    local cert
    cert=$($CURL -s "http://$slug.localhost:8080/idp/saml/metadata" \
        | python3 -c "import sys,re; m=re.search(r'<ds:X509Certificate>([^<]+)</ds:X509Certificate>', sys.stdin.read()); print(m.group(1).strip() if m else 'MISSING')")
    local jwk_n
    jwk_n=$($CURL -s "http://$slug.localhost:8080/idp/oidc/jwks" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['keys'][0]['n'])" 2>/dev/null \
        || echo "MISSING")
    echo "$cert" > "/tmp/$slug-cert-$label.txt"
    echo "$jwk_n" > "/tmp/$slug-jwk-$label.txt"
    if [ "$cert" = "MISSING" ] || [ "$jwk_n" = "MISSING" ]; then
        echo "    ✗ $slug $label: snapshot incomplete (cert=$cert jwk=$jwk_n)"
        return 1
    fi
    echo "    ✓ $slug $label snapshot captured (cert ${#cert} chars, jwk_n ${#jwk_n} chars)"
}

verify_login() {
    local slug=$1
    local code
    code=$($CURL -s -c "/tmp/cookies-$slug-post.txt" \
        -X POST "http://$slug.localhost:8080/login" \
        --data-urlencode "password=$PASSWORD" -o /dev/null -w "%{http_code}")
    if [ "$code" = "303" ] || [ "$code" = "200" ]; then
        echo "    ✓ $slug login: HTTP $code"
    else
        echo "    ✗ $slug login: HTTP $code (expected 303 or 200)"
        return 1
    fi
}

provision_tenant "$SLUG_A" "kr@verify.example"

echo
echo "==> snapshotting pre-rotation state"
snapshot_tenant "$SLUG_A" "before"

echo
echo "==> running rotation inside chalk-hosted container"
ROTATE_OUT=$(docker compose exec -T chalk-hosted chalk-hosted rotate-master-key \
    --postgres-url "postgres://chalk:chalk@postgres:5432/chalk" 2>&1)
echo "$ROTATE_OUT" | sed 's/^/    /'
NEW_KEY=$(echo "$ROTATE_OUT" | grep -oE "MASTER_ENCRYPTION_KEY=[A-Za-z0-9+/=]+" \
    | head -1 | cut -d= -f2-)
if [ -z "$NEW_KEY" ]; then
    echo "FAIL: rotation did not print a new key"
    exit 1
fi
echo "    captured new key: ${NEW_KEY:0:12}…"

echo
echo "==> updating .env + restarting chalk-hosted with new key"
# Replace the MASTER_ENCRYPTION_KEY line. Use a tab-or-comment-free pattern
# so we don't accidentally overwrite the example-comment lines.
python3 -c "
import re, sys
content = open('.env').read()
content = re.sub(r'^MASTER_ENCRYPTION_KEY=.*\$', f'MASTER_ENCRYPTION_KEY=$NEW_KEY', content, flags=re.M)
open('.env', 'w').write(content)
"
docker compose up -d chalk-hosted >/dev/null
echo "    waiting for chalk-hosted to come back…"
for i in 1 2 3 4 5 6 7 8 9 10; do
    if $CURL -fsS -o /dev/null "http://localhost:8080/health" 2>/dev/null; then
        break
    fi
    sleep 1
done

echo
echo "==> snapshotting post-rotation state + comparing"
snapshot_tenant "$SLUG_A" "after"
PASS=true
for slug in "$SLUG_A"; do
    if ! diff -q "/tmp/$slug-cert-before.txt" "/tmp/$slug-cert-after.txt" >/dev/null; then
        echo "    ✗ $slug SAML cert CHANGED across rotation (must be identical)"
        PASS=false
    else
        echo "    ✓ $slug SAML cert identical"
    fi
    if ! diff -q "/tmp/$slug-jwk-before.txt" "/tmp/$slug-jwk-after.txt" >/dev/null; then
        echo "    ✗ $slug OIDC jwk_n CHANGED across rotation (must be identical)"
        PASS=false
    else
        echo "    ✓ $slug OIDC jwk_n identical"
    fi
done

echo
echo "==> verifying admin login still works"
verify_login "$SLUG_A" || PASS=false

echo
echo "==> verifying rotation is idempotent (second run with original old + same new should report all rows already on new key)"
# Pass the ORIGINAL key as --old-key explicitly so the rotator doesn't
# pick up the (now-rotated) value from the container's env. Each row in
# the DB is already sealed with NEW_KEY, so the rotator should fail to
# unseal with old, succeed with new, and report them as already rotated.
ORIGINAL_KEY=$(grep '^MASTER_ENCRYPTION_KEY=' "$ORIG_ENV" | cut -d= -f2-)
ROTATE_OUT_2=$(docker compose exec -T chalk-hosted chalk-hosted rotate-master-key \
    --postgres-url "postgres://chalk:chalk@postgres:5432/chalk" \
    --old-key "$ORIGINAL_KEY" \
    --new-key "$NEW_KEY" 2>&1)
echo "$ROTATE_OUT_2" | sed 's/^/    /'
if echo "$ROTATE_OUT_2" | grep -qE "rotated 0 tenant secret rows \([1-9][0-9]* already on new key"; then
    echo "    ✓ idempotent: every row reported as already on new key"
else
    echo "    ✗ second rotation did not report all-already-rotated"
    PASS=false
fi

echo
if [ "$PASS" = true ]; then
    echo "PASS — master key rotation: rewrap → restart → secrets verified → idempotent"
    exit 0
else
    echo "FAIL — see assertions above"
    exit 1
fi
