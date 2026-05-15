#!/usr/bin/env bash
# ldap-target scenario:
#   1. up bitnami/openldap on :1389
#   2. import the synthetic OneRoster CSV bundle into a temp SQLite DB
#   3. configure chalk's ad_sync to point at the container
#   4. test-connection → ad-sync → ldapsearch verification
#   5. down -v (always — even on failure or interrupt)

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
cd "$HERE"

# Verify ldapsearch is available — we need it to confirm what's in LDAP
# from outside the container.
if ! command -v ldapsearch >/dev/null 2>&1; then
    echo "ldapsearch not found on PATH"
    echo "  install with: brew install openldap   (macOS)"
    echo "             or: apt install ldap-utils (Debian/Ubuntu)"
    exit 1
fi

WORK=$(mktemp -d)
cleanup() {
    echo
    echo "tearing down LDAP container + work dir"
    docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

echo "==> bringing up OpenLDAP"
docker compose up -d >/dev/null
echo "    waiting for healthcheck…"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if docker compose ps --format json 2>/dev/null | grep -q '"Health":"healthy"'; then
        break
    fi
    sleep 2
done

echo
echo "==> building chalk CLI (cargo cache reused after first run)"
( cd "$ROOT" && cargo build -p chalk-cli --release --quiet )
CHALK="$ROOT/target/release/chalk"

echo
echo "==> generating temp config (ad-sync pointed at localhost:1389)"
cat > "$WORK/chalk.toml" <<EOF
[chalk]
instance_name = "ldap-test"
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

[ad_sync]
enabled = true

[ad_sync.connection]
server = "ldap://localhost:1389"
bind_dn = "cn=admin,dc=test,dc=local"
bind_password = "admin"
base_dn = "dc=test,dc=local"
tls_verify = false

[ad_sync.ou_mapping]
students = "Users"
teachers = "Users"
staff = "Users"

[ad_sync.options]
provision_users = true
deprovision_action = "disable"
manage_ous = true
manage_groups = false
# OpenLDAP uses inetOrgPerson, not the AD-specific `user` objectClass.
# Default is "active_directory" (preserves existing chalk behavior).
schema = "open_ldap"
EOF

echo
echo "==> importing OneRoster CSV bundle (reusing ../oneroster-csv/data)"
"$CHALK" --config "$WORK/chalk.toml" import --dir "$HERE/../oneroster-csv/data" >/dev/null

echo
echo "==> chalk ad-sync --test-connection"
"$CHALK" --config "$WORK/chalk.toml" ad-sync --test-connection

echo
echo "==> chalk ad-sync (real, provisions users)"
"$CHALK" --config "$WORK/chalk.toml" ad-sync

echo
echo "==> ldapsearch — confirm provisioned users"
SEARCH=$(ldapsearch -x \
    -H ldap://localhost:1389 \
    -D "cn=admin,dc=test,dc=local" \
    -w admin \
    -b "dc=test,dc=local" \
    "(|(uid=jdoe)(uid=bsmith)(uid=cwhite)(uid=tgreen)(uid=lbrown))" \
    dn uid givenName sn 2>&1)
echo "$SEARCH"

# Count how many of our 5 expected users came back.
FOUND=$(echo "$SEARCH" | grep -cE "^uid: (jdoe|bsmith|cwhite|tgreen|lbrown)$" || true)
EXPECTED=5

echo
if [ "$FOUND" -eq "$EXPECTED" ]; then
    echo "PASS — all $EXPECTED users provisioned to LDAP"
    exit 0
else
    echo "FAIL — expected $EXPECTED users in LDAP, found $FOUND"
    exit 1
fi
