#!/usr/bin/env bash
# bootstrap.sh - Idempotent provisioning script for the chalk hosted service.
#
# Target: a freshly-created Ubuntu 24.04 LTS Digital Ocean droplet.
# Run as root (or via `sudo bash bootstrap.sh`). Safe to re-run.
#
# What this does:
#   1. Installs base packages (firewall, postgres client, build tooling for xcaddy).
#   2. Configures ufw to permit only SSH + HTTP + HTTPS.
#   3. Creates the `chalk-hosted` system user that runs the multi-tenant binary.
#   4. Builds Caddy with the Cloudflare DNS module via xcaddy and installs the
#      official Caddy systemd unit.
#   5. Creates the directory layout: /etc/chalk-hosted, /var/lib/chalk-hosted,
#      /var/www/chalk-marketing.
#
# It does NOT:
#   - Copy the chalk-hosted binary (operator does that out-of-band).
#   - Write secrets.env (operator does that, see infra/env.example).
#   - Substitute <apex> in the Caddyfile.

set -euo pipefail

CADDY_VERSION="${CADDY_VERSION:-v2.8.4}"
XCADDY_VERSION="${XCADDY_VERSION:-v0.4.2}"

log() { printf '\n[bootstrap] %s\n' "$*"; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "bootstrap.sh must run as root" >&2
        exit 1
    fi
}

apt_install() {
    log "Updating apt and installing base packages"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y \
        ufw \
        postgresql-client \
        curl \
        ca-certificates \
        debian-keyring \
        debian-archive-keyring \
        apt-transport-https \
        golang-go
}

configure_ufw() {
    log "Configuring ufw (allow 22/80/443, deny all else)"
    ufw --force reset >/dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw --force enable
}

ensure_user() {
    local user="$1"
    if ! id -u "$user" >/dev/null 2>&1; then
        log "Creating system user: $user"
        useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
    else
        log "System user already exists: $user"
    fi
}

install_xcaddy() {
    if command -v xcaddy >/dev/null 2>&1; then
        log "xcaddy already installed: $(xcaddy version 2>/dev/null || true)"
        return
    fi
    log "Installing xcaddy ${XCADDY_VERSION}"
    # Official method: install the xcaddy package from cloudsmith.
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/gpg.key' \
        | gpg --dearmor -o /usr/share/keyrings/caddy-xcaddy-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/debian.deb.txt' \
        | tee /etc/apt/sources.list.d/caddy-xcaddy.list >/dev/null
    apt-get update -y
    apt-get install -y xcaddy
}

build_caddy() {
    # Skip rebuild if a caddy of the right version is already installed.
    if [[ -x /usr/local/bin/caddy ]]; then
        local current
        current="$(/usr/local/bin/caddy version 2>/dev/null | awk '{print $1}' || true)"
        if [[ "$current" == "$CADDY_VERSION" ]]; then
            log "Caddy ${CADDY_VERSION} already installed at /usr/local/bin/caddy"
            return
        fi
        log "Caddy present but version mismatch (have: $current, want: $CADDY_VERSION); rebuilding"
    fi

    log "Building Caddy ${CADDY_VERSION} with cloudflare DNS module via xcaddy"
    local tmpdir
    tmpdir="$(mktemp -d)"
    pushd "$tmpdir" >/dev/null
    xcaddy build "${CADDY_VERSION}" \
        --with github.com/caddy-dns/cloudflare \
        --output ./caddy
    install -m 0755 ./caddy /usr/local/bin/caddy
    popd >/dev/null
    rm -rf "$tmpdir"
}

install_caddy_unit() {
    ensure_user caddy

    mkdir -p /etc/caddy
    chown -R caddy:caddy /etc/caddy

    if [[ ! -f /etc/systemd/system/caddy.service ]]; then
        log "Installing official Caddy systemd unit"
        cat >/etc/systemd/system/caddy.service <<'UNIT'
# Official Caddy systemd unit, adapted from
# https://github.com/caddyserver/dist/blob/master/init/caddy.service
[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
EnvironmentFile=-/etc/caddy/caddy.env
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
    else
        log "Caddy systemd unit already present"
    fi
}

setup_directories() {
    log "Creating chalk-hosted directory layout"
    install -d -m 0750 -o root -g chalk-hosted /etc/chalk-hosted
    install -d -m 0700 -o chalk-hosted -g chalk-hosted /var/lib/chalk-hosted
    install -d -m 0755 /var/www/chalk-marketing
}

print_next_steps() {
    cat <<'EOF'

==========================================================================
 bootstrap complete - next steps (operator)
==========================================================================
 1. Copy the chalk-hosted binary:
       scp target/release/chalk-hosted root@<droplet>:/usr/local/bin/
       chmod 0755 /usr/local/bin/chalk-hosted

 2. Copy the marketing site bundle:
       rsync -a marketing/dist/ root@<droplet>:/var/www/chalk-marketing/dist/

 3. Install the Caddyfile and substitute the apex domain:
       cp infra/caddy/Caddyfile /etc/caddy/Caddyfile
       sed -i 's/<apex>/your.domain/g' /etc/caddy/Caddyfile
       chown caddy:caddy /etc/caddy/Caddyfile

 4. Install the chalk-hosted systemd unit:
       cp infra/systemd/chalk-hosted.service /etc/systemd/system/
       systemctl daemon-reload

 5. Write secrets (see infra/env.example):
       install -m 0640 -o root -g chalk-hosted /dev/null /etc/chalk-hosted/secrets.env
       $EDITOR /etc/chalk-hosted/secrets.env

 6. Write /etc/chalk-hosted/config.toml (TOML config for the runtime).

 7. Enable + start services:
       systemctl enable --now chalk-hosted caddy

 8. Tail logs to confirm:
       journalctl -u chalk-hosted -f
       journalctl -u caddy -f
==========================================================================
EOF
}

main() {
    require_root
    apt_install
    configure_ufw
    ensure_user chalk-hosted
    install_xcaddy
    build_caddy
    install_caddy_unit
    setup_directories
    print_next_steps
}

main "$@"
