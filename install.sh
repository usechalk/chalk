#!/bin/sh
set -eu

REPO="usechalk/chalk"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"

need_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "chalk install: need $1 in PATH" >&2
        exit 1
    fi
}

need_command curl
need_command install
need_command mktemp
need_command uname

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
    Darwin)
        case "$arch" in
            x86_64 | amd64)
                asset="chalk-x86_64-apple-darwin"
                ;;
            arm64 | aarch64)
                asset="chalk-aarch64-apple-darwin"
                ;;
            *)
                echo "chalk install: unsupported macOS architecture: $arch" >&2
                exit 1
                ;;
        esac
        ;;
    Linux)
        case "$arch" in
            x86_64 | amd64)
                asset="chalk-x86_64-unknown-linux-gnu"
                ;;
            arm64 | aarch64)
                asset="chalk-aarch64-unknown-linux-gnu"
                ;;
            *)
                echo "chalk install: unsupported Linux architecture: $arch" >&2
                exit 1
                ;;
        esac
        ;;
    *)
        echo "chalk install: unsupported operating system: $os" >&2
        exit 1
        ;;
esac

case "$VERSION" in
    latest)
        url="https://github.com/$REPO/releases/latest/download/$asset"
        ;;
    v*)
        url="https://github.com/$REPO/releases/download/$VERSION/$asset"
        ;;
    *)
        echo "chalk install: VERSION must be 'latest' or a tag like v1.46.0" >&2
        exit 1
        ;;
esac

tmp="$(mktemp "${TMPDIR:-/tmp}/chalk.XXXXXX")"
cleanup() {
    rm -f "$tmp"
}
trap cleanup EXIT HUP INT TERM

echo "chalk install: downloading $asset"
if ! curl -fsSL "$url" -o "$tmp"; then
    if [ "$asset" = "chalk-aarch64-unknown-linux-gnu" ]; then
        echo "chalk install: Linux ARM64 maps to $asset, but this release does not publish that binary yet." >&2
        echo "chalk install: Use Docker instead: curl the compose file, then run \`docker compose up -d\`." >&2
    else
        echo "chalk install: release asset not found: $asset" >&2
    fi
    exit 1
fi

target="$INSTALL_DIR/chalk"
if mkdir -p "$INSTALL_DIR" 2>/dev/null && [ -w "$INSTALL_DIR" ]; then
    install -m 0755 "$tmp" "$target"
elif command -v sudo >/dev/null 2>&1; then
    sudo mkdir -p "$INSTALL_DIR"
    sudo install -m 0755 "$tmp" "$target"
else
    echo "chalk install: $INSTALL_DIR is not writable; rerun as root or set INSTALL_DIR" >&2
    exit 1
fi

echo "chalk install: installed $target"
echo "chalk install: run \`chalk update\` later to pick up future releases."
