#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"

fail() {
    echo "install-test: $*" >&2
    exit 1
}

make_stubs() {
    stub_dir="$1"

    cat <<'EOF' >"$stub_dir/uname"
#!/bin/sh
case "${1:-}" in
    -s)
        printf '%s\n' "$FAKE_UNAME_S"
        ;;
    -m)
        printf '%s\n' "$FAKE_UNAME_M"
        ;;
    *)
        exec /usr/bin/uname "$@"
        ;;
esac
EOF

    cat <<'EOF' >"$stub_dir/curl"
#!/bin/sh
set -eu

out=""
url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            out="$2"
            shift 2
            ;;
        -*)
            shift
            ;;
        *)
            url="$1"
            shift
            ;;
    esac
done

printf '%s\n' "$url" >"$FAKE_CURL_LOG"
if [ "${FAKE_CURL_FAIL:-0}" = "1" ]; then
    exit 22
fi

printf 'chalk binary from %s\n' "$url" >"$out"
EOF

    cat <<'EOF' >"$stub_dir/install"
#!/bin/sh
set -eu

while [ "$#" -gt 0 ]; do
    case "$1" in
        -m)
            mode="$2"
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

src="$1"
dest="$2"
cp "$src" "$dest"
chmod "${mode:-0755}" "$dest"
EOF

    cat <<'EOF' >"$stub_dir/sudo"
#!/bin/sh
set -eu
exec "$@"
EOF

    chmod +x "$stub_dir/uname" "$stub_dir/curl" "$stub_dir/install" "$stub_dir/sudo"
}

run_success_case() {
    name="$1"
    fake_os="$2"
    fake_arch="$3"
    expected_asset="$4"

    case_dir="$TMPDIR_ROOT/$name"
    stub_dir="$case_dir/stubs"
    install_dir="$case_dir/bin"
    mkdir -p "$stub_dir" "$install_dir"
    make_stubs "$stub_dir"

    log_file="$case_dir/curl.log"

    env \
        PATH="$stub_dir:/usr/bin:/bin" \
        FAKE_UNAME_S="$fake_os" \
        FAKE_UNAME_M="$fake_arch" \
        FAKE_CURL_LOG="$log_file" \
        INSTALL_DIR="$install_dir" \
        sh "$ROOT/install.sh"

    [ -x "$install_dir/chalk" ] || fail "$name did not install chalk"
    grep -F "$expected_asset" "$log_file" >/dev/null || fail "$name downloaded wrong asset"
}

run_failure_case() {
    case_dir="$TMPDIR_ROOT/linux-arm64-missing"
    stub_dir="$case_dir/stubs"
    install_dir="$case_dir/bin"
    mkdir -p "$stub_dir" "$install_dir"
    make_stubs "$stub_dir"

    log_file="$case_dir/curl.log"
    output_file="$case_dir/output.log"

    if env \
        PATH="$stub_dir:/usr/bin:/bin" \
        FAKE_UNAME_S="Linux" \
        FAKE_UNAME_M="arm64" \
        FAKE_CURL_LOG="$log_file" \
        FAKE_CURL_FAIL="1" \
        INSTALL_DIR="$install_dir" \
        sh "$ROOT/install.sh" >"$output_file" 2>&1; then
        fail "linux-arm64-missing unexpectedly succeeded"
    fi

    grep -F "chalk-aarch64-unknown-linux-gnu" "$output_file" >/dev/null \
        || fail "linux-arm64-missing did not explain the mapped asset"
    grep -F "Use Docker instead" "$output_file" >/dev/null \
        || fail "linux-arm64-missing did not suggest Docker"
}

TMPDIR_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/install-test.XXXXXX")"
cleanup() {
    rm -rf "$TMPDIR_ROOT"
}
trap cleanup EXIT HUP INT TERM

run_success_case "macos-arm64" "Darwin" "arm64" "chalk-aarch64-apple-darwin"
run_success_case "macos-x86_64" "Darwin" "x86_64" "chalk-x86_64-apple-darwin"
run_success_case "linux-x86_64" "Linux" "x86_64" "chalk-x86_64-unknown-linux-gnu"
run_failure_case

echo "✓ install-test passed: platform mapping and Linux ARM64 failure mode."
