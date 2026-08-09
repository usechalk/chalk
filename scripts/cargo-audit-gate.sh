#!/usr/bin/env bash
# cargo-audit with deny-warnings semantics that respect the ignore list.
#
# cargo-audit 0.22.x counts flag-ignored advisories as "denied warnings"
# under --deny warnings, so the strict flag re-fails the exact advisories the
# ignore was for. This gate keeps both properties instead: the exit code
# fails on any non-ignored VULNERABILITY, and the JSON pass below fails on
# any WARNING-class advisory (unmaintained, unsound, informational) that is
# not on the list — so a new warning still breaks the build loudly.
#
# The ignore list lives in .cargo/audit.toml — the file cargo-audit reads on
# its own — with the reason beside each entry. This script parses the same
# file, so a bare local `cargo audit`, this gate, and CI can never disagree.
set -euo pipefail
cd "$(dirname "$0")/.."

out="$(cargo audit --json --file ./Cargo.lock)" || {
  echo "$out" | python3 -m json.tool >&2 || echo "$out" >&2
  echo "cargo-audit-gate: vulnerabilities found (see above)" >&2
  exit 1
}

python3 - "$out" <<'PYEOF'
import json, sys, tomllib
report = json.loads(sys.argv[1])
with open(".cargo/audit.toml", "rb") as f:
    ignored = set(tomllib.load(f)["advisories"]["ignore"])
bad = []
for kind, entries in (report.get("warnings") or {}).items():
    for w in entries:
        advisory = (w.get("advisory") or {}).get("id", "unknown")
        if advisory not in ignored:
            pkg = (w.get("package") or {}).get("name", "?")
            bad.append(f"{advisory} ({kind}: {pkg})")
if bad:
    print("cargo-audit-gate: warning-class advisories not on the ignore list:",
          file=sys.stderr)
    for b in sorted(bad):
        print(f"  {b}", file=sys.stderr)
    sys.exit(1)
print(f"✓ cargo-audit-gate passed ({len(ignored)} advisories on the documented ignore list).")
PYEOF
