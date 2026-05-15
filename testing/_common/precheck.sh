#!/usr/bin/env bash
# Asserts the chalk-marketing docker stack is up before running a scenario.
# Source this from each scenario's run.sh:
#
#   . "$(dirname "$0")/../_common/precheck.sh"
#
# Exits non-zero with a helpful message if the stack isn't reachable.

set -euo pipefail

CURL=${CURL:-/usr/bin/curl}
APEX=${CHALK_APEX:-localhost:8080}

if ! "$CURL" -fsS -o /dev/null "http://${APEX}/health" 2>/dev/null; then
    echo "✗ chalk-hosted not reachable at http://${APEX}/health"
    echo
    echo "  Bring up the main stack first:"
    echo "    cd ../../chalk-marketing && docker compose up -d"
    echo
    exit 1
fi
echo "✓ chalk-hosted is up at http://${APEX}"
