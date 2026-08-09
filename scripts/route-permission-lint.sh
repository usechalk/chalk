#!/usr/bin/env bash
# Every route the console router serves must have a declaration in
# crates/console/src/authz.rs — the GP-2 rule that a permission is a decision
# someone made, not a default someone forgot. The middleware fails closed on
# undeclared MUTATING routes at runtime; this catches the omission at build
# time, for reads too, the way messaging-lint catches a retired claim.
#
# The route list is derived from lib.rs itself (path literals and *_PATH
# consts), never hand-maintained — a hand list here would be the exact bug
# class this repo keeps a changelog of.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PYEOF'
import re, sys, glob

lib = open('crates/console/src/lib.rs').read()
authz = open('crates/console/src/authz.rs').read()
flat = re.sub(r'\s+', ' ', lib)

consts = {}
for f in glob.glob('crates/console/src/**/*.rs', recursive=True):
    for m in re.finditer(r'pub const ([A-Z_]+_PATH): &str = "([^"]+)"', open(f).read()):
        consts[m.group(1)] = m.group(2)

routes = []
for m in re.finditer(r'\.route\( ?("(?:[^"]+)"|[A-Za-z_:]+_PATH) ?,', flat):
    raw = m.group(1)
    if raw.startswith('"'):
        routes.append(raw.strip('"'))
    else:
        name = raw.split('::')[-1]
        if name not in consts:
            print(f'route-permission-lint: cannot resolve const {raw}', file=sys.stderr)
            sys.exit(1)
        routes.append(consts[name])

missing = sorted({r for r in routes if f'"{r}"' not in authz})
if missing:
    print('route-permission-lint: routes with NO declaration in authz.rs '
          '(add a route_authz arm — a permission is a decision, not a default):',
          file=sys.stderr)
    for r in missing:
        print(f'  {r}', file=sys.stderr)
    sys.exit(1)

print(f'✓ route-permission-lint passed: {len(set(routes))} routes, all declared.')
PYEOF
