#!/usr/bin/env bash
# Every GET page the console serves must be reachable from some other page.
#
# The sidebar-crawl test proves every rendered link serves; this is its
# inverse — a page nobody links to passed every test and shipped invisible
# FIVE times (2FA enrollment, attestation campaigns, purchase orders,
# funding sources, identity settings — audit of 2026-08-09). The route list
# is derived from lib.rs, never hand-maintained; a page may be exempted only
# by adding it to the documented allowlist below with a reason.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PYEOF'
import re, sys, glob

# Pages a user is not meant to click to, each with its reason.
ALLOW = {
    "/": "the post-login landing page",
    "/health": "monitoring endpoint",
    "/devices/scan": "a form action (circulation search), not a link target",
    "/devices/sync/status": "htmx polling fragment",
    "/sync/history": "htmx fragment embedded in /sync",
    "/ad-sync/history": "htmx fragment embedded in /ad-sync",
    "/google-sync/history": "htmx fragment embedded in /google-sync",
    "/identity/saml-cert.pem": "linked via a handler-built variable href",
}

lib = open('crates/console/src/lib.rs').read()
flat = re.sub(r'\s+', ' ', lib)
consts = {}
for f in glob.glob('crates/console/src/**/*.rs', recursive=True):
    for m in re.finditer(r'pub const ([A-Z_]+_PATH): &str = "([^"]+)"', open(f).read()):
        consts[m.group(1)] = m.group(2)

pages = set()
for m in re.finditer(r'\.route\( ?("(?:[^"]+)"|[A-Za-z_:]+_PATH) ?, ?get\(', flat):
    raw = m.group(1)
    path = raw.strip('"') if raw.startswith('"') else consts.get(raw.split('::')[-1], '?')
    if path.startswith(('/static', '/api', '/share/', '/csat', '/attest/',
                        '/help', '/login', '/set-password', '/inbound')):
        continue
    # Parameterized detail pages are reached through handler-built URLs. Axum
    # 0.8 spells parameters as `{id}` rather than `:id`.
    if re.search(r'\{[^}]+\}', path) or path in ALLOW:
        continue
    pages.add(path)

# A page is reachable if any OTHER template names it (href, action, hx-get)
# or a Rust file outside the router/authz builds an href to it.
refs = {}
for f in glob.glob('crates/console/templates/**/*.html', recursive=True):
    refs[f] = open(f).read()
rust = ''
for f in glob.glob('crates/console/src/**/*.rs', recursive=True):
    if f.endswith(('lib.rs', 'authz.rs')) or '/tests' in f or f.endswith('tests.rs'):
        continue
    rust += open(f).read()

def own_template(path):
    # crude but effective: the page's own template usually contains its POST
    # action or self href; a reference only counts from a different file.
    stem = path.strip('/').replace('/', '_').replace('-', '_')
    return [f for f in refs if stem in f.replace('/', '_').replace('-', '_')]

orphans = []
for p in sorted(pages):
    own = set(own_template(p))
    linked = any(p in body for f, body in refs.items() if f not in own)
    linked = linked or f'"{p}' in rust
    if not linked:
        orphans.append(p)

if orphans:
    print('orphan-page-lint: pages nothing links to (add a link where a user '
          'would look, or an ALLOW entry with a reason):', file=sys.stderr)
    for o in orphans:
        print(f'  {o}', file=sys.stderr)
    sys.exit(1)
print(f'✓ orphan-page-lint passed: {len(pages)} pages all reachable, '
      f'{len(ALLOW)} documented exemptions.')
PYEOF
