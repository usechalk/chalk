#!/usr/bin/env bash
# UI ergonomics rules, derived from the templates themselves (v1.44.1's
# watch-list audit, made permanent). Three rules, each closing a class of
# drift that a reviewer's eye missed while it accumulated:
#
#   1. A page-header meta row holds at most SIX links. The inventory header
#      reached eleven before anyone counted; past six, the overflow belongs
#      in a <details class="menu">.
#   2. Sidebar labels are unique. Two entries both named "Dashboard" shipped
#      and read as a bug.
#   3. A template stacking five or more detail-cards carries an .anchor-nav
#      ("on this page" chips). The device page reached nine cards with no
#      wayfinding.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PYEOF'
import re, sys, glob

fail = []

for f in glob.glob('crates/console/templates/**/*.html', recursive=True):
    body = open(f).read()
    name = f.split('templates/')[-1]

    # Rule 1: meta-row link cap.
    for m in re.finditer(r'class="page-header__meta"[^>]*>(.*?)</p>', body, re.S):
        links = m.group(1).count('<a ')
        if links > 6:
            fail.append(f'{name}: page-header meta has {links} links (cap 6) — '
                        'move the overflow into a <details class="menu">')

    # Rule 3: card stacks need wayfinding.
    cards = body.count('class="detail-card"')
    if cards >= 5 and 'anchor-nav' not in body:
        fail.append(f'{name}: {cards} detail-cards with no anchor-nav — '
                    'add "on this page" chips')

# Rule 2: sidebar label uniqueness.
base = open('crates/console/templates/base.html').read()
nav = base.split('sidebar-nav', 1)[1].split('</nav>', 1)[0]
labels = []
for m in re.finditer(r'</svg>\s*\n\s*([A-Za-z][^<\n{]*)', nav):
    labels.append(m.group(1).strip())
dupes = {l for l in labels if labels.count(l) > 1}
if dupes:
    fail.append(f'base.html: duplicate sidebar labels {sorted(dupes)} — '
                'two entries with one name read as a bug')

if fail:
    print('ui-lint:', file=sys.stderr)
    for f in fail:
        print(f'  {f}', file=sys.stderr)
    sys.exit(1)
print(f'✓ ui-lint passed: meta caps, {len(labels)} unique sidebar labels, card-stack wayfinding.')
PYEOF
