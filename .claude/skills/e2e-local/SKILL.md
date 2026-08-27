---
name: e2e-local
description: Run the local live e2e rig — server, logins, mail catcher, and the traps that make greps lie
---

# The local e2e rig

Unit tests prove the seam; a live server proves the wiring. Both are
mandatory before a release (AGENTS.md), and live e2e has caught what 600+
unit tests missed (a store never wired in `chalk serve`, a button on the
wrong login template).

## Start it

```bash
cargo build
./target/debug/chalk serve --port 8792   # 8080 is taken by keel-api locally
```

Config lives at `~/Library/Application Support/chalk/chalk.toml` — the
standing rig has the IdP enabled, seeded roster + fleet, and
`alerts_email` set. `[mail]` is a TOP-LEVEL section, not `[chalk.mail]`.

## Sessions with curl

```bash
T=$(curl -s -c adm.txt "$B/login" | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | cut -d'"' -f4)
curl -s -b adm.txt -c adm.txt -X POST "$B/login" \
  --data-urlencode "password=e2e-password-123" --data-urlencode "csrf_token=$T"
CS=$(grep chalk_csrf adm.txt | awk '{print $7}')   # send as x-csrf-token header AND csrf_token field
```

Console users log in with `email=` + `password=`. The IdP portal is
different: `POST /idp/login/password` with `username=` (not email).

## Mail flows

```bash
python3 $SCRATCH/smtp_catcher.py OUTPUT_FILE 2626 &   # argument is a FILE, not a directory
```

Then grep the file for the message. Mock consoles: `mdm_mock.py` :2727,
`graph_mock.py` :2828.

## The traps (each has burned a session)

- **Vacuous greps.** A grep that "verifies" a feature can match a form
  placeholder, a template comment, or the dropdown that lists all schools.
  Before trusting a match, know which element produced it; prefer matching
  the exact rendered fragment (`Hinge kit</td><td...`).
- **`grep -c` exits 1 on zero** — an `&&` chain dies on the success case
  when zero is the expected count.
- **First-uuid grabs.** `grep -o '[a-f0-9-]{36}' | head -1` picks whatever
  option renders first, which on a seeded database is rarely the row you
  just created. Grab ids from the repo/table you targeted, or match the
  label text.
- Auto-attach and similar heuristics depend on seed data (a requester with
  several devices attaches nothing) — when a flow "fails", check whether the
  rig's data satisfies its preconditions before debugging the code.
