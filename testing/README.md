# `testing/` — bolt-on scenario stacks

Side-quest docker stacks for exercising chalk features that need an external
counterpart (a webhook receiver, an LDAP server, etc.). Each scenario is a
self-contained subfolder that brings up its dependencies, runs an end-to-end
check, and tears everything down.

These are **not** unit or integration tests — those live in each crate's
`tests/` directory and run on every `cargo test`. The stacks here are for
manual or CI verification of features that require a network peer.

## Layout

```
testing/
├── README.md             # this file
├── _common/              # shared helpers (see below)
│   └── precheck.sh       # asserts the chalk-marketing docker stack is up
├── webhook-receiver/     # scenario 1
├── saml-sp/              # scenario 2 (no docker — uses SAMLtest.id)
├── oneroster-csv/        # scenario 4
├── ldap-target/          # scenario 3
├── sis-live/             # docs only — real SIS needs district credentials
└── google-workspace/     # docs only — real GWS needs a service account
```

## Conventions

Every scenario subfolder has:

- `README.md` — what the scenario covers, prerequisites, and how to read the output.
- `docker-compose.yml` — the side stack (skipped for scenarios that don't need one).
- `run.sh` — single-command entry point: brings up the stack, runs the test, tears down on exit (including on failure, via `trap`). Exits non-zero if the test fails.
- `data/` (optional) — seed files, fixtures, sample CSV bundles.

All scenarios assume the main chalk-hosted stack from `../chalk-marketing/docker-compose.yml` is already running on `localhost:8080`. Run `_common/precheck.sh` to confirm.

## Running a scenario

```bash
cd testing/<scenario>
./run.sh
```

Each `run.sh` prints a clear PASS / FAIL banner and exits 0 / non-zero accordingly. Containers come down on completion or interrupt — use `docker compose down -v` from the scenario directory to force-clean if needed.

## Why not in CI?

These scenarios depend on the chalk-marketing docker stack being live. They're for local verification and pre-release smoke. CI runs `cargo test` against in-process mocks, which is faster and self-contained. Promote a scenario to CI when there's a reliable way to start the full stack in CI runners.

## What's documented but not testable here

- `sis-live/` — PowerSchool / Skyward / Infinite Campus sync. Each needs a real plugin OAuth client_id/secret + base URL from a district instance.
- `google-workspace/` — Google Directory sync. Needs a Google Workspace tenant + service-account JSON with domain-wide delegation.
