# WS-1, next section — C1 + C2, the first-run arc

**Status:** planned, not started · July 2026
**Prereqs met:** C0, B1/B2, B5, B6 (read path), C3, C5 are shipped and CI-green.

---

## 1. Why these two, and why now

The arc the whole workstream exists to deliver is:

```
Connect Google ──▶ Sync (live progress) ──▶ "4,812 of 5,000 matched to students"
                                                    │
                        ┌───────────────────────────┴──────────────┐
                        ▼                                          ▼
                 Device inventory  (C3 ✓)                 Unmatched queue  (C5 ✓)
```

**The back half is built. The front half does not exist.** Today the only way
to get a device into Chalk is `chalk devices sync` from a terminal, so the
wedge — *connect Google and watch thousands of Chromebooks appear already
attached to real students* — cannot be demonstrated to anyone, and the
30-minute acceptance criterion cannot even be attempted.

C1 and C2 are what close that gap. Nothing else in WS-1 unblocks a demo.

---

## 2. The blocking structural decision

**`chalk-console` does not depend on `chalk-devices`.** `DeviceSyncEngine` is
constructed in exactly one place — `crates/cli/src/commands/devices.rs:80` —
and the console has no way to reach it. Both C1's "Test connection" and C2's
"Run first sync" need to.

| Option | Cost | Verdict |
|---|---|---|
| **(a) Console depends on `chalk-devices`, spawns a background task** | One crate edge; a CAS guard against double-runs | **Recommended** |
| (b) Console writes a `requested` row; a worker picks it up | Needs `jobs` + `JobRunner`, which are WS-3 and not built | Defer |
| (c) Leave sync CLI-only; C2 only *displays* past runs | Cheap | Fails the acceptance criterion — no demo |

**Take (a).** It mirrors the SIS trigger that already exists
(`sync_trigger` + `sync_in_flight`, `console/src/lib.rs:992`): a compare-and-swap
flag, a spawned task, and a template that reports "already running" to the
second click rather than queueing it. That pattern is proven in this codebase
and needs no new infrastructure. (b) is the right long-term shape and is
exactly what WS-3's `JobRunner` is for — this should be written so that
swapping to it later touches the trigger and nothing else.

**Consequence to accept knowingly:** a sync running in the web process dies if
the process restarts mid-run. The cursor in `google_device_sync_cursors` makes
that resumable rather than corrupting, and the run row is left `running` with
no `completed_at` — so the UI needs a liveness window past which a run is
displayed as *interrupted*. Do not auto-resume; §6.3 of ARCHITECTURE already
takes that position for change sets and the same reasoning applies.

---

## 3. C1 — Connect Google

### What already exists
- A Google-sync settings page and the **secret-set idiom** (`{% if key_set %}`
  + "leave blank to keep existing" + "Clear stored key") — exactly right here.
- `DeviceSyncConfig` with `service_account_key_path`, `admin_email`, and
  `resolved_key_path()` falling back to `google_sync`.
- `TokenProvider` (B1) already abstracts credential → token, with both
  service-account and OAuth variants.

### What is genuinely new

**1. Getting the key in.** `service_account_key_path` is a **path**, not
content. A console upload has to put the JSON somewhere. Two options, and this
needs deciding before any code:

- *Self-host:* write to `data_dir` with mode 0600 and store the path. Simple,
  matches the existing config shape, and the operator owns the filesystem.
- *Hosted:* seal into `tenant_config` via `core::crypto` and materialize on
  use. `tenant_config_loader.rs` already materializes secrets to disk, so this
  fits — but note B7 flagged that an OAuth **refresh token** is the first
  secret that is *not* a path, which will break that assumption when OAuth
  lands. Better to design the storage as "sealed bytes + optional materialized
  path" now than to retrofit it.

**Never echo the key back.** Show a fingerprint and a "replace" control.

**2. "Test connection" — the highest-value affordance in the flow.** One real
read call, reporting what it can actually see:

> Connected. 5,000 ChromeOS devices, 47 org units visible.

There is no precedent for this in the console. It is worth building carefully
because it converts the single worst failure mode — a silent misconfiguration
discovered an hour into a sync — into a five-second answer.

**3. Telling the admin what to paste into Google.** Domain-wide delegation is
configured in *their* Admin console, not by us: they must authorise our client
ID against an exact scope list. If the flow does not show the client ID and the
scopes as copyable text, every delegation mistake arrives as "Chalk is broken".
**This is the largest support-cost item in the whole feature** and it is a
copywriting problem more than an engineering one.

### Scope cut
**Do not build the OAuth refresh-token path.** It cannot be tested end to end
until the Cloud project clears CASA (WS-6), and the `TokenProvider` seam means
it drops in later without touching sync code. Cutting it costs nothing today.

---

## 4. C2 — First sync progress

### What already exists — more than expected
- `google_device_sync_runs` carries every counter the UI needs: `devices_seen`,
  `created`, `updated`, `matched`, `unmatched`, `api_calls`, `throttle_events`,
  plus `status`, `mode`, `dry_run` and `error_message`.
- **The engine updates counters mid-run** (`devices/src/sync.rs:289`), so
  polling shows real progress rather than 0% then 100%.
- `latest_run`, `get_run`, `list_runs` are all on `GoogleDeviceSyncRepository`.

So C2 is mostly UI over data that is already being written correctly.

### What is new
- The trigger (see §2).
- A polled fragment, `hx-trigger="every 2s"`, against the run row — the same
  region-swap contract C3 and C5 already use.
- **A result framed as the win**, not as a process report:
  *"4,812 of 5,000 devices matched to students."* Announced through the live
  region on completion.
- Run history listing past runs with `throttle_events` visible, so *"why was
  the sync slow"* is answerable. §5.3 requires recording it; this is where it
  finally surfaces.

### The trap to avoid
The existing SIS "Running…" indicator displays only during the ~10ms POST, not
during the actual sync — it is actively misleading, and it is precisely what
C2 must not copy. A 20k fleet is ~100 requests: minutes, not seconds.

---

## 5. Verification

- Unit tests per `CLAUDE.md`, with the client under wiremock as B6's tests
  already do.
- The polled fragment needs a test that a `running` run with no `completed_at`
  past the liveness window renders as *interrupted* rather than as in-progress
  forever.
- **A wiremock-backed fake tenant can prove the entire arc** except credential
  validity — worth doing, because it does not wait on anything external.
- **The real end-to-end test is blocked on task #1**, the Google service
  account: three `.readonly` scopes, domain-wide delegation, a super-admin to
  impersonate. Until that exists the 30-minute criterion cannot be timed, and
  no amount of further building changes that.

---

## 6. Sequencing

1. Wire `chalk-devices` into the console behind a trigger (§2) — everything
   else depends on it.
2. **C1** connect + test connection.
3. **C2** trigger + live progress + run history.
4. Then the deliberately-last chunk: **write-back + C4 diff preview**, which
   ship together because filter-scoped selection is only safe with a preview
   between the filter and Google. C5's bulk actions stay page-scoped until then.
5. **B7** CLI parity (`devices sync`, `push --dry-run`, `changeset …`) and
   **C7** the accessibility pass.

---

## 7. Open questions for the owner

1. **Key storage shape** (§3.1) — path-on-disk for self-host only, or sealed
   bytes from the start so hosted and OAuth do not force a retrofit?
2. **Is a sync in the web process acceptable** for self-host (§2), given it
   dies on restart and resumes from cursor, or is WS-3's `JobRunner` a
   prerequisite rather than a follow-on?
3. **Task #1** — the service account. Nothing after C2 can be validated against
   a real tenant without it.
