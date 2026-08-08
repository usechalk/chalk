# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.36.0] - 2026-08-08

### Added
- **Two-factor authentication for console accounts.** Any TOTP authenticator
  app works: enroll from `/account/security` (QR + eight one-time recovery
  codes, shown exactly once), prove possession with a code to arm it, and
  from then on sign-in interposes a second step. Challenges are single-use
  and expire in five minutes; a wrong code burns the attempt rather than
  giving a guesser a stationary target; recovery codes work exactly once;
  disabling requires a current code so a walked-away-from session cannot
  strip 2FA silently. A half-finished enrollment never gates login — you
  cannot lock yourself out by closing the tab. The TOTP core is
  self-contained and pinned to the RFC 3174/2202/6238 test vectors, and the
  live flow was cross-verified against an independent implementation.

## [1.35.0] - 2026-08-08

### Added
- **Custody self-attestation campaigns.** The scan audit covers the building;
  this covers what went home. One click at `/devices/attestations` asks every
  open loan's holder — by email, with a tokenized link — whether they still
  have their device and what shape it is in. The public form takes one answer
  (first answer wins, revisits end politely, exactly like CSAT), and "I do
  not have it" surfaces on the campaign table as the finding it is. Re-running
  a campaign nags the unanswered instead of duplicating asks, and a holder
  with no email address stays visibly uncovered rather than silently skipped.

## [1.34.0] - 2026-08-08

### Added
- **E-signatures at the circulation desk.** The checkout form grows a
  signature pad — flip the screen around and the student signs on the device
  they are being handed. The mark is stored as a PNG with the custody record
  it accepted, shown on the device page beside the agreement with a Signed
  badge. Entirely optional and progressive: no JavaScript, no pad, and the
  checkout still works. A submission that is not a PNG data URL (or is
  implausibly large) refuses the whole checkout rather than half-completing
  it.

## [1.33.0] - 2026-08-08

WS-15 closes with Entra ID: districts on Azure AD get the same roster-driven
provisioning districts on LDAP have had, over the Microsoft Graph API.

> **Validation caveat:** exercised against a mocked Graph API only — token
> flow, adoption, creation, updates, disables, and the hash gate are unit-
> and e2e-tested against local mock servers, but no real Entra tenant has
> been touched yet.

### Added
- **Entra ID user provisioning.** `chalk entra-sync` provisions active roster
  users into Entra ID under `username@domain`: an account that already exists
  under the UPN is adopted and updated in place (never a colliding create);
  a new account is created enabled with a random single-use password and
  forced first-sign-in reset; a renamed user is patched; a departed user is
  disabled exactly once, never deleted. Unchanged users are hash-gated to
  zero Graph calls. `--dry-run` counts the work without contacting anything —
  not even the token endpoint; `--status` shows the last run.
- Run history (`entra_sync_runs`) and per-user state (`entra_sync_state`,
  migration 041) mirror the AD sync's tables one-for-one, so the two
  directory syncs share their operational shape. A per-user failure is
  isolated — counted with its detail, marked for retry with an empty hash,
  and the rest of the run proceeds.
- `[entra]` config: `tenant_id`, `client_id`, `client_secret`, `domain` —
  the same app-registration shape as `[mdm.intune]`. Token-refusal errors
  deliberately omit the response body: a client secret does not belong in a
  log line.

## [1.32.0] - 2026-08-08

The annotated-fields write-back exists: Chalk's assignment and sticker now
reach the Google Admin console, through the same plan → preview → approve →
commit pipeline every Google write uses.

> **Validation caveat:** the Google `PATCH` itself is exercised against a
> mocked Directory API only, like every Google write before it — no real
> tenant has received one yet.

### Added
- **"Push assignments to Google"** on the device list's bulk bar: plans a
  per-device diff writing each device's assigned student (roster email) into
  `annotatedUser` and its asset tag into `annotatedAssetId`. Unassigned
  devices clear the annotation; a tag Google has that Chalk lacks is never
  blanked; devices already in sync are counted unchanged, not padded into the
  preview. Applied writes mirror into Chalk's own annotated columns so the
  next sync sees agreement.
- `AnnotatedFields` gains `annotatedAssetId` (200-char limit, validated
  locally with the field name and limit before anything is sent), and
  `ChromeOsClient::update_annotated_fields` — one `PATCH` per device, empty
  clears, absent leaves untouched.
- `RemoteWriter::write_field` — the third remote operation. The unavailable
  writer refuses it with the same actionable message as the other two, and
  the commit path groups annotated items per (field, value) so two columns
  never share a call.

## [1.31.0] - 2026-08-08

The OneRoster API learns the list-query parameters every vendor sends
reflexively — an endpoint that silently ignores `filter=role='student'`
returns *wrong* data, not just unsorted data.

### Added
- **`filter`** on every OneRoster list endpoint: the 1.1 grammar — predicates
  over the response's own camelCase fields (dotted paths reach into
  `metadata`), operators `= != > >= < <= ~`, values single-quoted, joined by
  a single `AND` or `OR`. `X-Total-Count` counts what the filter matched. A
  malformed filter is a 400 with the reason, never an empty page — an
  integrator typo'ing a field name must hear about it, not sync zero rows.
- **`sort` + `orderBy`** on every list endpoint; rows missing the sort field
  order last in either direction, so a paging client meets every row exactly
  once.
- **`fields`** selection on every list endpoint; `sourcedId` always survives
  it, because a row a consumer cannot re-identify is useless.

## [1.30.0] - 2026-08-08

WS-15 begins: the identity console stops stubbing. The two `/identity` pages
that shipped as placeholders now render real data, and the AD sync gets the
same operator surface the Google sync has had all along.

### Added
- **Active sessions.** `/identity/sessions` lists everyone signed in through
  the identity provider right now — who, how (SAML, QR badge, picture
  password, password), since when, and until when. Expired sessions are gone,
  not greyed.
- **QR badge management.** `/identity/badges` lists every badge ever issued
  with its status; issue one by roster id or email; revoke from the list.
  Revoked badges stay listed so a found badge can be traced to when it died.
  The per-user issue shortcut on the users page now actually issues instead
  of saying "coming soon".
- **AD sync parity.** `/ad-sync` grows the affordances `/google-sync` has had
  all along: a manual trigger (background run; a failure before the engine
  starts is recorded as a failed run rather than vanishing into the logs), an
  embedded recent-history panel, `/ad-sync/history` (runs with per-run counts,
  groups, and error detail), and `/ad-sync/users` (every user the sync tracks
  and where it left them).

## [1.29.0] - 2026-08-08

WS-13: physical inventory. Everything here is built for a barcode scanner in
keyboard-wedge mode — a device that types what it reads and presses Enter — so
there is no hardware dependency, and a keyboard drives every flow identically.

### Added
- **Scan lookup.** `/devices/scan?code=…` jumps from a scanned tag or serial
  straight to the device page. One hit navigates; no hit or a duplicated tag
  lands on the searched inventory, whose empty and multi-row states already
  say the right things. The circulation desk gets an autofocused scan box —
  scan a label, land on the device, check it out.
- **Label sheets.** `/devices/labels` prints the current filtered view as QR
  labels (tag, serial, model), one crisp inline SVG per device, encoding the
  same string the scan lookup resolves. "Labels for the 400 Chromebooks at
  the middle school" is a filter, not a picker — the link on the inventory
  carries the active filter, exactly like the CSV export. A per-device sheet
  at `/devices/labels/{id}` covers the replacement sticker. Sheets over 1,000
  devices say they were cut rather than pretending they weren't.
- **Physical audit.** `/devices/audit` — pick a school (optionally an org
  unit), then walk the room scanning. The page reconciles every scan against
  what the inventory expects there: accounted for, not yet seen, and
  unexpected (a device from another school links to what it actually is; a
  code the inventory has never heard of says so). State lives entirely in the
  page — an interrupted audit loses nothing but its tab, and the server holds
  nothing between scans.

## [1.28.0] - 2026-08-08

WS-14: the fleet is no longer only Chromebooks. A generic MDM connector seam
brings Microsoft Intune (Windows) and Jamf (iPad) devices into the same
inventory, under the same matching discipline the ChromeOS sync established.

> **Validation caveat:** both connectors have been exercised against a mocked
> Graph/Jamf API only — token flow, pagination, field mapping, and the sync
> discipline are unit- and e2e-tested against local mock servers, but nobody
> has pointed them at a real Intune or Jamf tenant yet. Nothing here should be
> described as field-proven until somebody has.

### Added
- **MDM connector seam.** A read-only `MdmConnector` trait with a shared sync
  engine that inherits the ChromeOS rules verbatim: the console owns hardware
  facts, Chalk owns assignment and status, `manual`/`ignored` decisions are
  untouchable, the district's asset-tag sticker is never overwritten, and a
  merge into an existing CSV/manual row is recorded with the rule that joined
  them. Identity resolves by `(source, external id)`, then serial, then
  normalized asset tag.
- **Microsoft Intune connector.** App-only client-credentials against the
  Graph API, paged walk of `managedDevices`. Windows machines land as laptops,
  Apple mobile devices as tablets; enrolled-user UPNs match against the roster
  by exact email. Configured under `[mdm.intune]`.
- **Jamf Pro connector.** OAuth client credentials, paged `mobile-devices`
  walk, tablets with the enrolled username matched when it is an email.
  Configured under `[mdm.jamf]`.
- **`chalk mdm sync`** — `--source intune|jamf|all`, `--dry-run` walks the
  fleet and reports without writing. Also runs as a background job
  (`mdm_sync`) when a connector is configured, so `chalk serve` keeps the
  inventory fresh.
- **Source-aware console.** The device list grows a Source filter (derived
  from the enum, never a hand-kept list), and the device page states its
  source and shows a "From Microsoft Intune"/"From Jamf" card with the
  console's identity for the row — the Google card no longer claims devices
  it does not own.
- `assets.external_id` column: the row's identity in whichever console owns
  it, indexed with `source`.

## [1.27.0] - 2026-08-08

This completes the 1:1 device lifecycle loop: check-out with agreements and due
dates, repairs with costs, fees with a family ledger, lost/stolen with police
reports, loaners, and the emails that keep families informed along the way.

### Added
- **Lost / stolen.** Mark a device Lost from its page, record the police
  report (kept on the device, not just in the log), and optionally assess the
  replacement cost to whoever held it. "Mark found" brings it back.
- **Loaner pool.** A checkout can be flagged as a loaner — a temporary swap.
  The student keeps their primary device assignment while carrying it, and the
  circulation list says so.
- **Family notifications.** The requester's family is emailed when a device is
  checked out to them (with its due date), when a repair completes, and when a
  fee is assessed — each a courtesy, never a gate: with no mail server
  configured the desk works exactly as before. Scheduled return-due reminders
  arrive separately.

## [1.26.0] - 2026-08-08

### Added
- **Repair records.** "Repair" was only a status — now it is a record: what
  broke, the vendor, when it went out and came back, and what it cost. Opening
  a repair marks the device In repair; closing it returns the device to Active
  and can assess the cost as a fee to whoever holds it, in one step.
- **Fees and fines, surfaced.** A Fees card on the device page assesses
  repair fees, damage fines, loss replacement or other charges against the
  current holder, protection-plan aware. The person's page becomes the ledger a
  front office works from: every charge with its device and reason, the
  outstanding balance, and Waive / Mark-settled actions. **Assessment only** —
  Chalk records what is owed and how it was resolved; collection happens in the
  district's own system, and no payment-card details are ever taken. Amounts
  are immutable once recorded: a mistake is waived and re-assessed, so the
  ledger reads like a ledger.

## [1.25.0] - 2026-08-08

The first slice of the 1:1 device lifecycle loop.

### Added
- **The circulation desk.** Check a device out to a student or staff member
  from its page — by roster id or exact email, with an optional due date, a
  condition note, and a device-agreement acknowledgement — and check it back
  in with the return condition. Custody records carry what the single
  "assigned to" field never could: when it went out, due when, what shape it
  left and came back in, and who ran the desk. One open loan per device,
  enforced in the schema.
- **Checkout assigns, checkin unassigns — audited.** The desk writes through
  the same transactional audit path as every other assignment, and marks the
  match manual so a nightly sync cannot undo a hand-out.
- **/devices/circulation** — every open loan, soonest due first, overdue
  called out. The year-end collection list, linked from the sidebar.

## [1.24.0] - 2026-08-08

This completes the help-desk maturity workstream: everything a district
evaluating Chalk against Incident IQ or Vizor expects of a help desk now
exists — assignment, both SLAs, notifications, analytics, canned replies,
tags, saved views, routing, CSAT, an API, and now a knowledge base.

### Added
- **Knowledge base.** Articles IT writes once instead of answering the same
  question forever. Authored in the console at **Knowledge Base** (drafts and
  published, edit and unpublish any time); published articles appear on the
  staff help portal at `/help/kb`, readable without signing in. A draft is
  never visible on the portal — by list or by direct link — until published.

## [1.23.0] - 2026-08-08

### Added
- **Routing rules (auto-assignment).** "Hardware goes to Ana; anything from
  Beta Middle goes to Ravi." Rules match on category and/or school, the most
  specific rule wins, and ties go to the older rule so a new rule cannot
  silently steal traffic an admin already directed. Applied the moment a ticket
  is created — identically whether it was typed into the console, raised in the
  staff portal, or arrived by email. Managed at **Settings → Routing Rules**.
- **CSAT surveys.** Resolving a ticket emails the requester five one-click
  rating links. No sign-in needed — an unguessable token is the credential —
  only the first answer counts, and a ticket is surveyed once ever, however
  many times it is re-resolved. The analytics page gains a Satisfaction card
  with the average rating and response rate.

## [1.22.0] - 2026-08-08

### Added
- **Ticket tags.** Free-form labels — "wifi", "cart-3" — edited on the ticket
  page and shown as chips on the queue and detail views, each a link to the
  queue filtered to that tag. Tags are normalized (trimmed, lowercased,
  de-duplicated), and a tag dropdown appears in the queue toolbar once any
  ticket is tagged.
- **Saved queue views.** Name the filter you are looking at — "Unassigned
  urgent", "Gym wifi" — and it becomes a one-click bookmark above the queue,
  with a delete control. A saved view stores the queue's own query string, so
  it can never drift from what filtering actually does.

## [1.21.0] - 2026-08-08

### Added
- **Resolution SLA** — the second deadline the PRD promised alongside first
  response. Each priority gets its own resolution target (looser defaults than
  the response windows, because answering fast and fixing fast are different
  promises), computed at creation and recomputed when the priority changes. The
  ticket page shows both targets, each with a "Past due" badge, and a ticket can
  meet its first-response deadline while still missing this one. Working-hours
  calendars remain deliberately out of scope — they need a district's own term
  dates and holidays.

## [1.20.0] - 2026-08-08

### Added
- **Canned responses** (reply macros). Shared, district-wide reply templates a
  technician can drop into a ticket instead of retyping the same answer —
  "have you tried a hard reset", "your device is ready for pickup". Managed at
  **Settings → Canned Replies**; every ticket's reply box gains a picker that
  fills the box from a saved reply, as a starting point to edit rather than a
  send button.

### Fixed
- **Migration robustness.** The SQLite migration runner splits each file on `;`
  with no SQL parsing, so a semicolon inside a comment silently corrupted a
  migration — a mistake that shipped twice. Full-line `--` comments are now
  stripped before the split, making the whole class of failure impossible
  rather than something to remember not to do.

## [1.19.0] - 2026-08-08

Help-desk maturity, part two. Where 1.18.0 taught the help desk to hand out
work and talk back, this makes it legible: a lead can see how the team is doing,
a technician on a device sees its ticket history, and an integration can read
the desk over HTTP.

### Added
- **Ticket analytics** at `/tickets/analytics`: volume by status and priority,
  the backlog that is unassigned or breached, per-technician workload, and
  volume by school. Every figure links to the queue filtered to exactly it.
  Per-technician workload is the number that only exists now — it needs the
  technician identity (1.17.0) and assignment (1.18.0) to be real — and it
  carries a "past target" column that says who needs a hand.
- **Device → ticket back-link.** A ticket already carries the device it is
  about; the device page now lists the tickets raised about it, linked, so a
  technician sees a device's help-desk history without searching the queue for
  its serial.
- **Read-only ticket REST API** at `/api/helpdesk/v1` (gated with the module):
  list tickets, one ticket, and one ticket's thread. Scope is applied in SQL, so
  a scoped token's `X-Total-Count` never leaks the size of the part of the desk
  it was denied, and a ticket outside the scope is 404, not 403.

### Changed
- **Editable priority and category** after a ticket is raised — and changing the
  priority now recomputes the response deadline. Previously the deadline was set
  once at creation and never recomputed, so escalating a ticket to Urgent left
  it at the relaxed Normal target and the breach badge lied. The new target is
  anchored to the ticket's arrival time, since the first-response clock has been
  running since it came in.

## [1.18.0] - 2026-08-08

The help desk starts talking back. Two things a district evaluating against
Incident IQ or Vizor expects on day one — a technician can be handed a ticket,
and the person who raised it hears back when IT replies — were both missing.
This is the first slice of WS-11 (help-desk maturity), built on the technician
identity (F1) and the general notifier (F2) that shipped in 1.17.0.

### Added
- **Ticket assignment.** A ticket can now be assigned to a technician — a
  console user (F1), not a roster user, because the person who works the help
  desk is IT staff, not a student or teacher in the SIS. The detail page gains
  an assign dropdown and a one-click **Claim** for whoever is signed in. The
  queue's "unassigned" count and filter now mean *no technician has picked it
  up*, and the assignee shown throughout is the real person.
- **Reply notifications.** When a technician posts a public reply, the requester
  is emailed it, threaded under the ticket, with a link back to their portal.
  Internal notes send nothing — the disclosure boundary is kept. Uses the F2
  notifier, so self-host degrades cleanly when no transport is configured.

### Notes
- Migration 029 adds `assignee_console_user_id`; the original roster assignee
  column is left in place, harmless and unused. A suspended technician cannot be
  assigned to, and a non-active assignee id is refused server-side — the foreign
  key alone is not enough, since a suspended account still satisfies it.
- **Groundwork (no user-facing surface yet):** a `charges` ledger (migration
  028) landed in core — the F3 foundation for repair-cost and fee/fine
  *tracking*, insurance-aware, assessment-only (no payment gateway, no card
  handling). The student-balance UI arrives with the device-lifecycle loop
  (WS-12).

## [1.17.0] - 2026-08-08

The console gets real people. Until now it authenticated one shared district
password and attributed every action to "console:admin", so a district could
not see which technician resolved a ticket or changed a device, assign work to
a person, or hold anyone accountable in the audit log. This is the first
foundation of the feature-completion program (a market-parity audit against
Incident IQ and Vizor); the notification groundwork that unblocks an
email-capable help desk landed alongside it.

### Added
- **Per-person console accounts.** `console_users` is a namespace separate from
  the SIS roster on purpose — IT technicians are frequently not in PowerSchool
  (contractors, department staff, a help-desk vendor), so tying console identity
  to the roster would lock them out. Each account has an email, a password, and
  a role: **admin**, **technician**, or **read_only**.
- **Named attribution.** A signed-in technician's device edits now record their
  name in the audit history instead of the anonymous "console:admin", which is
  kept for the shared-password path (self-host is unchanged).
- **Role enforcement.** A read-only account may look but change nothing; only an
  admin may manage console accounts. Enforced in the auth middleware before any
  handler runs.
- **Management UI** at `/settings/console-users` — list, create, and disable
  accounts — plus `chalk console-users add|list` to bootstrap the first account
  from the CLI (the account you would otherwise need in order to reach the UI).
  The password is read from stdin, so it never lands in shell history.

### Changed
- **The mailer is now a general `Notifier`.** It could send exactly one thing —
  a sign-in link — which is why the help desk is inbound-only: a technician's
  reply cannot reach the requester because nothing can send it. The trait now
  sends any message; the sign-in email is unchanged, byte-for-byte. This is the
  groundwork for outbound help-desk and device-lifecycle notifications.

### Migration
- Migration 027 adds `console_users` and identity columns on `admin_sessions`.
  Additive and backward compatible: an install that never creates a console
  account behaves exactly as before.

## [1.16.1] - 2026-08-07

### Security
- **Two more SAML paths still downgraded to unsigned assertions.** v1.15.1
  removed that fallback from one of three issuing sites; `routes.rs` and the
  launcher portal kept theirs, and the portal is the most-used SSO path. Both
  now fail the login rather than emit an unsigned assertion.

### Changed
- **One function now decides whether a SAML response is signed.**
  `build_response_for_login` takes the signing material as an `Option` and
  returns a `Result`: no key configured means unsigned, which is honest for a
  deployment that never promised otherwise; a key configured means signed or an
  error. There is no third outcome, and a caller cannot express one.

  This replaces a grep-based test that looked for the mistake textually. That
  test could not work: the legitimate unsigned branch sits a few lines from the
  signed call and reads identically, so any window wide enough to catch a
  fallback also flags correct code. Mutation testing showed it silently failing
  to fire. The unsigned builder is now `pub(crate)` with no callers outside its
  own module, so the fallback is not something that can be written.

## [1.16.0] - 2026-08-07

### Fixed
- **SAML assertions were still rejected by conforming Service Providers, even
  after the signing fix.** An SP validates two things: that the signature over
  `<ds:SignedInfo>` is good, and that the `<ds:DigestValue>` inside it matches
  the referenced element recomputed with the `<ds:Signature>` removed. Only the
  first was correct.

  The digest was taken over the assertion as it stood *before* the signature was
  spliced in. The splice injects an indent ahead of the signature, and removing
  the element leaves that indent behind — so the SP hashed a string two
  characters longer than the one we hashed. A correctly signed assertion with a
  Reference that did not match, which an SP reports as a generic validation
  failure.

  The digest is now taken over the post-removal document, assembled from the
  same pieces the final document is, so the two cannot drift apart. A test
  performs the SP's own check.

  **This means v1.15.1's fix was necessary but not sufficient**: signing worked
  from that release, and interoperable assertions only from this one.

### Known limitation
- The XML-DSig implementation does not canonicalise. It declares
  `exc-c14n` and digests the document as written, which matches only because
  the XML we emit is already close to canonical form. An SP that strictly
  canonicalises before hashing may still disagree, and that cannot be settled
  without testing against a real Service Provider. **SAML SSO should be treated
  as unverified against third-party SPs until that test happens.**

## [1.15.3] - 2026-08-07

### Fixed
- **CI's new Postgres step forced illustrative doc examples to compile.**
  `--ignored` means two unrelated things: `#[ignore]` on a test is "skip unless
  asked", while ```` ```ignore ```` on a doc example is "this is illustrative,
  do not compile it". Running `cargo test --all -- --ignored` forced the second
  kind, and two `str_enum!` examples failed — a broken command that read as a
  broken test suite. Now scoped with `--lib --tests`.

## [1.15.2] - 2026-08-07

### Fixed
- **Concurrent Postgres migrations could fail or apply against a half-built
  schema.** Two races, both reachable in the hosted runtime, where tenant state
  is built on demand and two simultaneous first requests for the same tenant
  run migrations at once.

  `CREATE SCHEMA IF NOT EXISTS` is a check-then-act against the system catalog
  and takes no lock, so both callers see "not there" and the loser fails with a
  unique violation on `pg_namespace`. Losing that race means the object exists,
  which is what the caller wanted, so it is now treated as success.

  The second is worse. Each migration version was claimed atomically with
  `INSERT ... ON CONFLICT DO NOTHING RETURNING`, and a caller that lost the
  claim skipped to the next migration **without waiting** — applying 002 while
  the winner was still running 001, and failing with `relation "users" does not
  exist`. Claim-and-skip makes a version atomic; it does not order them. The
  whole run is now serialised per schema with a Postgres advisory lock, keyed
  off the schema name so unrelated tenants never block each other.

  The previous comment argued an advisory lock was impossible because pinning a
  connection trips an sqlx HRTB and makes the future non-`Send`. It does not:
  the lock is held on its own connection while the DDL keeps running on the
  pool, and advisory locks are per-session rather than per-statement.

  Found by turning on the `#[ignore]`d Postgres suites in CI — the test for
  this had been written, marked ignored, and never run.

## [1.15.1] - 2026-08-07

### Security
- **Every SAML assertion was being issued unsigned.** `generate_saml_keypair`
  used `rcgen::KeyPair::generate()`, which defaults to ECDSA P-256, while the
  signer uses `rsa::pkcs1v15` and writes a `<ds:SignatureMethod>` advertising
  `rsa-sha256`. It could never load the key it was given, and failed with
  "unknown/unsupported algorithm OID" on every attempt.

  Nothing surfaced that. The caller caught the error, logged a warning, and
  fell back to the *unsigned* response builder — so assertions went out with no
  `<ds:Signature>` at all. A Service Provider that validates signatures rejects
  those, which looks like a broken SSO integration; one that does not validate
  accepts an unauthenticated login.

  Two fixes. The generator now produces RSA-2048 explicitly, matching what it
  advertises. And a signing failure no longer downgrades: if an administrator
  configured a signing key, an assertion that cannot be signed fails the login
  instead of going out unsigned, because promising `rsa-sha256` and then
  sending nothing is worse than refusing.

  **Anyone already running SAML SSO should regenerate their keypair** — an
  existing ECDSA key on disk will still fail to sign, and now fails the login
  rather than silently downgrading.

  Found by writing the cross-tenant SAML isolation test that had been an
  `unimplemented!()` stub since it was added.

### Added
- **Tests at the seam between key generation and signing.** The existing cert
  tests checked PEM headers and non-emptiness, which an unusable ECDSA key
  satisfies perfectly — generation and signing were each internally consistent
  and only using one against the other catches this. Also a real cross-tenant
  test: two tenants get distinct keypairs, and an assertion signed by one does
  not verify against the other.
- **CI now runs the `#[ignore]`d Postgres suites.** `cargo test --all` skips
  them, so the only database CI ever exercised was SQLite while every hosted
  tenant runs on Postgres. Schema parity, migration serialisation and tenant
  isolation were checked only when someone remembered to run them locally.

## [1.15.0] - 2026-08-07

Dependency modernisation. Every open Dependabot PR is answered here, several
of them differently than proposed.

### Security
- **`quinn-proto` updated past RUSTSEC-2026-0185** (remote memory exhaustion,
  high). Pre-existing and only newly disclosed — the same lockfile passed
  `cargo audit` in CI a day earlier.
- **`jsonwebtoken` 10 needs a crypto provider chosen explicitly.** It defaults
  to neither and panics at the first signature. It compiles clean, so nothing
  but a runtime test catches it; ours did. Left unpinned this would have been
  a crash on a district's first Google sync. Now on `rust_crypto` — pure Rust,
  because release builds cross-compile to four targets including Windows.
- **A malformed webhook payload could panic the process.** `decrypt_payload`
  passed a base64-decoded nonce straight to `Nonce::from_slice`, which panics
  on the wrong length, and nothing checked it was twelve bytes. Valid base64 of
  the wrong size is trivial to send. Now an error, with a test.

### Changed
- **RustCrypto moves to the digest 0.11 line**: `sha2` 0.11, `hmac` 0.13,
  `hkdf` 0.13, `aes-gcm` 0.11. These have to move together or the types stop
  composing. The graph now carries two `sha2` versions, because `rsa` has not
  shipped a stable release on the new line (latest is `0.10.0-rc.18`) and
  `argon2` stable is still 0.5. That resolves when `rsa` 0.10 lands.
- **`rand` 0.9**, which renames the core API and moves `OsRng` behind
  `TryRngCore`. Webhook secret generation stays on the OS RNG rather than
  moving to `rand::rng()`, and panics if it is unavailable: there is no weaker
  entropy worth falling back to for a signing key.
- **`askama` 0.16**, `askama_axum` removed. It was deprecated and nothing
  imported it; the axum integration now comes from `askama_web`. In templates,
  `{% endcall %}` became mandatory (47 sites) and the escaper writes `&#38;`
  where it used to write `&amp;` — identical to a browser.
- **`toml` 1.1, `rcgen` 0.14, `ldap3` 0.12**, and CI actions to current. Note
  Dependabot's proposals were themselves stale: it offered `actions/cache` 4→5
  when v6 exists, and a `quick-xml` 0.40.1 bump for a workspace already on 0.41.

### Added
- **Regression guards for values that outlive a dependency bump.** A ciphertext
  written by aes-gcm 0.10 is now a fixture, because a round-trip test moves
  both ends together and cannot detect a format change — every sealed secret a
  district already holds was written by that version. The webhook signature and
  derived key are pinned to values from an independent HMAC/HKDF
  implementation, since receivers verify them. SAML signatures are now verified
  cryptographically, including that a tampered `SignedInfo` fails; nothing
  checked that before, so the suite would have passed with the wrong hash and
  the symptom would have been districts unable to log in.

## [1.14.0] - 2026-08-07

### Security
- **`chalk serve` refuses to start a console that nothing authenticates.** The
  console has always skipped authentication entirely when `[chalk]` has no
  `admin_password_hash` and magic-link login is off — written as a
  local-development convenience, but `serve` binds `0.0.0.0` and always has, so
  it was never confined to the laptop it was meant for. In that state the
  roster, the help desk and every ticket attachment were served to anyone who
  could reach the port, with nothing in the console or the logs to distinguish
  it from a properly closed one.

  `chalk init` writes a password hash, so reaching this state takes a
  hand-edited or partially-restored config — which is exactly the case worth
  catching, because it is invisible from the inside. Startup now fails with a
  message naming the fix.

  Chalk behind a reverse proxy that authenticates in front of it is a real
  deployment, so the door remains: set `CHALK_ALLOW_UNAUTHENTICATED=true` and
  it starts, logging a warning every time. **If you run Chalk without a console
  password today, set one before upgrading, or set that variable** — otherwise
  this release will stop your server rather than continue exposing it.

### Added
- **`chalk passwords admin-hash`.** Reads a password from stdin and prints the
  `admin_password_hash` line to paste into `chalk.toml`. `chalk init` was the
  only thing that ever wrote that key, so an operator whose console had no
  password had no supported way to give it one — a startup error naming a fix
  that does not exist is not a guard, it is a wall.

  It prints rather than edits, because rewriting `chalk.toml` means
  re-serialising it and discarding the comments and ordering the operator put
  there. Reading from stdin rather than an argument keeps the password out of
  shell history and out of `ps`.

## [1.13.1] - 2026-08-06

### Fixed
- **The help portal's sign-in page offered a button it could not honour.** On
  a deployment with no mailer it correctly said "Email sign-in is not set up"
  and then rendered a working "Email me a link" form underneath, because the
  form was gated on the *notice* being empty and a refusal puts its message in
  *error*. Somebody reads the refusal, types their address anyway, and presses
  a button that does nothing. Found by running the hosted runtime against a
  real Postgres, where no Postmark token means no mailer.

## [1.13.0] - 2026-08-06

The help desk becomes something a district can actually run. Until now it had
a queue and a way for an administrator to type into it; now the person with
the broken Chromebook can reach it themselves — from a browser, or by simply
replying to an email — and send a photograph of what is wrong.

### Added
- **The staff help portal (`/help`).** Sign in with a link emailed to a roster
  address, ask for help, follow what happens, reply. Deliberately not behind
  the roster/SSO module: that module is not in the Devices + Helpdesk tier, and
  a district sold a help desk with nowhere for its staff to use it would be a
  bad joke. A requester sees their own requests and nothing else — enforced in
  SQL, and a request that is not yours is *not found* rather than *forbidden*,
  because a distinguishable refusal confirms the id exists.
- **Attachments, from either side.** "The screen is broken" and a photograph of
  the screen are not the same request: the photograph says whether it is the
  panel or the digitiser, and whether it is an insurance claim, before anyone
  walks to the classroom. Files are typed by their leading bytes rather than
  their name, only formats that cannot carry script render in place (SVG is
  deliberately unrecognised), and every response carries `nosniff` and a
  sandbox CSP.
- **Email ingestion, with a provider seam.** `postmark` for the hosted
  webhook and `generic` for any relay that can POST a documented JSON shape.
  The provider-specific part is one small parser each; threading, deduplication
  and whether `From:` may be trusted are shared, so a district on one provider
  cannot quietly get different behaviour from a district on another. Auto-
  replies are dropped (and answered `200`, or the provider redelivers the
  vacation responder forever), redeliveries find what they already created, and
  an unauthenticated sender still files a ticket — attributed to the address
  rather than to a person, because `From:` is a claim.
- **SMTP (`[mail]`).** Chalk speaks SMTP to a server the district already runs.
  There is deliberately no integration with a third-party sending service:
  self-hosting must not mean signing up for somebody else's account or routing
  pupils' names through a vendor nobody chose. An unrecognised `security` value
  selects starttls, never plaintext.

### Changed
- **`modules.roster_sso` is enforced.** It had existed as a config field that
  gated nothing, which on hosted meant giving away the thing separating the
  Devices + Helpdesk tier from Full stack. It gates Chalk serving identity
  *outward* — the SAML IdP, OIDC, the launcher portal, the OneRoster API,
  Workspace/AD provisioning — and deliberately not roster ingestion, because
  the device inventory and the help desk are built on that roster. The API is
  withheld with the pages: one left answering is the door a script uses.
- Config validation no longer demands `idp.saml_cert_path` when the module is
  off. Turning a module off has to be a way *out* of a misconfiguration.
- `chalk --help` no longer describes Chalk as an "SIS integration platform" —
  the positioning WS-0 retired, still shipping three releases later because
  `messaging-lint.sh` watched marketing copy and nobody greps a clap attribute.
  It has a rule now.

### Fixed
- **The sidebar offered a Marketplace page this build has never served** — the
  marketplace lives in the hosted runtime, so every self-hosted install since
  that entry was added showed a nav item that 404'd.
- **A redelivered email *reply* returned 500**, so a provider would retry it
  forever — the exact loop the design is about. A reply's message id lives on
  the comment, not the ticket, and idempotency only checked tickets.
- **`From: Lisa Nowak <lisa@example.edu>`** matched no roster user, because the
  whole header was compared instead of the address inside it. The ticket was
  still created, merely attributed to something that is not an address.
- **An emailed sign-in link had no host** when `chalk.public_url` was unset —
  the message arrived, looked correct, and could not be opened. Both a mailer
  and a public URL are now required, and the same latent bug in the admin
  magic-link path is fixed.

## [1.12.0] - 2026-08-04

Until now a ticket could only be created by writing to the database. The queue
existed and nothing could fill it.

### Added
- **Raise a ticket (`/tickets/new`).** For the request that arrived by phone or
  in person. Search the roster for the requester, or give an email address for
  a parent, a substitute, or staff whose account has not synced — refusing them
  for want of a roster row sends their request nowhere.
- **`TicketService` (`chalk_core::ticket_service`)** — the policy that must not
  differ by how a request arrived. Three things will create tickets (an
  administrator, the teacher portal, inbound email); if each computed its own
  response target, the email-sourced ticket from the person least able to chase
  it would quietly get the worst treatment. The surfaces collect input; this
  owns what is derived.
- **Response targets (`[helpdesk]`).** Hours to *first response* per priority,
  because that is the number a district can commit to and a technician can
  control — resolution time depends on parts, vendors and the requester
  replying. Defaults 2/8/24/72 hours. Set one to `0` for "no target at this
  priority", which is honest; a deadline you do not mean is worse than none.
- **The requester's device is attached automatically.** The helpdesk half of
  the wedge: the device module already knows who holds what, so nobody types an
  asset tag and the ticket's school is taken from the device. Deliberately
  silent when a person has several devices — the wrong asset tag on a repair
  ticket sends a technician to the wrong machine, and a blank one sends them to
  look. Configurable via `attach_requester_device`.

### Changed
- A refused form comes back with what was typed still in it, including the
  description, which is the part that took effort to write.
- `ChalkError::Validation` — input a person supplied, with a message written
  for them. Distinct from `Config` because a handler may render it straight
  into a form, which it must never do with a database or upstream-API error.

## [1.11.1] - 2026-08-04

### Fixed
- **The sidebar offered a Marketplace page this build has never served.** The
  marketplace lives in the hosted runtime, which merges its own `/marketplace`
  router on top of the console's; this repository has no such route. The link
  was drawn unconditionally, so every self-hosted install since the entry was
  added has shown a nav item that 404s. It is now gated on
  `marketplace.enabled`, which is off by default and documented as
  hosted-only.

  Found by walking every console page by hand after 1.11.0 — **not** by the
  nav test shipped in that release, which enumerated the two modules it was
  written for and passed while sitting next to this. That test has been
  replaced by one that extracts every link `base.html` actually rendered and
  asserts each resolves, so a new sidebar entry cannot be forgotten: a guard
  that only checks the cases you thought of certifies your assumptions rather
  than the invariant.

## [1.11.0] - 2026-08-03

The helpdesk gets a face. Tickets have had a data model since 1.10; this is the
screen a technician actually opens in the morning to answer one question —
*what should I do next?*

### Added
- **The technician queue (`/tickets`).** Filter by status, priority, assignment
  and free text; sort by number, status, priority or age; page and bookmark it,
  because a filtered view is a URL. Three counts sit above the table — past due,
  unassigned, open — each computed over the whole queue rather than the visible
  page, and each a link to the filter that produced it.
- **The ticket thread (`/tickets/{id}`).** The request, the people, the device,
  and a conversation. Replies and internal notes post from the same form;
  internal notes are marked in words as well as colour and are filtered out in
  SQL, not in a template, so one cannot reach a requester by someone reordering
  a loop.
- **Status transitions with honest timestamps.** Resolving stamps
  `resolved_at`; closing keeps it and adds `closed_at`; reopening clears both,
  because a ticket that is open again was not resolved and leaving the stamp
  would make every resolution-time report lie.
- **`NewTicketComment::from_console`** — a comment authored by the admin
  console, which has no per-person identity to record. The thread says
  "IT staff" rather than inventing a name, and `author_user_sourced_id` is a
  foreign key into `users`, so an invented one was never storable anyway.

### Fixed
- **A ticket waiting on its requester is no longer shown as past due.**
  `waiting` pauses the SLA clock — that is the documented reason the status
  exists — but the breach rule was written out three times (Rust, SQLite,
  Postgres) and all three checked only "not resolved or closed". A technician
  saw a red badge on a ticket they could not clear by doing anything. All three
  now derive from `TicketStatus::clock_runs`, and a test sweeps every status to
  keep them agreeing.
- **Sorting by priority ordered alphabetically.** The stored strings sort as
  high, low, normal, urgent, which put *low* above *normal* and buried *high* —
  backwards for the sort a triage queue exists to offer. Priority and status
  now sort by rank through a `CASE` built from the enum, so a new variant
  cannot be left unranked.
- **`chalk serve` never attached the ticket repository**, so `/tickets` 404'd
  even with `modules.helpdesk = true`.
- **The sidebar advertised modules this deployment does not have.** Routes for
  a disabled module were withheld, but the link to them was still drawn, so
  turning the helpdesk off left a Helpdesk entry that went straight to a 404 —
  which an operator reasonably reads as the product being broken rather than
  the module being off. The shell now takes a `Nav` carrying both the current
  page and the enabled modules, so `base.html` and the router read the same
  flags. Because `base.html` refers to those fields, a template that extends
  the shell without supplying them does not compile. A test asserts, for every
  gated module and in both directions, that a link is shown exactly when its
  routes are served.
- **The past-due triage card rendered with no left border at all.** Its
  modifier lived in `components.css` while `.stat-card` lives in `console.css`,
  which loads later — so at equal specificity the base rule won and the most
  urgent card became the only one with no accent. A new cascade lint
  (`assets::cascade`) fails the build when a `.block--modifier` is declared
  before a `.block` rule that sets the same property family.

### Changed
- The queue resolves display names for only the people named on the page,
  rather than loading the whole roster. A district with twenty thousand users
  would otherwise have loaded all of them to label fifty rows.

## [1.10.0] - 2026-08-02

Chalk can change a district's Google fleet, not only read it — behind the same
preview every other bulk change goes through, and a second gate for the one
action that cannot be undone.

### Added
- **Google write-back.** Move devices between org units, disable, re-enable and
  deprovision. The planner emits items marked `remote_target = google`; the
  commit path applies local items first, then groups the remote ones by exactly
  what will be sent, so five hundred devices bound for one org unit is one call
  and two destinations can never share a request.
- **`RemoteWriter` (`chalk_core::remote_write`)** — the seam that keeps
  `chalk-core` a leaf. It never learns the Directory API exists;
  `chalk-devices` implements the trait over `ChromeOsClient`. The writer answers
  **per device**, never per request: chunking is the implementation's business,
  and the commit loop cannot record what happened to each device if it is handed
  one verdict for fifty.
- **A third outcome.** `moveDevicesToOu` and `batchChangeStatus` are
  chunk-granular, so a timeout says nothing about any individual device. Items
  can end `indeterminate` — "may have applied, verify" — which is never
  auto-retried. `failed` now means Google refused *before* touching anything,
  and is therefore safe to re-arm.
- **Chunked write methods** on `ChromeOsClient`, at Google's documented ceiling
  of 50, executed serially so each outcome persists before the next call.
- **`write_back_enabled`** — a separate per-tenant opt-in (TOML and migration
  026), off by default, with a toggle on the Connect Google page. Reading a
  district's fleet and changing it are different levels of trust.
- **A typed confirmation for deprovision** (DESIGN_SYSTEM §5.11). The
  consequence is the heading, the device count is typed, and the *server* checks
  it — recounted from the stored items, so striking a row out changes the number
  that confirms. There is deliberately no "do not ask again".
- **`chalk devices changeset list|show|retry-failed`** — inspect and re-arm a
  fleet change from a terminal. The moment an operator most needs to look at a
  change set is when something went wrong, which is exactly when they may be on
  SSH with the server misbehaving; the previous answer was `sqlite3`.
- **`chalk devices push --to-ou`** — plan a move and print it. Never applies:
  reviewing and committing stay in the console, where the diff is checked row by
  row.

### Changed
- Three Google API constants, verified against the live documentation, each of
  which would otherwise have been a production bug: `orgUnitPath` on
  `moveDevicesToOu` is a **query** parameter rather than a body field;
  `batchChangeStatus` is colon-transcoded (`chromeos:batchChangeStatus`); and
  only four of Google's eleven deprovision reasons are selectable by a district
  — four are deprecated and one is settable only by a repair centre during an
  RMA. Both write endpoints cap at 50, correcting the plan's 20.
- A deprovision carries its reason inside the enum variant, so a deprovision
  without the reason Google requires cannot be constructed.
- `ARCHITECTURE.md` §5.2, §5.4, §6.3 and §6.4 record what shipped, including
  that nothing writes `partial` and that the third item state exists.

### Fixed
- **Write-back had no way to be turned on.** The handler read the field, the
  page never sent it, so every save of Connect Google silently set it to false —
  while the commit path's own error told operators to turn it on in Settings.
- **The delegation panel showed the wrong scopes.** It always listed the
  read-only set. That panel is the exact text an administrator pastes into their
  Admin console, and domain-wide delegation matches the literal string: a tenant
  that enabled write-back would have granted read-only and then had Chalk request
  read/write, which returns a 403 that looks nothing like a scope problem. "Test
  connection" had the same flaw, so it would have reported a healthy connection
  right up until the first write failed.
- The preview no longer tells operators that Google rows "cannot" be applied and
  will be "left alone" — they can, and saying otherwise claimed an approved
  change would be ignored.
- A status action is shown as "Deprovision — Retiring from the fleet" rather
  than its wire encoding `deprovision:retiring_device`.

## [1.9.1] - 2026-08-01

### Fixed
- **A page past the end of a result set could report a reversed range** —
  `51–1 of 1` for page 2 of a single result. Handlers clamp before they query,
  so it never surfaced in the console, but the guarantee lived in every caller
  rather than in the type doing the describing. `TableNav` now holds the
  displayed page inside the table's real bounds, so it cannot describe a page
  that does not exist.

  Found by replacing a flaky test rather than by the bug being reported. The
  old test searched the whole rendered document for the substring `"801"` to
  catch exactly this reversed range — but the page also carries a random 64-hex
  CSRF token, which contains that substring about 1.5% of the time. It was a
  1-in-66 coin flip that passed locally for months and failed on CI. Replacing
  it with an invariant sweep over every page/per_page/total combination — no
  HTML, no randomness — surfaced the real defect immediately.

## [1.9.0] - 2026-07-31

Devices can get in and out of Chalk without Google. A district's existing
inventory arrives as a spreadsheet, and leaves as one.

### Added
- **CSV export of the filtered inventory (`/devices/export.csv`).** Whatever the
  inventory is currently showing, as a file. An open-source product a district is
  weighing against Snipe-IT has to be able to say "your data is yours, here it
  is", and a filtered export is that sentence in working form. Capped at 50,000
  rows.
- **CSV import, through the diff preview (`/devices/import`).** Rows are matched
  to devices by serial number first, then asset tag — serial wins because it is
  stamped on by the manufacturer, while tags get reused across refresh cycles — so
  a re-import updates rather than duplicating. A row matching nothing adds a
  device, marked `source = csv`.

  The upload writes nothing. It compiles to a change set and lands on the same
  preview a bulk edit produces, which is the third entry point ARCHITECTURE §6.4
  anticipated and needed no new screen. A spreadsheet is the highest-leverage and
  least-reviewed input a district has — someone sorts one column without extending
  the selection and the file still looks fine — so it gets the gate every other
  fleet-wide write gets.
- **One shared column contract (`chalk_core::asset_csv`).** Export and import read
  the same list, so a round trip is lossless by construction rather than by luck.
  Google-owned columns — org unit, annotated user, AUE date, device id — are
  written for reference and **ignored on the way back in**: accepting them would
  let a CSV appear to change values the next sync immediately overwrites.
- `ChangeSetRepository::mark_item_created` — the create counterpart to
  `mark_item_applied`. One transaction over the asset insert, its audit event, and
  the item's status, with the item pointed at the device it just made.
- `AssetRepository::find_assets_by_asset_tag`, returning a list rather than an
  `Option` because asset tags carry no unique index.

### Changed
- The preview's summary strip counts **changes**, not devices. A bulk edit is one
  item per device; a CSV import is one item per field, and the same strip renders
  both.
- Audit events written by a commit record which entry point produced them
  (`via: csv_import` / `via: bulk_edit`) rather than always claiming a bulk edit.
- `AssetCsvRow` parses dates rather than carrying strings, so `08/01/2024` is
  reported as "row 47" while the operator still has the file open — not as a
  failed item after they approved a preview.

### Fixed
- **Every console table rendered with a broken header below 768px.** A
  `table { display: block }` mobile-scroll hack stopped rows stretching to the
  table's width, so the sticky header's grey background — and the hover state,
  the selected-row tint and the struck-out preview row — ended at content width
  instead of spanning the row. The state telling an operator which rows they had
  picked was the thing that disappeared. Narrow screens now scroll the
  *container*, which fixes all twelve tables across the console — including the
  nineteen templates whose tables have no `.table-container` wrapper and which a
  wrapper-scoped fix silently missed.
- A created row's "not in Chalk" is no longer struck through in the diff preview.
  Nothing is being superseded, and a strikethrough on the one row type that
  cannot be undone by planning the opposite was exactly the wrong place to be
  confusing.
- **Uploads between 4 MiB and their route's stated limit were rejected with a bare
  400.** The CSRF middleware buffers a multipart body before any route's
  `DefaultBodyLimit` applies, and its own cap was an independent literal in a
  different file. It is now one constant, `csrf::MULTIPART_BODY_LIMIT`, and every
  upload route asserts at compile time that it sits at or below it — a build
  failure rather than a rule to remember.

## [1.8.0] - 2026-07-31

The first-run arc, end to end: connect Google Workspace, watch a sync run, and
land on an inventory of devices already attached to real students — with the
ones that could not be placed shown honestly rather than hidden.

### Added
- **The unmatched queue (`/devices/unmatched`).** The screen that makes "4,812 of
  5,000 devices attached to students" believable, by being conspicuously honest
  about the rest. Every row states its own evidence — no Google user (a cart),
  free text where an address was expected, or an address no roster user claims —
  because those three have completely different remedies. Per-row resolve with a
  roster type-ahead seeded from the stale address, plus ignore and bulk ignore for
  shared devices. Selection is page-scoped, not filter-scoped: treating a filter as
  a write scope is only safe once a diff preview stands between the filter and the
  write, and that does not exist yet.
- **Action history, per device and district-wide.** `asset_events` rendered as
  sentences naming the rule that fired — "Matched by the Google user set on the
  device" — with the matched address underneath, because that is what makes a wrong
  match checkable. A human decision and a rule firing are worded so they can never
  be confused. Filterable by event type, by school, and by actor. A new device
  detail page at `/devices/{id}` is the home for per-device history.
- **Background jobs (`jobs`, migration 023) and a `JobRunner`.** The queue is a
  table; a worker in the server process claims rows with a conditional `UPDATE`
  checked by `rows_affected`, which is correct on both drivers without
  `SKIP LOCKED`. Handlers are registered by the binary rather than matched inside
  the runner, so `chalk-core` stays a leaf crate and the console never learns that
  `chalk-devices` exists. Startup recovery fails abandoned jobs and never re-queues
  them: a job that writes to Google may have applied part of its work.
- **Connect Google Workspace (`/devices/connect`).** Upload a service-account key
  and have it stored sealed. The client ID and exact scope list Google's
  domain-wide delegation form asks for are rendered as click-to-select fields taken
  from the key itself — that panel exists because a mistyped delegation grant is
  the largest support cost in this feature, and every symptom of one looks like a
  Chalk bug. "Test connection" makes one real read and reports what it can *see*,
  distinguishing "delegation was never granted" from "granted, but not these
  scopes", which Google reports with the same status code.
- **Sync trigger and live progress (`/devices/sync`).** The console enqueues a job;
  the worker runs it. Real counters from the run row, which the engine updates
  mid-run, and a result that leads with devices matched to students rather than
  records processed. Polling stops when the work does. A run whose worker died is
  reported as interrupted rather than left spinning, and is never resumed
  automatically. Throttling is surfaced while a sync is still slow, not after.
- **Sealed per-tenant configuration on self-host.** `core::db::sealing` provides a
  `TenantConfigRepo` wrapper that seals secrets with the master key `chalk init`
  already writes. The only such wrapper previously lived in the hosted crate, which
  is why every settings page on a self-hosted install rendered "not configured".
- **`tenant_config_devices` (migration 024).** Device-sync configuration with an
  AES-256-GCM sealed service-account key. Sealed bytes rather than a filesystem
  path, because hosted has no filesystem the operator controls and an OAuth refresh
  token — the next credential this module will hold — is not a path at all.
- **`chalk jobs list|show|retry`.** The runner never retries a Google-writing
  job automatically — a human decides — but nothing gave the human anything to
  decide with, or any way to see the queue short of opening the database.
  `retry` queues fresh work rather than resetting the failed row, so the record
  of what went wrong survives the act of trying again.
- **Roster search pushed into SQL.** `UserFilter` gained `search` and `limit`,
  which also fixed a console users page that fetched every user and filtered the
  `Vec` in Rust.

### Changed
- Device-sync credentials are no longer required in `chalk.toml`. Requiring them
  made a server whose key lives in the database refuse to start, which made the
  console's own setup screen unreachable. A missing credential now fails at run
  time, where the error can name what is actually missing; a path that is set but
  wrong is still a hard error.
- `AssetRepository` gained `apply_patch_with_event`, applying a change and its
  audit row in one transaction. The two used to sit on separate traits, so a
  caller could leave an asset changed with no record of who changed it.

### Fixed
- The device inventory showed the first-run "connect Google" empty state on an
  out-of-range page, telling a technician holding thousands of devices that the
  fleet was gone. The same clamp is now in the queue and the activity log.
- The inventory forced a horizontal scrollbar. Free-text columns were `nowrap`
  with no cap, so the widest single value set the column width — unbounded, since
  one long org-unit path would have widened the table by hundreds of pixels.
- Every submit button in the console rendered as a primary button regardless of
  its class: `button[type="submit"]` outscored `.btn-secondary` on specificity, so
  a form offering two choices showed two identical primary buttons.
- `parse_datetime` returned "now" for any timestamp it could not parse, and 21
  tables default `created_at` to a format it did not accept. In an audit trail that
  is an invisible lie rather than a cosmetic defect.

### Known
- `TenantConfigRepo` gained two methods, so `chalk-hosted` will not compile against
  this version until its own sealing wrapper implements them. Default
  implementations were deliberately not added: a default would make that wrapper
  silently skip sealing device configuration.

## [1.7.0] - 2026-07-26

The first release of the Devices workstream, plus the design-system foundation
the console UI will be built on — and two bugs that were breaking real districts.

### Added
- **Device, sync-state and change-set schema (migrations 019, 021, 022).** `assets`
  and an append-only `asset_events` audit trail; `google_device_sync_cursors` and
  `google_device_sync_runs` for resumable ingestion; `change_sets` and
  `change_set_items` for diff-preview-then-commit. Four standalone repository
  traits with real SQL pagination — deliberately not added to the `ChalkRepository`
  supertrait, which would have forced ~40 stub methods into a mock that exists to
  test user provisioning. `mark_item_applied` is a single transaction, so an asset
  update, its audit event and the item's status land atomically or not at all.
- **`TokenProvider` for the Google Admin SDK.** A trait over token provision with
  service-account and OAuth-refresh implementations, an explicit `token_uri` seam,
  and single-flight refresh — a cached token expiring under concurrency previously
  would have fired one exchange per caller, which is itself a rate-limit trigger.
- **Google API error classification and backoff (`google-sync/src/backoff.rs`).**
  The Directory API returns 403 for rate limiting *and* 403 for genuine permission
  failure, so classification dispatches on the JSON `reason` field rather than the
  HTTP status, and fails closed. Reads retry up to 8 times with full jitter; writes
  retry only on definitive pre-execution rejections, never on an ambiguous outcome.
  `Retry-After` beyond a 120s clamp aborts with a clear message rather than
  stalling invisibly.
- **A real design system.** Tokens, base, components and console CSS served with
  content-hashed cache-busting, replacing an inline `<style>` block that had been
  copy-pasted into `base.html`, three standalone auth templates, ten IdP templates
  and the hosted portal. `scripts/contrast.py` computes every colour pair and gates
  CI.
- **Migration guard tests.** SQLite has no migration version table — every file
  re-executes on every process start, split on the semicolon character. A semicolon
  inside a comment therefore fails the migration on every boot. That is now caught
  by tests rather than by discipline, along with re-runnability, `IF NOT EXISTS`
  discipline, and registration in both `include_str!` arrays.

### Fixed
- **Skyward and Infinite Campus were unconfigurable on hosted Chalk (migration
  025).** Both connectors require an OAuth `token_url` that is not derivable from
  `base_url`, but `tenant_config_sis` shipped with only `powerschool_token_url` and
  the loader populated it only for PowerSchool. A hosted district on either
  provider had nowhere to store the value, no form field to enter it, and a sync
  that could never succeed — two of the four advertised SIS providers, unusable.
  Found from a production tenant failing every 60 seconds since May.
- **Sync tokens could not outlive an hour.** `GoogleAdminClient` copied the access
  token into an owned `String` and `GoogleAuth::is_expired()` had no callers, so
  any run longer than the token lifetime failed with no recovery. A 20,000-device
  fleet walk is exactly that run.
- **Five WCAG 2.1 AA contrast failures** in the shipped console: muted text at
  2.56:1, sidebar section labels at 3.75:1, the active nav link at 2.84:1, the
  sidebar badge at 2.96:1, and an auth error pill at 3.95:1. Fixed at the token
  level so templates using the legacy `--c-*` aliases inherit the fix. The wordmark
  deliberately keeps its brand indigo under WCAG 1.4.3's Logotypes exception.
- **The admin console footer** had reported `v1.0.0` since 1.0, six releases stale.
  It now renders the crate version, asserted by a test.
- `AssetFilter.assigned`'s documentation was inverted relative to both drivers,
  which would have made the unmatched-devices queue backwards and plausible.
- Importing a Skyward or Infinite Campus tenant's TOML silently dropped its token
  endpoint, and a NULL column in the hosted loader blanked file-provided config.

### Changed
- `str_enum!` gained a `with_default` arm, so a marked variant carries the default
  instead of ten hand-written `impl Default` blocks that could drift from the DDL
  defaults they mirror.
- The Rust toolchain is pinned in `rust-toolchain.toml` and CI reads the pin rather
  than naming `stable`, so a green local run means a green CI run.

## [1.6.4] - 2026-05-30

### Added
- **Launcher-tile SSO partners (`SsoProtocol::Link`).** A new generic, marketplace-
  agnostic partner type that renders as a portal tile and, when launched, simply
  redirects to a configured destination (`SsoPartner.launch_url`) instead of
  performing SSO. Role and audience (school/grade/section) filtering apply exactly
  as for other partners. This is the primitive behind the hosted Google Workspace
  built-in tiles, and also lets self-hosters add bookmark tiles. New nullable
  `sso_partners.launch_url` column (migration `018`); the `protocol` CHECK now
  allows `'link'`.

## [1.6.3] - 2026-05-30

### Changed
- **Launch portal now uses a role-aware left sidebar.** The student/teacher
  portal moved from a top header to a dark sidebar matching the rest of the
  product. Nav items adapt to the signed-in user's role: everyone sees
  **My Apps**; teachers also see **My Classes** (the teacher-only roster pages).
- **Console: enabled the Marketplace nav item** (previously a disabled "Soon"
  placeholder) — it now links to `/marketplace`.

## [1.6.2] - 2026-05-30

Unified visual design across the admin console and the student/teacher launch
portal, bringing them onto the same brand as the marketing site and hosted
portals.

### Changed
- **Console + launch portal restyled onto the shared design system.** Migrated
  the admin console and the IDP login/launch/teacher pages off their previous
  teal/secondary-blue palette and Inter web font onto the unified **indigo**
  brand (`#4f46e5`) with a self-hosted **Bricolage Grotesque** display face for
  headings over the system body stack. Tokenized color, radius, and shadow
  scales now match across surfaces; the login pages share the portal's look.
- The display font is self-hosted (no external font CDN) and served same-origin
  at `/static/bricolage-grotesque.woff2`.

## [1.6.1] - 2026-05-30

Audience-scoped SSO partners — the launch portal now hides an app from users
outside its data-sharing scope, not just outside its allowed roles. This is the
generic primitive hosted marketplace installs use so a section- or
school-scoped install only surfaces its app to the students/teachers actually
covered (closing a tile over-exposure where a teacher's classroom app, or a
grade-scoped district install, appeared to every student tenant-wide).

### Added
- **`SsoPartner.audience` (`Option<SsoAudience>`).** A marketplace-agnostic
  audience scope of allowed classes, orgs (schools), and grades. Each populated
  dimension is a constraint (empty = wildcard) and the dimensions are AND-ed, so
  an install scoped to "school A, grade 9" reaches only grade-9 students at
  school A. `None`/unrestricted = visible to everyone in an allowed role —
  preserving existing behavior for TOML/database partners and OSS self-hosters.
  Persisted in the new nullable `sso_partners.audience_json` column (migration
  `017`). New `SsoPartner::is_within_audience(classes, orgs, grades)`.

### Security
- **The launch portal enforces audience scope at both tile-render and launch.**
  `portal_home` filters tiles by the user's enrollments/orgs/grades, and
  `portal/launch/:id` re-checks audience so an out-of-scope user can't reach an
  app by guessing its launch URL (defense in depth alongside the existing role
  check).

## [1.6.0] - 2026-05-30

Optional passwordless admin login — the building block hosted/cloud
deployments use to drop admin passwords entirely. Off by default; OSS
self-hosters keep the password flow unless they opt in.

### Added
- **Magic-link admin login (opt-in).** A binary can now enable passwordless
  console login by injecting a `chalk_core::mail::MagicLinkMailer` via
  `AppState::with_magic_login(...)`. When enabled, `/login` emails a one-time
  link (15-min, single-use, hashed at rest in the new `magic_login_tokens`
  table; migration `016`) and `/login/verify` redeems it into an admin
  session. Only `Administrator`-role users with a matching email may log in,
  and the response is uniform regardless of whether the email matches (no
  account enumeration). The mailer abstraction keeps email-provider code out
  of the core/console crates; a `LoggingMailer` is provided for dev.

### Security
- **`auth_middleware` enforces the session whenever magic-link login is
  enabled.** Previously the console skipped authentication entirely when no
  `admin_password_hash` was configured (an OSS "run-open-in-dev" shortcut).
  That shortcut now applies *only* when both no password is set **and**
  magic-link is disabled — so any deployment using magic-link (e.g. hosted
  multi-tenant) always requires a valid session on protected paths.

## [1.5.0] - 2026-05-28

Foundation for scoped third-party data access — the generic primitive the
hosted marketplace builds on, kept fully marketplace-agnostic so OSS installs
are unaffected.

### Added
- **API tokens can carry an optional read scope.** A new `TokenScope`
  (`chalk_core::models::token_scope`) narrows what a single OneRoster API token
  may read along five dimensions — orgs (schools/districts), grades, subjects,
  sections (class sourcedIds), and per-resource allow/deny — plus a
  `redact_fields` list that strips sensitive fields (e.g. `birthDate`) from
  serialized `users`/`demographics` payloads. The scope is persisted on
  `api_tokens.scope` (JSONB on Postgres, JSON text on SQLite; migration `015`)
  and is **nullable**: a `NULL` scope means unrestricted, so every existing
  token and self-hosted deployment behaves exactly as before.
- **OneRoster API enforces token scope.** `oneroster_bearer_middleware` now
  loads the authenticated token's scope into the request, and every
  `/api/oneroster/v1p1` list/get handler filters rows, gates resources
  (`403` for denied families), and redacts fields accordingly. Out-of-scope
  `get` lookups return `404` so a scoped token can't probe for records it
  can't see. Section/subject scopes resolve a user's enrollments to decide
  visibility ("share students in math sections").

## [1.4.5] - 2026-05-28

Three bugs surfaced by a user trying to get their first hosted tenant
configured from the webui:

### Fixed
- **SIS / Google / AD dashboards now link to their settings pages.**
  The `/sync`, `/google-sync`, and `/ad-sync` dashboards rendered the
  current config and a "Trigger Sync" button but offered no path to the
  matching `/<dashboard>/settings` editor — the only way to find it was
  to know the URL. Each dashboard now has a "Configure …" call-to-action
  next to its Actions section. The Google and SIS dashboards also dropped
  the stale "(manual trigger only — scheduled syncs coming soon)"
  annotation; scheduled syncs shipped earlier this wave.
- **`chalk serve` auto-discovers `chalk.toml` after `chalk init`.**
  On Windows (and any platform where the data directory isn't the cwd),
  `chalk init` wrote `chalk.toml` under the platform's data directory
  (`%LOCALAPPDATA%\chalk` on Windows, `~/Library/Application Support/chalk`
  on macOS, `/var/lib/chalk` on Linux), but `chalk serve` defaulted
  `--config` to `chalk.toml` in the cwd and failed with a confusing
  "file not found." `--config` is now optional; when omitted, chalk
  probes the cwd first, then the platform data directory, and reports
  every path it tried if none exist.
- **API Tokens page is now reachable from the sidebar.** `/settings/api-tokens`
  was only discoverable by reading source. Added a sidebar entry with
  its own active-page highlight.

## [1.4.4] - 2026-05-28

### Fixed
- **Hosted OIDC `/authorize` now finds manually-created SSO partners.**
  A user created an OIDC SSO Partner via `/sso-partners/new`, got a
  `client_id` back from the console, then hit
  `/idp/oidc/authorize?client_id=…` and was rejected with
  `{"error":"invalid_request","error_description":"unknown client_id"}`
  — even though the partner showed `Enabled` in the admin console.
  Root cause: hosted `TenantContext::build` constructed `OidcState`
  with `Vec::new()` (empty partners) and only loaded the real partner
  list afterward for the Clever / ClassLink compat-router gates. The
  OSS `chalk serve` path (cli/serve.rs) already did this correctly.
  Hosted now loads partners up front and passes the same list into
  `OidcState::new`. The existing SSO-invalidator hook already evicts
  the cached `TenantContext` on partner CRUD, so a freshly-created
  partner is queryable on the next request.

## [1.4.3] - 2026-05-27

Same-day follow-up to 1.4.2. The SAML download button shipped in 1.4.2
only resolved certs from `idp.saml_cert_path` (a filesystem path) — but
on hosted tenants the cert lives sealed in `_meta.tenants.saml_keypair`
and is only unsealed into memory at context build, never written to
disk. A brand-new hosted tenant clicking Download therefore got a
404 ("SAML certificate not configured…") even though their cert was
already generated at signup and reachable via `/idp/saml/metadata` XML.

### Fixed
- `/identity/saml-cert.pem` now falls back to the in-memory provisioned
  SAML cert when no on-disk path is set. Resolution order:
  1. `AppState::saml_signing_cert_pem` — populated by the hosted
     context from the unsealed `_meta.tenants.saml_keypair`.
  2. `state.config.idp.saml_cert_path` — used by self-hosted OSS
     installs and hosted tenants who've uploaded a custom cert.
- New `AppState::with_saml_signing_cert(pem)` builder so hosted code
  can pass through the provisioned cert without exposing
  `IdpState`'s internals to the console crate.

## [1.4.2] - 2026-05-27

Two bugs caught by an early user during local self-hosted setup. Patch
release.

### Fixed
- **`chalk init` now picks a platform-appropriate default `--data-dir`.**
  The CLI hard-coded `/var/lib/chalk` regardless of platform, so on Windows
  the printed init summary (Database / SAML cert / SAML key / Master key
  paths) showed `/var/lib/chalk/…` while files were actually being written
  somewhere else on the C: or D: drive — the summary didn't match what
  the filesystem had. New `chalk_core::config::default_data_dir()` picks:
  - Windows → `%LOCALAPPDATA%\chalk` (e.g. `C:\Users\<user>\AppData\Local\chalk`).
    Falls back to `%USERPROFILE%\chalk` then `C:\ProgramData\chalk`.
  - macOS → `$HOME/Library/Application Support/chalk`.
  - Linux / other Unix → `/var/lib/chalk` (unchanged for existing installs).
  Pass `--data-dir <path>` to override on any platform. The same helper
  now also drives `ChalkConfig::generate_default()`.
- **`/identity/saml-setup` shows a download button for the SAML
  certificate** instead of just a server filesystem path. The page told
  admins to "Upload the SAML certificate from `/var/lib/chalk/saml.crt`"
  — a path their browser can't reach when they're configuring Google
  Workspace from a different machine. New `GET /identity/saml-cert.pem`
  route streams the cert as `application/x-pem-file` with
  `Content-Disposition: attachment; filename="chalk-saml-cert.pem"`.
  The server path is still surfaced behind a collapsed `<details>` for
  self-hosters who want to back up or inspect it.

## [1.4.1] - 2026-05-27

Pre-launch hardening pass. Wave B's webui shipped a real bug list on first
production smoke-test — multipart submissions died on CSRF, settings saves
didn't propagate to the running engines, the LDAP-URI round-trip was
broken, the OneRoster API had no pagination, and the cron scheduler logged
ticks but never dispatched. This release fixes those and adds the missing
ops escape hatches schools need to actually run the service.

### Fixed
- **Multipart settings forms now pass CSRF.** The CSRF middleware only
  validated `csrf_token` on `application/x-www-form-urlencoded` bodies, so
  every save on `/google-sync/settings`, `/identity/settings`, and
  `/ad-sync/settings` (all multipart for file uploads) returned `403 CSRF
  token missing`. Middleware now scans the multipart body for the token
  part, with case-preserving boundary parsing.
- **Settings saves immediately invalidate the cached `TenantContext`.**
  Previously a save persisted the row but the running engines kept their
  old config until the LRU evicted naturally — materialized secret files
  never appeared on disk, schedule changes were ignored. The four
  settings POST handlers now call `notify_tenant_config_changed()` so the
  next request rebuilds the context with the fresh row.
- **AD `connection.server` round-trips cleanly.** `import-toml` used to
  store the full `ldaps://host:port` URI in the `host` column with
  `port = NULL`; the loader then re-prefixed the scheme, emitting
  `ldap://ldaps://host:port:port`. Importer now parses the URI into
  `(use_tls, host, port)` triples; `use_tls` is derived from the scheme
  (not the unrelated `tls_verify` cert-validation flag). New
  `chalk_core::ldap::{parse_ldap_uri, build_ldap_uri}` helpers shared by
  the importer, loader, and the AD settings form (which now auto-parses
  pasted full URIs in the Host field).
- **Webhook delete no longer fails with FK violation.** The
  `webhook_deliveries → webhook_endpoints` foreign key now has `ON DELETE
  CASCADE` (migration 014 for existing tenants + corrected DDL in
  migration 005 for fresh ones).
- **Webhook form accepts checkbox-group submissions.** Selecting any
  combination of `entity_types` previously returned `400 invalid type:
  string, expected a sequence` because `axum::Form` collapses repeated
  keys. A hand-written `FromRequest` impl now aggregates repeated keys
  into the `Vec<String>` field.
- **Google sync init failures surface in the History table.** Previously
  a pre-engine failure (bad service-account JSON, missing admin email)
  only logged `tracing::error` server-side — the user got "background
  sync started" and then the history list stayed empty. We now record a
  `google_sync_runs` row up front and update its status to Failed with
  the error message.
- **Malformed JSON in settings forms redirects with an actionable
  message** instead of silently wiping the prior row or coercing to
  `Value::String` (which later broke `apply_idp` on every cache miss).
  Applies to `default_password_roles`, `ou_mapping`, and `groups`.
- **`SealingTenantConfigRepo` treats `Some(empty)` as unset** on both
  seal and unseal, so empty secret submissions can't blank a field via a
  non-`None` sealed blob.
- **`/settings/api-tokens` form includes a `csrf_token` hidden input** —
  previously only the `hx-headers` attribute was set, so non-htmx submits
  hit `CSRF token missing`.
- **CSP allows Google Fonts.** The Caddy CSP blocked `fonts.googleapis.com`
  + `fonts.gstatic.com`, falling back to system fonts and (on
  chrome-in-chrome) tripping a "Security error" tab title. Added
  explicit `style-src` + `font-src` entries.
- **SIS "provider not set" error message points at the SIS Settings
  page** instead of `chalk.toml` (which doesn't exist in hosted mode).
- **CI no longer fails with "No space left on device."** The
  `ubuntu-latest` runner's ~14 GB free space couldn't fit the grown
  cargo cache during restore. Added the `jlumbroso/free-disk-space`
  prelude and dropped `target/` from the cache key.
- **`/identity` no longer blocks browser debuggers from attaching.**
  Changed `hx-trigger="load"` → `hx-trigger="revealed"` on the auth-log
  panel so the htmx XHR doesn't race the page load.
- **Signup form accepts both JSON and `application/x-www-form-urlencoded`.**
  Previously rejected non-JSON submissions with `415` — users with JS
  disabled (or curl) got an unrecoverable error.

### Added — Pre-launch features
- **`chalk-hosted reset-admin-password --tenant <slug>`** — ops escape
  hatch for customers who forget their admin password. Generates a 24h
  one-time reset URL, audits the issuance, prints to stdout. Self-serve
  forgot-password flow is post-launch scope.
- **OneRoster 1.1 pagination.** All seven list endpoints accept
  `?limit=N&offset=N` (default 100 / 0, cap 1000), and emit
  `X-Total-Count` + RFC 5988 `Link` headers (`rel="next"`, `"prev"`,
  `"first"`, `"last"`). Real Clever / ClassLink / vendor integrations
  paginate by default and would otherwise re-ingest the full collection
  on every page.
- **Multi-tenant cron scheduler now dispatches sync engines.** The
  scheduler tick previously read schedules and did nothing. It now runs
  the SIS, Google Sync, and AD Sync engines per tenant on their cron
  schedules. Uses a new `cron_due` helper with a 24h lookback so a
  paused tenant catches up with one run, not hundreds; accepts both
  POSIX 5-field (`min hour dom mon dow`) and `cron`-crate 6-field
  (`sec min hour dom mon dow`) expressions.
- **Hosted signup seeds `tenant_config_sis` with the operator's
  chooser pick.** Previously the choice was logged at activation but
  never written to the per-tenant row — first-login operators saw
  "Provider: Not configured" even though they'd picked PowerSchool.
- **`/webhooks` admin section wired into the router.** The handlers had
  existed in `crates/console/src/webhooks.rs` since Phase 3.1 but were
  never registered. List / new / detail / edit / delete / test routes
  all exposed; sidebar nav entry added.
- **Self-hosted htmx** at `/static/htmx-2.0.4.min.js`. Pinned bundle
  embedded via `include_str!`, served with long cache headers, exempt
  from auth + CSRF. CSP no longer needs a unpkg.com exception (it
  didn't have one and silently broke other htmx pages).

### Changed
- Settings-page source badge says `"defaults"` (was `"toml"`) when no
  DB row exists yet — hosted tenants have no TOML file.
- Dashboard surfaces `Hosting: managed` for Postgres tenants instead of
  leaking the per-tenant schema name.
- `AdSyncEngine` repo bound loosened to `R: ChalkRepository + ?Sized`
  so callers can pass an `Arc<dyn ChalkRepository>` (matches the
  existing `GoogleSyncEngine`).
- Schedule fields on `/sync` and `/google-sync` previously annotated
  "manual trigger only — scheduled syncs coming soon"; now that the
  cron scheduler dispatches, the annotation is stale and should be
  removed in 1.4.2.

## [1.4.0] - 2026-05-18

Hosted tenant config moves out of TOML and into the database. Hosted operators
no longer need to edit server-side files to configure SIS, Google Sync, IDP,
or AD sync — every setting is editable from the admin console settings pages.
Secrets (OAuth client secrets, Google service-account JSON, SAML cert/key,
AD bind password, TLS CA) are sealed with the master key at rest.

### Breaking
- `sis.provider` is now optional in TOML (`Option<SisProvider>`). Previously
  a missing `provider` key under `[sis]` silently meant `"powerschool"`; that
  implicit default has been removed. Self-hosters who relied on the implicit
  default and have `enabled = true` under `[sis]` **must** now add
  `provider = "powerschool"` (or the appropriate provider) explicitly. At
  startup the binary logs a `warn!` when `sis.enabled = true && provider`
  is unset, and `chalk sync` / the admin-console "Trigger Sync" button
  refuse to run rather than guessing PowerSchool.

### Added — Hosted tenant config in the database
- New per-tenant tables (`migrations/postgres/013_tenant_config.sql` +
  sqlite parity): `tenant_config_sis`, `tenant_config_google_sync`,
  `tenant_config_idp`, `tenant_config_ad_sync` (singleton rows). All
  secret-bearing columns are sealed `BYTEA` (AES-256-GCM under
  `MASTER_ENCRYPTION_KEY`).
- `TenantConfigRepo` trait with paired `get_*`/`put_*` methods; Postgres and
  SQLite implementations. Hosted code accesses the trait through
  `SealingTenantConfigRepo`, which seals/unseals at the boundary.
- `TenantContext::build` folds the four DB sections onto the synthesized
  `ChalkConfig` per cache miss. Independent gets fan out via `tokio::try_join!`.
- Console settings pages: `/sync/settings`, `/google-sync/settings`,
  `/identity/settings`, `/ad-sync`, `/ad-sync/settings`. Multipart uploads for
  Google SA JSON, SAML cert/key, and AD TLS CA. Each page shows a
  `source: toml | database` badge; secrets render as `(set)` placeholders
  with an explicit Replace affordance — values are never re-rendered to HTML.
- `chalk-hosted import-toml --tenant <slug> --file <path>`: one-shot migration
  tool that imports a legacy TOML into the per-tenant tables, sealing secrets.
  Idempotent on retry.
- Hosted signup form lets new tenants pick their SIS provider (or "I'll set
  this up later"); the choice seeds the `tenant_config_sis` row.
- `rotate-master-key` re-seals the 8 new tenant-config sealed columns across
  every tenant in a single transaction.
- Materialized secret files under `<data_dir>/tenants/<slug>/` are cleaned up
  by `TenantContext`'s `Drop` impl on LRU eviction.

### Fixed
- AD `connection.server` round-trips correctly through `import-toml` → loader.
  Previously the importer stored the full `ldaps://host:port` URI in the
  `host` column with `port = NULL`, and the loader re-prefixed the scheme,
  producing `ldap://ldaps://host:port`. The importer now parses the URI into
  `(use_tls, host, port)` and the loader rebuilds it via `build_ldap_uri`.
- AD `use_tls` is now derived from the URI scheme on import (was incorrectly
  populated from `tls_verify`, which controls cert validation, not transport).
- Console settings forms surface a `?err=…` redirect when `default_password_roles`,
  `ou_mapping`, or `groups` JSON fails to parse. Previously a malformed value
  silently wiped the prior row (or, worse, coerced to `Value::String`, which
  later broke `apply_idp` at every cache miss).
- `SealingTenantConfigRepo` treats `Some(empty)` plaintext as `None`, so
  empty secret submissions cannot blank out a field via a non-`None` sealed blob.

## [1.3.0] - 2026-05-09

Major release: Postgres support, multi-tenant hosted runtime, security hardening.

### Added — Postgres support (OSS)
- `PostgresRepository` implementing `ChalkRepository` against `sqlx::PgPool` (~1400 LOC, parity with SQLite impl)
- 9 ported migrations under `migrations/postgres/` (BOOLEAN/TIMESTAMPTZ/JSONB/BIGSERIAL types)
- `DatabasePool::new_postgres(url, schema)` with per-pool `search_path` pinning
- `run_migrations_postgres` with PL/pgSQL-aware SQL splitter, `_meta_schema_migrations` tracking, and `pg_advisory_xact_lock` per-schema serialization
- `[chalk.database] schema = "..."` config field with regex validation
- `chalk serve` Postgres branch wired (CLI subcommands other than `serve` remain SQLite-only with a uniform helpful error)

### Added — Hosted multi-tenant runtime (`crates/hosted/`)
- New private workspace crate; excluded from `default-members` so OSS self-hosters' `cargo build` is unchanged
- `_meta` schema with `tenants` and `signup_pending` tables
- Tenant resolver middleware: `Host` header → tenant lookup with LRU pool cache (`parking_lot::Mutex`, single-flight on miss)
- `TenantContext` per-tenant: pinned Postgres pool, OSS state structs (`AppState`, `IdpState`, `OidcState`), per-tenant SAML keypair + OIDC JWK sealed at rest with master key (AES-256-GCM)
- Defense-in-depth: `task_local!` `CURRENT_TENANT_SCHEMA` asserted on every `ChalkRepository` method via `TenantScopedRepository` wrapper
- Multi-tenant scheduler: per-tick iteration over active tenants with bounded concurrency, per-tenant SyncEngine dispatch in scoped tenant context
- Per-tenant `tokio::sync::Semaphore` (default 32 permits) and global 30 s `tower_http::timeout::TimeoutLayer` for noisy-neighbor protection
- `SIGHUP` handler clears the state cache so `tenant suspend/unsuspend` takes effect without restart

### Added — `chalk-hosted` CLI
- `serve`, `provision`, `deprovision`, `migrate-all`, `rotate-master-key`, `tenant suspend/unsuspend`
- Shared `meta::connect_meta(url)` helper consolidating admin pool boilerplate across subcommands
- `provision` shares the `activate_tenant` path with the signup verify callback

### Added — Self-serve signup
- Apex `POST /api/signup` and `GET /api/signup/verify` on the hosted binary
- Cloudflare Turnstile validation, per-IP `governor` rate limiting (3/hour), Postmark verification email (spawned off the request path)
- Reserved-slug blocklist + slug regex `^[a-z][a-z0-9-]{2,30}$` shared with manual provisioning
- Verify callback activates tenant, bootstraps admin user, redirects with single-use reset token

### Added — Password reset tokens (OSS)
- New `password_reset_tokens` table (sqlite + postgres migrations) with SHA-256 indexed lookup, atomic single-use consumption, 24 h expiry, GC method
- `PasswordResetTokenRepository` sub-trait on `ChalkRepository`
- `/set-password` route in console consumes a reset token and sets the user's password
- Replaces previous reset-token-stored-as-password-hash anti-pattern

### Added — Marketing site
- New repo `chalk-marketing` (Astro static): landing, pricing, docs, signup pages
- Dev-only `/api/signup` mock with `prerender = false` (production routes via Caddy)

### Added — Operator infra (`infra/`)
- `Caddyfile` with DNS-01 wildcard via Cloudflare module, security headers (HSTS, CSP, frame/content-type/referrer policies)
- `chalk-hosted.service` systemd unit
- `bootstrap.sh` idempotent Ubuntu 24.04 droplet provisioner
- `env.example`, `runbook.md` operator runbook

### Added — CI hygiene
- `cargo audit` GitHub Actions workflow (PR + weekly)
- Dependabot configs for cargo + github-actions (chalk repo) and npm + github-actions (chalk-marketing)

### Security
- Cookies set `Secure` flag when `public_url` is `https://` (5 cookie sites, both console and idp); plain-HTTP self-host deployments unaffected
- All argon2 verify call sites wrapped in `tokio::task::spawn_blocking` to keep the runtime worker pool free
- Audit log events emitted on tenant activation: `tenant_provisioned` and `admin_bootstrapped`
- Per-tenant SAML keypair + OIDC JWK sealed with master key; `rotate-master-key` re-seals all rows in a single transaction
- Reset tokens are single-use, expire in 24 h, cannot be replayed
- Defense-in-depth: every per-tenant repository call asserts the active schema matches the request context

### Performance
- `list_users` 4001 queries → 5 (junction batching via `WHERE x = ANY($1::text[])`); same pattern applied to `list_orgs`, `list_classes`, `list_courses`, `list_academic_sessions`
- Per-tenant Postgres pool default `max_connections` reduced from 10 → 3 (manageable footprint at LRU cap × pool size)
- New junction-table indexes (migration 011) for postgres + sqlite
- StateCache moved to `parking_lot::Mutex` (sync critical section) with single-flight build on cache miss

### Refactoring (DRY)
- New `chalk_core::auth` (`hash_password`, `verify_password`) replaces duplicated argon2 wrappers in console + idp
- New `chalk_core::cookies` (`set_cookie`, `clear_cookie`, `SameSite`, `CookieAttrs`) replaces 5 inline cookie-format sites
- New `chalk_cli::commands::common::{assert_sqlite_only, unwrap_sqlite_pool}` replaces 16 drift-prone Postgres bail arms across 8 CLI subcommand files
- `ChalkRepository` consumers across the workspace migrated from `Arc<SqliteRepository>` to `Arc<dyn ChalkRepository>`; state struct constructors made `pub`
- `TenantStatus` enum bound everywhere (5 raw SQL/JSON status literals eliminated)

## [1.2.4] - 2026-02-27

### Added
- Teacher Dashboard: "My Classes" view at `/portal/my-classes` where teachers can see their enrolled classes with student counts
- Class roster view at `/portal/my-classes/:class_id` showing students enrolled in each class
- Teacher-initiated password reset for students in their classes (auto-generate or set custom password)
- Teacher-initiated QR badge generation for students in their classes
- HTMX-powered inline password reset and badge generation with no page reloads
- `list_enrollments_for_user` and `list_enrollments_for_class` repository methods for efficient enrollment queries
- "My Classes" navigation link in portal header for teacher users
- Audit logging for teacher password resets and badge generation actions (includes student name in badge audit)
- Shared `chalk_core::http::extract_client_ip` utility with security documentation (replaces duplicated helpers)
- SRI integrity hash on HTMX CDN script tag to prevent CDN compromise

### Fixed
- `error_html` now HTML-escapes messages to prevent XSS if user-controlled data flows into error pages
- Class roster `onclick` handler uses `data-student-id` attribute instead of injecting IDs into JS string context (XSS hardening)
- `extract_client_ip` returns `None` for empty X-Forwarded-For headers instead of `Some("")`
- Deduplicated enrollment row-mapping in SQLite repository (4 copies → shared `enrollment_from_row` helper)
- Deduplicated teacher-class authorization into `validate_teacher_for_class` helper (used by 3 handlers)
- Deduplicated student-in-class validation into `validate_student_in_class` helper (used by 2 handlers)
- Console `client_ip` now delegates to shared `extract_client_ip` from chalk-core
- Portal "My Classes" link uses consistent `.nav-link` CSS class instead of inline styles

### Security
- Teacher actions strictly scoped: teachers can only manage students in classes where they have a teacher enrollment
- Cross-class access denied for all teacher dashboard operations
- All teacher dashboard endpoints require valid portal session and teacher role verification

## [1.2.3] - 2026-02-23

### Fixed
- ClassLink `sourced_id_to_integer` now uses SHA-256 instead of `DefaultHasher` for deterministic, cross-platform hashing
- Clever `role_to_clever_type` uses exhaustive match instead of catch-all wildcard; `Aide`, `Proctor`, `Guardian`, `Parent` now map to `"staff"` instead of `"student"`
- Replaced O(n) user lookup loop in Clever SSO with indexed `find_user_by_external_id` query using `json_extract`
- Access tokens now stored in dedicated `access_tokens` table instead of reusing OIDC authorization codes with scope prefix hack

### Added
- `compat_common` module in IDP crate with shared `extract_cookie`, `generate_random_hex`, and `extract_client_credentials` helpers (deduplicated from 5 files)
- `AccessTokenRepository` trait and SQLite implementation with migration 008
- AD Sync group management: automatic creation and membership sync of role-based groups (Students, Teachers, Staff) with migration 009
- `find_user_by_external_id` repository method for efficient external ID lookups

## [1.2.2] - 2026-02-23

### Added
- Clever-compatible SSO endpoints (`/oauth/authorize`, `/oauth/tokens`, `/v3.0/me`, `/v3.0/users/{id}`, etc.) for drop-in Clever API replacement
- ClassLink-compatible SSO endpoints (`/oauth2/v2/auth`, `/oauth2/v2/token`, `/v2/my/info`) for drop-in ClassLink API replacement
- Active Directory sync via LDAP with delta sync engine, OU management, and username/password generation
- `chalk ad-sync` CLI command with `--dry-run`, `--status`, `--test-connection`, `--full`, and `--export-passwords` flags
- `CleverCompat` and `ClassLinkCompat` SSO protocol types for partner configuration
- Student portal auto-redirect for Clever and ClassLink compatible partners (instant SSO)
- External IDs column on users for Clever/ClassLink ID mapping
- AD sync state tracking tables (ad_sync_state, ad_sync_runs) with database migration 007
- Password generation with template patterns (`{firstName}`, `{lastName}`, `{grade}`, `{random4}`)
- Documentation for all three new features

## [1.2.1] - 2026-02-22

### Fixed
- GitHub API URL pointing to wrong organization (`anthropics/chalk` → `usechalk/chalk`)
- git clone URL in README (`chalk-education/chalk` → `usechalk/chalk`)

### Added
- Self-update capability to `chalk update` command (downloads and replaces binary)
- `--check` flag to `chalk update` for check-only behavior
- Install section to README with download links for all platforms

## [1.2.0] - 2026-02-22

### Added
- Universal SSO partner support with both SAML 2.0 and OIDC Authorization Code flow
- Multi-SP SAML with RSA-SHA256 signed assertions and SP-initiated/IDP-initiated flows
- OIDC provider with discovery, JWKS, authorization, token exchange, and userinfo endpoints
- Student/teacher launch portal at `/portal` with role-based app tiles and auto-login
- Portal session system (`chalk_portal` cookie) — separate from admin sessions for security
- SSO partner management in admin console (list, add, edit, toggle, detail views)
- TOML-based `[[sso_partners]]` configuration for SAML and OIDC partners
- Database-managed SSO partners with admin console CRUD
- Role-based app visibility (restrict which apps students vs teachers see)
- Backward-compatible `[idp.google]` config synthesis as an SSO partner
- AuthnRequest parsing with DEFLATE decompression for SP-initiated SAML
- Partner integration guide (`docs/sso-partner-guide.md`)
- School setup guide (`docs/sso-school-setup.md`)
- Database migration 006 for sso_partners, oidc_authorization_codes, and portal_sessions tables

## [1.1.0] - 2026-02-22

### Added
- Webhook delivery system for pushing OneRoster data to external partners
- TOML-based `[[webhooks]]` configuration for self-service partner integrations
- Two security modes: HMAC-SHA256 signing (`sign_only`) and AES-256-GCM payload encryption (`encrypted`) with HKDF key derivation
- Scoping engine with entity type, org, role, and field-level filtering
- Automatic change detection during sync (created/updated/deleted entity tracking)
- Batched and per-entity delivery modes
- Exponential backoff retry strategy (5 attempts: 1min, 5min, 30min, 2hr, 12hr)
- Webhook delivery audit log in database
- Marketplace webhook endpoint injection support (Phase 2 ready)
- Partner documentation with signature verification and decryption code samples in Python, Node.js, Ruby, Go, and Java

## [1.0.0] - 2026-02-22

### Added
- SIS connectors for PowerSchool, Infinite Campus, and Skyward via OneRoster 1.1
- Identity provider with SAML 2.0 SSO, QR badge login, and picture passwords
- Google Workspace sync with automated user provisioning and OU management
- Admin console with dashboard, user directory, sync management, and settings
- OneRoster 1.1 REST API for third-party integrations
- Migration tools for Clever and ClassLink platform transitions
- CLI with init, sync, serve, import, export, migrate, and google-sync commands
- Session authentication with CSRF protection and AES-256-GCM encryption at rest
- Admin audit logging
- SQLite database with automatic migrations
