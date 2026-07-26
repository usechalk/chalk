# Chromebook Getter — capability study

**Date:** July 25 2026 · **Method:** direct read of all three repos, read-only
**Repos:** `Chromebook-Getter` (Apps Script add-on + sidebar, ~1.8k LOC) · `getter-suite-api` (TS/Express, ~3k) · `getter-suite-functions` (Node 18 cloud functions, ~8k)
**Purpose:** WS-0 Phase 4. This suite is the field-tested version of the ChromeOS ingestion path Chalk is about to build (WS-1) and the spreadsheet UX WS-3 must beat. Port the lessons, never the code.

> **Status of claims.** Every file:line below was read directly. The three findings that change the WS-1 client signature — `maxResults=200`, 50-device OU chunking, and exclusive use of the deprecated `action` endpoint — were independently re-verified against the source before this document was written.

---

## 1. Google Admin SDK surface

`chromeosdevices.list` with **`projection=FULL`, `maxResults=200`**. Uses the **deprecated `/devices/chromeos/{id}/action` endpoint**, never `batchChangeStatus`. Calls `moveDevicesToOu` chunked to **50** device IDs. Uses `issueCommand` for REBOOT / WIPE_USERS / REMOTE_POWERWASH, guarded by a checkbox plus a `Browser.msgBox` confirm.

| Call | Where | Params |
|---|---|---|
| `chromeosdevices.list` | `getter-suite-functions/src/newBuildSheetPubSub/index.ts:220` | `maxResults=200&orgUnitPath={ouId}&projection=FULL` (+ `query=`, `pageToken=`) |
| same, Apps Script fallback | `Chromebook-Getter/index.ts:1247-1253` | `maxResults: 200, projection: 'FULL'` |
| `chromeosdevices.list` (search) | `Chromebook-Getter/index.ts:457-459` | `query=asset_id:…`/`id:…`, **no projection → BASIC**, no pagination |
| `chromeosdevices.list` (batch tag lookup) | `Chromebook-Getter/index.ts:514-536` | one URL per tag/serial, `fetchAll` in chunks of 100 |
| `orgunits.list?type=all` | `newBuildSheetPubSub/index.ts:109` | whole-tree pull |
| `chromeosdevices` PUT | `newChromebookUpdatePubSub/index.ts:74-83` | body = `{annotatedUser, annotatedLocation, annotatedAssetId, notes}` |
| `moveDevicesToOu` | `newChromebookUpdatePubSub/index.ts:140-145` | chunked at 50 — `// can only push 50 changes at a time` |
| `{id}/action` **(deprecated)** | `newChromebookActionPubSub/index.ts:31` | `{action}`, `{action, deprovisionReason}` |
| `{id}:issueCommand` | `Chromebook-Getter/index.ts:571-587` | sequential `UrlFetchApp.fetch` per row |
| Chrome Management telemetry | `buildTeletrySheetPubSub/index.ts:53-75` | `pageSize=1000`, explicit 17-field `readMask` |

**Fetch order:** sidebar → `multipleOrgGet` → POST `/build` → PubSub → resolve OU set → **`Promise.all` fan-out, one paginated list loop per OU concurrently** (`newBuildSheetPubSub/index.ts:331-347`, no concurrency cap) → devices `SADD`'d into Redis by jobId → WRITE_NEW_SHEET → sheet written.

OU targeting uses `orgUnitId`, not `orgUnitPath`, everywhere but root (`:333-334`) — paths break on special characters (§8).

## 2. Resilience

**No backoff module.** All retry behavior is `got` v11's, configured per call site, and configured *worse* on writes than reads.

- **Reads** — `retry: { limit: 5 }` and nothing else, so got's defaults apply: exponential + jitter, `Retry-After` honored on 413/429/503. Correct backoff **inherited by accident, not designed**.
- **Metadata PUT** (`newChromebookUpdatePubSub/index.ts:85-88`) — `calculateDelay: ({attemptCount}) => attemptCount * 50`. Supplying `calculateDelay` replaces got's default entirely: **linear 50–250 ms, `Retry-After` discarded**. Concurrency **100**.
- **`moveDevicesToOu`** (`:153-156`) — same linear delay, and `methods` left at got's default, which **excludes POST**. The `retry` block is dead config; OU moves are effectively single-attempt.
- **Device actions** (`newChromebookActionPubSub/index.ts:36-47`) — the one deliberate config: `limit: 3, methods: ["POST"], statusCodes: [403]`, jittered exponential capped at 1 s. Retries **only 403**; 429 and 5xx are not retried. Concurrency **2**.
- **403 handling is self-contradictory:** `afterResponse` hooks throw on 403 (`:100-104`), which converts the HTTP error into a non-retryable one — so on the PUT path the 403 hook and the 403 retry fight each other. User-facing string says "retried 10 times"; config says 3.
- **No mid-pagination resume.** State is a Redis set keyed by jobId; any failure restarts the whole fleet walk.
- **No client-side rate limiting.** No token bucket, no quota accounting.

## 3. Field validation

**Zero length validation of `annotatedUser` / `annotatedLocation` / `annotatedAssetId` / `notes` anywhere in all three repos.** Google rejects and the job dies.

`getAndCheckChromebooks` (`newChromebookUpdatePubSub/index.ts:240-373`) validates per row before any call: OU path non-empty; OU exists in the domain; `deviceId` non-empty; `deviceId` matches a **UUID regex** (guard against pasting the wrong column); row count matches the earlier pending-count pass. Each **throws out of the reduce**, so one bad row aborts the batch before any write — good, and the same path a length violation would take if it were checked.

Mid-batch, PUTs are already in flight at concurrency 100. A rejection marks the job `hasError` and leaves the sheet **half-applied with no record of which rows landed**. Only counts are reconciled. The authors knew — verbatim at `:210-212`:

> `// really no way to ensure all chromebooks have been updated except to throw here`
> `// this will force the update job to never stop...`

## 4. Auth model

**Pure OAuth user-consent. No service account, no domain-wide delegation.** The user's live access token is POSTed to a third-party server and forwarded through PubSub.

Scopes (`appsscript.json:17-27`): `admin.directory.device.chromeos`, `admin.directory.orgunit`, `admin.directory.user` — all **read-write**, no `.readonly` variants — plus `chrome.management.telemetry.readonly`, sheets, external_request, userinfo.

`ScriptApp.getOAuthToken()` → sent as a **form field named `Authorization`** in the POST body (`Chromebook-Getter/index.ts:1303-1310`) → republished into the job payload → reconstituted as a header (`newBuildSheetPubSub/index.ts:302-305`). No refresh; the ~1 h token is the whole credential, which is why jobs are built to finish fast.

**The backend is not a trust boundary.** `getter-suite-api/src/api/index.ts` mounts cors, body-parser, helmet, routers — **no auth middleware**. Entitlement (`isPremium`/`isCore`/`isFree`) is computed client-side and passed in the request body (`Chromebook-Getter/index.ts:1322-1324`); the worker branches on it.

**The one property worth envying:** there is no credential custody problem at all — nothing long-lived is ever stored. That is precisely the property hosted Chalk gives up and must earn back through CASA.

### 4.1 Security findings

Reported, **not fixed** — this was a read-only study, and all of it is in AdminRemix-owned third-party code, not Chalk. Severity is this study's judgement.

| # | Sev | Finding | Location |
|---|---|---|---|
| **A1** | ~~High~~ → **Low / by design** | Static HMAC key `'SUPERTEST-FRICTION-FREE-SECRET-123'` signs a JWT whose only claim is `iss: <user email>`, handed to AssetRemix as a cross-login. **This is intended behavior and out of scope** — see the note below. | `Chromebook-Getter/index.ts:1777` (key), `:1747-1785` (createJWT/generateToken), consumed at `sidebar.html:543-547` → `webhooks.adminremix.com/friction-free-signup?token=` |
| **A2** | **High** | Backend API has **no authentication of any kind** — `cors()` with no origin restriction, bodyParser, helmet, then routers. Every route is open; anything reachable at that host can enqueue work. | `getter-suite-api/src/api/index.ts:20-36`; routes at `chromebooks/index.ts:9,25,74,112,170,224`, `job-status/index.ts:7`, `build-sheet/index.ts:6` |
| **A3** | **Medium** (see note) | `isPremium`/`isCore`/`isFree` are computed client-side and sent in the request body, then trusted server-side with no recheck. `if (!jobId || !isPremium) throw` is the *only* application-level gate on bulk disable/deprovision. | Sent `Chromebook-Getter/index.ts:1322-1324`, `:708`, `:966`; trusted `newChromebookActionPubSub/index.ts:123`, `newBuildSheetPubSub/index.ts:306-310`, `newWriteSheetPubSub/index.ts:281-331` |
| **A4** | **High** | A live Google OAuth access token **bearing `admin.directory.device.chromeos` write scope** is POSTed as a form field literally named `Authorization`, republished into the PubSub/BullMQ payload, and rehydrated as a header in the worker — so it sits **at rest in queue/Redis storage**. | Sent `Chromebook-Getter/index.ts:656-663, 700-707, 900-907, 959-966, 1306-1311`; queued `chromebooks/index.ts:84-96, 135-151, 191-206`; used `newBuildSheetPubSub/index.ts:302-305` |
| **A5** | **Medium** | `ScriptApp.getIdentityToken()` is base64-decoded and `payload.email` read **without signature verification**. Acceptable inside Apps Script; the problem is that the same unverified email becomes the backend's notion of identity, and per A2 nothing re-derives it. | `Chromebook-Getter/index.ts:352-357, 366-370`, consumed `:1321`, `:662` |
| **A6** | **Medium** | Unauthenticated endpoint accepts a **100 MB** urlencoded body — cheap memory-pressure DoS. | `getter-suite-api/src/api/index.ts:20-26` |
| **A7** | **Low/Med** | `GET /update-status/:jobId` has no ownership check; returns job detail to anyone holding the UUID. `errorNotes` can contain device IDs and OU paths. Mitigated by UUIDv4 entropy. | `job-status/index.ts:7-27`, `lib.ts:14-31` |
| **A8** | **Low/Med** | `jobId` is client-generated and never bound to a user, yet `findOrCreate({where:{jobId}})` uses it as a replay guard — an idempotency key doing double duty as an authorization primitive. | `chromebooks/index.ts:130-155, 186-209`; generated `Chromebook-Getter/index.ts:697, 955, 1304` |
| **A9** | **Low** | Abuse control is `BLOCKED_DOMAINS = ["firefly"]` substring-matched against the whole email — over-matches, and changing it requires a redeploy. | `blockedDetails.ts:1-6`, enforced `newBuildSheetPubSub/index.ts:311-313` |

**Accuracy note on A3 — do not overstate it.** Every Google call uses the `Authorization` token *the caller supplied* (`newChromebookActionPubSub/index.ts:129-131`), so **Google is the real authorization boundary**. An attacker cannot deprovision another district's fleet without that district's admin OAuth token — and with it, they could already do so via GAM. `isPremium` is a **paywall, not a security boundary**. Real impact of A2+A3 is bypassing paid-tier gating and enqueueing work (DoS), not remote fleet destruction.

**A1 — resolved, working as intended. Do not re-raise it.** This study originally rated it High on the assumption that the signing key was obtainable. It is not:

- `hkd987/Chromebook-Getter` is a **private** repository.
- A published Workspace Marketplace add-on's Apps Script source is **not** readable by installers — it executes under the developer's project.

So the key is a shared secret between two systems the same owner controls, not a distributed credential. The design (confirmed by the owner): Apps Script has already authenticated the user against Google, so Chromebook Getter mints a short-lived assertion of that identity and AssetRemix accepts it. The trust chain is Google → Apps Script → signed assertion, which is sound; forging requires the key, and obtaining the key requires access the threat model already treats as compromise.

Residual hygiene notes only, explicitly **not** action items for Chalk: the secret is static with no rotation path, and the token travels in a **URL query string** (referrer headers, browser history, proxy logs) where a POST body or fragment would leak less. Both are AssetRemix-side and out of scope per D11 (maintenance mode).

Recorded at this length because a future session reading the raw finding will reach the same wrong conclusion this one did.

**Chalk design takeaway (not remediation):** A2+A3+A4 together are the argument for hosted Chalk's posture — a real session boundary, server-side entitlement from `_meta.tenant_plans` (ARCHITECTURE §8.2), and refresh tokens **sealed at rest** (§5.1) rather than access tokens living in queue payloads. A3 specifically is why destructive-operation authorization must sit behind §9.2's guard and the §9.1 role model, never in a request field.

## 5. The spreadsheet round-trip UX

### Columns

23 server-side (`newWriteSheetPubSub/index.ts:18-42`), 21 in the Apps Script copy:

`Org Unit Path · Annotated User · Annotated Location · Annotated Asset ID · Notes | Mac Address · Ethernet Mac · etag · Platform Version · Device ID · Serial Number · Status · Last Enrollment · Recent Users · Active Time · Model · Firmware · Last Sync · OS Version · Boot Mode · Support End Date · Last Known LAN · Last Known WAN`

**The first five are editable and the sheet says so visually:** A–E blue header, F–W grey (`:442-491`), `frozenColumnCount: 5` pinning exactly the editable block (`:370`). *This five-column convention is the single most transferable UX fact in the study — these users read blue as "you may type here."*

Headers are localized (en/es/ja) as parallel arrays, so column identity is **positional**; downstream code indexes by number throughout.

### Editing and write-back

Plain cell editing. Column A is a **validated dropdown of every OU** (`strict: true`); above 500 OUs it becomes a range-backed dropdown off a hidden sheet. Row-1 basic filter applied automatically.

**Write-back is an explicit button, never on-edit** — there are no `onEdit` triggers in the project.

**The filter *is* the selection model, and this is the load-bearing idea.** Every write operates on *all currently viewable rows*; rows hidden by the sheet filter are excluded (`isRowHiddenByFilter`, and server-side `rowMetadata[].hiddenByFilter` via `includeGridData=true`). "Select 400 of 5,000" is expressed as "filter the sheet, then press the button." No checkboxes, no row-selection UI.

### Preview / confirm

**No diff preview, ever.** The only gate is a `Browser.msgBox` OK/Cancel.

What exists instead is a **count-then-confirm two-phase** worth stealing:
1. POST `/update-chromebooks-pending-v2` → server re-reads the sheet and records how many rows are visible.
2. Add-on polls for that count, uses it for the free-tier quota check, shows the user the number.
3. POST `/update-chromebooks-v2` — the worker **re-derives the row set independently and refuses to proceed unless the counts agree** (`newChromebookUpdatePubSub/index.ts:367-371`). Optimistic concurrency against the user editing between phases.

Destructive actions add ceremony, not preview: typed-out understanding checkbox → mandatory reason radio → second `msgBox` → pre-flight refusal naming the offending row if any device is already in the target state.

### Errors and partial failure

- **One error at a time, in a modal.** No per-row annotation, no error column, no highlighting. Row numbers embedded in the message string (`row ${index + 2}`).
- **Partial failure is unrepresented.** "37 of 500 applied" produces one generic count-mismatch modal and no per-item record. Retry means re-filtering and pressing the button again over rows that already succeeded.
- **During a long run:** a spinner and "Loading | Please Wait". No progress, no count, no cancel. Polling starts at 3 s and multiplies by 1.25, giving up after 50 polls — but **Apps Script's 6-minute execution limit is the real ceiling on any single operation.** On timeout the job keeps running server-side and the user gets nothing.
- **Audit trail lives in the workbook.** Premium users get a red-tabbed `Action History` sheet (`Email · Action Type · Device Count · Sheet Name · Date/Time · Errors`) and a `Command Tracking` sheet for remote commands. **These users expect an in-workbook history tab.**

## 6. Architecture split — what genuinely needs a server

| Layer | Owns | Server genuinely required? |
|---|---|---|
| Apps Script | UI, confirms, token, identity, OU create/delete, single-device edit, `issueCommand`, report math (pure sheet-local reduces) | No, beyond UI + token |
| Express API | Normalize body, `findOrCreate` **keyed on jobId for idempotency**, publish, serve `/update-status/{jobId}` | Only as queue front-door + status oracle (~250 LOC of real logic) |
| Cloud functions | Fleet pagination, OU walk, Redis spooling, Sheets I/O, all Google writes, telemetry | Yes — for three reasons |

**The three real reasons a server exists:**
1. **Apps Script's 6-minute execution limit** — a 20k fleet walk cannot finish in-process. Fossil evidence of fighting this without one: `buildDataSheet(..., extendTime)` returns the payload so the sidebar can call *back* in and restart the clock.
2. **Memory / payload size** — devices spooled to Redis and streamed with `sscanStream({count: 5000})`; the API accepts a **100 MB** body.
3. **Parallelism** — `UrlFetchApp` is serial; the server writes at concurrency 100.

**Not real reasons:** credential custody (nothing stored) and entitlement enforcement (client-supplied). The only server-shaped requirements are *long-running* and *concurrent*.

**Good news for WS-3:** Chalk's in-process `JobRunner` (§6) covers all three natively — no 6-minute wall, no cross-process payload limit, `tokio` concurrency, durable job state. **Nothing in this suite argues for an external queue.**

## 7. Device → user matching

**There is none.** Not one line in any of the three repos maps a device to a person.

`annotatedUser` is an opaque admin-typed string — written to column B, read back and PUT verbatim, never parsed, never validated as an email, never joined. `recentUsers` is display-only, exposed as a *search filter* (`recent_user:{email}`) rather than a matching rule. The Postgres `Chromebook` model has **no user column at all**; devices belong to districts, never people.

So **`ARCHITECTURE.md` §5.6's matching ladder has no field-tested precedent here** — it stands on `chromebookInitialSync.ts` (AssetRemix) alone. The one thing this suite does prove: districts *do* put meaningful data in `annotatedUser` by hand, which is why §5.6's rule 1 is the right first rule.

## 8. Surprises — the hard-won lessons

**Leading zeros destroy asset tags.** `annotatedCleaner` (`newWriteSheetPubSub/index.ts:242-248`) prefixes `'` to any `annotatedAssetId`/`annotatedLocation` starting with `0`. Without it, tag `00123` round-trips as `123` and the write-back **silently renames the device**. Combined with `valueInputOption: "USER_ENTERED"` this is a data-corruption class Chalk will hit on day one of CSV/Sheets round-trip.

**OU names containing `&` or `+` break the API; the shipped fix is to refuse.** Guarded with a three-language message. The real mitigation: address OUs **by `orgUnitId`, never `orgUnitPath`**. Chalk should key OUs on ID for the same reason.

**Google returns 403, not 429, for Directory API rate limiting.** The action path retries *only* 403 for exactly this reason. But 403 is also "your admin permissions are wrong," and the code cannot tell them apart, so it guesses in the error message. **Chalk must dispatch on the JSON error `reason` (`rateLimitExceeded` vs `forbidden`), not the status code.** This is the suite's single most expensive ambiguity.

**412 Precondition Failed means "device is already in that state."** Given its own message, and the reason the pre-flight status check exists.

**Concurrency 100 for metadata vs 2 for destructive actions.** A 50× gap that wasn't designed — it's a scar. **Chalk should start destructive Google writes serial.**

**A hardcoded domain blocklist ships in the worker** (`blockedDetails.ts`). It tells you the operational reality: at scale you eventually need to cut off an abusive tenant *now*, and there was no admin surface to do it with. **Hosted Chalk should have a real tenant-suspend switch from the start.**

**Telemetry has no 403 "not licensed" probe** — an unlicensed tenant gets a generic failure. Confirms §5.5's planned probe is needed.

**Sheet rewrite is destructive by design** — rebuilding resets grid properties, clears the filter, and blanks all cells. User formulas and extra columns are annihilated on every refresh. These users have learned not to add columns; Chalk's grid needn't inherit the limitation but should know the expectation.

**`Promise.all` over the entire OU tree with no concurrency cap** — almost certainly the real source of the 403 storms the retry logic exists to paper over.

---

## Deltas vs the planned WS-1 design

Ordered by how much each should change `ARCHITECTURE.md` §5. Each is labeled **PORT** (evidence §5 is right / a lesson to adopt) or **AVOID** (a bug not to repeat).

| # | Delta | Verdict |
|---|---|---|
| 1 | **`maxResults=200`, not 100.** §5.2 comments `maxResults=100 (hard max)`; §5.4 sizes the walk at "20k = 200 requests". Production uses 200 in both paths against a large install base. If 200 is accepted, §5.4's request count halves. | **PORT** — §5.2's "hard max" note is wrong as written. Verify against current docs, then correct. |
| 2 | **OU-move chunk size 50, not 20.** §5.2 says ≤20; production chunks at 50 with `// can only push 50 changes at a time`. | **PORT** — resolve before the client signature hardens. 20 is safe; 50 is 2.5× fewer calls. |
| 3 | **Dispatch on error `reason`, not HTTP status.** 403 is overloaded between `rateLimitExceeded` and genuine permission failure; no status-code policy can be correct. | **AVOID** their ambiguity — §5.3 must add this explicitly. |
| 4 | §5.3's jittered exponential backoff has **no** field validation — the suite's linear delay discards `Retry-After`, and `retry` is dead config on POST because `methods` wasn't set. | **AVOID.** §5.3 is a strict improvement, but the plan cannot claim CG as evidence *for* it — the evidence is that its absence hurt. |
| 5 | §5.3's rule that **writes never auto-retry after ambiguous failure** — CG retries writes at concurrency 100 and cannot report which succeeded. | **PORT** — keep the rule; confirmed by the authors' own comment. |
| 6 | §5.4's **mid-pagination cursor** is genuinely novel. CG restarts a 20k walk on failure at device 18,000; its Redis set is a cache, not a cursor. | **PORT** — `google_device_sync_cursors` is a real advance. |
| 7 | **Bound the OU fan-out.** §5.3 specifies a request-rate token bucket but says nothing about per-OU parallelism, the likely root cause of CG's 403 storms. | **AVOID.** Better: list at root with `orgUnitPath=/` and filter locally. CG only fans out because it needs per-OU counts; Chalk doesn't. |
| 8 | §5.2's typed `AnnotatedFields` rejecting oversize input has **no precedent**, and its absence is a real user-visible failure in CG. | **PORT** — clearest UX win over the incumbent; worth saying so in WS-5.3 copy. |
| 9 | §5.2 correctly rejects the deprecated `action` endpoint; CG uses it exclusively. **Add 412 handling** — `batchChangeStatus` shares the "already in that state" semantics. | **PORT** CG's pre-flight status check, but relocate it into the change-set **plan** phase so §6.4 surfaces it as a per-item exclusion rather than an abort. |
| 10 | **§6.3 (per-item `pending → applied\|failed`, persisted before the next remote call) is the direct answer to CG's worst limitation** — and their comment admits it is unfixable in their design. | **PORT** — "the UI shows exactly which 37 of 500 applied" is the highest-value differentiator the study surfaced. |
| 11 | §6.4's diff-preview has no incumbent equivalent, but CG's **count reconciliation** (re-derive at commit, refuse if counts disagree) is optimistic concurrency Chalk's change set also needs — planned at T0, committed at T1 over data that moved. | **PORT** — add a plan-hash or row-count guard to the commit step. |
| 12 | §5.6's matching ladder has **zero** support here (§7). | Flagged so nobody reads Phase 4 as having validated it. |

**UX facts WS-3 should encode** (not currently in §5/§6): five-editable-columns-blue-and-frozen; **filter-as-selection** ("what you can see is what will be written"); in-workbook `Action History` / `Command Tracking` tabs users expect; mandatory reason-code radio before deprovision; and that **every operation today is capped at ~6 minutes** by Apps Script — so a longer-running Chalk job needs progress UI these users have never had, and can beat trivially.

### Scoring §5 against the field

The PORT/AVOID column above says what to *do*. This says what it means for the **document** — the two are different, and conflating them is how a spec gets rewritten in the wrong places.

| Verdict on ARCHITECTURE §5/§6 | Deltas | What to change |
|---|---|---|
| **Outright factual error** | 1 (`maxResults`) | Fix the constant and §5.4's request math. |
| **Probably wrong, unresolved** | 2 (chunk size 50 vs 20) | Verify against current Google docs. 20 is the safe fallback; 50 is 2.5× fewer calls. |
| **Right, but incomplete** | 3 (dispatch on error `reason`, not status), 6 (bound the OU fan-out), 8 (412 "already in that state"), 11 (plan→commit staleness guard) | Add the missing clause. The decision stands; the edge case isn't covered. |
| **Right, and validated by CG's failures** | 3, 4, 5, 7, 10 | Change nothing. CG's pain is the evidence. |
| **Not validated by this study** | 9 (§5.6 matching ladder) | Don't cite Phase 4 as support. It rests on `chromebookInitialSync.ts` alone. |
| **Not covered at all** | 12 (spreadsheet UX conventions) | New material for WS-3. |

**The short version: §5's engineering judgement holds up almost everywhere — its errors are in the API constants, not the architecture.** That split is the useful result. Constants are exactly where field-tested code beats a spec, and architecture is exactly where a spec beats field-tested code: the three things CG's authors documented as unfixable in their own design (partial-failure invisibility, no pagination resume, no pre-write validation) are all things §5/§6 already solve on paper.
