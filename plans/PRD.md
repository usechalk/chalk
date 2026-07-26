# Chalk PRD v2.0 — The Open-Source K-12 IT Stack
**Status:** Ready for engineering
**Owner:** Lundin Matthews / AdminRemix LLC
**Date:** July 2026
**Supersedes:** PRD v1.0; folds in the Gate A memo (now canon)
**Companion docs (same directory, same commit):**
- `DESIGN_SYSTEM.md` — brand, tokens, components, accessibility (build UI from this)
- `ARCHITECTURE.md` — current + target technical state, DDL, crate plan (build code from this)
- `GATE_A_MEMO.md` — the assessment that closed Gate A (rationale record)

---

## 1. What changed since v1.0

Gate A is **closed**. All seven codebases were inspected directly. The verdict is **Branch C — strangler pattern**, with one correction to v1.0's framing: "federate AssetRemix as a companion container" is not possible (its stack — Pub/Sub, Redis, Firebase, Chargify, WorkOS, BoxyHQ, Postmark, Cloud Run — cannot be self-hosted or shipped as a sidecar). Instead:

- **AssetRemix enters maintenance mode** and keeps serving its three paying districts indefinitely. It is the revenue bridge, not the future platform.
- **Chalk's Devices + Helpdesk modules are built natively in Rust** against a deliberately small schema. This is *not* a rewrite of AssetRemix (~100k LOC, 76 models, used broadly by all three customers); it is the scoped-down free-funnel product. AssetRemix's code is the field-tested **reference spec** — port the lessons, never the code.
- **No new Sheets add-on.** The spreadsheet lives inside Chalk (AG Grid island + CSV/Sheets round-trip). Chromebook Getter is frozen after two bug fixes and becomes a pure funnel via in-app CTA — which is our only channel to that install base.
- Customer facts locked in: the three districts **use AssetRemix broadly** (advanced modules are load-bearing), run cost is **moderate** (12–24 month strangle horizon is sustainable), Chromebook Getter reach is **in-app only**, capacity is **10–15 hrs/wk with heavy AI-agent leverage**.

Everything else in v1.0's spine survived contact with the code and carries forward below.

---

## 2. Context

- **Chalk** (open source, AGPL-3.0): K-12 rostering, SIS-sync (PowerSchool, Infinite Campus, Skyward), SAML IdP, Google/AD provisioning. Single Rust binary, HTMX console, SQLite. ~52k LOC across 9 crates, ~16 releases, near-zero distribution. A separate private hosted control plane (`chalk-hosted-crate`, ~13k LOC) already does multi-tenant signup/provisioning.
- **AssetRemix** (proprietary): Snipe-IT-class ITAM + full helpdesk + integrations platform. ~54k LOC TS backend (5 deployed processes) + ~47k LOC Vue 2 SPA (EOL framework). Three K-12 district customers (Llano ISD, Malakoff ISD, KIPP Indy) at $99/mo flat.
- **Chromebook Getter**: Google Sheets add-on, verified restricted OAuth scopes, large install base, per-user pricing. 1.8k LOC Apps Script. The *listing* is the asset, not the code.
- **chalk-marketing**: Astro + Tailwind static site (Caddy-fronted), pricing page is placeholder.

### 2.1 Product thesis

> Chalk is the open-source K-12 IT stack: device tracking, help desk, rostering, SSO, and Workspace sync in one binary. Self-host it free, or we host it.

The differentiating claim the engineering work must make true:

> **Chalk is the only asset tracker that already knows your students.** Because Chalk owns the SIS connectors, the Devices module is populated with every student, teacher, school, and enrollment on install — no CSV import marathon. Snipe-IT cannot do this and has no help desk.

### 2.2 Personas (v1 scope)

| Persona | Surface | What winning looks like |
|---|---|---|
| **The technician** (2-person district IT shop) | Technician console | Lives in dense tables all day; bulk-moves 500 Chromebooks without leaving the keyboard; trusts the audit trail |
| **The IT director** (buyer) | Reports, pricing page, compliance docs | Sees AUE/refresh planning, gets a quotable price without a sales call, gets an NDPA without friction |
| **The teacher** (never trained) | Teacher portal | Reports a broken Chromebook in under 60 seconds from a phone, device auto-attached, no account creation |

### 2.3 GTM sequencing (constrains build order)

Modules ship and sell in **inverse order of blast radius**:
1. **Devices** — breaks → someone updates a spreadsheet for a day. Front door.
2. **Helpdesk** — breaks → tickets go to email for a day. Front door.
3. **Rostering / SSO** — breaks → nobody in the district can log in. **Act 2, sold only after trust exists.** (The idp/ad-sync/google-sync crates are already built; this is marketing order, not build-from-scratch order.)

---

## 3. Decisions locked (do not relitigate)

D1–D10 carry forward from v1.0 unchanged. D11–D15 are new (from Gate A).

| # | Decision | Rationale |
|---|---|---|
| D1 | One product, one brand: **Chalk**. AssetRemix retired as a public name. | Two zero-distribution brands = half attention each. Existing customers keep their running instance quietly. |
| D2 | **Self-hosted is free forever**, full feature set, AGPL-3.0. No crippleware. | The funnel, and the way past procurement — free needs no PO. |
| D3 | **Hosted is the paid product**, sold annually on POs. | Districts don't buy on monthly credit cards. |
| D4 | **Kill the vendor marketplace** as a revenue line. (Dormant code in the hosted crate stays but is not routed to or sold.) | Two-sided cold start with zero districts and zero vendors. Year 3+ maybe. |
| D5 | **Kill "drop-in Clever/ClassLink compatibility."** Clean-room OAuth2/OIDC + SAML + OneRoster only. | Vendor apps hard-code provider hostnames/credentials; Clever's terms prohibit derivatives. Doesn't work technically or legally. |
| D6 | **Never modify the Chromebook Getter listing's identity or scopes.** Separate Cloud project + listing for hosted Chalk. | The one verified, working asset. A hosted server storing restricted-scope data triggers fresh CASA anyway. |
| D7 | **Reprice off per-user** to per-enrollment annual tiers. Grandfather all existing payers (trivial: 3 customers, config flag). | A 5,000-Chromebook district with 2 admins paying ~$18–40/mo is structurally broken. |
| D8 | **Free hosted tier gated on asset breadth (Chromebooks only), not volume.** Unlimited devices/admins, no operation caps, no data redaction. | The prior 500-upload cap and AUE/OS redaction caused documented churn. Gate on growth moments, not punishment moments. |
| D9 | **Single-binary distribution preserved for Chalk core.** Assets embedded at compile time (rust-embed). | The product's most distinctive property and the basis of the self-host funnel. |
| D10 | **WCAG 2.1 AA is a build constraint from day one.** | ADA Title II: Apr 26 2027 (≥50k pop.) / Apr 26 2028 (most districts). VPAT demanded in procurement. |
| **D11** | **Strangler, not migration.** AssetRemix → maintenance mode (security + bugfixes + billing only, ~2 hrs/wk cap, no new features). The three districts stay on it until Chalk covers *what they actually use*, verified per-district from their DBs — possibly SY2027-28, possibly never. No forced date, ever. | They use it broadly; forcing them onto v1 Chalk churns 100% of current revenue. Run cost is moderate → sustainable. |
| **D12** | **No new Sheets add-on.** Spreadsheet UX lives inside Chalk (AG Grid island, CSV/Sheets round-trip, one-click export). Chromebook Getter: fix the two known bugs, add one well-designed CTA, then feature-freeze. | The add-on's value is the listing + install base, and our only channel is in-app — a CTA works identically pointing at Chalk signup. A second listing = a second OAuth cycle + policy risk, zero added reach. |
| **D13** | **No Vue 3 port, no AssetRemix frontend investment** beyond maintenance-mode fixes. | Porting a dying SPA is the year-losing rewrite in different clothes. Behind auth with a small user base, Vue 2 EOL is acceptable for the strangle horizon. Revisit only if horizon exceeds ~2 years. |
| **D14** | **Chalk billing is manual-first: annual PO + invoice, entitlement flags in the hosted control plane. No Chargify (or any billing SaaS) in Chalk.** Chargify stays in AssetRemix-land and retires with it. | Three-figure customer counts don't justify billing infrastructure. The PO workflow *is* the K-12-native flow. |
| **D15** | ~~**Design direction locked: "slate + chalk" system per `DESIGN_SYSTEM.md`.** Light-first warm-paper UI, deep slate ink, chalk-dust **blue** accent (#33688E family), system font stack in-app.~~ **SUPERSEDED BY D17** — the accent and font decisions are reversed; the rest of `DESIGN_SYSTEM.md` stands. | Professional for district IT, distinctive without gimmick, AA-verified pairs throughout. |

### D16–D20 — added July 25 2026 (WS-0 planning session)

| # | Decision | Rationale |
|---|---|---|
| **D16** | **Pricing anchors to Snipe-IT, not to §7's original table.** Match Snipe-IT's rungs and win on *inclusion* — every Chalk tier carries a full help desk and an SIS-populated roster, which Snipe-IT offers at no price. Ladder in §7. Supersedes §7's $2,000–$18,000 table. | Snipe-IT is the product every K-12 IT director already benchmarks against, and its hosted ladder ($399.99 → $999.99 → $2,499.99 → $5k → $7.5k/yr, self-hosted free, no education discount) sets the price a district *expects* to pay for asset tracking. Being 4× that price for a product with no track record loses the deal before the feature comparison starts. "Same price, twice the product" is a stronger and more defensible line than either "cheapest" or "premium". Accepted cost: ~4× less revenue per district than the original table assumed — bought deliberately, in exchange for logo velocity in the SY2027-28 land grab. |
| **D17** | **Keep the shipped indigo + Bricolage Grotesque brand** (`--c-primary #4f46e5`, self-hosted variable woff2). Adopt *everything else* in `DESIGN_SYSTEM.md`: token architecture, semantic-over-primitive discipline, status color language, component specs, and the WCAG 2.1 AA contract. D15's chalk-blue accent and zero-embedded-font rule are reversed. | The indigo system shipped three releases ago (v1.6.2) and is already unified across console, IdP, and hosted portal — re-theming buys no user value and burns WS-2 time the schedule doesn't have. D15's *reasoning* survives intact and is what actually mattered: the accent must not be green, because green is load-bearing as a status color across thousands of table rows. Indigo satisfies that constraint. Contrast verified: white on `#4f46e5` = **5.93:1**; `#4f46e5` as text on `--paper-0 #FCFBF9` = **6.16:1** — both AA, and within 0.1 of the blue-600 values the document's token architecture was built around, so it transplants without structural change. `DESIGN_SYSTEM.md` §3/§4 ratio tables must be recomputed against indigo before WS-2 ships. |
| **D18** | **The Clever/ClassLink compat *code* stays and keeps working.** WS-0 removes the *claims* only. Export-bundle import parsers (`crates/core/src/migration/`) are legitimate, are not derivative works, and stay advertised. Deprecation of the compat endpoints is a separate post-Gate-B decision. | D5's kill is a positioning and legal-exposure decision about what we *claim*, not a demand to break running integrations. The endpoints are 2,773 LOC with 25+ existing tests; deleting them in a hygiene pass is a breaking change with no offsetting benefit and destroys test coverage. Districts mid-migration keep working; we simply stop selling it as a drop-in replacement. |
| **D19** | **Domain stays `usechalk.xyz`.** `usechalk.com` is not acquired. Every domain reference stays env-driven so the swap is one variable. | WS-0.1 is unresolved and non-blocking. The Spamhaus/content-filter risk of `.xyz` is real and still worth fixing — but it is a purchase, not an engineering task, and nothing else waits on it. |
| **D20** | **`/migrate-from-clever` and `/migrate-from-classlink` are unpublished with 301s → `/vs-snipe-it`.** | Both pages are built end-to-end on the two premises D5 and D3/D4 killed ("drop-in OAuth compatibility", "hosting is free, funded by the vendor marketplace"). There is no honest version of either page that keeps its structure. Snipe-IT replaces them as the comparison target — it matches the new Devices-first front door, and the sourced-pricing honesty infrastructure in `competitorPricing.ts` carries over unchanged. |

---

## 4. Gates

### Gate A — CLOSED ✅
Verdict: Branch C (strangler). Full inventory and reasoning in `GATE_A_MEMO.md`. Consequences are D11–D14 above. WS-3/WS-4 are **unblocked**.

### Gate B — Customer validation (OPEN, non-engineering, runs now)
Unchanged in substance from v1.0, plus one addition:

- **Before interviews: run the per-district module-usage audit** against AssetRemix production (which models/tables each district actually touches). Interviews then ask "what would you miss?" against facts, and the output doubles as the D11 strangle checklist per district.
- Structured interviews with Llano, Malakoff, KIPP Indy + 15–20 cold conversations with district IT directors and ESC/BOCES tech directors. Script per v1.0 §4.
- **Kill signals (any → stop and rethink before WS-3/4 ships):** the "already knows your students" wedge fails to interest ≥⅓; no commitment to ≥$2,000/yr on PO; SOC 2 demanded pre-pilot at small-district scale; Google Admin Console is "good enough" for nearly everyone.
- **Go signal:** ≥3 non-customer districts would pilot hosted Devices+Helpdesk this school year.

Gate B does **not** block WS-0/1/2/6 or self-host beta. It gates the *hosted sales push* and any decision to expand v1 scope.

---

## 5. Product scope — v1.0

### 5.1 Devices module (`chalk-devices`)
- Asset CRUD with immutable `asset_events` audit trail.
- **The wedge:** assign/unassign devices to roster users (`users.sourced_id`), auto-derive school from enrollment. Populated on install via existing SIS connectors.
- Google Admin SDK ingestion (ChromeOS devices, OUs, directory users) with scheduled + on-demand sync and **diff-preview-before-commit** on all write-backs.
- Device→roster matching: `annotatedUser`/`recentUsers` → user email; fallback serial/asset tag; unmatched-devices resolution queue.
- Bulk operations: OU move, status change, annotated-field set, remote commands (reboot/powerwash), and **guarded deprovision** (admin role + typed confirmation + audit record; console-only, no API path in v1).
- CSV / Google Sheets round-trip: export → edit → re-import with diff preview.
- Spreadsheet-style bulk editing in the AG Grid island (`DESIGN_SYSTEM.md` §6).
- Reports: AUE/refresh planning, OS version distribution, unassigned devices, devices by school (`DESIGN_SYSTEM.md` §8 for viz standards).
- **Free-hosted gate:** Chromebooks only. Other asset types (laptop, tablet, projector, hotspot, other) = paid. Enforced as hosted entitlement config — never compiled out of the OSS build (D2).

### 5.2 Helpdesk module (`chalk-helpdesk`)
- Tickets: statuses, priorities, categories, assignment, SLA timers (first-response + resolution), feedback-free v1 (no CSAT yet).
- **Teacher portal** (`/report`): one screen, mobile-first, SSO'd, free-text + category chips + auto-attached device from assignment, submit < 60s, no account creation (`DESIGN_SYSTEM.md` §7).
- Technician queue: saved filters (bookmarkable URLs), bulk actions, inline device + repair history on every ticket.
- Email-to-ticket: hosted via Postmark inbound webhook; self-host via IMAP polling or webhook (`ARCHITECTURE.md` §7). Outbound notifications through the generalized mailer.
- Asset↔ticket bidirectional linkage — every ticket carries device, student, school context automatically.

### 5.3 Explicitly not in v1 (see also §9 Non-goals)
Licenses, accessories, consumables, custody verification/signatures, fines, invoices, funding tracking, dashboard builder, white-label branding, Snipe-IT/Lansweeper sync, AI features. These are AssetRemix capabilities that its three customers keep using *there* (D11). Each returns to the roadmap only when a paying Chalk district asks and Gate-B evidence supports it.

### 5.4 Data model
`ARCHITECTURE.md` §4 is authoritative (it corrected v1.0's sketch against the real codebase: schema-level tenancy → no `tenant_id` columns; FKs target `users(sourced_id)`/`orgs(sourced_id)`; sync-state tables renamed to avoid an existing-table collision; migrations 019–024 specified in-convention). The v1.0 acceptance criterion stands: **fresh install → SIS connected → Google authorized → populated device inventory with students attached in under 30 minutes, zero CSV.**

---

## 6. Architecture & design (delegated to companion docs)

- `ARCHITECTURE.md` — crate shape (models/traits/migrations in `chalk-core`; behavior in `chalk-devices`/`chalk-helpdesk`; UI + REST API in `console` with scoped `api_tokens`), Google client design honoring every API limit, single-binary background jobs (no Redis), diff-preview-then-commit change sets, tenancy/entitlements, security model.
- `DESIGN_SYSTEM.md` — tokens, components, status color language, dense-table pattern, AG Grid theming, teacher portal spec, accessibility standards feeding the VPAT.
- Key deployment fact from Gate A analysis: **self-hosted Google integration uses the customer's own Cloud project + service account (domain-wide delegation) — no dependency on our OAuth verification.** Self-host beta therefore ships on our schedule regardless of CASA (de-risks Schedule Risk #1).

---

## 7. Workstreams

### WS-0 — Immediate hygiene (in progress; scoped July 25 2026)

The messaging debt measured larger than v1.0 assumed. It is not a handful of lines — it is the *thesis* of two SEO landing pages, the funding story on `/pricing`, and ~15 free-hosted promises. Revised scope:

| ID | Task | Status |
|---|---|---|
| 0.1 | Acquire `usechalk.com` (+`.org` defensively); 301 `.xyz` (Spamhaus-flagged TLD; filtered by M365 and school content filters) | **Deferred (D19)** — non-blocking; all domain refs kept env-driven for a one-variable swap |
| 0.2 | Fix README false pricing claim (Clever rostering is free to districts; ClassLink ~$3.50/user/yr) | In progress |
| 0.3 | Remove all "drop-in Clever/ClassLink" and "inherit the vendor network" language from repo, site, docs (D5). **Claims only — the code stays (D18)** | In progress |
| 0.4 | **Fix the live free-hosted promise** on the site — it contradicts D3. Rewrite landing + pricing on `chalk-marketing` to Devices-first positioning with the §7 D16 ladder | In progress |
| ~~0.5~~ | ~~Fix the two Chromebook Getter reliability complaints, then feature-freeze~~ | **Deferred.** Replaced this pass by a read-only capability study of all three Getter codebases (`Chromebook-Getter`, `getter-suite-api`, `getter-suite-functions`) feeding WS-1/WS-3 — the suite is the field-tested version of the ChromeOS ingestion path we're about to build |
| 0.6 | Retire AssetRemix naming on public surfaces; 301 `adminremix.com/it-asset-management` | Partial — the sole AdminRemix reference on the Chalk site sits inside a page being deleted (D20); the adminremix.com property itself is outside this working set |
| **0.7** | **Unpublish `/migrate-from-clever` + `/migrate-from-classlink` with 301s → `/vs-snipe-it` (D20)** | New |
| **0.8** | **Remove public marketplace surfaces (D4):** delete `/marketplace` + `/marketplace/apply`, strip vendor tiers from `/pricing`, drop the vendor CTA from `/app-gallery` (the gallery itself survives — it is district-facing, not a revenue pitch), and stop routing `vendors.{apex}` in the hosted control plane. Code retained, unrouted, reversible | New |
| **0.9** | **Build `/vs-snipe-it`** — the replacement comparison page and new funnel entry (D16/D20) | New |
| **0.10** | **Messaging lint in CI** on `chalk` and `chalk-marketing` — fails the build if a killed claim reappears. This is what makes WS-0 stay done | New |

### WS-1 — Google Admin SDK ingestion (start immediately)
Per v1.0 spec, unchanged in substance; implemented as `google-sync/src/chromeos.rs` + backoff module (`ARCHITECTURE.md` §5). Non-negotiables: `batchChangeStatus` not the deprecated `action`; 100/page list + `projection=FULL`; 20-device OU-move chunking; annotated-field length validation (200/500/100); telemetry licence-gated — no promised dashboards without confirming district licensing; backoff designed to the **unraiseable** per-Workspace ceiling; deprovision guarded per §5.1.

### WS-2 — UI foundation (parallel; blocks WS-3/4 UI)
Implement `DESIGN_SYSTEM.md`: tokens + base components in `crates/console` assets, page shell + role-based routing, dense-table pattern, AG Grid island, teacher portal, HTMX live-region announcement bus, focus management on partial swaps. VPAT drafted before the first large-district conversation.

### WS-3 — Devices module (UNBLOCKED, per §5.1) · WS-4 — Helpdesk module (UNBLOCKED, per §5.2)
Crate-level task breakdown in `ARCHITECTURE.md` §11.

### WS-5 — Spreadsheet surface (revised per D12)
| ID | Task |
|---|---|
| 5.1 | REST API for asset/ticket read-write with scoped token auth (needed regardless) |
| ~~5.2~~ | ~~New Apps Script client~~ **Killed.** Revisit only on explicit post-launch demand |
| 5.3 | CTA inside existing Chromebook Getter — "Your fleet, synced free →" panel, well-designed, zero scope/identity changes. This is our only channel to the install base; treat it as a first-class growth surface, not a footer link |
| 5.4 | One-click export of any Chalk asset view to Google Sheets / CSV download |

### WS-6 — OAuth verification, CASA, Marketplace listing (START FIRST — longest external lead)
Unchanged from v1.0: new Cloud project + OAuth client for **hosted** Chalk only; minimal restricted scope set; CASA Tier 2 (~$500–1k/yr, recurring); new Chalk listing after verification clears. Now explicitly *not* on the self-host critical path (§6).

### WS-7 — Pricing, billing, tenancy (per D14)
Enrollment count snapshotted nightly from roster data as the billing dimension; module entitlement flags flow control plane → tenant config; annual PO/invoice workflow (manual-first); grandfather flags pin the three existing payers at current spend indefinitely.

**Published tiers (annual, hosted, on PO)** — **revised per D16, Snipe-IT-anchored.** Publishing prices is itself a wedge (Clever, ClassLink, and Snipe-IT's dedicated tiers are all quote-or-contact-only above the entry rung):

| Fleet size | Devices + Helpdesk | Full stack (+ roster/SSO) | Snipe-IT comparable |
|---|---|---|---|
| ≤ 1,000 devices | **$499** | **$1,499** | $399.99 Basic (community support only) |
| ≤ 5,000 devices | **$999** | **$2,999** | $999.99 Small Business |
| ≤ 20,000 devices | **$2,499** | **$5,999** | $2,499.99 Dedicated (Small) |
| 20,000+ / ESC · BOCES | **$4,999** | quote | $5,000–7,500 Dedicated (Med/Large) |

Positioning line: **"Snipe-IT's price. Plus a help desk. Plus it already knows your students."**

What makes the match honest rather than a discount: Snipe-IT has **no help desk at any tier, no SIS connectors, and no student roster**. Every Chalk tier includes all three. Snipe-IT self-hosted is free (as is Chalk, D2) and offers **no education discount**.

Free hosted tier: unlimited Chromebooks, unlimited admins, full get/set/bulk-OU/telemetry, no caps, no redaction (D8). Self-hosted: everything, forever (D2).

Honesty constraint on all published surfaces: Devices + Helpdesk are labeled **"Shipping SY2027-28"** until they actually ship. Roster sync, SAML IdP, and Google/AD provisioning ship **today** and carry no such label. Competitor figures are governed by the sourced-pricing honesty contract in `chalk-marketing/src/lib/competitorPricing.ts` — every number needs a source and a verification date, reviewed quarterly.

### WS-8 — Strangle plan (renamed from "migration", per D11)
| ID | Task |
|---|---|
| 8.1 | Per-district capability checklist sourced from actual DB usage (from Gate B audit); reviewed each semester |
| 8.2 | `chalk import assetremix --from <export>` — built when the first district's checklist clears, not before |
| 8.3 | Parallel-run tooling; any cutover lands at semester/summer break; white-glove; price locked 12 months |
| 8.4 | Chromebook Getter payer comms framed as **upgrade, not price change** ("same price, now you also get Helpdesk, non-Chromebook assets, and the open-source platform"). Free CG users are never migrated, gated, or nagged — bridge, never a wall |

### WS-9 — Distribution / packaging
Unchanged from v1.0: Docker Hub + compose; awesome-selfhosted PR + GitHub topics; Proxmox VE helper script; DO/Railway/Render/Coolify one-clicks; Cloudron/YunoHost/CasaOS/TrueNAS/Unraid; Homebrew.

### WS-10 — AssetRemix maintenance mode (NEW, per D11)
| ID | Task |
|---|---|
| 10.1 | Define + document the maintenance contract: security patches, data integrity, billing continuity, uptime. No features. ~2 hrs/wk budget cap |
| 10.2 | Pin dependencies; document the deploy runbook (5 processes) so incidents don't cost a weekend |
| 10.3 | Quarterly check: run cost, incident count, Vue 2 exposure review; revisit D13 only if strangle horizon extends past ~2 years |

---

## 8. Sequencing

```
Week  0    2    4    6    8   10   12   14   16   18   20   22   24
WS-6  ████████████████████████░░░░  OAuth+CASA (external clock)   ◀ file week 0
WS-0  ██                            Hygiene
Gate B ████████                     Validation + DB usage audit (parallel)
WS-1  ████████░░                    Admin SDK client (∥ WS-2)
WS-2  ████████░░                    UI foundation (∥ WS-1)
WS-3  ░░░░░░░░████████░░            Devices
WS-4  ░░░░░░░░░░████████            Helpdesk
      ░░░░░░░░░░░░░░░░████          SELF-HOST BETA (~wk 10–12, no CASA dependency)
WS-5  ░░░░░░░░░░░░░░░░████          Spreadsheet surface + CG CTA
WS-7  ░░░░░░░░░░░░░░░░████          Pricing/billing
WS-9  ░░░░░░░░░░░░░░░░░░░░████      Distribution push
WS-8/10 ─ continuous ─              Strangle checklists / maintenance mode
```

**Critical path:** WS-6 for *hosted* launch only. Self-host beta ships on our schedule (~week 10–12).

### 8.1 Calendar alignment (unchanged — the clock that matters)
- **Aug–Dec 2026** — build + self-host land-grab. Off-cycle for purchasing; nothing lost by not selling.
- **Jan–Mar 2027** — district budget season for FY2028. **Hosted quotes must exist and be quotable.**
- **May–Jun 2027** — board adoptions, POs. **Jul–Aug 2027** — summer installs for SY2027-28.
- SY2026-27 = validation + free-tier land grab. SY2027-28 = first real revenue harvest. Missing Jan–Mar 2027 costs a full year.

---

## 9. Non-goals (explicitly parked)

All v1.0 non-goals stand: vendor marketplace revenue (D4); Clever/ClassLink compat endpoints (D5); SOC 2 (defer until a deal demands); SMB/MSP + HRIS connectors; standalone helpdesk product; plugin runtime; OneRoster certification + SIS partner listings (Year 2); SPA rewrite of the console. New from Gate A:
- **New Sheets add-on** (D12)
- **Vue 3 port / any AssetRemix frontend investment** (D13)
- **Billing SaaS integration in Chalk** (D14)
- **AssetRemix feature parity in Chalk** — the §5.3 list returns item-by-item on evidence, never as a block
- **User Getter / Meet Enhancement Suite changes** — untouched; same CTA playbook later if warranted

---

## 10. Risks

| Risk | Sev | Mitigation |
|---|---|---|
| ~~Gate A reveals AssetRemix larger than modeled~~ | — | **Realized and handled** (D11 strangler). |
| OAuth/CASA review exceeds 90 days | High→Med | Self-host path fully decoupled (customer's own Cloud project + service account). Hosted quotes can even be *taken* before listing goes live if verification is in flight by Jan 2027. |
| Solo bandwidth (10–15 hrs/wk) | High | Ruthless scope (§9). AI-agent leverage compresses build; the bottleneck is review bandwidth + external clocks — hence WS-6 week 0 and docs-first engineering (this trio of documents is the agent brief). |
| Alienating the Chromebook Getter base | High | D12: freeze + fix bugs + generous free tier. Never force anything. One prior freemium change already caused public churn — treat that reviewer as the canary. |
| Damaging the verified Marketplace listing | High | D6. Separate project/listing. No scope or identity changes, ever. |
| Vue 2 EOL on the paid product | Med | Maintenance island behind auth, small user base, ~2 yr horizon (D13, WS-10.3). |
| Live messaging debt (false Clever claim, free-hosted promise) | Med | WS-0 this week. It's in front of the exact audience we'll later sell to. |
| Google closes the device-assignment gap natively | Med | Lean on helpdesk + multi-asset + roster context Admin Console won't build. |
| Trust as an unknown project near district infrastructure | Med | Devices-first sequencing; self-host option; NDPA + DPA ready; security whitepaper points at real architecture (`ARCHITECTURE.md` §9). A security incident on a login-adjacent product is existential — treat every auth-path change as high-scrutiny. |
| AGPL wariness in district legal review | Low | FAQ; hosted sidesteps entirely. |

---

## 11. Compliance (parallel track, sales-blocking)

Unchanged from v1.0: SDPC NDPA v2 pre-signed + Resource Registry listing (**highest priority, low cost**); NY Ed Law 2-d rider (NIST-aligned DSPP + Parents' Bill of Rights), IL SOPPA, CA SOPIPA — strictest first; Student Privacy Pledge; DPA template + security whitepaper before first sales conversation; cyber/E&O insurance before any district contract; VPAT before first large-district deal (WS-2); SOC 2 deferred (§9).

### 11.1 Standing condition — the uncapped-liability mitigation is conditional (added July 26 2026)

The published Terms state **no liability cap for paid tiers**. Rather than invent one, WS-0's remediation mitigated it *procedurally*: a paid tier exists only on a mutually executed order form, and the cap is set there — so no paid use is ungoverned by a negotiated cap.

**That mitigation is load-bearing on one fact: there is no self-serve paid signup.** The moment anything resembling self-serve paid upgrade or card checkout ships, the mitigation is void and §11 becomes a live uncapped-liability exposure on a public page. This is consistent with D14 (manual-first, annual PO + invoice, no billing SaaS) and D3 — so honoring D14 *is* the control. Treat any future proposal to add self-serve paid signup as **requiring a drafted liability cap first**, not as a product decision alone.

Related gaps left explicitly for counsel, not invented in-house: paid-tier SLA (availability target, support response times, service credits); fee, invoicing and renewal mechanics; the cap itself and its carve-outs. Pre-existing and separate: §15's Texas governing law with no venue carve-out (a live procurement blocker for many districts), one-way indemnification, and the absence of state-specific student-privacy recitals (NY Ed Law 2-d, CA SOPIPA/AB 1584, IL SOPPA) in the DPA — any of those states will reject the DPA as currently drafted.

One factual claim now published and worth confirming stays true: privacy policy states **Chalk does not take payment-card details.** That follows from D14 and from the hosted control plane having no billing substrate at all, and it must be re-checked if billing ever changes.

---

## 12. Open questions

1. ~~Is `usechalk.com` / `.org` available or held?~~ **Deferred, not blocking (D19).** `.xyz` stays for now; every domain reference is env-driven (`PUBLIC_SITE_DOMAIN` in `chalk-marketing/src/lib/config.ts`), so acquisition remains a one-variable change. The Spamhaus/content-filter concern is unchanged and still worth resolving before the Jan–Mar 2027 quote season, when the site starts landing in district inboxes.
2. Which SIS do Llano, Malakoff, KIPP Indy run — covered by existing connectors? (Feeds strangle checklists.)
3. Chromebook Getter install count from the Marketplace console — sizes the CTA funnel (channel is confirmed in-app only).
4. Does User Getter warrant the same CTA treatment post-launch? (Parked; §9.)
5. Gopher for Chrome's current free-tier mechanic — verify on the live listing before using in competitive copy.
6. Architecture opens (5, in `ARCHITECTURE.md` §12): hosted process topology; technician identity when techs aren't in the SIS; day-one Postgres CI parity; telemetry licence probing; hosted attachment store + AV stance.
7. Design opens (3, in `DESIGN_SYSTEM.md`): per-tenant accent presets; AG Grid bundle vs no-build purity; command palette timing (default: post-v1). **New, from D17:** indigo and the `--violet-*` *status* hue (open tickets, deprovisioned devices) sit closer together than chalk-blue and violet did. If they prove indistinguishable at badge size, move the violet status hue — not the accent. Resolve during WS-2's token extraction.
8. **Snipe-IT pricing drift (D16).** Our published ladder is anchored to competitor prices we do not control. `competitorPricing.ts` already enforces a quarterly review and a 9-month staleness rule — Snipe-IT must be added to that rotation, and a move on their side is a pricing decision on ours, not a copy edit.

---

## Appendix A — Acceptance criteria for v1.0 hosted launch

- [ ] Fresh install → SIS connected → Google authorized → **populated device inventory with students attached in under 30 minutes**, zero manual CSV
- [ ] Teacher submits a ticket in **under 60 seconds**, no training, no account creation
- [ ] Technician performs a **bulk OU move on 500 devices** without leaving the console
- [ ] Round-trip **500 devices** to a spreadsheet, edit, re-import with diff preview
- [ ] Single binary builds and runs on Linux/macOS/Windows with **no external dependencies beyond SQLite**
- [ ] Self-hosted build has **zero feature gates** relative to hosted (entitlements are hosted-config only)
- [ ] WCAG 2.1 AA audit passes on teacher portal and technician console; VPAT drafted
- [ ] Bulk deprovision requires admin role + typed confirmation and writes `asset_events` + admin audit records
- [ ] **Three existing districts remain on AssetRemix with zero disruption; ≥3 new districts live on hosted Chalk Devices+Helpdesk** *(replaces v1.0's "migrate all three" criterion — see D11)*
