# Gate A Memo + PRD v1.0 Amendments
**Date:** July 25, 2026 · **Prepared from:** direct inspection of all 7 repos + live sites
**Closes:** PRD §3 (Gate A), Open Questions #1, #2, #6 (partial), #7 (partial)

---

## 1. Gate A verdict: **Branch C — Federate/Strangle** (no inversion)

### 1.1 The assessment inputs, now measured

| Repo | Stack | Size (excl. tests, deps, generated) |
|---|---|---|
| `asset-getter-backend` | TypeScript · Express + Apollo GraphQL · Sequelize/Postgres (+ Cockroach/Neon variants) · Redis + BullMQ · GCP Pub/Sub, Cloud Run, GCS · Firebase · Chargify · BoxyHQ SAML · WorkOS dsync · OpenAI + pgvector | **~54k LOC**, 76 models, 148 migrations, **5 separately deployed processes** (graphql, express/webhooks, processor, consumers, crons) |
| `asset-getter-frontend` | **Vue 2.7 SPA (EOL Dec 2023)** · Buefy (unmaintained) · Apollo codegen · Netlify | **~47k LOC**, ~50 view areas |
| `getter-suite-api` | TS/Express | ~3k LOC |
| `getter-suite-functions` | TS, Node 18 functions | ~8k LOC |
| `Chromebook-Getter` | Apps Script + Vue-in-HTML sidebar | **~1.8k LOC** |
| `chalk` | Rust workspace, 9 crates | ~52k LOC (core 25k, console 9.7k, idp 8.5k, ad-sync 2.9k, google-sync 2.7k, cli 2.6k, telemetry, agent, marketplace stub) |
| `chalk-hosted-crate` | Rust, multi-tenant control plane v1.5.10 (signup, tenants, scheduler, mailer, vendor/marketplace portal) | ~13k LOC |

AssetRemix = **~100k+ LOC across two repos**, far past the 40k Branch-C trigger, and plainly >12 person-months.

### 1.2 The capability inventory (Open Question #2, finally answered)

AssetRemix is not "assets + tickets." It is a **Snipe-IT-class ITAM plus a full helpdesk plus an integration platform**:

- **ITAM:** assets, accessories, components, consumables, licenses, bundles, categories, manufacturers, suppliers, locations, status labels, departments
- **Chain of custody:** checkout/checkin confirmations, custody verification, signature capture, bulk-assign documents, EULA versioning
- **Money:** fines, invoices, funding sources, funding history, grant provisioning, Chargify billing with per-component entitlements
- **Helpdesk:** tickets, custom tickets, categories/statuses/priorities, auto-assign rules, inbound email→ticket, comments with @mentions, feedback, agent-count billing sync
- **Platform:** roles/permissions, dashboards + dashboard templates, reports, read-only shares, webhooks, user-defined cron jobs, email branding (white-label), bulk data mapper/merger
- **Integrations:** Google directory sync, WorkOS dsync, BoxyHQ SAML SSO, ClassLink, Snipe-IT sync, Lansweeper
- **AI:** OpenAI embeddings + pgvector similarity

And per your answer today: **the three paying districts use this breadth — the advanced modules are load-bearing.**

### 1.3 Why not C′ (inversion)

AssetRemix cannot be the center of gravity for the go-forward product:

1. **The frontend is on a dead framework.** Vue 2 reached EOL Dec 2023; Buefy is unmaintained. The SPA is a depreciating asset regardless of any decision here.
2. **The backend cannot be self-hosted.** It requires Pub/Sub, Cloud Run, Redis, Firebase, Chargify, WorkOS, BoxyHQ, Postmark, GCS. The entire D2 funnel (free self-host → hosted revenue) is impossible on this stack.
3. Chalk's 52k LOC of modern Rust + working hosted control plane is real, current, and matches the distribution thesis.

AssetRemix is not the future platform — but it **is the present revenue**, and §2 below treats it that way.

---

## 2. The amendment the PRD needs: Branch C ≠ "ship AssetRemix as a companion container"

The PRD's Branch C says "AssetRemix ships as a companion service or container." **That option does not actually exist**, for the same reason C′ fails: a self-hoster (or even hosted-Chalk) cannot run the AssetRemix dependency stack as a sidecar. Federation as described is a fiction.

The workable version is a **strangler pattern**:

1. **AssetRemix enters maintenance mode, not a rewrite and not a sidecar.** Security patches, bug fixes, billing keeps working. No new features. Budget ~2 hrs/wk. Your "moderate" run cost makes a 12–24 month strangle horizon sustainable.
2. **The three districts stay on AssetRemix indefinitely.** They use it broadly; Chalk's §6 schema covers a fraction of what they touch. Migrating them onto v1 Chalk would be churning 100% of current revenue to satisfy an org-chart aesthetic. They migrate **only when** Chalk covers what *they actually use* (audit their DBs per-district — don't guess) — likely SY2027–28 at the earliest, possibly never for KIPP-style broad users. That's fine.
3. **Chalk's Devices + Helpdesk modules are built natively in Rust against the PRD §6 schema — deliberately smaller than AssetRemix.** This is not "rewriting AssetRemix" (the trap the PRD warns about). It's building the *scoped-down free product* the funnel needs: Chromebooks-first devices, simple tickets, roster join. AssetRemix's code becomes the **reference spec** — its 148 migrations and consumer jobs (esp. `chromebookInitialSync`, `emailToTickets`, `ticketAssignBot`) encode years of learned edge cases. Port the lessons, not the code.
4. **Naming:** publicly, AssetRemix retires per D1. The three customers keep using what they have; no forced rebrand of their running instance. Quiet is fine.

### Consequently, two PRD edits:

- **Delete acceptance criterion** "All three existing district customers migrated with no data loss" from v1.0 hosted launch. Replace with: *"Three existing districts remain on AssetRemix with zero disruption; ≥3 new districts live on hosted Chalk Devices+Helpdesk."*
- **WS-8 is renamed from "migration" to "strangle plan":** per-district capability checklist sourced from their actual DB usage, reviewed each semester. `chalk import assetremix` still gets built — but its deadline is driven by district readiness, not launch.

---

## 3. Your add-on question: **do not build a new Sheets add-on**

Your instinct is right. The reasoning:

1. **The distribution channel and the functionality are separate assets.** Chromebook Getter's value is the verified listing, ranking, and install base — the codebase is 1.8k lines of Apps Script. You reach that audience via the in-app CTA (your only channel, per today's answer), and a CTA works identically whether it links to "a companion add-on" or to a Chalk signup page. A second add-on adds zero reach.
2. **The spreadsheet UX already lives inside Chalk's plan.** WS-2.4 (AG Grid bulk-edit island) + WS-3.4 (CSV/Sheets round-trip with diff preview) *are* the "spreadsheet built into Chalk." That's the durable version — no Marketplace review, no scope risk, works for self-hosters.
3. **A new listing = a new OAuth verification cycle** and, per the PRD's own WS-5 caution, an add-on authenticating to arbitrary user-supplied servers invites policy trouble. All cost, no distribution.

**Revised WS-5:**
- **Keep 5.1** (REST API + tokens) — needed for everything anyway.
- **Kill 5.2** (new Apps Script client) as v1 scope. Revisit only if CG users explicitly demand live in-Sheets sync after Chalk launch.
- **Keep 5.3** (CTA inside existing Chromebook Getter, zero scope/identity changes) — and since in-app is your *only* channel to that base, invest in it: a well-designed "Your fleet, synced free →" panel, not a footer link.
- **Add 5.4:** one-click **export of a Chalk asset view to Google Sheets / CSV download** from inside Chalk. Cheap, satisfies the "I live in Sheets" habit, no Marketplace involvement.
- Chromebook Getter itself: fix the two reliability bugs (WS-0.4), then **feature-freeze**. It's a marketing asset now.

---

## 4. Findings that confirm or sharpen other PRD items

| Item | Finding |
|---|---|
| **WS-0.2/0.3 are urgent and live** | Both the current site (usechalk.xyz) and the GitHub README still say "drop-in Clever replacement," "same capabilities without the recurring costs," and "districts pay thousands per year to services like Clever." Per D5 these must go — and note the site also currently promises **hosted at no cost**, which contradicts D3 (hosted is the paid product). The messaging debt is bigger than the PRD lists: it includes the pricing promise. |
| **chalk-marketing exists** (Astro + Tailwind, Caddy-fronted) | WS-0's copy fixes have a home. Pricing page is placeholder — the §7 tiers can go straight in. Add a task: rewrite landing/pricing to Devices-first positioning. |
| **chalk-hosted-crate already has marketplace/vendor-portal code** (`vendor.rs`, `tenant_marketplace.rs`, `portal_ui.rs`) | D4 kills marketplace as a revenue line — don't delete the code, just don't surface or sell it. No engineering work needed; just don't route to it. |
| **Act 2 assets already exist** | `idp` (8.5k LOC, SAML/QR/picture-password) and `ad-sync`/`google-sync` crates are real. The Devices-first sequencing is about *marketing order*, and the PRD is right that nothing here needs building first — WS-1's Admin SDK work extends `google-sync` rather than starting cold. |
| **Devices/Helpdesk are true greenfield in Chalk** | No asset/ticket tables exist in Chalk's migrations. §6 schema stands as written. AssetRemix's schema (76 models) is the field-tested reference for the ~10 tables you're keeping. |
| **Grandfathering is trivial** | Three customers at $99/mo flat. A config flag, not a billing project. |
| **Open Q6 (User Getter)** | Confirmed to exist on adminremix.com alongside Meet Enhancement Suite. Same treatment as Chromebook Getter: leave alone, CTA later. Not a v1 concern. |

---

## 5. Revised risk table (delta only)

| Risk | Change |
|---|---|
| "Gate A reveals AssetRemix is far larger than modeled" | **Realized.** ~100k LOC, broad usage by all 3 customers. Handled by §2 strangle plan. |
| **NEW: Vue 2 EOL on the paid product** | Medium. Behind auth, small user base → acceptable in maintenance mode for 12–24 months. Do **not** port to Vue 3 (that's the year-losing rewrite in different clothes). If the strangle horizon extends past ~2 years, revisit. |
| **NEW: messaging debt on live surfaces** | The false Clever-pricing claim and free-hosted promise are live *today* in front of the exact audience you'll later sell to. WS-0 this week, as written. |
| Solo bandwidth | Softened slightly: heavy AI-agent leverage compresses WS-1/WS-3/WS-4 build time. The bottleneck shifts to **your review bandwidth and the external clocks** (CASA review, K-12 buying calendar) — which is more reason WS-6 starts first, as the PRD already says. |

---

## 6. What does NOT change

The PRD's spine survives contact with the code:

- **D1–D10 all stand.** Notably D6 (never touch the CG listing) and D9 (single binary for *Chalk core* — now cleanly true, since AssetRemix stays a separate maintained service rather than pretending to be a module).
- **Build order stands:** WS-6 first (longest external lead), WS-0 this week, WS-1 (extend `google-sync`), WS-2, then WS-3/WS-4 — now unblocked, since Gate A is closed with this memo.
- **Gate B still gates the big build.** One addition to the interview work: pull per-module usage stats from the three districts' databases before the interviews, so "what would you miss?" is asked against facts.
- **Calendar logic stands:** Jan–Mar 2027 quotable-or-bust.

## 7. Immediate next actions (this week)

1. WS-0 as written — plus the free-hosted-promise fix on usechalk.xyz (§4 row 1) and `usechalk.com` acquisition check.
2. Open the WS-6 Cloud project + start scope enumeration (the clock that matters most).
3. Run the per-district module-usage audit query against AssetRemix prod (feeds Gate B and the strangle checklist).
4. Kick off Gate B outreach.
