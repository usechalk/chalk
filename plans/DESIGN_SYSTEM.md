# Chalk Design System v1.0

**Status:** Canon for all Chalk UI work (WS-2, WS-3, WS-4 surfaces).
**Owner:** Lundin Matthews / AdminRemix LLC — July 2026
**Applies to:** technician console, teacher portal, admin console (existing HTMX/Askama pages), the AG Grid island, and (one section only) the marketing site.
**Non-negotiable baseline:** WCAG 2.1 AA on every surface, both themes, from the first commit (PRD D10). Every color pair in this document has a computed contrast ratio next to it. If you introduce a pair that is not in this document, you compute and record its ratio before merging.

How to use this doc: Section 3 is copy-pasteable CSS. Sections 4–8 are build specs. Section 9 is the audit contract. Section 10 tells you where files go and what "done" means. An engineer or agent should be able to build any listed component from this document alone, without a design review.

---

## 1. Design principles

1. **Density is respect for the technician.** A tech triaging 4,000 Chromebooks in August does not want whitespace; they want 30+ rows on screen, sortable columns, and keyboard everything. Compact is the default density in the console. We never "consumerize" the console.

2. **Zero training means zero onboarding UI.** The teacher portal has no tour, no tooltips-on-first-run, no empty-state explainer videos. If a screen needs instructions, the screen is wrong. Target: a teacher who has never seen Chalk submits a ticket in under 60 seconds (v1.0 acceptance criterion).

3. **Boring where it counts.** Buttons look like buttons, links are blue and underlined on hover, destructive actions are red and ask twice. District IT directors are evaluating whether to trust us with student data; visual novelty spends trust we haven't earned. Personality lives on the marketing site, not in the app.

4. **The server is the source of truth; the UI is a projection of it.** HTMX swaps, no client state to reconcile. Every interaction must work as a plain form POST first, then get progressively enhanced (hx- attributes, transitions). If JavaScript fails to load, a technician can still move 500 devices to an OU.

5. **Accessible is the definition of built.** WCAG 2.1 AA is a build constraint, not a QA phase (D10; ADA Title II deadlines Apr 2027/2028; VPAT demanded in procurement). A component without keyboard operability, a focus state, and a passing contrast pair does not exist yet.

6. **One token set, two rooms.** Light mode is paper in a well-lit office; dark mode is the slate board after hours. Both are generated from the same primitives and the same semantic names — no component ever references a raw hex, so no component can drift between themes.

7. **Status is a language, not a decoration.** Six device states, five ticket states, four priorities, three SLA states — each has exactly one hue, used identically in tables, badges, charts, and the grid island. A tech should be able to squint at a screen and read fleet health from color alone (with text/icon always present for the non-squinters and screen readers).

---

## 2. Brand foundations

### 2.1 Name and wordmark direction

- **Name:** Chalk. Always capitalized as a proper noun ("Chalk", never "CHALK" or "chalk" in prose; the CLI binary is `chalk`).
- **Wordmark:** lowercase geometric wordmark `chalk` set in the marketing display face (Space Grotesk, see §2.4), ink color on paper or chalk-white on slate. The mark's only flourish: the terminal of the "k" may carry a subtle dry-edge/dust break — this is the single place chalk texture touches the identity.
- **Symbol/favicon:** a rounded square slate tile (slate-900 `#212D36`) with a chalk-white lowercase "c", or in monochrome contexts a simple stick of chalk at 45°. In the app UI, only the tile mark appears (sidebar header, favicon). No textured mark in the app.

### 2.2 The chalk metaphor: usage rules

The metaphor is a whisper, not a costume.

**Allowed (marketing surfaces only — usechalk.com, social cards, README hero):**
- Subtle chalk-dust grain texture on hero backgrounds (≤4% opacity noise, never behind body text).
- Slate-board panels with chalk-white handwriting-style *illustrations* (diagrams, arrows) — never handwriting fonts for real copy.
- The dusty accent gradient on section dividers.

**Banned everywhere:**
- Handwriting/script/chalkboard fonts for any UI or body text.
- Skeuomorphic chalkboard frames, wood trim, erasers, apples, ABC blocks, crayon anything. Chalk is a K-12 *infrastructure* product; the buyer is an IT director, not a kindergartner.
- Texture of any kind inside the admin app, console, or teacher portal. App surfaces are flat, clean, Linear/Stripe-grade.

**In-app expression of the metaphor** (the entire allowance): the warm paper light theme, the slate dark theme, the dusty-blue accent, and the name. That's it.

### 2.3 Voice and tone

| Surface | Voice | Example |
|---|---|---|
| **Technician/admin console** | Terse, technical, exact. Verb-first labels. Counts everywhere. Never chatty, never apologetic filler. | "Move 512 devices to OU /Students/HS?" — not "You're about to move some devices!" |
| **Teacher portal** | Plain, warm, human. Second person. No jargon (never "asset", "OU", "provision"). Friendly but not cutesy — no exclamation marks in error states, no emoji. | "What's wrong with your device?" / "Got it — the tech team has your ticket." |
| **Destructive/irreversible flows** | Blunt. State the consequence in the first sentence. | "Deprovisioning is permanent and affects the device's license. This cannot be undone in Chalk or in Google Admin." |
| **Marketing site** | Confident, direct, slightly dry. Publish real numbers (pricing is a wedge). Anti-hype: we sell against quote-only vendors by being concrete. | "Chalk already knows your students. Install to populated inventory in 30 minutes, zero CSVs." |
| **Errors (all surfaces)** | Own the failure, state what happened, give one next step. Never blame the user, never say "oops". | "Google sync failed: rate limit reached. Chalk will retry automatically in 32 seconds." |

Microcopy rules: sentence case for everything (buttons, headings, labels — "Save changes", not "Save Changes"); no Oxford-comma debates in UI strings (keep labels ≤3 words where possible); dates absolute in the console (`2026-07-25 14:32`), relative in the portal ("2 hours ago").

### 2.4 Typography decision

> **AMENDED July 25 2026 — PRD D17.** The "no embedded font" rule below is **reversed**. Chalk already ships **Bricolage Grotesque** as a self-hosted variable woff2 (weights 200–800, `font-display: swap`), served from `console/src/lib.rs:335-355` and declared at `console/templates/base.html:9`. It stays, as `--font-display`, used for headings and the wordmark.
>
> The binary-size argument below was sound in the abstract but is moot in practice: the font is already in the binary, already unified across console/IdP/hosted portal (v1.6.2), and removing it is pure churn against a schedule with no slack. It also gives the app a single shared identity with the marketing site, which the original plan achieved only by paying for Space Grotesk there.
>
> **What survives unchanged and is still binding:** the *body/UI* stack stays the system font stack (`--font`), so dense tables cost zero download and zero FOUT; `--font-mono` is unchanged; `font-variant-numeric: tabular-nums` on all numeric and table content is still mandatory; and the layout rule below — never depend on exact text width, use `ch`-based widths for mono columns — still applies, now for the additional reason that a variable display face reflows differently at different weights.
>
> Net: **display face = Bricolage Grotesque; body/UI/tables = system stack; code = system mono.** One embedded font, not zero, and not two.

---

**App (console, portal, admin): system UI font stack. No embedded font.**

```css
--font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
             "Helvetica Neue", Arial, "Noto Sans", sans-serif;
--font-mono: ui-monospace, "SF Mono", "Cascadia Code", "Segoe UI Mono",
             Menlo, Consolas, monospace;
```

Justification (this is a decision, not an option):
- **Binary size (D9):** Inter variable, even subset to Latin, is ~110–330 KB woff2. rust-embed puts it in every release binary on 4 platforms forever, and it must be served + cached per tenant. The system stack costs 0 bytes and renders in 0 ms with zero FOUT/FOIT — meaningful when the whole pitch is "one small binary."
- **Fitness:** SF, Segoe UI, and Roboto are all excellent dense-UI faces. Our densest surface is a data table where the deciding features are tabular figures and small-size legibility — the system faces deliver both; apply `font-variant-numeric: tabular-nums` on all numeric/table content and `--font-mono` on serials, asset tags, and MAC addresses.
- **Risk accepted:** cross-platform metric variance (~2–4% width). Mitigation: never design layouts that depend on exact text width; min-widths on buttons; `ch`-based widths for mono columns.

**Marketing site (separate repo, Astro + Tailwind, no size constraint):** Inter variable for body/UI, **Space Grotesk** (weights 500/700) for display headings and the wordmark. Space Grotesk is geometric with a slightly technical character — pairs with Inter, reads modern-infrastructure, and is the closest we get to "personality" in type. Both via self-hosted woff2 (no Google Fonts CDN — student-privacy optics matter even on marketing).

---

## 3. Design tokens

### 3.1 Accent color decision

> **AMENDED July 25 2026 — PRD D17 supersedes D15.** The accent is **indigo `#4f46e5`**, the brand that already shipped in v1.6.2, not the chalk-dust blue below. The *reasoning* in this section is unchanged and still binding — it is why the accent must not be green — and indigo satisfies it identically. Likewise §2.4's "no embedded font" rule is reversed: **Bricolage Grotesque stays** as the display face (self-hosted variable woff2, already embedded and served at `/static/bricolage-grotesque.woff2`).
>
> **Why the swap is structurally free.** The token architecture in §3.2–§3.3 was built around `--blue-600`'s contrast behavior, and indigo matches or beats it on both critical pairs:
>
> | Pair | chalk-blue `#33688E` | indigo `#4f46e5` | AA? |
> |---|---|---|---|
> | Accent ↔ `#ffffff` — white-on-accent (button fill) **and** accent-on-white (link text) are the *same pair*; contrast is symmetric | 5.98:1 | **6.29:1** | ✅ |
> | Accent as text on `--paper-0 #FCFBF9` — the warm background this doc was written around, never adopted | 5.78:1 | **6.08:1** | ✅ |
> | Accent as text on `#f8fafc` — `--c-bg`, the app background we actually ship | 5.72:1 | **6.01:1** | ✅ |
>
> Relative luminance: `#4f46e5` = 0.11700, `#33688E` = 0.12557.
>
> *(Corrected in WS-1 C0. This table previously gave white-on-indigo as 5.93:1
> and indigo-on-paper as 6.16:1; both were wrong, and both are better than
> claimed, so nothing was ever at risk. It also listed the button pair and the
> link pair as two separate rows with different values — they cannot differ,
> because WCAG contrast is symmetric in its two colours. **If you ever see
> white-on-accent and accent-on-white quoted as two different numbers, one of
> them is wrong.** Every figure here and in §3.2 is script-computed, never
> estimated by hand.)*
>
> So the semantic layer transplants unchanged: `--accent`, `--accent-hover`, `--accent-ink`, `--accent-subtle`, `--accent-subtle-ink`, `--link`, `--focus-ring` keep their names, roles, and usage rules. What still must be done **before WS-2 ships**:
> 1. ✅ **Done (WS-1 C0).** Full indigo primitive ramp built and every ratio computed and recorded — see §3.2.
> 2. Re-derive the dark-theme accent (light mode can use `#4f46e5` as button fill and link; dark mode needs a lighter step, the analogue of `--blue-400`/`--blue-300`, verified ≥4.5:1 on `--surface` and ≥3:1 for the focus ring).
> 3. Re-verify §8's categorical chart palette — series 1 is the accent hue and its ratio changes.
> 4. ✅ **Done (WS-1 C0) — and they did collide.** ΔE between indigo and violet at the 50-step badge tint is 2.2, i.e. barely perceptible. Per this rule the *status hue* moved: `--violet-*` is retired and the extended status hue is now `--fuchsia-*`. Full ΔE table and reasoning in §3.2.
>
> Items 2 and 3 remain open: 2 is deferred with dark mode itself (§3.3), and 3 (§8's categorical chart palette) still names `--blue-500`/`--violet-500`, which no longer exist — it must be re-derived on the indigo/fuchsia ramps before any chart ships. §5–§7 likewise still reference `--ink-secondary`, a token the shipped set does not define (the shipped pair is `--ink` / `--ink-muted`, with `--ink-muted-aa` for AA-safe secondary text); reconcile during the components pass.
>
> Reality check for whoever implements this: per `ARCHITECTURE.md` §2.1, there are **no CSS files today** — all tokens live in an inline `<style>` at `console/templates/base.html:15-44`, copy-pasted into 10 IdP templates and again into the hosted crate's `portal_ui.rs`. WS-2's first job is extracting those three copies into the single file tree §10.1 describes. Doing the indigo ramp *during* that extraction costs nearly nothing; doing it after costs it three times.

---

**The accent is the "chalk dust blue" family (anchor `--blue-600 #33688E`).** Chalkboard green was seriously considered and rejected for one dominant reason: **green is load-bearing as a status color.** In this product, green means "device active", "ticket resolved", "SLA ok" — across thousands of table rows. If green were also the interactive accent (buttons, links, selected rows, focus), the fleet-health-at-a-glance property of the status language (Principle 7) would be destroyed, and every primary button would whisper "success" before the action ran.

Dusty blue wins on the merits, not just by elimination:
- It *is* the chalk metaphor: blue-grey chalk dust on slate, desaturated and calm — not tech-startup electric blue.
- Blue is the strongest learned convention for "interactive" — zero-training surfaces (Principle 2) should spend zero novelty on affordances.
- It photographs as trustworthy/institutional to district IT directors, and it harmonizes with the slate neutral ramp (both are cool; the paper warmth provides the contrast).

The **info** semantic maps onto the accent family (acceptable collision: "informational" and "interactive" share meaning; the rare info banner reading slightly branded is harmless, unlike buttons reading as "success").

### 3.2 Primitive color scales

> **SHIPPED — WS-1 C0.** These are the primitives now living in
> `crates/console/assets/css/tokens.css`, which is the source of truth; this
> section is the contrast registry for them. Every ratio below is a computed
> WCAG 2.1 relative-luminance value, not an estimate. Primitives are
> theme-independent raw values; **components must never reference primitives
> directly** — only the semantic tokens in §3.3.
>
> The ramps are Tailwind's indigo / slate / green / amber / red / fuchsia. That
> is not laziness: every colour the console had already shipped was a Tailwind
> step (`#4f46e5` = indigo-600, `#e2e8f0` = slate-200, `#15803d` = green-700,
> and so on), so filling in the surrounding ramp keeps each scale internally
> coherent *and* keeps the extraction a zero-visual-change refactor. Inventing
> neighbours by eye would have made every 300/400/500 step a guess.

```css
/* tokens.css — layer 1: primitives. Never used directly in components. */
:root {
  /* Accent — indigo (D17) */
  --indigo-50: #eef2ff;  --indigo-100: #e0e7ff;  --indigo-200: #c7d2fe;
  --indigo-300: #a5b4fc;  --indigo-400: #818cf8;  --indigo-500: #6366f1;
  --indigo-600: #4f46e5;  --indigo-700: #4338ca;  --indigo-800: #3730a3;
  --indigo-900: #312e81;  --indigo-950: #1e1b4b;

  /* Neutrals — slate (cool, all the way down; there is no warm-paper end) */
  --slate-50: #f8fafc;  --slate-100: #f1f5f9;  --slate-200: #e2e8f0;
  --slate-300: #cbd5e1;  --slate-400: #94a3b8;  --slate-500: #64748b;
  --slate-600: #475569;  --slate-700: #334155;  --slate-800: #1e293b;
  --slate-900: #0f172a;  --slate-950: #020617;  --white: #ffffff;

  /* Success / warning / danger */
  --green-50: #f0fdf4;  … --green-700: #15803d;  … --green-950: #052e16;
  --amber-50: #fffbeb;  … --amber-700: #b45309;  … --amber-950: #451a03;
  --red-50:   #fef2f2;  … --red-600:   #dc2626;  --red-700: #b91c1c;  … --red-950: #450a0a;

  /* Extended status hue — FUCHSIA, not violet. See the note below. */
  --fuchsia-50: #fdf4ff;  … --fuchsia-700: #a21caf;  … --fuchsia-950: #4a044e;
}
```

**Computed ratios for the pairs that matter (light theme, the only theme shipped):**

| Pair | Role | Ratio | AA? |
|---|---|---|---|
| `--white` on `--indigo-600` | primary button, solid accent fill | **6.29:1** | ✅ text |
| `--white` on `--indigo-700` | primary button hover | **7.90:1** | ✅ text |
| `--indigo-600` on `--white` | links on cards | **6.29:1** | ✅ text |
| `--indigo-600` on `--slate-50` | links on app background | **6.01:1** | ✅ text |
| `--indigo-700` on `--indigo-100` | text on `--accent-subtle` | **6.41:1** | ✅ text |
| `--indigo-700` on `--indigo-50` | info badge | **7.07:1** | ✅ text |
| `--indigo-600` vs `--white` / `--slate-50` / `--slate-100` | focus ring (non-text) | **6.29 / 6.01 / 5.74:1** | ✅ ≥3:1 |
| `--slate-700` on `--white` | body text | **10.35:1** | ✅ text |
| `--slate-800` on `--white` | headings | **14.63:1** | ✅ text |
| `--slate-500` on `--white` / `--slate-50` | AA-safe muted text | **4.76 / 4.55:1** | ✅ text |
| `--slate-400` on `--white` / `--slate-50` | **shipped** muted text | **2.56 / 2.45:1** | ❌ **fails** |
| `--slate-300` on `--slate-900` | sidebar link text | **12.02:1** | ✅ text |
| `--white` on `--slate-900` | sidebar hover / wordmark | **17.85:1** | ✅ text |
| `--slate-500` on `--slate-900` | **shipped** sidebar section label | **3.75:1** | ❌ **fails** |
| `--slate-400` on `--slate-900` | AA-safe sidebar section label | **6.96:1** | ✅ text |
| `--indigo-600` on `--slate-900` | **shipped** active sidebar link | **2.84:1** | ❌ **fails** (<3:1) |
| `--indigo-300` on `--slate-900` | AA-safe active sidebar link | **8.96:1** | ✅ text |
| `--green-700` on `--green-50` | success badge | **4.79:1** | ✅ text |
| `--amber-700` on `--amber-50` | warning badge | **4.84:1** | ✅ text |
| `--red-700` on `--red-50` | danger badge | **5.91:1** | ✅ text |
| `--white` on `--red-700` | solid destructive button | **6.47:1** | ✅ text |
| `--white` on `--red-600` | solid destructive hover | **4.83:1** | ✅ text |
| `--fuchsia-700` on `--fuchsia-50` | extended-status badge | **5.89:1** | ✅ text |
| `--slate-700` on `--slate-100` | neutral badge | **9.45:1** | ✅ text |

**Every ratio above is reproducible: `python3 scripts/contrast.py`.** That
script holds this table as data and prints it with pass/fail per pair, so the
registry is never re-derived by hand — the two wrong figures corrected below
were both hand-arithmetic slips. It also takes an ad-hoc pair
(`scripts/contrast.py '#4f46e5' '#ffffff'`). Adding a colour pair to the design
system means adding a row there and pasting the output here, in the same PR.

> **Correction to §3.1's amendment table.** It recorded white-on-`#4f46e5` as
> 5.93:1 and `#4f46e5`-on-paper as 6.16:1. Recomputed, white on `#4f46e5` is
> **6.29:1**; on the surfaces we actually ship (`#ffffff` / `#f8fafc`, not the
> warm `--paper-0` that was never adopted) indigo as text is **6.29:1** and
> **6.01:1**. Both are better than recorded, so nothing was at risk — but this
> table is the registry of record and the old figures are now removed.

> **Four shipped pairs fail AA and are marked ❌ above.** They are preserved
> exactly as-is because C0 was a zero-visual-change extraction; fixing them is
> a visual decision. `tokens.css` already defines the compliant replacements
> (`--ink-muted-aa`, `--sidebar-ink-section-aa`, `--sidebar-active-ink-aa`) so
> the accessibility pass is a three-line change with the ratios pre-verified.
> `--ink-muted` is the widest-reaching of them: it is the colour of every
> `<small>`, every table header, every stat-card caption and the footer.

**The violet → fuchsia move (the risk D17 named, resolved).** D17 warned that
indigo sits closer to the extended *status* hue than chalk-blue did, and that
if they collide at badge size we move the status hue, never the accent. They
do collide. A badge is mostly its tinted background, and CIE76 ΔE between the
indigo and violet ramps is:

| Step | indigo ↔ violet | indigo ↔ purple | indigo ↔ **fuchsia** |
|---|---|---|---|
| 50 (badge background) | **2.2** | 3.8 | **4.9** |
| 100 | 4.2 | 6.4 | **8.9** |
| 200 (badge border) | 6.7 | 10.9 | **16.6** |
| 700 (badge text) | 17.2 | 18.7 | **33.1** |

ΔE 2.2 at the tint that carries most of a badge's pixels is at the threshold of
*any* perceptible difference — an indigo `storage` badge and a violet
`deprovisioned` badge would read as the same colour in a scanned column.
Fuchsia roughly doubles the separation at every step, decisively so at the
border and text steps that do the disambiguating work, and still reads as
"purple-ish, not red, not blue". **Shipped as `--fuchsia-*`; `--violet-*` is
retired.** If it still reads too close once the Devices badges are on screen,
the next lever is the badge background (fuchsia-100 instead of -50 — 5.43:1,
ΔE 8.9), not another hue.

### 3.3 Semantic tokens

Components use ONLY these. Layer 3 of `tokens.css` additionally aliases the
historical `--c-*` names (`--c-primary` → `var(--accent)`, and so on) onto this
layer, so the ~30 templates that still write `var(--c-primary)` inline keep
working and migrate one at a time. Nothing new may use a `--c-*` name.

```css
/* tokens.css — layer 2: semantic. */
:root {
  color-scheme: light;

  --bg: var(--slate-50);       --surface: var(--white);
  --surface-2: var(--slate-50);  --surface-3: var(--slate-100);
  --surface-raised: var(--white);  --backdrop: rgba(0,0,0,.5);

  --ink: var(--slate-700);        --ink-heading: var(--slate-800);
  --ink-muted: var(--slate-400);  /* 2.56:1 — shipped, fails AA */
  --ink-muted-aa: var(--slate-500);  --ink-inverse: var(--white);

  --border: var(--slate-200);  --border-strong: var(--slate-300);
  --border-input: var(--slate-200);

  --accent: var(--indigo-600);        --accent-hover: var(--indigo-700);
  --accent-ink: var(--white);         --accent-subtle: var(--indigo-100);
  --accent-subtle-ink: var(--indigo-700);  --link: var(--indigo-600);

  --focus-ring: var(--accent);  --focus-width: 2px;  --focus-offset: 2px;
  --focus-glow: rgba(79,70,229,.15);

  --success-*  → green-700 / green-50 / green-200
  --warning-*  → amber-700 / amber-50 / amber-200
  --danger-*   → red-700   / red-50   / red-200
  --info-*     → indigo-600, indigo-700 badge / indigo-50 / indigo-200
  --status-*   → fuchsia-700 / fuchsia-50 / fuchsia-200   (the ex-violet role)
  --neutral-*  → --ink-muted on --bg, --border

  --danger-solid: var(--red-700);  --danger-solid-hover: var(--red-600);
  --danger-solid-ink: var(--white);

  /* Sidebar is a dark region inside a light theme and gets its own set:
     --sidebar-bg/-ink/-ink-strong/-ink-section/-active-ink/-active-bg/
     -hover-bg/-border/-border-strong/-veil/-badge-bg/-badge-ink */

  --shadow-1: 0 1px 2px rgba(15,23,42,.06);
  --shadow-2: 0 4px 16px rgba(15,23,42,.08);
  --shadow-3: 0 10px 15px -3px rgba(15,23,42,.1);
}
```

**Dark theme is not shipped.** The console has no theme switch, so a dark block
would be untestable code and the byte-identical-duplicate maintenance hazard
§10.3 describes with nothing to show for it. The strategy in §10.3 stands; when
it lands, the dark accent is `--indigo-300` (8.96:1 on `--slate-900`) for text
and links, `--indigo-400` (5.98:1) for button fills, and the ratios for the
dark side of every status pair get added to the tables above **in that PR**.

### 3.4 Typography tokens

Root stays at the user's browser default (never set `html { font-size }` in px
— that breaks user zoom). Display face is **Bricolage Grotesque**, self-hosted
variable woff2 at `/static/bricolage-grotesque.woff2` (§2.4's "no embedded
font" rule is reversed by D17); body text is the system sans stack.

```css
--font-display: 'Bricolage Grotesque', ui-sans-serif, system-ui, sans-serif;
--font-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto,
             Helvetica, Arial, sans-serif;
--font-mono: ui-monospace, "SF Mono", "Cascadia Code", "Segoe UI Mono",
             Menlo, Consolas, monospace;

--text-2xs: 0.625rem;   /* 10px — sidebar badge only */
--text-xs:  0.6875rem;  /* 11px — small-caps nav section labels */
--text-sm:  0.75rem;    /* 12px — badges, table headers, captions */
--text-md:  0.8125rem;  /* 13px — <small>, footer, dense meta */
--text-lg:  0.875rem;   /* 14px — buttons, inputs, labels, table cells */
--text-xl:  0.9375rem;  /* 15px — console body default */
--text-2xl: 1rem;       /* 16px — topbar title */
--text-3xl: 1.1rem;     /* h3 */
--text-4xl: 1.25rem;    /* h2 */
--text-5xl: 1.5rem;     /* sidebar wordmark */
--text-6xl: 1.75rem;    /* h1, stat-tile numbers */

--leading-tight: 1.3;  --leading-normal: 1.6;  --leading-loose: 1.75;
--weight-regular: 400;  --weight-medium: 500;
--weight-semibold: 600; --weight-bold: 700;
--tracking-tight: -0.02em;  /* display face */
--tracking-caps:   0.05em;  /* small-caps labels: table headers, nav sections */
```

Minimum text size anywhere: 10px, and only for the sidebar "Beta"-style badge,
whose meaning is always available from its adjacent link text.

### 3.5 Spacing, radii, borders

```css
--space-0: 0;         --space-1: 0.125rem;  /*  2px */
--space-2: 0.25rem;   /*  4px */  --space-3: 0.375rem;  /*  6px */
--space-4: 0.5rem;    /*  8px */  --space-5: 0.75rem;   /* 12px */
--space-6: 1rem;      /* 16px */  --space-7: 1.25rem;   /* 20px */
--space-8: 1.5rem;    /* 24px */  --space-9: 2rem;      /* 32px */
--space-10: 2.5rem;   /* 40px */  --space-11: 3rem;     /* 48px */
--space-12: 4rem;     /* 64px */

--radius-xs: 0.25rem;  --radius-sm: 0.5rem;  --radius-md: 0.7rem;
--radius-lg: 1rem;     --radius-xl: 1.25rem; --radius-full: 9999px;

--border-w: 1px;  --border-w-strong: 2px;
--sidebar-width: 260px;  --content-max-w: 1200px;
```

Two amendments to what this section originally specified, both "the document
now matches production" rather than a redesign:

- **The scale is not pure 4px.** 6px (small-label bottom margin) and 20px
  (button and fieldset gutters) are steps the shipped console genuinely uses.
  Rounding them to the grid would have been a visual change; leaving them off
  the scale is how ~30 templates ended up with inline `style="padding:.375rem"`.
  They are now real tokens.
- **Radii are 8 / 11.2 / 16px, not 4 / 6 / 8.** `--radius-md: 0.7rem` is the
  button and card corner that shipped and it is visibly rounder than the
  original spec. Documented as-is.

### 3.6 Motion

```css
--duration-1: 0.15s;  /* hovers, presses, HTMX indicator */
--duration-2: 0.2s;   /* sidebar slide, dropdowns */
--duration-3: 0.24s;  /* modals, drawers, toasts */
--ease-out: cubic-bezier(0.2, 0, 0, 1);
--ease-in:  cubic-bezier(0.4, 0, 1, 1);
--ease-swap: cubic-bezier(0.25, 0.1, 0.25, 1);
```

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

Shipped in `base.css`. Rules unchanged: nothing animates position except
overlays entering/leaving; no parallax, no auto-playing anything. Note the
consequence for the one existing keyframe animation — `.spinner` becomes a
static ring under reduced motion, which is intended (§5.15 prefers a text swap
anyway).

### 3.7 Z-index scale

```css
--z-base: 0;
--z-sticky: 50;    /* sticky topbar */
--z-bulkbar: 80;   /* bulk-action toolbar */
--z-overlay: 99;   /* sidebar scrim (mobile) */
--z-nav: 100;      /* sidebar */
--z-dropdown: 400;  --z-modal-backdrop: 500;  --z-modal: 510;
--z-toast: 600;     --z-debug: 900;
```

Values are the shipped stacking order (topbar 50 under sidebar 100, scrim 99
between them), not the original spec's 100/150/200 — same relationships,
existing numbers. Never write a literal z-index; add a token here in a
dedicated commit instead.

### 3.8 Focus ring spec

One ring for the entire product. Visible focus is a release blocker, not
polish. Shipped in `base.css`:

```css
:where(a, button, input, select, textarea, summary, [tabindex]):focus-visible {
  outline: var(--focus-width) solid var(--focus-ring);
  outline-offset: var(--focus-offset);
  border-radius: inherit;
}
/* Inside table rows an offset ring would be clipped by the row box. */
:where(tr, [role="row"]):focus-visible {
  outline: var(--focus-width) solid var(--focus-ring);
  outline-offset: calc(-1 * var(--focus-offset));
}
/* Text controls keep the shipped border + halo treatment. Specificity (0,1,1)
   beats the zero-specificity :where() ring in either source order. */
input:focus, select:focus, textarea:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--focus-glow);
}
```

Contrast: the ring is `--indigo-600` — **6.29:1** vs `--surface`, **6.01:1** vs
`--bg`, **5.74:1** vs `--surface-3` (row hover), all far past WCAG 1.4.11's
3:1 for non-text UI. `:focus-visible` (not `:focus`) so mouse clicks don't
paint rings and keyboard always does. Never `outline: none` without a
same-rule replacement — the input rule above is the only sanctioned instance.

**Open gap:** text inputs currently signal focus with a border-colour change
plus a 15%-alpha halo. The halo is decorative and the border change is a
`--slate-200` → `--indigo-600` swap, which *is* ≥3:1 against the adjacent
surface, so it passes — but it is a weaker cue than the ring and should get an
explicit review in the a11y pass rather than being assumed fine.
---

## 4. Status color system

Design law: **color is never the only channel.** Every badge = text label + hue; `lost`, `urgent`, and `breached` additionally get an icon (see below).

> **Ratios updated for the shipped indigo/fuchsia ramps (WS-1 C0).** Every
> figure below is recomputed against `tokens.css`; the old chalk-blue/violet
> numbers are gone. **Dark-theme columns are removed, not left stale** — dark
> mode is not shipped (§3.3) and a ratio for a colour that does not exist is
> worse than no ratio. They come back, computed, in the PR that adds it.

### 4.1 Badge anatomy

```html
<span class="badge badge--success">Active</span>
<span class="badge badge--danger badge--solid">
  <svg class="badge__icon" aria-hidden="true">…</svg> Breached
</span>
```

```css
.badge {
  display: inline-flex; align-items: center; gap: var(--space-2);
  font-size: var(--text-xs); font-weight: var(--weight-medium);
  line-height: 1; padding: 3px var(--space-3);
  border-radius: var(--radius-full);
  border: var(--border-w) solid var(--badge-border);
  background: var(--badge-bg); color: var(--badge-fg);
  white-space: nowrap;
}
.badge--success { --badge-bg: var(--success-bg); --badge-fg: var(--success-badge-fg); --badge-border: var(--success-border); }
.badge--warning { --badge-bg: var(--warning-bg); --badge-fg: var(--warning-badge-fg); --badge-border: var(--warning-border); }
.badge--danger  { --badge-bg: var(--danger-bg);  --badge-fg: var(--danger-badge-fg);  --badge-border: var(--danger-border); }
.badge--info    { --badge-bg: var(--info-bg);    --badge-fg: var(--info-badge-fg);    --badge-border: var(--info-border); }
.badge--status  { --badge-bg: var(--status-bg);  --badge-fg: var(--status-badge-fg);  --badge-border: var(--status-border); }  /* ex-violet, now fuchsia */
.badge--neutral { --badge-bg: var(--neutral-bg); --badge-fg: var(--neutral-badge-fg); --badge-border: var(--neutral-border); }
.badge--solid   { --badge-bg: var(--danger-solid); --badge-fg: var(--danger-solid-ink); --badge-border: transparent; }
```

### 4.2 Device status (`assets.status`)

| Status | Variant | Pair (computed ratio) | Notes |
|---|---|---|---|
| `active` | success | green-700 on green-50 — **4.79:1** | Default healthy state |
| `repair` | warning | amber-700 on amber-50 — **4.84:1** | |
| `storage` | info | indigo-700 on indigo-50 — **7.07:1** | "Parked, intentional" |
| `retired` | neutral | slate-700 on slate-100 — **9.45:1** | End of life, unremarkable |
| `deprovisioned` | status (fuchsia) | fuchsia-700 on fuchsia-50 — **5.89:1** | Irreversible; distinct hue on purpose |
| `lost` | danger + icon (⚠ triangle) | red-700 on red-50 — **5.91:1** | Needs action; icon marks it beyond hue |

`success` and `warning` (4.79 and 4.84) clear AA's 4.5:1 but with little room.
They are the shipped `#15803d`/`#b45309` on their shipped tints and were kept
rather than darkened, because those two badges are already on screen in the
sync history table. If a future step darkens them, green-800 on green-50 and
amber-800 on amber-50 are the moves, and the ratios go in this table.

**Do not use `--neutral-*` for the `retired` badge as currently defined.**
`--neutral-badge-fg` aliases `--ink-muted`, which is 2.45:1 on `--bg` — the
shipped `.status-pending` badge, and one of the four known AA failures listed
in §3.2. The 9.45:1 figure above is slate-700 on slate-100, which is what this
badge must use; that is a `--neutral-*` change to make in the components pass.

### 4.3 Ticket status (`tickets.status`)

| Status | Variant | Pair (computed ratio) | Meaning cue |
|---|---|---|---|
| `new` | info | indigo-700/indigo-50 — **7.07:1** | Untriaged |
| `open` | status (fuchsia) | fuchsia-700/fuchsia-50 — **5.89:1** | In a technician's hands |
| `pending` | warning | amber-700/amber-50 — **4.84:1** | Waiting on requester/parts |
| `resolved` | success | green-700/green-50 — **4.79:1** | |
| `closed` | neutral | slate-700/slate-100 — **9.45:1** | |

The extended status hue appears in both domains (`open` ticket,
`deprovisioned` device). Accepted: the domains never share a column, and the
text label always disambiguates. Do not "fix" this by inventing a seventh hue.

**`info` is now the accent hue.** With indigo as both accent and info, an
`storage`/`new` badge is the brand colour. §3.1 called this collision
acceptable for *banners*; at badge size in a status column it is worth a look
during the components pass, because a row's status should not read as
"interactive". The text label carries it either way.

### 4.4 Ticket priority (`tickets.priority`)

Priorities render as a **dot + text** inline in queue tables (quieter than a second badge per row), and as full badges on the ticket detail page.

| Priority | Treatment | Computed ratio |
|---|---|---|
| `low` | neutral dot `--slate-400` + text `--ink` | text 10.35:1 on `--surface` |
| `normal` | info dot `--indigo-500` + text `--ink` | text 10.35:1; dot 4.47:1 (non-text, ≥3:1 ✅) |
| `high` | warning badge | amber-700/amber-50 — **4.84:1** |
| `urgent` | **solid** danger badge + double-chevron icon | white on red-700 — **6.47:1** |

The dots are decorative — priority is always spelled out in the adjacent text,
so they are not the sole channel and the 3:1 non-text threshold is the bar they
must clear. The `low` dot (`--slate-400`, 2.56:1) does **not** clear it and is
therefore only ever paired with its label, never used alone.

Only `urgent` (and SLA `breached`) ever use the solid fill. Solid = "interrupt what you're doing." If everything shouts, nothing does.

### 4.5 SLA states (computed from `sla_due_at`, `first_response_at`, `resolved_at`)

| State | Treatment | Computed ratio | Extra channel |
|---|---|---|---|
| `ok` | success badge, or no badge at all in dense queues | 4.79:1 | Default may be *absence* — only exceptions shout |
| `at-risk` (< 25% of SLA window left) | warning badge + clock icon + remaining time text ("1h 12m") | 4.84:1 | Countdown text |
| `breached` | **solid** danger badge + ⚠ icon + overdue time ("2d over") | white on red-700 — **6.47:1** | Icon + text |

Queue default sort: breached first, then at-risk by time remaining. The SLA column is never hidden in the "My queue" saved view.

---

## 5. Component specifications

Global notes that apply to every component: semantic HTML first; every interactive element ≥ 24×24px hit area in console (WCAG 2.5.8), ≥ 44×44px in teacher portal; all states below must exist: default, hover, active/pressed, focus-visible, disabled, and (where applicable) loading, invalid, selected. Class naming per §10.2.

### 5.1 Buttons

```html
<button class="btn btn--primary" type="submit">Save changes</button>
<button class="btn btn--secondary">Export CSV</button>
<button class="btn btn--ghost">Cancel</button>
<button class="btn btn--destructive">Deprovision 12 devices…</button>
```

```css
.btn {
  display: inline-flex; align-items: center; justify-content: center;
  gap: var(--space-3); min-height: 32px; padding: 0 var(--space-4);
  font: var(--weight-medium) var(--text-md)/1 var(--font-sans);
  border-radius: var(--radius-md); border: var(--border-w) solid transparent;
  cursor: pointer; transition: background-color var(--duration-1) var(--ease-out);
}
.btn--primary     { background: var(--accent); color: var(--accent-ink); }
.btn--primary:hover { background: var(--accent-hover); }
.btn--secondary   { background: var(--surface); color: var(--ink); border-color: var(--border-strong); }
.btn--secondary:hover { background: var(--surface-2); }
.btn--ghost       { background: transparent; color: var(--ink-secondary); }
.btn--ghost:hover { background: var(--surface-3); color: var(--ink); }
.btn--destructive { background: var(--danger-solid); color: var(--danger-solid-ink); }
.btn--lg { min-height: 44px; font-size: var(--text-lg); padding: 0 var(--space-6); } /* portal */
.btn--sm { min-height: 26px; font-size: var(--text-sm); padding: 0 var(--space-3); } /* table row actions */
.btn[disabled] { opacity: 0.5; cursor: not-allowed; }
.btn[aria-busy="true"] { pointer-events: none; }
```

Rules: exactly one `btn--primary` per view region; destructive style only for actions that destroy or are irreversible (delete, deprovision, wipe) — "Remove filter" is a ghost, not destructive; icon-only buttons require `aria-label` and a tooltip; buttons that open menus/dialogs get `aria-haspopup` + `aria-expanded`. Loading state: server round-trips use HTMX — set `hx-indicator` to an inner spinner span and `hx-disabled-elt="this"`; keep the label visible ("Saving…" swap is done server-side on validation redisplay, not client-side).

Text-on-fill contrast: primary 5.98:1 (both themes), destructive 7.27:1 light / 4.57:1 dark, secondary/ghost inherit AA text tokens.

### 5.2 Form fields and validation

Structure (Askama partial `form_field.html`):

```html
<div class="field" data-invalid="false">
  <label class="field__label" for="asset-tag">Asset tag</label>
  <p class="field__hint" id="asset-tag-hint">Printed on the white sticker.</p>
  <input class="field__input" id="asset-tag" name="asset_tag"
         aria-describedby="asset-tag-hint asset-tag-err" autocomplete="off">
  <p class="field__error" id="asset-tag-err" hidden>
    <svg aria-hidden="true">…</svg> Asset tag already exists (CB-01422).
  </p>
</div>
```

- Labels always visible, always `<label for>` — no placeholder-as-label ever. Placeholder text is example-only and uses `--ink-placeholder` (deliberately sub-AA at 2.55:1 because it is not content; the hint carries any required information).
- Input: min-height 36px console / 44px portal; `font-size: var(--text-lg)` (16px) in the portal so iOS doesn't zoom; border `--border-input`, radius `--radius-md`, background `--surface-raised` (light: white) for affordance against paper.
- Invalid state: `data-invalid="true"` → border `--danger-fg` at `--border-w-strong`, error text `--danger-fg` (7.03:1 light on paper-0), `aria-invalid="true"`, error `<p>` unhidden and referenced by `aria-describedby`. Error icon ensures non-color signal.
- **Validation is server-side, rendered by HTMX**: form has `hx-post` + `hx-swap="outerHTML"` on itself; the server re-renders the form partial with errors. On error response, move focus to the first invalid input (`hx-on::after-swap="this.querySelector('[aria-invalid=true]')?.focus()"`) and prepend an error summary box (`role="alert"`) linking each error to its field — this is the APG/ARIA pattern that makes long forms navigable for screen readers.
- Required fields: append `*` inside the label with `<span aria-hidden="true">*</span>` and set `required` — but in the console prefer marking *optional* fields ("Notes (optional)") since most fields are required.
- Field-length constraints from WS-1.6 (location ≤200, notes ≤500, annotatedUser ≤100) render as live `maxlength` + a character counter (`aria-live="polite"`, updates at 90%).

### 5.3 Dense data table (technician console pattern)

The flagship component. Server-rendered `<table>` wrapped in a `<form>` (the PRD's form-wrapped-table bulk select), enhanced with a small vanilla-JS controller (`table.js`, ~2KB) for keyboard nav and shift-click. AG Grid is NOT this component — this table covers browsing/filtering/bulk-select; AG Grid (§6) covers cell-level bulk *editing* only.

**Anatomy:**

```html
<form id="assets-form" hx-post="/assets/bulk" hx-target="#assets-region">
  <div class="table-toolbar">…filters, saved views, density toggle, column picker…</div>
  <div class="bulkbar" hidden> … </div>
  <div class="table-scroll" tabindex="0" role="region" aria-label="Devices" >
    <table class="table" data-density="compact">
      <caption class="sr-only">Devices — 3,412 results, filtered by Status: Repair</caption>
      <thead><tr>
        <th class="table__check"><input type="checkbox" aria-label="Select all on page"></th>
        <th aria-sort="ascending">
          <a href="?sort=asset_tag&dir=desc" hx-get="…" hx-target="#assets-region"
             hx-push-url="true">Asset tag <svg class="sort-arrow" aria-hidden="true">…</svg></a>
        </th>
        …
      </tr></thead>
      <tbody> <tr data-id="…"> <td><input type="checkbox" name="ids[]" value="…"
              aria-label="Select CB-01422"></td> … </tr> </tbody>
    </table>
  </div>
  <nav class="pagination" aria-label="Devices pages">…</nav>
</form>
```

**Density options** (user preference, persisted per-user server-side, applied via `data-density`):

| Density | Row height | Cell font | Cell padding-y | Default for |
|---|---|---|---|---|
| `compact` | 32px | `--text-sm` | 6px | Technician console |
| `cozy` | 40px | `--text-sm` | 10px | Admin console |
| `comfortable` | 48px | `--text-md` | 14px | Touch/projector contexts |

**Visual spec:** header row background `--surface-2`, `--weight-medium`, `--text-xs` uppercase with `--tracking-caps`, sticky (`position: sticky; top: 0; z-index: var(--z-sticky)`) with bottom border `--border-strong`; body rows separated by `--border` hairlines, zebra striping OFF by default at compact (hairlines suffice; stripes available as a preference using `--surface-2`); row hover `--surface-3`; selected row `--accent-subtle` with a 2px `--accent` left edge inset; numeric columns right-aligned with `tabular-nums`; serials/tags in `--font-mono`; truncation with `title` attr + full value in the row detail.

**Sortable columns:** `<th aria-sort>` + link with full URL (works JS-free), HTMX intercepts for partial swap of `#assets-region`, `hx-push-url="true"` so sorts/filters are bookmarkable — saved filters are literally URLs (§5.4). Sort arrow visible on the sorted column, ghosted on hover for others.

**Selection model:**
- Checkbox column, fixed 36px, first. Header checkbox = select page; when page-selected, an inline bar offers "Select all 3,412 matching" → sets a hidden `select_all_query` input carrying the filter hash (never ship 3,412 ids in a form body).
- Shift-click range select; row click (outside links/controls) toggles in select-mode only; plain row click navigates to the device drawer/detail.
- Keyboard: the table body is a roving-tabindex grid per APG Grid pattern — `↑/↓` move row focus, `Space` toggles selection, `Shift+↑/↓` extends, `x` also toggles (Gmail muscle memory), `Enter` opens the row, `Ctrl/Cmd+A` selects page, `Esc` clears selection. Focused row shows the inset focus ring (§3.8). Column header cells reachable by `Tab`, sorted with `Enter`.
- Every checkbox has an `aria-label` naming the row ("Select CB-01422").

**Sticky bulk-action bar:** appears (unhidden, no animation beyond `--duration-2` fade) when selection ≥ 1; `position: sticky; bottom: 0; z-index: var(--z-bulkbar)`; background `--surface-raised`, top border `--border-strong`, `--shadow-3` upward. Contents: "**512 selected**" count (`aria-live="polite"` so SR users hear selection changes), then actions as buttons: `Move to OU…`, `Set status…`, `Assign…`, `Export`, ghost `Clear`, and overflow menu. Destructive bulk actions (Deprovision) sit only in the overflow, styled destructive, and always open the typed-confirmation modal (§5.11). The bar is inside the `<form>`; each action button is `formaction`/`hx-post` to its endpoint with the selected ids or `select_all_query`. Bar is keyboard-reachable in DOM order right after the table; `F2` (documented in the shortcut sheet) jumps focus to it when visible.

**Inline row expansion (device/repair history):** chevron button per row, `aria-expanded`, `hx-get="/assets/{id}/history" hx-target="next tr .row-detail" hx-swap="innerHTML"` — lazy-loads an embedded event timeline `<tr class="row-detail">` (colspan full width, background `--surface-2`). One expanded row at a time is NOT enforced — techs compare devices.

**HTMX region contract:** toolbar + table + pagination live in one `#assets-region` partial. All sorting/filtering/pagination targets that region; the URL always reflects state; browser Back works (`hx-push-url`). After swap, restore focus to the control that triggered (HTMX does this by default when the element persists — give toolbar controls stable `id`s).

### 5.4 Saved-filter chips

Saved views are named URLs (query strings) stored per-user. Rendered as a chip row under the page title:

```html
<nav class="chips" aria-label="Saved views">
  <a class="chip" aria-current="page" href="/assets?status=repair&school=hs">
    Repair — HS <span class="chip__count">38</span></a>
  <a class="chip" href="/assets?aue_before=2027-06">AUE &lt; Jun 2027</a>
  <button class="chip chip--add" hx-get="/views/new" hx-target="#modal">＋ Save current view</button>
</nav>
```

Chip spec: `--radius-full`, height 28px, `--text-sm`, border `--border-strong`, background `--surface`; current chip: background `--accent-subtle`, text `--accent-subtle-ink` (7.23:1 L / 7.74:1 D), border `--accent`, plus `aria-current="page"` (never color alone). Count in `--ink-muted`. Chips are links (real URLs) — middle-click opens in a tab. Editing/deleting a view happens in a small menu on the current chip only. Filter chips *within* the toolbar (active ad-hoc filters) reuse the same chip style with a ✕ remove button (`aria-label="Remove filter: Status is Repair"`).

### 5.5 Pagination

Server-side, page-size options 50/100/250 (compact density defaults 100). Structure: `<nav aria-label="…pages">` with Prev/Next buttons + page numbers as links (HTMX-boosted into the region, `hx-push-url`), current page `aria-current="page"`, and a right-aligned "1–100 of 3,412" summary in `--ink-muted`. Keyboard: plain links, nothing custom. Never infinite-scroll in the console (breaks bookmarkability, footer reachability, and "select all matching" reasoning).

### 5.6 Search and command palette

- **v1:** a per-table search input in the toolbar (`hx-get` with `hx-trigger="input changed delay:300ms, search"`, targeting the table region; `role="searchbox"`, results announced via the live region: "38 devices match"). Global search in the top bar searches assets + tickets + users, returning a grouped result page.
- **Command palette (`Ctrl/Cmd+K`): deferred, post-v1.** Flagged as Open Question 3 (§11). When built: APG combobox + listbox pattern, server-rendered results via HTMX into a modal, actions limited to navigation + "New ticket/asset" — not bulk operations.

### 5.7 Badges

Specified in §4. Additional rule: max two badges per table row (status + one of priority/SLA); further metadata goes to the detail view. Badges are never interactive — a clickable status is a filter link *around* a badge, with the focus ring on the link.

### 5.8 Cards and stat tiles

Card: background `--surface` (dark: `--surface` = slate-900), border `--border`, radius `--radius-lg`, padding `--space-6`, `--shadow-1` (light only; dark relies on border). Card title `--text-xl`/`--weight-semibold`.

Stat tile (dashboard): value `--text-4xl`/`--weight-semibold`/`tabular-nums`, label above in `--text-xs` uppercase `--ink-muted`… correction: label uses `--ink-secondary` when tile background is `--surface-3`-tinted (muted fails AA there, §3.3). Optional delta line: `▲ 12 this week` in `--success-fg` / `▼` in `--danger-fg` with the arrow as text (SR-readable) — and the delta direction also encoded in words on hover/title ("up 12"). A stat tile whose metric warrants action links the whole tile (focus ring on the tile). Grid: 4-up desktop / 2-up tablet / 1-up mobile, gap `--space-4`.

### 5.9 Navigation

**Console/admin sidebar:** fixed left, 240px, background `--surface-2` (dark: `--slate-900`), border-right `--border`. Structure: `<nav aria-label="Main">` → product mark (slate tile, §2.1) → module sections gated by config flags (§5.1 PRD: modules toggle nav visibility) → items: icon (20px, `stroke: currentColor`) + label, height 36px, radius `--radius-md`, default `--ink-secondary`, hover `--surface-3` + `--ink`, active `--accent-subtle` bg + `--accent-subtle-ink` + `aria-current="page"` + 2px accent left bar. Collapse to 56px icon rail (button at bottom, state in the same server-side preference store; collapsed items get tooltips + retain `aria-label`s). Below `1024px` the sidebar becomes an off-canvas drawer behind a hamburger (`<dialog>`-based, §5.11 focus rules). First element in DOM: a skip link (`.sr-only` until focused) "Skip to main content".

**Teacher portal: no navigation.** A minimal top bar: Chalk tile mark + district name (`--text-sm`, `--ink-muted`) + the signed-in teacher's name. Nothing else. No sidebar, no menu, no settings. (Principle 2.)

### 5.10 Dropdown menus

Use `<details class="menu">`/`summary` for zero-JS correctness, enhanced by a 1KB controller for: Esc-to-close, outside-click close, arrow-key item traversal, `aria-haspopup="menu"` semantics on the summary and `role="menu"/"menuitem"` on the list (APG Menu Button pattern). Panel: `--surface-raised`, border `--border`, radius `--radius-lg`, `--shadow-2`, min-width 180px, item height 32px, item hover `--surface-3`, destructive items `--danger-fg` text with a divider above. Z-index `--z-dropdown`. Menus never nest more than one level; if you need a submenu, you need a dialog.

### 5.11 Modals and the typed-confirmation destructive pattern

Modals use native `<dialog>`, opened via HTMX loading the dialog partial into `#modal` then `showModal()` (inline `hx-on::after-swap`). Native `<dialog>` gives focus trapping, `Esc`, and `::backdrop` for free. Spec: max-width 480px (forms 560px), background `--surface-raised`, radius `--radius-lg`, `--shadow-3`, backdrop `--backdrop`; title `--text-2xl` + `aria-labelledby`; footer right-aligned: ghost Cancel then the action button. On close, HTMX puts focus back on the invoker (stable `id`s again). Entry animation: 160ms fade+2%-scale, none under reduced motion.

**Typed-confirmation destructive pattern** (required for deprovision — PRD WS-1 safety: role check + typed confirmation + `asset_events` entry; also for bulk delete, powerwash):

1. Server checks role *before* rendering the dialog (the button isn't rendered for unauthorized roles at all — but the endpoint still enforces).
2. Dialog content, in order: title "Deprovision 12 devices"; consequence sentence first, blunt voice (§2.3): "Deprovisioning is permanent and affects Chrome licenses. This cannot be undone in Chalk or Google Admin."; a scrollable list (max-height 160px) of affected asset tags; the reason `<select>` Google requires for batchChangeStatus; then the typed gate:
   ```html
   <label for="confirm-word">Type <strong>deprovision</strong> to continue</label>
   <input id="confirm-word" autocomplete="off" autocapitalize="none"
          spellcheck="false" data-confirm-expected="deprovision">
   ```
   For single high-value objects, the expected string is the asset tag itself.
3. The destructive submit button is `disabled` until the input matches exactly (tiny inline script; server re-validates the `confirm` field regardless — the disabled button is UX, not security).
4. Submit → server performs role re-check, executes, writes `asset_events`, responds with the updated table region + an OOB toast + OOB live-region announcement ("12 devices deprovisioned").
5. No "don't ask again" option exists for this pattern. Ever.

### 5.12 Toasts, inline alerts, and HTMX live-region announcements

**Inline alert** (embedded in page flow, for form-level and page-level conditions):

```html
<div class="alert alert--warning" role="status">
  <svg aria-hidden="true">…</svg>
  <div><strong>Google sync is 2 days stale.</strong> Last successful sync 2026-07-23 04:12.
       <a href="/settings/sync">Review sync settings</a></div>
</div>
```

Variants map to the badge token pairs (§4.1): background `--*-bg`, border-left 3px `--*-fg`, text `--ink` with the leading strong in `--*-badge-fg`. `role="alert"` only for errors that demand immediate announcement; `role="status"` otherwise.

**Toasts** (transient results of actions): fixed bottom-right (bottom-center on mobile), width ≤ 380px, `--surface-raised` + `--shadow-3`, same variant edge treatment, auto-dismiss 6s **except** danger toasts and any toast with an action (e.g. "Undo assignment") which persist until dismissed; dismiss button always present (`aria-label="Dismiss"`). Stack max 3, oldest collapses. Hover pauses the timer. Toast container is `#toasts` with `role="region" aria-label="Notifications"`; individual toasts are NOT aria-live (double-announcement) — announcements go through the dedicated live region:

**HTMX polite live region (the announcement bus):** one permanent element in the base layout:

```html
<output id="announcer" class="sr-only" aria-live="polite"></output>
```

Server responses that change state include an out-of-band swap:

```html
<output id="announcer" class="sr-only" aria-live="polite" hx-swap-oob="true">
  512 devices moved to /Students/HS.
</output>
```

Rules: announce results ("Saved", "38 results", "3 errors on form"), not process ("loading…" is handled by `aria-busy` on the region); keep under 120 characters; `assertive` only for data-loss-risk errors. This single pattern satisfies WCAG 4.1.3 (status messages) across all HTMX interactions — use it every time a swap changes something a sighted user notices peripherally.

### 5.13 Diff-preview component (Google sync + CSV/Sheets re-import)

Purpose: PRD WS-3.4/3.3 — "round-trip 500 devices to spreadsheet with diff preview." Shown before any import/sync apply.

Anatomy: summary header + grouped, paginated tables + confirm footer.

- **Summary strip** — three stat chips using badge pairs: `＋ 24 added` (success), `± 117 changed` (warning), `− 3 removed` (danger), plus `2,868 unchanged` (neutral, collapsed by default). Each chip is a filter toggle for the table below (`aria-pressed`).
- **Added rows:** table rows with background `--success-bg`, left edge 3px `--success-fg`, and a `＋` cell (with `aria-label="Added"`).
- **Removed rows:** background `--danger-bg`, `−` marker, values struck through — plus the word "removed" in the marker cell title; strikethrough is never the only signal.
- **Changed rows:** neutral row; only changed *cells* are highlighted: old value struck in `--ink-muted`, `→`, new value in `--ink` on `--warning-bg` cell tint; cell gets `aria-label="location: changed from Cart 4 to Cart 7"`. A per-row expander lists all field changes vertically when >3 fields changed.
- **Row-level opt-out:** each row has an "Apply" checkbox (checked default) so a tech can exclude a suspicious change; header supports select-all per group.
- Footer: ghost "Cancel", secondary "Download diff as CSV", primary "Apply 141 changes". If any removal touches a device with an open ticket, the apply button routes through a standard (non-typed) confirm modal listing them.
- The same component renders sync *dry-runs* (Google → Chalk) and import previews (CSV/Sheets → Chalk); it is one Askama partial (`diff_preview.html`) parameterized by source.

### 5.14 Empty states

One pattern, three intensities — never an illustration heavier than a single-color 48px icon, never marketing tone in-app:

1. **First-run** (no data yet): icon + one sentence + one primary action. "No devices yet. Connect Google Workspace to import your fleet in minutes." → `[Connect Google]`. (This state is rare by design — the wedge is auto-population.)
2. **Filtered-to-zero:** "No devices match these filters." + ghost `[Clear filters]`. Never show the first-run state when filters are active — techs will think data was lost.
3. **Positive-empty** (queues): "No breached SLAs. Nothing needs you here." — allowed one plain-language sentence of warmth, no emoji.

Empty states live inside the table region so HTMX swaps them naturally; they include the result count announcement via the live region.

### 5.15 Loading, skeletons, and HTMX indicators

- **Principle: the fastest indicator is none.** Sub-300ms swaps show nothing (HTMX default delay: add `htmx-indicator` with `transition-delay: 300ms` opacity so brief requests never flicker).
- **In-region loads** (sort, filter, paginate): keep the old content, set `aria-busy="true"` on the region (via `hx-on::before-request`/`after-settle` or the `htmx-request` class), overlay a 2px indeterminate progress bar across the top of the region in `--accent`, and reduce old content to 60% opacity. No layout shift.
- **Skeletons** only for *initial* loads of drawers/row-expansions where content shape is known: `--surface-3` blocks, radius `--radius-sm`, shimmer animation 1.2s (static under reduced motion), matching final layout heights to prevent shift. Max one skeleton screen per navigation — nested skeletons are banned.
- **Buttons:** `hx-disabled-elt="this"` + inline spinner via `hx-indicator`; label stays.
- **Row-flash on update:** after a swap settles, updated rows get `htmx-settling` background `--accent-subtle` fading to transparent over `--duration-2` — the polite "this changed" cue (disabled under reduced motion; the live region still announces).

### 5.16 Tabs

Server-rendered links styled as tabs (each tab is a URL — device detail: Overview | History | Tickets). Underline style: container bottom border `--border`; tab: `--ink-secondary`, `--weight-medium`, padding `--space-3` `--space-4`; active: `--ink` + 2px `--accent` underline + `aria-current="page"`. These are navigation tabs (`<nav>` + links, no `role="tablist"` — they load URLs; APG says tablist is for same-page panels). If a genuinely same-page tab set appears (settings sub-panels swapped by HTMX), then and only then use the APG Tabs pattern with `role="tablist"`, arrow-key traversal, and `tabindex="-1"` inactive tabs.

### 5.17 (Consolidated elsewhere)

Dropdowns §5.10, badges §4, chips §5.4 — listed here so the section numbering in build tickets can reference one place per component.

---

## 6. The AG Grid island

Scope discipline: AG Grid Community appears on exactly one route per module — "Bulk edit" (spreadsheet-style editing of annotated fields, locations, status, assignments). Everything else uses the server table (§5.3). The island mounts into an HTMX-loaded page; data loads via the REST API (WS-5.1) as JSON; edits post back in batches with a diff-preview (§5.13) before commit — the grid edits a *staging buffer*, never live data directly.

**Version and theming approach (decided):** pin AG Grid Community v33+ and use the **Theming API** (`themeQuartz.withParams`), not the legacy CSS-file themes. Params are mapped to our CSS custom properties so the island re-themes automatically with light/dark:

```js
// grid-theme.js (embedded asset, plain ES module, no bundler)
import { themeQuartz } from "./vendor/ag-grid-community.esm.js";

const v = (name) => `var(${name})`;
export const chalkGridTheme = themeQuartz.withParams({
  backgroundColor:            v("--surface"),
  foregroundColor:            v("--ink"),
  headerBackgroundColor:      v("--surface-2"),
  headerTextColor:            v("--ink-secondary"),
  borderColor:                v("--border"),
  rowHoverColor:              v("--surface-3"),
  selectedRowBackgroundColor: v("--accent-subtle"),
  accentColor:                v("--accent"),          // checkboxes, range borders
  invalidColor:               v("--danger-fg"),
  fontFamily:                 v("--font-sans"),
  fontSize:                   "0.8125rem",            // --text-sm
  headerFontWeight:           500,
  cellHorizontalPadding:      8,
  rowHeight:                  32,                     // match table compact
  headerHeight:               36,
  borderRadius:               4,
  wrapperBorderRadius:        8,
  focusShadow: { color: v("--focus-ring"), spread: 2 }, // match §3.8 ring
});
```

Density: fixed at compact (32px rows) to match the console table; do not expose AG Grid's own density knobs. Cell edit states: invalid cell gets `--danger-bg` tint + message in the grid's tooltip AND in a below-grid error summary list (screen-reader reachable — grid tooltips are not reliably announced). Changed-but-uncommitted cells: `--warning-bg` tint + dot marker, mirrored in a "117 pending changes" counter button that opens the diff preview.

**A11y caveats to audit every AG Grid upgrade** (PRD WS-2.6 — the island is the one place we don't fully control the DOM):
1. Grid announces via `role="grid"`/ARIA row/col indexes — verify `aria-rowcount`/`aria-colcount` are correct with our pagination/virtualization settings (virtualized rows confuse counts if misconfigured).
2. Keyboard: verify Tab enters/exits the grid (no keyboard trap — WCAG 2.1.2), F2/Enter edit, Esc cancels, arrow navigation, header reachable. Document the grid's keys in the shortcut sheet.
3. Checkbox selection column: confirm per-row `aria-label`s include the row's asset tag (custom `checkboxSelection` label formatter).
4. Focus visibility: confirm our `focusShadow` ring renders ≥3:1 on both themes over tinted (warning/danger) cells.
5. Screen reader pass (NVDA + VoiceOver) on: enter grid → navigate → edit a cell → hear the committed value → reach the error summary. AG Grid's SR behavior shifts between minors; this is a pinned-version product.
6. `prefers-reduced-motion`: disable grid animations (`animateRows: false` always — we don't need them).
7. Our live region (§5.12) announces batch results ("117 changes staged") — grid-internal announcements don't replace it.

If an AG Grid upgrade regresses any of these, we hold the version. The VPAT will carry a scoped note for this island; keep its blast radius one route.

Binary-size note: the AG Grid Community ESM bundle (~1 MB min+gz ~250KB) is embedded via rust-embed like all assets, served with long-cache headers and a content hash. Accepted cost, one island (Gate A memo: AG Grid is the durable spreadsheet UX). See Open Question 2 (§11) on trimming via module registry.

---

## 7. Teacher portal pattern spec

**The contract:** an SSO'd teacher lands, types what's wrong, taps a category, submits — under 60 seconds, zero training, no account creation (v1.0 acceptance criterion). One screen. Anything that doesn't serve the 60-second path is cut.

### 7.1 Anatomy (single route: `/report`)

Mobile-first, one column, max-width 480px card centered on `--bg` (paper). Top to bottom:

1. **Minimal top bar** (§5.9): Chalk tile + district name + teacher name. Confirms "right place, signed in" without a login screen (SSO already happened).
2. **Device line (auto-attached):** "Your device: **CB-01422** · Lenovo 300e · Room 114" with a quiet `Not this device?` link → expands a search-select of the teacher's other assigned/nearby devices (HTMX inline swap). Auto-attachment from roster assignment is the magic moment — show it, don't ask for it. If no device is assigned: the picker shows expanded with a plain prompt ("Which device is this about?") and a "Not about a device" option.
3. **The question:** `<h1>` `--text-2xl`: "What's wrong?" — then a `<textarea>` (label visually merged with the h1 via `aria-labelledby`), 4 rows, `--text-lg` (16px, no iOS zoom), placeholder *example* text: "e.g. The screen is cracked in the corner". No minimum length. Free text is the primary input (PRD WS-2.5).
4. **Category chips:** single-select chip row (`role="radiogroup"`, chips are `<input type="radio">` + label styled per §5.4 at 44px height): `Screen` `Keyboard` `Won't turn on` `Charger` `Wi-Fi` `Software` `Something else`. Optional — server infers category from text if none picked; chips exist because tapping is faster than typing for the top cases. Selected chip: `--accent-subtle` bg + `--accent-subtle-ink` + `--accent` border + check glyph (not color-only).
5. **Photo (optional):** single "Add a photo" ghost button → `<input type="file" accept="image/*" capture="environment">`. One photo, thumbnail with remove button. Never required.
6. **Submit:** full-width `btn--primary btn--lg` (44px+): "Send to the tech team". One button. No draft, no cancel, no reset.

Nothing else. No priority picker (teachers always pick urgent), no ticket-type taxonomy, no description-vs-subject split (server derives subject from the first ~60 chars).

### 7.2 Success state

Full-card swap (HTMX `hx-post` on the form, target the card):

- Check icon (48px, `--success-fg`), "Got it — the tech team has your ticket." (`--text-2xl`), ticket number **#4187** in `--font-mono` (teachers reference it verbally), and one line of expectation: "You'll get an email when someone picks it up."
- One action: ghost "Report another problem" (resets the form). No dashboard link, no upsell to "track your ticket" in v1 — email is the tracking channel.
- Focus moves to the success heading (`tabindex="-1"` + focus on after-swap); live region announces "Ticket 4187 created."

### 7.3 Error handling

- Network/server failure: the form persists exactly as typed (HTMX error → keep DOM, show inline alert above the button): "That didn't go through — your text is still here. Try again." + the submit button re-enabled. Never lose their text; never make them retype. `role="alert"`.
- Validation is nearly impossible to fail (only requirement: non-empty text OR a category). If both empty: inline error under the textarea, focus to textarea.
- SSO session expired: full-page redirect back through SSO and return to `/report` — with the draft preserved server-side via a short-lived stash keyed to a hidden token, restored on return (the one piece of state we bother to save, because retyping kills the 60-second promise).
- Offline (schools have dead zones): plain message "You're offline. Your text is safe on this page — send when you're back on Wi-Fi." No service-worker queue in v1.

### 7.4 The 60-second budget

| Step | Budget |
|---|---|
| Land (SSO redirect already warm) | 5s |
| Read "What's wrong?", start typing | 10s |
| Type 1–2 sentences | 25s |
| Tap a chip | 3s |
| Submit + success render | 2s |
| Slack | 15s |

Instrument it: log `created_at - portal_landed_at` per ticket; the p75 of that metric is the portal's health KPI. If p75 > 60s, the portal has a bug — treat as such.

Portal-specific token overrides: base font `--text-lg`; all hit targets ≥ 44px; spacing scale shifted one step up (`--space-5` where console uses `--space-4`); radius `--radius-xl` on the card. Same tokens file, no fork.

---

## 8. Data-viz starter guidance (reports: AUE planning, OS distribution)

Charts are server-rendered SVG (Askama templates or a tiny Rust SVG helper) — no charting JS library in v1. Bars and lines cover every v1 report; if a report seems to need more than bars/lines/a table, it needs a table.

**Categorical palette** (derived from the token scales; ≥3:1 against the theme background per WCAG 1.4.11 for chart marks). Assign in this order, and keep series→color assignment *stable per report across visits*:

| Series | Light (on paper-0) | ratio | Dark (on slate-900) | ratio |
|---|---|---|---|---|
| 1 | `--blue-500` #477FA6 | 4.18 | `--blue-300` #97BAD2 | 6.88 |
| 2 | `--green-600` #23744A | 5.54 | `--green-300` #7FC498 | 6.87 |
| 3 | `--amber-500` #A97613 | 3.84 | `--amber-300` #E0AE55 | 6.93 |
| 4 | `--violet-500` #6F5CA9 | 5.37 | `--violet-300` #AEA1D6 | 5.94 |
| 5 | `--red-500` #B93E31 | 5.35 | `--red-300` #E28D83 | 5.61 |
| 6 | `--slate-600` #556166 | 6.18 | `--slate-300` #C7C7C1 | 8.28 |

But: **when a chart's categories ARE statuses, use the status hues** (§4), never the sequence above — an OS-distribution bar uses the sequence; a devices-by-status bar uses status colors. This keeps Principle 7 intact.

Semantic-time charts (AUE planning): time buckets colored by urgency — past-AUE `--red-500`, <12 months `--amber-500`, <24 months `--amber-300`… no: keep it two-tone — past/`<12mo` in danger/warning, everything else `--blue-500`. Urgency thresholds also labeled in text on the axis ("expires within 12 months").

**Do:**
- Horizontal bars for categorical rankings (school names are long); vertical bars for time series buckets; lines only for continuous time.
- Direct-label bars with values (`--text-xs`, `--ink-secondary`, tabular-nums); legend only when >1 series, and legend chips double as text labels (color + text, never color alone).
- Gridlines `--border`, axis text `--ink-secondary` at `--text-xs` (6.18:1 — axis text is text, needs 4.5:1, passes).
- Every chart has a heading, a one-sentence takeaway in prose above it ("214 devices reach AUE before July 2027"), and a `<figure>/<figcaption>` + an adjacent "View as table" link rendering the same data as a real `<table>` — that table is the accessible representation; the SVG gets `role="img"` + `aria-label` summary.

**Don't:** pies/donuts (OS distribution is a sorted horizontal bar), stacked bars beyond 3 segments, dual axes, gradients or 3D anything, animation on charts (even without reduced-motion), red/green as the only distinction between adjacent series (the palette order above never puts them adjacent).

---

## 9. Accessibility standards summary

Target: **WCAG 2.1 AA** on every surface (D10), documented in an **ITI VPAT 2.5 (WCAG edition)** before the first large-district conversation (WS-2.7). This section is the audit contract; §3–§8 embed the implementation details.

### 9.1 Per-component APG pattern references

| Component | Pattern | Notes |
|---|---|---|
| Dense table | APG *Grid* (data grid) | Roving tabindex, `aria-sort`, labeled selection checkboxes (§5.3) |
| Dropdown menu | APG *Menu Button* | §5.10 |
| Modal / typed confirm | APG *Dialog (Modal)* via native `<dialog>` | Focus return to invoker (§5.11) |
| Category chips (portal) | Native radio group styled as chips | No ARIA needed beyond the fieldset/legend (§7.1) |
| Filter chips / saved views | Links + `aria-current`; toggles use `aria-pressed` | §5.4 |
| Tabs (URL-based) | Plain navigation links | `role="tablist"` only for same-page panels (§5.16) |
| Toasts/alerts | `role="status"` / `role="alert"`; announcements via single `<output aria-live="polite">` | §5.12; WCAG 4.1.3 |
| Combobox (device picker, assignee) | APG *Combobox with listbox popup* | Server-filtered via HTMX, `aria-activedescendant` |
| AG Grid island | Vendor grid — audited per §6 checklist | Scoped VPAT note |
| Skip link, landmarks | `header/nav/main/footer` + one `h1` per page | Skip link first in DOM (§5.9) |

### 9.2 Focus management with HTMX partial swaps

The five rules (violations are bugs, not polish):

1. **Stable trigger, stable focus.** If the triggering element survives the swap (same `id`), HTMX keeps focus — therefore toolbar controls, sort links, and pagination keep stable `id`s across renders.
2. **Content replacement moves focus intentionally.** When a swap replaces the element that had focus (form → success card), the response's first meaningful element gets `tabindex="-1"` and an `hx-on::after-swap` focus call. Never let focus silently fall to `<body>`.
3. **Dialogs:** focus into the dialog on open (native `showModal`), back to the invoker on close (HTMX default + stable ids).
4. **Announce what focus can't show.** Any swap that changes content outside the focused element ships an OOB live-region update (§5.12).
5. **`hx-push-url` swaps are navigations:** move focus to the new region's heading and update `<title>` (server includes `<title>` OOB swap), so back/forward behaves like real navigation for SR users.

### 9.3 Testing checklist (per feature PR, and full pass per release)

Per PR touching UI:
- [ ] **axe-core** automated scan (Playwright + `@axe-core/playwright` against the route, both themes) — zero violations; exceptions require a written waiver in the PR.
- [ ] **Keyboard-only pass:** every action reachable and operable; visible focus everywhere; no traps; documented shortcuts work; Esc closes what Enter opened.
- [ ] **Contrast:** any *new* color pair computed and recorded in this doc (§3/§4 tables are the registry).
- [ ] **Zoom:** 200% zoom and 320px-wide viewport — no loss of content/function (reflow; the data table may horizontally scroll within its labeled region — allowed for data tables).
- [ ] **Reduced motion:** toggle `prefers-reduced-motion` — no animation beyond opacity.
- [ ] **Live-region check:** state-changing actions announce (§5.12) — verify with a SR or the accessibility tree.

Per release (rotating deeper pass):
- [ ] **NVDA + Firefox (Windows)** and **VoiceOver + Safari (macOS)** spot-checks of the four golden paths: (1) teacher submits ticket; (2) tech filters, selects 500, bulk-moves OU; (3) tech deprovisions with typed confirm; (4) admin reviews sync diff and applies. iOS VoiceOver on the portal path.
- [ ] AG Grid island checklist (§6) if the pinned version changed.
- [ ] Update the VPAT working sheet: each WCAG 2.1 A/AA criterion → Supports / Partially supports / Does not support + remarks. Maintaining this continuously makes the eventual VPAT a formatting task, not an audit scramble.

### 9.4 Systemic guarantees (write once, hold forever)

Semantic HTML before ARIA; `lang` on `<html>`; visible labels for all inputs; error identification in text; no keyboard trap (2.1.2); focus order = DOM order (2.4.3); status messages via live region (4.1.3); target size ≥24px console / ≥44px portal (2.5.5/2.5.8); no content flashing >3/sec; session timeout on the portal preserves drafts (§7.3, WCAG 2.2.5-adjacent courtesy).

---

## 10. Implementation and file structure

### 10.1 Where things live (chalk repo)

```
crates/console/assets/
  css/
    tokens.css        # §3 verbatim: primitives + semantic themes. THE source of truth.
    base.css          # reset, typography defaults, focus ring, sr-only, reduced-motion
    components.css    # §5 components, one commented section per component
    console.css       # console/admin layout: sidebar, table regions, toolbars
    portal.css        # teacher portal only (loads tokens+base+portal — NOT components/console)
  js/
    htmx.min.js       # pinned, vendored
    chalk.js          # ≤8KB: table controller, menu controller, dialog opener,
                      # typed-confirm matcher, toast timers. No framework. ES modules, no build.
    grid-theme.js     # §6
    vendor/ag-grid-community.esm.js   # pinned; loaded ONLY on bulk-edit routes
  img/                # single-color SVG icons, currentColor strokes; sprite.svg
crates/console/templates/
  layout/base.html    # <html data-theme>, head, skip link, #announcer, #toasts, #modal
  partials/           # form_field.html, badge.html, table_*.html, diff_preview.html,
                      # pagination.html, alert.html, empty_state.html …
```

Serving (**as shipped in WS-1 C0**, `crates/console/src/assets.rs`): there is no
rust-embed and no build step. Each stylesheet is `include_str!`-embedded and
served by a plain handler with `Cache-Control: public, max-age=31536000,
immutable`, matching how the htmx bundle and the brand font were already
served. Cache busting is a **content-hash query string** — `tokens.css?v=9f3a2b1c`,
the first 8 hex of the SHA-256 of the bytes being served, computed once via
`LazyLock` — rather than a hashed filename, which would have needed either a
build script or a wildcard route with a fallible parse. The hash is derived
from file contents, not `CONSOLE_VERSION`: a version string only busts on
release, so a CSS fix shipped without a version bump would never reach a
returning admin. Templates call `crate::assets::{tokens,base,components,console}_css_href()`.
CSS load order: `tokens → base → components → (console|portal)`. Plain CSS +
custom properties, plain ES modules; total first-load CSS budget 50KB
uncompressed, JS (excluding AG Grid route) 60KB.

Portal isolation rule: `portal.css` may use tokens and base only — if the portal needs a component, it gets a portal-weight copy; the portal never pays for console CSS, and console churn can never break the teacher's screen.

Marketing repo (`chalk-marketing`, Astro + Tailwind): map the §3 primitives into `tailwind.config` theme colors (`paper`, `slate`, `chalk-blue`, …) so both properties share hex values; texture/display-font rules per §2.2/§2.4. Do not import app CSS into marketing or vice versa.

### 10.2 Naming conventions

- **BEM-lite classes:** `.block`, `.block__element`, `.block--modifier` (`.btn--primary`, `.table__check`, `.field__error`). Blocks are the §5 component names. No utility-class system in the app (that's Tailwind's job on marketing); a tiny sanctioned utility set lives in base.css: `.sr-only`, `.mono`, `.text-muted`, `.stack-*` (vertical rhythm), nothing else without a doc update.
- **State via attributes, not classes:** `data-state`, `data-density`, `data-invalid`, `aria-*` (style on `[aria-current="page"]`, `[aria-expanded="true"]`, `[aria-pressed]`) — states that matter visually should be states that matter semantically; styling ARIA keeps the two honest.
- **Tokens:** `--{concept}` semantic (components) / `--{hue}-{step}` primitive (tokens.css only). This is **enforced by a unit test**, not a grep convention: `assets::tests::only_tokens_css_contains_hex_literals` strips CSS comments and fails the build if any stylesheet other than `tokens.css` contains a hex colour. `assets::tests::legacy_c_aliases_are_all_defined` likewise guards the layer-3 `--c-*` alias set that ~30 un-migrated templates still depend on — deleting an alias while a template still references it is otherwise a silent, invisible regression.
- Askama partials named for their block: `badge.html` renders `.badge`.

### 10.3 Theme switching implementation

Server reads `chalk_theme` cookie (`auto|light|dark`, default `auto`), renders `<html data-theme="light|dark">` or no attribute for auto (media query takes over). The toggle is a three-option form in the user menu posting to `/prefs/theme` (HTMX, returns 204 + `HX-Refresh: true` — full refresh is fine for a theme change). No inline script, no flash, works with JS off.

### 10.4 Definition of Done — any new UI

A UI PR merges when all boxes tick:

- [ ] Uses semantic tokens only — no raw hex, no primitive tokens, no literal z-index/px-shadows (CI grep passes)
- [ ] Works with JavaScript disabled (form posts, real links), then enhanced with HTMX
- [ ] All interaction states implemented: hover, active, focus-visible, disabled, loading, invalid/selected where applicable — both themes screenshotted in the PR
- [ ] Keyboard pass done and noted in PR description; focus behavior on swap follows §9.2
- [ ] New color pairs (if any) have computed ratios added to §3/§4 tables
- [ ] Live-region announcement for every state-changing action (§5.12)
- [ ] `prefers-reduced-motion` respected (no new keyframes outside the sanctioned set)
- [ ] axe scan clean on the affected route, light + dark
- [ ] Voice/tone strings match §2.3 (terse console / plain portal); sentence case
- [ ] Dark-mode media-query block still byte-identical to `[data-theme="dark"]` block (§3.3 note)
- [ ] If the component is new: spec added to this document in the same PR

Cross-references: unit/e2e testing, clippy, fmt per repo `CLAUDE.md`; the axe Playwright scan counts as the feature's e2e a11y test.

---

## 11. Open questions (the only three)

1. **Per-tenant accent overrides for hosted districts.** Districts love their school colors. The token architecture supports overriding `--accent`/`--accent-*` per tenant, but arbitrary accents break our computed contrast guarantees. Proposed resolution (needs a decision before hosted GA, not before v1): offer 4–6 pre-computed, pre-audited accent presets instead of a free color picker. Until decided: no theming UI.
2. **AG Grid bundle size in the binary.** ~250KB gz embedded forever vs. using AG Grid's module registry to tree-shake (requires introducing a JS build step, which we otherwise avoid). Ship v1 with the full Community ESM bundle; revisit only if binary-size pushback materializes from self-hosters.
3. **Command palette (Ctrl/Cmd+K).** Deferred post-v1 (§5.6). Open: whether it's worth building before the Jan–Mar 2027 quote season as a demo-wow feature, or whether saved-view chips + global search already cover technician speed. Default: defer.

---

*Change control: this document is canon for UI. Amend it in the same PR as the change it describes; the §3/§4 ratio tables are the contrast registry of record.*
