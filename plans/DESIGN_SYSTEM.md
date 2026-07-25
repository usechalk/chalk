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
> **Why the swap is structurally free.** The token architecture in §3.2–§3.3 was built around `--blue-600`'s contrast behavior, and indigo lands within 0.1 of it on both critical pairs:
>
> | Pair | chalk-blue `#33688E` | indigo `#4f46e5` | AA? |
> |---|---|---|---|
> | White text on accent (primary button) | 5.98:1 | **5.93:1** | ✅ |
> | Accent as text on `--paper-0 #FCFBF9` (links) | 5.78:1 | **6.16:1** | ✅ |
>
> So the semantic layer transplants unchanged: `--accent`, `--accent-hover`, `--accent-ink`, `--accent-subtle`, `--accent-subtle-ink`, `--link`, `--focus-ring` keep their names, roles, and usage rules. What still must be done **before WS-2 ships**:
> 1. Build a full indigo primitive ramp (`--indigo-50` … `--indigo-950`) replacing `--blue-*`, with every step's ratio computed and recorded — §3/§4 are the contrast registry of record and must not carry stale numbers.
> 2. Re-derive the dark-theme accent (light mode can use `#4f46e5` as button fill and link; dark mode needs a lighter step, the analogue of `--blue-400`/`--blue-300`, verified ≥4.5:1 on `--surface` and ≥3:1 for the focus ring).
> 3. Re-verify §8's categorical chart palette — series 1 is the accent hue and its ratio changes.
> 4. Confirm indigo still reads as distinct from `--violet-*`, which is a *status* hue here (open tickets, deprovisioned devices). Indigo and violet are closer than chalk-blue and violet were — **this is the one real risk the swap introduces.** If they collide at badge size, move the violet status hue, not the accent.
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

All ratios in this document are WCAG 2.1 relative-luminance contrast ratios, computed, not estimated. Primitives are theme-independent raw values; **components must never reference primitives directly** — only the semantic tokens in §3.3.

```css
/* tokens.css — layer 1: primitives. Never used directly in components. */
:root {
  /* Neutrals: warm "paper" at the light end, cool slate at the dark end.
     The warm→cool drift is intentional: paper in daylight, slate at night. */
  --paper-0:    #FCFBF9;  /* app background, light */
  --paper-50:   #F7F5F1;  /* stripes, wells, secondary surfaces */
  --paper-100:  #EFEDE7;  /* hovers, neutral badge bg */
  --slate-200:  #E0DFD9;  /* hairline borders on paper */
  --slate-300:  #C7C7C1;  /* strong borders, disabled text (decorative) */
  --slate-400:  #9CA0A0;  /* placeholders (light), muted text (dark) */
  --slate-500:  #666F73;  /* muted text on paper-0/50 — 4.97:1 / 4.72:1 */
  --slate-600:  #556166;  /* secondary text — 6.18:1 on paper-0 */
  --slate-700:  #404E56;  /* strong secondary — 8.31:1 on paper-0 */
  --slate-800:  #2E3B44;  /* dark raised surface */
  --slate-900:  #212D36;  /* dark surface (cards, tables) */
  --slate-950:  #16212A;  /* dark app background */
  --ink-1000:   #0F1A22;  /* primary text on paper — 17.05:1 on paper-0 */
  --chalk-white:#E9EDEC;  /* primary text on slate — 11.91:1 on slate-900 */

  /* Accent — "chalk dust blue" */
  --blue-50:  #EEF4F8;
  --blue-100: #DCE8F0;
  --blue-200: #BFD5E4;
  --blue-300: #97BAD2;   /* dark-mode accent/link — 6.88:1 on slate-900 */
  --blue-400: #6C9CBC;   /* dark-mode primary button bg (ink text: 5.98:1) */
  --blue-500: #477FA6;   /* light-mode focus ring — 4.18:1 vs paper-0 */
  --blue-600: #33688E;   /* light-mode primary button bg (white text: 5.98:1), links (5.78:1 on paper-0) */
  --blue-700: #2A5474;   /* button hover; badge text — 7.23:1 on blue-50 */
  --blue-800: #26445D;
  --blue-900: #22384B;
  --blue-950: #16242F;

  /* Success — green */
  --green-50:  #ECF6EE;
  --green-100: #D6EDDC;
  --green-200: #AFDCBD;
  --green-300: #7FC498;  /* 6.87:1 on slate-900 */
  --green-400: #4FA771;
  --green-500: #2E8B57;
  --green-600: #23744A;  /* white text: 5.72:1; as text on paper-0: 5.54:1 */
  --green-700: #1F5E3E;  /* badge text — 6.96:1 on green-50 */
  --green-800: #1C4A33;
  --green-900: #17392A;
  --green-950: #0E241A;

  /* Warning — amber */
  --amber-50:  #FBF3E4;
  --amber-100: #F7E5C4;
  --amber-200: #EECF93;
  --amber-300: #E0AE55;  /* 6.93:1 on slate-900 */
  --amber-400: #C98E24;
  --amber-500: #A97613;  /* chart use — 3.84:1 vs paper-0 (non-text ok) */
  --amber-600: #8A5F0E;
  --amber-700: #6E4C10;  /* badge text — 7.04:1 on amber-50; white on it: 7.77:1 */
  --amber-800: #573D12;
  --amber-900: #433012;
  --amber-950: #2B1E0B;

  /* Danger — red */
  --red-50:  #FBEFED;
  --red-100: #F7DBD7;
  --red-200: #EFB9B2;
  --red-300: #E28D83;  /* 5.61:1 on slate-900 */
  --red-400: #D05F53;  /* dark destructive btn bg (ink text: 4.57:1) */
  --red-500: #B93E31;
  --red-600: #9E2F25;  /* light destructive btn (white text: 7.27:1); as text: 7.03:1 on paper-0 */
  --red-700: #802A22;  /* badge text — 8.22:1 on red-50 */
  --red-800: #66261F;
  --red-900: #4F211C;
  --red-950: #331410;

  /* Violet — extended semantic (open tickets, deprovisioned devices) */
  --violet-50:  #F3F1FA;
  --violet-100: #E6E1F4;
  --violet-200: #CDC5E8;
  --violet-300: #AEA1D6;  /* 5.94:1 on slate-900 */
  --violet-400: #8B7AC0;
  --violet-500: #6F5CA9;
  --violet-600: #5B4A8F;  /* white text: 7.44:1 */
  --violet-700: #4A3D74;  /* badge text — 8.49:1 on violet-50 */
  --violet-800: #3C325C;
  --violet-900: #2F2848;
  --violet-950: #1E192E;
}
```

**Contrast rule of thumb baked into the scales:** on light theme, steps 600+ of any hue are AA text on paper-0/50; steps 700+ are AA text on their own 50 tint. On dark theme, step 300 of any hue is AA text on slate-800/900/950 and on its own 950 shade. Do not use 400/500 steps as text.

### 3.3 Semantic tokens — light and dark from one set

Dark mode strategy (decided): `prefers-color-scheme` is the default; a manual override is stored in a `chalk_theme` cookie (`light` | `dark` | `auto`) and rendered server-side as `data-theme` on `<html>` (no FOUC, works without JS after first toggle). The toggle itself is a three-state control in the user menu, posted as a normal form.

```css
/* tokens.css — layer 2: semantic. Components use ONLY these. */
:root, [data-theme="light"] {
  color-scheme: light;

  /* Surfaces */
  --bg:             var(--paper-0);
  --surface:        var(--paper-0);   /* cards, table bodies */
  --surface-2:      var(--paper-50);  /* wells, stripes, page sections */
  --surface-3:      var(--paper-100); /* hover, active nav, neutral chip */
  --surface-raised: #FFFFFF;          /* modals, menus, popovers */
  --backdrop:       rgb(15 26 34 / 0.45);

  /* Ink */
  --ink:            var(--ink-1000);  /* 17.05:1 on --bg */
  --ink-secondary:  var(--slate-600); /*  6.18:1 on --bg */
  --ink-muted:      var(--slate-500); /*  4.97:1 on --bg; 4.72:1 on --surface-2.
                                          NOT AA on --surface-3 — use --ink-secondary there. */
  --ink-placeholder:var(--slate-400); /* placeholders only, never for content */
  --ink-inverse:    var(--chalk-white);

  /* Borders */
  --border:         var(--slate-200);
  --border-strong:  var(--slate-300);
  --border-input:   var(--slate-400);

  /* Accent / interactive */
  --accent:         var(--blue-600);
  --accent-hover:   var(--blue-700);
  --accent-ink:     #FFFFFF;          /* text on accent — 5.98:1 */
  --accent-subtle:  var(--blue-50);   /* selected rows, active chips */
  --accent-subtle-ink: var(--blue-700); /* 7.23:1 on --accent-subtle */
  --link:           var(--blue-600);  /* 5.78:1 on --bg */

  /* Focus */
  --focus-ring:     var(--blue-500);  /* 4.18:1 vs --bg, 3.97:1 vs --surface-2 (≥3:1) */

  /* Semantic status (fg = AA text on --bg; -bg/-fg pairs for badges, §4) */
  --success-fg: var(--green-600);  --success-bg: var(--green-50);  --success-badge-fg: var(--green-700);  --success-border: var(--green-200);
  --warning-fg: var(--amber-700);  --warning-bg: var(--amber-50);  --warning-badge-fg: var(--amber-700);  --warning-border: var(--amber-200);
  --danger-fg:  var(--red-600);    --danger-bg:  var(--red-50);    --danger-badge-fg:  var(--red-700);    --danger-border:  var(--red-200);
  --info-fg:    var(--blue-600);   --info-bg:    var(--blue-50);   --info-badge-fg:    var(--blue-700);   --info-border:    var(--blue-200);
  --violet-fg:  var(--violet-600); --violet-bg:  var(--violet-50); --violet-badge-fg:  var(--violet-700); --violet-border:  var(--violet-200);
  --neutral-bg: var(--paper-100);  --neutral-badge-fg: var(--slate-700); --neutral-border: var(--slate-300);

  --danger-solid: var(--red-600);  --danger-solid-ink: #FFFFFF;  /* 7.27:1 */

  /* Shadows (slate-tinted, restrained) */
  --shadow-1: 0 1px 2px rgb(15 26 34 / 0.06);
  --shadow-2: 0 2px 8px rgb(15 26 34 / 0.08), 0 1px 2px rgb(15 26 34 / 0.06);
  --shadow-3: 0 8px 24px rgb(15 26 34 / 0.14), 0 2px 6px rgb(15 26 34 / 0.08);
}

[data-theme="dark"] {
  color-scheme: dark;

  --bg:             var(--slate-950);
  --surface:        var(--slate-900);
  --surface-2:      var(--slate-800);
  --surface-3:      #38464F;          /* one step above slate-800 for hover */
  --surface-raised: var(--slate-800);
  --backdrop:       rgb(0 0 0 / 0.6);

  --ink:            var(--chalk-white); /* 13.84:1 on --bg, 11.91:1 on --surface */
  --ink-secondary:  var(--slate-300);   /*  8.28:1 on --surface */
  --ink-muted:      var(--slate-400);   /*  5.32:1 on --surface, 6.19:1 on --bg */
  --ink-placeholder:#7B858A;
  --ink-inverse:    var(--ink-1000);

  --border:         #3A4750;
  --border-strong:  #4A575F;
  --border-input:   #5A676F;

  --accent:         var(--blue-400);   /* buttons */
  --accent-hover:   var(--blue-300);
  --accent-ink:     var(--ink-1000);   /* 5.98:1 on blue-400 */
  --accent-subtle:  var(--blue-950);
  --accent-subtle-ink: var(--blue-300); /* 7.74:1 on blue-950 */
  --link:           var(--blue-300);   /* 6.88:1 on --surface, 5.63:1 on --surface-2 */

  --focus-ring:     var(--blue-300);   /* 7.99:1 vs --bg, 6.88:1 vs --surface */

  --success-fg: var(--green-300);  --success-bg: var(--green-950);  --success-badge-fg: var(--green-300);  --success-border: var(--green-800);
  --warning-fg: var(--amber-300);  --warning-bg: var(--amber-950);  --warning-badge-fg: var(--amber-300);  --warning-border: var(--amber-800);
  --danger-fg:  var(--red-300);    --danger-bg:  var(--red-950);    --danger-badge-fg:  var(--red-300);    --danger-border:  var(--red-800);
  --info-fg:    var(--blue-300);   --info-bg:    var(--blue-950);   --info-badge-fg:    var(--blue-300);   --info-border:    var(--blue-800);
  --violet-fg:  var(--violet-300); --violet-bg:  var(--violet-950); --violet-badge-fg:  var(--violet-300); --violet-border:  var(--violet-800);
  --neutral-bg: var(--slate-800);  --neutral-badge-fg: var(--slate-300); --neutral-border: var(--slate-600);

  --danger-solid: var(--red-400);  --danger-solid-ink: var(--ink-1000); /* 4.57:1 */

  /* Dark shadows: mostly borders do the work; shadows are subtle black */
  --shadow-1: 0 1px 2px rgb(0 0 0 / 0.35);
  --shadow-2: 0 2px 8px rgb(0 0 0 / 0.45);
  --shadow-3: 0 10px 28px rgb(0 0 0 / 0.55);
}

/* System preference, only when user hasn't overridden (server renders
   data-theme="auto" or omits the attribute for auto). */
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]):not([data-theme="dark"]) {
    /* duplicate the [data-theme="dark"] block here at build/paste time;
       keep the two blocks byte-identical (checked in review). */
  }
}
```

> Maintenance note: the dark block appears twice (attribute + media query). Keep them identical; this is the price of no-build-step CSS and is called out in the Definition of Done (§10.4).

### 3.4 Typography tokens

Root stays at the user's browser default (never set `html { font-size }` in px — that breaks user zoom preferences). Tokens in rem; px shown for a 16px root.

```css
:root {
  /* Families: see §2.4 */
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               "Helvetica Neue", Arial, "Noto Sans", sans-serif;
  --font-mono: ui-monospace, "SF Mono", "Cascadia Code", "Segoe UI Mono",
               Menlo, Consolas, monospace;

  /* Scale */
  --text-2xs: 0.6875rem;  /* 11px — table meta, badge in compact rows ONLY */
  --text-xs:  0.75rem;    /* 12px — badges, captions, column meta */
  --text-sm:  0.8125rem;  /* 13px — console body: table cells, dense forms */
  --text-md:  0.875rem;   /* 14px — console default UI text, buttons, inputs */
  --text-lg:  1rem;       /* 16px — portal body & inputs (prevents iOS zoom), admin body */
  --text-xl:  1.125rem;   /* 18px — card titles, portal labels */
  --text-2xl: 1.25rem;    /* 20px — section headings */
  --text-3xl: 1.5rem;     /* 24px — page titles */
  --text-4xl: 1.875rem;   /* 30px — stat tile numbers, portal heading */

  /* Line heights */
  --leading-tight: 1.25;   /* headings, table cells, stat numbers */
  --leading-normal: 1.5;   /* body, forms */
  --leading-loose: 1.65;   /* portal long text, help text */

  /* Weights (system faces: stick to these three) */
  --weight-regular: 400;
  --weight-medium: 500;   /* labels, buttons, table headers, nav */
  --weight-semibold: 600; /* headings, stat numbers, active states */

  --tracking-caps: 0.04em; /* the ONLY letter-spacing we use: small-caps labels */
}

/* Global numeric alignment for data surfaces */
table, .stat, .badge, [data-numeric] { font-variant-numeric: tabular-nums; }
code, .mono, [data-mono] { font-family: var(--font-mono); font-size: 0.9375em; }
```

Usage matrix: console UI = `--text-md`, console tables = `--text-sm` (compact rows may use `--text-sm` cells with `--text-2xs` meta); teacher portal = `--text-lg` minimum everywhere (mobile); page title = `--text-3xl`/`--weight-semibold`. Minimum text size anywhere: 11px, and only for non-essential meta that is also available elsewhere.

### 3.5 Spacing, radii, borders

```css
:root {
  /* 4px base grid */
  --space-0: 0;
  --space-1: 0.125rem;  /*  2px */
  --space-2: 0.25rem;   /*  4px */
  --space-3: 0.5rem;    /*  8px */
  --space-4: 0.75rem;   /* 12px */
  --space-5: 1rem;      /* 16px */
  --space-6: 1.5rem;    /* 24px */
  --space-7: 2rem;      /* 32px */
  --space-8: 2.5rem;    /* 40px */
  --space-9: 3rem;      /* 48px */
  --space-10: 4rem;     /* 64px */

  --radius-sm: 4px;     /* badges, chips, inputs in compact contexts */
  --radius-md: 6px;     /* buttons, inputs, dropdown items */
  --radius-lg: 8px;     /* cards, modals, popovers */
  --radius-xl: 12px;    /* portal card, marketing */
  --radius-full: 9999px;/* pills: filter chips, priority dots */

  --border-w: 1px;
  --border-w-strong: 2px;   /* focus, selected chip, invalid input */
}
```

Layout constants: console content max-width none (tables want the room); admin settings pages max-width 720px; teacher portal card max-width 480px; sidebar width 240px (collapsible to 56px icon rail); page gutter `--space-6` desktop / `--space-4` mobile.

### 3.6 Motion

```css
:root {
  --duration-1: 80ms;    /* hovers, presses, checkbox ticks */
  --duration-2: 160ms;   /* dropdowns, tooltips, chip toggles, HTMX swap settle */
  --duration-3: 240ms;   /* modals, drawers, toasts */
  --ease-out:   cubic-bezier(0.2, 0, 0, 1);     /* default: entering, expanding */
  --ease-in:    cubic-bezier(0.4, 0, 1, 1);     /* exiting only */
  --ease-swap:  cubic-bezier(0.25, 0.1, 0.25, 1); /* htmx settle transitions */
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
  .skeleton { animation: none; } /* static shimmer block, still visible */
}
```

Rules: nothing animates position except overlays entering/leaving; no parallax, no auto-playing anything; loading spinners are allowed under reduced motion only as opacity pulses ≤1Hz — prefer the static "Loading…" text swap. HTMX `htmx-settling` class gets `transition: background-color var(--duration-2) var(--ease-swap)` for the row-flash pattern (§5.13).

### 3.7 Z-index scale

```css
:root {
  --z-base: 0;
  --z-sticky: 100;      /* sticky table header, sticky first column */
  --z-bulkbar: 150;     /* bulk-action toolbar (above sticky header) */
  --z-nav: 200;         /* sidebar, portal top bar */
  --z-dropdown: 400;    /* menus, comboboxes, tooltips */
  --z-overlay: 500;     /* modal backdrop */
  --z-modal: 510;
  --z-toast: 600;
  --z-debug: 900;
}
```

Never write a literal z-index. If a new layer is needed, add a token here in a dedicated commit.

### 3.8 Focus ring spec

One ring for the entire product. Visible focus is a release blocker, not polish.

```css
:where(a, button, input, select, textarea, summary, [tabindex],
       [role="row"], [role="gridcell"]):focus-visible {
  outline: 2px solid var(--focus-ring);
  outline-offset: 2px;
  border-radius: inherit;
}
/* On accent-colored controls, add separation so ring never melts into fill */
.btn--primary:focus-visible, .chip[aria-pressed="true"]:focus-visible {
  outline-offset: 2px;
  box-shadow: 0 0 0 2px var(--bg); /* gap ring */
}
/* Inside table rows (offset would clip): inset ring */
tr:focus-visible, .table [role="row"]:focus-visible {
  outline: 2px solid var(--focus-ring);
  outline-offset: -2px;
}
```

Contrast: light ring `--blue-500` = 4.18:1 vs paper-0, 3.97:1 vs paper-50; dark ring `--blue-300` = 7.99:1 vs slate-950, 6.88:1 vs slate-900 — all ≥ 3:1 (WCAG 1.4.11). Never `outline: none` without a same-rule replacement. `:focus-visible` (not `:focus`) so mouse clicks don't paint rings, but keyboard always does.

---

## 4. Status color system

Design law: **color is never the only channel.** Every badge = text label + hue; `lost`, `urgent`, and `breached` additionally get an icon (see below). Ratios shown as light `L` / dark `D`; light = badge-fg on badge-bg tint, dark = 300-step text on 950-step shade.

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
.badge--violet  { --badge-bg: var(--violet-bg);  --badge-fg: var(--violet-badge-fg);  --badge-border: var(--violet-border); }
.badge--neutral { --badge-bg: var(--neutral-bg); --badge-fg: var(--neutral-badge-fg); --badge-border: var(--neutral-border); }
.badge--solid   { --badge-bg: var(--danger-solid); --badge-fg: var(--danger-solid-ink); --badge-border: transparent; }
```

### 4.2 Device status (`assets.status`)

| Status | Variant | Light pair (ratio) | Dark pair (ratio) | Notes |
|---|---|---|---|---|
| `active` | success | green-700 on green-50 — **6.96:1** | green-300 on green-950 — **7.97:1** | Default healthy state |
| `repair` | warning | amber-700 on amber-50 — **7.04:1** | amber-300 on amber-950 — **8.01:1** | |
| `storage` | info | blue-700 on blue-50 — **7.23:1** | blue-300 on blue-950 — **7.74:1** | "Parked, intentional" |
| `retired` | neutral | slate-700 on paper-100 — **7.35:1** | slate-300 on slate-800 — **6.78:1** | End of life, unremarkable |
| `deprovisioned` | violet | violet-700 on violet-50 — **8.49:1** | violet-300 on violet-950 — **7.19:1** | Irreversible; distinct hue on purpose |
| `lost` | danger + icon (⚠ triangle) | red-700 on red-50 — **8.22:1** | red-300 on red-950 — **6.71:1** | Needs action; icon marks it beyond hue |

### 4.3 Ticket status (`tickets.status`)

| Status | Variant | Light (ratio) | Dark (ratio) | Meaning cue |
|---|---|---|---|---|
| `new` | info | blue-700/blue-50 — **7.23:1** | blue-300/blue-950 — **7.74:1** | Untriaged |
| `open` | violet | violet-700/violet-50 — **8.49:1** | violet-300/violet-950 — **7.19:1** | In a technician's hands |
| `pending` | warning | amber-700/amber-50 — **7.04:1** | amber-300/amber-950 — **8.01:1** | Waiting on requester/parts |
| `resolved` | success | green-700/green-50 — **6.96:1** | green-300/green-950 — **7.97:1** | |
| `closed` | neutral | slate-700/paper-100 — **7.35:1** | slate-300/slate-800 — **6.78:1** | |

Violet appears in both domains (`open` ticket, `deprovisioned` device). Accepted: the domains never share a column, and the text label always disambiguates. Do not "fix" this by inventing a seventh hue.

### 4.4 Ticket priority (`tickets.priority`)

Priorities render as a **dot + text** inline in queue tables (quieter than a second badge per row), and as full badges on the ticket detail page.

| Priority | Treatment | Light (ratio) | Dark (ratio) |
|---|---|---|---|
| `low` | neutral dot `--slate-400` + text `--ink-secondary` | text 6.18:1 on paper-0 | text 8.28:1 on slate-900 |
| `normal` | info dot `--blue-500` + text `--ink-secondary` | 6.18:1 | 8.28:1 |
| `high` | warning badge | amber-700/amber-50 — **7.04:1** | amber-300/amber-950 — **8.01:1** |
| `urgent` | **solid** danger badge + double-chevron icon | white on red-600 — **7.27:1** | ink-1000 on red-400 — **4.57:1** |

Only `urgent` (and SLA `breached`) ever use the solid fill. Solid = "interrupt what you're doing." If everything shouts, nothing does.

### 4.5 SLA states (computed from `sla_due_at`, `first_response_at`, `resolved_at`)

| State | Treatment | Light (ratio) | Dark (ratio) | Extra channel |
|---|---|---|---|---|
| `ok` | success badge, or no badge at all in dense queues | 6.96:1 | 7.97:1 | Default may be *absence* — only exceptions shout |
| `at-risk` (< 25% of SLA window left) | warning badge + clock icon + remaining time text ("1h 12m") | 7.04:1 | 8.01:1 | Countdown text |
| `breached` | **solid** danger badge + ⚠ icon + overdue time ("2d over") | white/red-600 — **7.27:1** | ink/red-400 — **4.57:1** | Icon + text |

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

Serving: rust-embed with content-hashed filenames (`tokens.9f3a.css`) emitted at compile time; `Cache-Control: immutable`. CSS load order: `tokens → base → components → (console|portal)`. **No build step**: plain CSS + custom properties, plain ES modules; total first-load CSS budget 50KB uncompressed, JS (excluding AG Grid route) 60KB.

Portal isolation rule: `portal.css` may use tokens and base only — if the portal needs a component, it gets a portal-weight copy; the portal never pays for console CSS, and console churn can never break the teacher's screen.

Marketing repo (`chalk-marketing`, Astro + Tailwind): map the §3 primitives into `tailwind.config` theme colors (`paper`, `slate`, `chalk-blue`, …) so both properties share hex values; texture/display-font rules per §2.2/§2.4. Do not import app CSS into marketing or vice versa.

### 10.2 Naming conventions

- **BEM-lite classes:** `.block`, `.block__element`, `.block--modifier` (`.btn--primary`, `.table__check`, `.field__error`). Blocks are the §5 component names. No utility-class system in the app (that's Tailwind's job on marketing); a tiny sanctioned utility set lives in base.css: `.sr-only`, `.mono`, `.text-muted`, `.stack-*` (vertical rhythm), nothing else without a doc update.
- **State via attributes, not classes:** `data-state`, `data-density`, `data-invalid`, `aria-*` (style on `[aria-current="page"]`, `[aria-expanded="true"]`, `[aria-pressed]`) — states that matter visually should be states that matter semantically; styling ARIA keeps the two honest.
- **Tokens:** `--{concept}` semantic (components) / `--{hue}-{step}` primitive (tokens.css only). Grep-check in CI: no hex literals and no `--paper-/--slate-/--blue-` etc. references outside `tokens.css` (`rg -n '#[0-9a-fA-F]{3,8}' crates/console/assets/css --glob '!tokens.css'`).
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
