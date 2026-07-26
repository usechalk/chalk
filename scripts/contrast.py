#!/usr/bin/env python3
"""Check — and gate on — the WCAG 2.1 contrast registry in DESIGN_SYSTEM.md §3.2.

`DESIGN_SYSTEM.md` is the contrast registry of record, and a stale or
hand-estimated ratio there is worse than none — someone will ship against it.
So no ratio in that document is ever computed by hand. Run this and paste.

    python3 scripts/contrast.py            # the registry table; exit 1 on a fail
    python3 scripts/contrast.py '#4f46e5' '#ffffff'   # one ad-hoc pair

**This gates.** A pair below its threshold exits non-zero and fails CI. D10
makes WCAG 2.1 AA a build constraint (ADA Title II lands Apr 2027/2028, and
procurement asks for the VPAT), so a contrast regression is a build break, not
a note. Every row below is a pair the product actually ships; if you change a
token, change the row with it. A registry that only reports goes stale, and a
registry that lists pairs nothing uses is a fiction that passes.

Colours here must stay in sync with crates/console/assets/css/tokens.css.

Two properties worth remembering, because both have already caused a wrong
number to be written down:

  * Contrast is **symmetric**. white-on-accent and accent-on-white are the
    same pair. If a table quotes two different values for them, one is wrong.
  * The thresholds differ by role. Text needs 4.5:1 (AA), large text 3:1, and
    non-text UI — focus rings, borders that carry meaning, chart marks — 3:1
    (WCAG 1.4.11). A 2.8:1 focus ring fails even though no text is involved.
"""

import sys

# --- tokens.css primitives (the steps the registry actually references) ------
# One flat map: a colour is foreground in one pair and background in another
# (white is both), so splitting them would only invite a KeyError.
COLORS = {
    "--white": "#ffffff",
    "--indigo-300": "#a5b4fc",
    "--indigo-400": "#818cf8",
    "--indigo-500": "#6366f1",
    "--indigo-600": "#4f46e5",
    "--indigo-700": "#4338ca",
    "--slate-300": "#cbd5e1",
    "--slate-400": "#94a3b8",
    "--slate-500": "#64748b",
    "--slate-700": "#334155",
    "--slate-800": "#1e293b",
    "--green-700": "#15803d",
    "--amber-700": "#b45309",
    "--red-600": "#dc2626",
    "--red-700": "#b91c1c",
    "--fuchsia-700": "#a21caf",
    "--slate-50": "#f8fafc",
    "--slate-100": "#f1f5f9",
    "--slate-900": "#0f172a",
    "--slate-600": "#475569",
    "--indigo-50": "#eef2ff",
    "--indigo-100": "#e0e7ff",
    "--green-50": "#f0fdf4",
    "--amber-50": "#fffbeb",
    "--red-50": "#fef2f2",
    "--fuchsia-50": "#fdf4ff",
}

# (foreground, background, role, threshold) — threshold 4.5 text / 3.0 non-text
#
# Each row names the token pair as it is USED, not as it is defined: the role
# column is where to look in the CSS when a row goes red. Rows for pairs the
# product no longer paints have been deleted rather than left passing.
REGISTRY = [
    ("--white", "--indigo-600", "primary button, solid accent fill", 4.5),
    ("--white", "--indigo-700", "primary button hover", 4.5),
    ("--indigo-600", "--white", "links, auth wordmark (same pair as row 1)", 4.5),
    ("--indigo-600", "--slate-50", "links on app background", 4.5),
    ("--indigo-700", "--indigo-100", "text on --accent-subtle", 4.5),
    ("--indigo-700", "--indigo-50", "info badge", 4.5),
    ("--indigo-600", "--white", "focus ring vs --surface", 3.0),
    ("--indigo-600", "--slate-50", "focus ring vs --bg", 3.0),
    ("--indigo-600", "--slate-100", "focus ring vs --surface-3 (row hover)", 3.0),
    ("--slate-700", "--white", "body text", 4.5),
    ("--slate-800", "--white", "headings, form labels", 4.5),
    ("--slate-500", "--white", "muted text (--ink-muted) on --surface", 4.5),
    ("--slate-500", "--slate-50", "muted text (--ink-muted) on --bg", 4.5),
    ("--slate-300", "--slate-900", "sidebar link text", 4.5),
    ("--white", "--slate-900", "sidebar hover / wordmark", 4.5),
    ("--slate-400", "--slate-900", "sidebar section label", 4.5),
    ("--indigo-300", "--slate-900", "active sidebar link + its 3px rail", 4.5),
    ("--slate-300", "--slate-600", "sidebar badge", 4.5),
    ("--green-700", "--green-50", "success badge, auth notice", 4.5),
    ("--amber-700", "--amber-50", "warning badge", 4.5),
    ("--red-700", "--red-50", "danger badge, auth error pill", 4.5),
    ("--white", "--red-700", "solid destructive button", 4.5),
    ("--white", "--red-600", "solid destructive hover", 4.5),
    ("--fuchsia-700", "--fuchsia-50", "extended-status badge", 4.5),
    ("--slate-700", "--slate-100", "neutral badge", 4.5),
    ("--indigo-500", "--white", "priority dot, normal (non-text)", 3.0),
    ("--indigo-400", "--slate-900", "dark-theme accent fill (unshipped)", 4.5),
]


def relative_luminance(hex_color: str) -> float:
    """WCAG 2.1 relative luminance of an sRGB colour."""
    h = hex_color.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    channels = [int(h[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    r, g, b = linear
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(a: str, b: str) -> float:
    """WCAG 2.1 contrast ratio. Symmetric in its arguments, by definition."""
    lighter, darker = sorted((relative_luminance(a), relative_luminance(b)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def main() -> int:
    if len(sys.argv) == 3:
        fg, bg = sys.argv[1], sys.argv[2]
        print(f"{fg} on {bg} = {contrast_ratio(fg, bg):.2f}:1")
        return 0
    if len(sys.argv) != 1:
        print(__doc__)
        return 2

    failures = 0
    width = max(len(f"{f} on {b}") for f, b, _, _ in REGISTRY)
    for fg, bg, role, threshold in REGISTRY:
        ratio = contrast_ratio(COLORS[fg], COLORS[bg])
        ok = ratio >= threshold
        failures += not ok
        mark = "ok  " if ok else "FAIL"
        kind = "text" if threshold == 4.5 else "ui  "
        print(f"{mark} {kind} {fg + ' on ' + bg:<{width}}  {ratio:5.2f}:1  {role}")

    print(f"\n{len(REGISTRY)} pairs, {failures} below threshold.")
    if failures:
        print("A shipped pair is below its WCAG 2.1 AA threshold. Fix the token in")
        print("crates/console/assets/css/tokens.css, or — if the pair is no longer")
        print("painted anywhere — delete its row here. Do not raise the threshold.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
