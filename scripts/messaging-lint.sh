#!/usr/bin/env bash
#
# messaging-lint.sh — fail the build if a retired product claim reappears.
#
# WS-0 removed a set of claims from Chalk's public surfaces because they were
# false, legally risky, or described a business model we no longer run. Copy
# gets rewritten constantly, by people and by agents, and a claim that was
# deleted once will be reintroduced by anyone working from an old draft. This
# script is the ratchet that stops that.
#
# It is deliberately narrow: every pattern below traces to a specific recorded
# decision, and each is precise enough that a hit is a real problem rather than
# a nuisance. A lint people disable protects nothing.
#
# Usage:
#   scripts/messaging-lint.sh          # lint this repo
#   scripts/messaging-lint.sh --list   # print the rules and exit
#
# The same script runs in `chalk` and `chalk-marketing`; it detects which repo
# it is in and scopes itself accordingly. Keep the two copies identical.
#
# Adding a rule: append to the four parallel arrays below, keyed by decision.
# Removing a rule requires a decision record saying the claim is allowed again.
#
# Portability: targets bash 3.2 (macOS system bash) — no mapfile, no
# associative arrays, no `grep -P`.

set -euo pipefail

# Capture the invocation flag *before* scope detection below, which uses
# `set -- <paths>` to build the pathspec list and therefore overwrites $1.
# Reading "$1" after that point silently compares the flag against "src" and
# makes --list a no-op that exits 0 — indistinguishable from a clean lint.
MODE="${1:-}"

# ---------------------------------------------------------------------------
# Rules. Four parallel arrays rather than delimited strings, because the
# patterns themselves contain '|' alternation.
# ---------------------------------------------------------------------------
RULE_ID=(); RULE_DECISION=(); RULE_PATTERN=(); RULE_WHY=()

add_rule() {
  RULE_ID+=("$1"); RULE_DECISION+=("$2"); RULE_PATTERN+=("$3"); RULE_WHY+=("$4")
}

add_rule "drop-in" "D5" \
  'drop-in (clever|classlink|oauth|replacement)' \
  "Claims Chalk is a drop-in replacement for Clever/ClassLink. Vendor apps hard-code provider hostnames and credentials, so it is not technically true, and Clever's terms prohibit derivative products. Describe the OAuth 2.0 compatibility endpoints factually instead."

# NOTE: "Clever-compatible endpoints" is deliberately NOT banned. D18 permits
# describing the compat endpoints factually — that phrasing is the *approved*
# replacement for "drop-in replacement", and it is also the on-the-wire name of
# a real enum variant (SsoProtocol::CleverCompat), a config value, and a
# settings-UI label. Banning it would flag ~40 legitimate technical identifiers
# and train everyone to ignore this script. What is banned is the *equivalence
# claim*, below.

add_rule "same-capabilities" "D5" \
  'same capabilities[^.]{0,60}(clever|classlink)|(clever|classlink)[^.]{0,60}same capabilities' \
  'Claims parity with Clever/ClassLink. We implement clean-room OAuth2/OIDC + SAML + OneRoster; we do not replicate their vendor networks or feature sets.'

add_rule "apps-keep-working" "D5" \
  "(your apps don't notice|apps keep working|seamless vendor migration|without changing your downstream apps)" \
  'Promises downstream vendor apps continue working across a provider switch. Vendor apps hard-code provider hostnames and credentials — we cannot promise this, and it was the central claim of the retired migrate-from-* pages.'

add_rule "clever-pricing" "WS-0.2" \
  '(thousands|per-student fees)[^.]{0,80}clever' \
  'Factually wrong: Clever rostering is free to districts. Only ClassLink charges per user (~$3.50/user/yr). Never imply Clever bills districts per student.'

add_rule "free-for-schools" "D3" \
  'free for schools' \
  'Blanket promise that Chalk is free for schools. Self-hosted is free forever (D2) and a free hosted tier exists (D8, Chromebooks only) — but hosted is the paid product. Say which one you mean.'

add_rule "free-either-way" "D3" \
  'free either way' \
  'Promises hosted and self-hosted are both free. Hosted is the paid product.'

add_rule "hosted-zero" "D3" \
  'both literally \$0|hosted or self-hosted[^.]{0,40}\$0|hosting is free' \
  'Promises hosted at no cost. Contradicts the published price ladder (PRD §7).'

add_rule "marketplace-funding" "D4" \
  'funded by the (curated )?vendor marketplace' \
  'Names the vendor marketplace as the business model. It is not a revenue line and is not being sold.'

add_rule "vendor-marketplace" "D4" \
  'vendor marketplace' \
  'The vendor marketplace is dormant: code retained, not routed, not sold. It must not appear on a public surface.'

add_rule "inherit-vendor-network" "D5" \
  'inherit the vendor network' \
  "Claims Chalk inherits Clever/ClassLink's integrated app ecosystem. It does not."

# --- Marketplace, narrower than the exact phrase "vendor marketplace" ---------
#
# The "vendor marketplace" rule above catches only that literal phrase, and the
# WS-1 audit found four surviving surfaces that walked straight past it: a sales
# motion on /contact, a console nav section in two docs pages, and a vendor
# certification program on /app-gallery. The rules below name the specific
# shapes those took.
#
# /app-gallery itself survives as a district-facing directory of apps that
# connect to Chalk. What is retired is the *program* framing around it — that
# Chalk reviews, certifies, or admits vendors, and that a vendor can be listed
# as a commercial motion. We run no such program.

add_rule "marketplace-listing" "D4" \
  'marketplace (listing|listings|apply|application|submission)|(list|submit) your app' \
  'Sells a marketplace listing as something a vendor can obtain from us. There is no vendor marketplace program and no listing to sell. (The public /api/marketplace/apps feed URL in src/lib/config.ts is a backend path, not a claim — reference it as MARKETPLACE_APPS_URL, not in prose.)'

add_rule "app-certification" "D4" \
  '(reviewed and certified|certified apps?|certification program|vetted and approved)|(we|chalk) (review|certif(y|ies)|vet|vets|approve|approves) (every |each |all )?(vendor|app)' \
  'Claims Chalk reviews, certifies, or vets apps before they may connect. We run no review program; a district authorizes apps itself from its own console, and Chalk is a standard SAML/OIDC IdP that any app can be wired up against. Describe the gallery as a directory, not a gate.'

add_rule "marketplace-console-nav" "D4" \
  'nav[^.]{0,80}marketplace|marketplace[^.]{0,40}(section|tab) (of|in) the console' \
  'Documents Marketplace as a section of the admin console. The nav item exists in the OSS template but registers no route (it 404s), and the hosted catalog is not part of what we sell. Do not document it as a console feature.'

# --- Migration wizards --------------------------------------------------------

add_rule "cutover-wizard" "D5" \
  '(cutover|migration) wizard|guided cutover|(clever|classlink) cutover' \
  'Advertises step-by-step Clever/ClassLink cutover wizards in the console. Twice wrong: it is the migrate-from-* funnel positioning D5 retired, and it is a false shipping claim — the wizard templates post to /migration/*/parse, which is not a registered route, so the button 405s. Import is CLI-only: `chalk migrate --from clever|classlink --path <dir>`.'

# ---------------------------------------------------------------------------
# Scope: which files count as a "published surface" in this repo.
#
# Excluded everywhere, deliberately:
#   CHANGELOG.md  — an immutable historical record. Past releases legitimately
#                   describe claims we have since retired; rewriting history to
#                   satisfy a linter would be worse than the claim.
#   plans/, this script, prod-redirects.caddy — they quote the banned phrases
#                   in order to reason about them.
#   build output, vendored assets, lockfiles — not authored here.
# ---------------------------------------------------------------------------
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

if [ -d "src/pages" ] && [ -f "package.json" ]; then
  REPO="chalk-marketing"
  set -- src public README.md
elif [ -f "Cargo.toml" ] && [ -d "crates" ]; then
  REPO="chalk"
  set -- README.md docs crates
else
  echo "messaging-lint: unrecognized repo at $ROOT — expected chalk or chalk-marketing" >&2
  exit 2
fi
SCOPE=("$@")

EXCLUDES=(
  ':(exclude)CHANGELOG.md'
  ':(exclude)plans/'
  ':(exclude)scripts/messaging-lint.sh'
  ':(exclude)docs/prod-redirects.caddy'
  ':(exclude)**/node_modules/**'
  ':(exclude)dist/'
  ':(exclude)target/'
  ':(exclude)*.lock'
  ':(exclude)*.woff2'
  ':(exclude)*.png'
  ':(exclude)*.ico'
  ':(exclude)*.min.js'
)

if [ "$MODE" = "--list" ]; then
  echo "messaging-lint rules ($REPO):"
  i=0
  while [ $i -lt ${#RULE_ID[@]} ]; do
    printf '\n  [%s] %s\n    pattern: %s\n    %s\n' \
      "${RULE_DECISION[$i]}" "${RULE_ID[$i]}" "${RULE_PATTERN[$i]}" "${RULE_WHY[$i]}"
    i=$((i + 1))
  done
  exit 0
fi

# Lint tracked files AND untracked-but-not-gitignored ones (--others
# --exclude-standard). Tracked-only would be a trap: a brand-new page is
# untracked until `git add`, so the author would get a green run locally and a
# red one in CI — exactly when the feedback is least useful. Gitignored files
# are still skipped, so build output and node_modules stay out.
#
# --deduplicate collapses the overlap between --cached and --others; it needs
# git >= 2.31, so fall back to sort -u on older gits.
FILES=()
if git ls-files --deduplicate >/dev/null 2>&1; then
  LIST_CMD=(git ls-files --cached --others --exclude-standard --deduplicate --)
else
  LIST_CMD=(git ls-files --cached --others --exclude-standard --)
fi

while IFS= read -r f; do
  # Skip blanks and files that are tracked but deleted from the working tree —
  # grep would error on them and 2>/dev/null would hide it, passing vacuously.
  [ -n "$f" ] && [ -f "$f" ] && FILES+=("$f")
done < <("${LIST_CMD[@]}" "${SCOPE[@]}" "${EXCLUDES[@]}" 2>/dev/null | sort -u || true)

if [ ${#FILES[@]} -eq 0 ]; then
  echo "messaging-lint: no files in scope for $REPO — check SCOPE" >&2
  exit 2
fi

failed=0
i=0
while [ $i -lt ${#RULE_ID[@]} ]; do
  # -I skips binaries, -n line numbers, -E extended regex, -i case-insensitive.
  if hits="$(grep -IniE -- "${RULE_PATTERN[$i]}" "${FILES[@]}" 2>/dev/null)"; then
    failed=1
    printf '\n\033[31m✗ RETIRED CLAIM\033[0m  (%s — rule: %s)\n' \
      "${RULE_DECISION[$i]}" "${RULE_ID[$i]}"
    printf '  %s\n\n' "${RULE_WHY[$i]}"
    printf '%s\n' "$hits" | sed 's/^/    /'
  fi
  i=$((i + 1))
done

echo
if [ $failed -eq 1 ]; then
  cat >&2 <<'EOF'
messaging-lint FAILED.

Each hit above is a product claim that was deliberately retired. Rewrite the
copy — do not add an exclusion. If a claim genuinely should be allowed again,
that is a decision to record in plans/PRD.md §3 first, and this script changes
in the same commit as the decision.

Run `scripts/messaging-lint.sh --list` to see every rule and its rationale.
EOF
  exit 1
fi

printf '\033[32m✓\033[0m messaging-lint passed (%s): %d rules, %d files.\n' \
  "$REPO" "${#RULE_ID[@]}" "${#FILES[@]}"
