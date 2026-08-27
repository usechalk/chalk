---
name: release
description: Cut a chalk release — version bump across all crates, changelog, gates, CI-gated tag, release notes
---

# Releasing chalk

The whole loop, in order. Every step exists because skipping it once shipped
a bug; the guards named below fail the build when the rule is broken, so
follow the loop and the guards confirm it.

## 1. Bump every crate

Never work from a list of crate names — derive it:

```bash
for c in $(ls crates/); do
  sed -i '' 's/^version = "OLD"/version = "NEW"/' crates/$c/Cargo.toml
done
grep -h '^version' crates/*/Cargo.toml | sort | uniq -c   # must print ONE line
```

Then sync the lockfile — CI's release build runs `--locked` and fails on a
stale lock:

```bash
cargo update -p chalk-core -p chalk-cli -p chalk-console -p chalk-idp \
  -p chalk-google-sync -p chalk-agent -p chalk-marketplace -p chalk-telemetry \
  -p chalk-ad-sync -p chalk-devices --precise NEW
```

(If a crate was added since this file was written, `ls crates/` already
covered it in the bump; add it to the `cargo update` line too.)

## 2. Changelog

Add the `## [NEW] - YYYY-MM-DD` entry at the top of `CHANGELOG.md`. Write
what a district operator gains, not what the code does. The release notes
are extracted from this entry verbatim in step 5.

## 3. Gates — all of them, locally, before pushing

```bash
cargo build --locked          # the lockfile is actually in sync
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
./scripts/messaging-lint.sh          # no retired product claims
./scripts/route-permission-lint.sh   # every route declares its permission
./scripts/cargo-audit-gate.sh        # advisories, ignore list in .cargo/audit.toml
```

A green local run must mean a green CI run — if CI later disagrees, that
difference is itself the bug to fix (see AGENTS.md).

## 4. Commit and push

Stage **explicit paths**, never `git add -A` — `plans/` is private and
gitignored, and a stray `-A` is how it leaks. Commit message: what and why,
plus the standard trailers.

## 5. CI-gate, tag, notes

Tag only after CI is green **on that exact commit** (pin the run by SHA —
`--limit 1` races with other pushes):

```bash
SHA=$(git rev-parse HEAD)
RUN=$(gh run list --commit $SHA --workflow CI --json databaseId -q '.[0].databaseId')
gh run watch $RUN --exit-status
git tag vNEW && git push origin vNEW
# release.yml builds all platforms; when it finishes:
gh release edit vNEW --notes "$(awk '/^## \[NEW\]/{f=1;next} /^## \[/{if(f)exit} f' CHANGELOG.md)"
```

Beware in shell chains: `grep -c` prints `0` and **exits 1** when the count
is zero — a `&&` chain dies on the success case. Use `grep -cE ... | grep -q '^0$'`
or separate statements.

## 6. Hosted

The hosted crate pins chalk by tag — see the `hosted-release` skill.
