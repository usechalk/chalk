## Web Searches
 - Never include the date or year in your web searches, its weird and doesn't help

## Using the browser
If your needing to use chrome to view a website use the remix-browser

## Work as a team
When asked to do work always spin up multiple agents and work as a team to get the job done as fast as possible. High quality code written fast as a team is the goal here. Working together and sharing when needed.

## Constant Improvement 
 - As needed update the lint rules to ensure high quality code
 - As needed update the claude.md to ensure high quality code
 - **When CI catches something local didn't, fix the gap, not just the error.** A
   green local run must mean a green CI run. If the two disagree, that difference
   is the bug — close it in the same change that fixes the symptom, and write down
   why. (Example: CI ran a newer `stable` than local, so new clippy lints only
   failed after push. Fixed by pinning `rust-toolchain.toml` and having CI read it
   instead of naming `stable`.)
 - **Prefer a guard that can't be forgotten over a rule someone has to remember.**
   Pin versions, add a CI step, write a lint. A checklist item that lives only in a
   doc will be skipped; a failing build will not.
 - **When you fix a class of mistake, make the class impossible.** Ask what would
   have caught this automatically, then add that. Retired product claims got
   `scripts/messaging-lint.sh`; toolchain drift got a pinned toolchain.
 - **A guard built on a hand-maintained list is still a rule someone has to
   remember.** Derive the list from the thing itself, or the guard only certifies
   the cases you already thought of. v1.11.0 shipped a test asserting "a sidebar
   link is shown exactly when its routes are served" — it walked an array naming
   the two modules it was written for, passed, and sat directly beside a
   Marketplace link that had 404'd in every self-hosted install since it was
   added. v1.11.1 replaced it with a crawl of every link `base.html` actually
   renders. Same shape as the release checklist that named eight crates when
   there were ten. Before writing the assertion, ask: *where does this list come
   from, and what happens when someone adds the eleventh thing?*
 - **A test fixture must be as wired as production, or a 404 means nothing.**
   `AppState` has ten `with_*` builders and `chalk serve` calls them all; a
   fixture calling three makes pages 404 because a repository is absent, which
   reads identically to "the route is not registered". That has produced a
   vacuous test three separate times. Console tests use
   `fully_wired_state` — extend it when a builder is added.

### Toolchain
 - `rust-toolchain.toml` pins the Rust version for local dev and CI both. Never
   name a Rust version in a workflow file — rustup reads the pin automatically.
 - Bumping it is a deliberate, standalone change: raise `channel`, run
   `cargo clippy --all-targets -- -D warnings`, fix what the new lints find, push
   that on its own. New lints should arrive in a reviewed commit, never as a
   surprise failure on someone else's PR.

 ## Code Quality
 - Always unit test code that we write ALWAYS. 
 - Always ensure the code is linted and or type checked
 - Always ensure the project builds
 - Always ensure the code is DRY
 - Always ensure you never use an `Any` type, we will always use high quality types in our code
 - If you find pre-exiting issues, you will fix them. 
 - Check clippy after major code is written
 - Check fmt after major code is written

## When testing
- Always ensure 100% unit test pass
- Always find a way to test your feature e2e
 
## When Planning or testing
 - Always see how you can validate a change you have made to ensure its correct
     - Examples
         - When asked to optimize code or make code faster, always have a performance benchmark you can run before and after
         - When asked to write a new feature, or extend code write supporting unit test if needed first then add the new feature then add more unit test as needed
 - If you are unsure about an ask, always use the AskUserQuestion tool and get the answers your need
 - If you plan a large or major feature make sure to update the changelog when done
 - If you make a new changelog record you should bump the cargo.toml version to match

## Releasing
 - Bump the version in **every** crate `Cargo.toml`. Do not work from a list —
   run `ls crates/` and bump them all, then confirm with
   `grep -h '^version' crates/*/Cargo.toml | sort | uniq -c`, which must show a
   single line. This instruction used to name eight crates and there are now ten
   (ad-sync and devices were added later), so a hand-maintained list is exactly
   the thing that ships a release with two versions in it.
 - Update `CHANGELOG.md` with the new version entry
 - Commit and push to `main`
 - Create and push a git tag: `git tag v<version> && git push origin v<version>`
 - The `release.yml` workflow will automatically build binaries for all 4 platforms and create the GitHub release
 - After the release workflow completes, update the release notes with the changelog entry: `gh release edit v<version> --notes "<changelog notes>"`