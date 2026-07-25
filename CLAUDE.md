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
 - Bump the version in all 8 crate `Cargo.toml` files (core, cli, console, idp, google-sync, agent, marketplace, telemetry)
 - Update `CHANGELOG.md` with the new version entry
 - Commit and push to `main`
 - Create and push a git tag: `git tag v<version> && git push origin v<version>`
 - The `release.yml` workflow will automatically build binaries for all 4 platforms and create the GitHub release
 - After the release workflow completes, update the release notes with the changelog entry: `gh release edit v<version> --notes "<changelog notes>"`