# Contributing to Chalk

## Prerequisites

- Rust stable (latest) via [rustup](https://rustup.rs/)
- SQLite3

## Building

```bash
git clone https://github.com/usechalk/chalk.git
cd chalk
cargo build --release
```

## Testing

```bash
cargo test --all
cargo clippy --all -- -D warnings
```

## Project Structure

| Crate | Description |
|---|---|
| `chalk-core` | OneRoster models, database layer, SIS connectors, sync engine |
| `chalk-cli` | Binary entry point and CLI commands |
| `chalk-console` | HTMX admin web UI |
| `chalk-idp` | Identity provider (SAML, QR badges, picture passwords) |
| `chalk-google-sync` | Google Workspace user provisioning |
| `chalk-agent` | AI diagnostic agent |
| `chalk-marketplace` | Vendor integrations (planned) |
| `chalk-telemetry` | Anonymous usage telemetry |

Only `chalk-cli` produces a binary; the rest are libraries.

## Contributor License Agreement (CLA)

By submitting a pull request or otherwise contributing to Chalk, you agree that:

1. **You grant AdminRemix LLC a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license** to use, reproduce, modify, distribute, sublicense, and otherwise exploit your contributions in any form, including under licenses other than AGPL-3.0.
2. **You represent that you have the right** to grant this license and that your contributions are your original work (or that you have permission from the copyright holder).
3. **You understand that Chalk is dual-licensed.** The open-source edition is available under AGPL-3.0, and AdminRemix LLC may offer commercial licenses for hosted or proprietary use.
4. **Your contributions remain credited** in the project's Git history and changelog where applicable.

This CLA allows AdminRemix LLC to sustain the project by operating a hosted version of Chalk while keeping the open-source edition freely available.

## Submitting Changes

1. Fork the repository and create a feature branch
2. Write tests for new functionality
3. Ensure `cargo test --all` and `cargo clippy --all -- -D warnings` pass
4. Submit a pull request

## Code Standards

- Run `cargo fmt` before committing
- No `Any` types — use concrete types
- Unit tests required for new code
- Follow existing patterns in the codebase
