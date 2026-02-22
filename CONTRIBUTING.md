# Contributing to Chalk

## Prerequisites

- Rust stable (latest) via [rustup](https://rustup.rs/)
- SQLite3

## Building

```bash
git clone https://github.com/chalk-education/chalk.git
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
