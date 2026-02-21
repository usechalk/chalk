# Contributing to Chalk

Thank you for your interest in contributing to Chalk.

## Development Setup

1. Install Rust (stable channel): https://rustup.rs/
2. Clone the repository
3. Build: `cargo build`
4. Test: `cargo test --all`

## Code Quality

Before submitting changes:

```bash
cargo build --release
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Project Structure

Chalk is a Rust workspace with 8 crates. See [docs/architecture.md](docs/architecture.md) for details.

## Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Write tests for new functionality
4. Ensure all checks pass
5. Submit a pull request with a clear description

## Coding Standards

- No `Any` types — use concrete, well-defined types
- All new code must have unit tests
- Keep code DRY
- Follow existing patterns and conventions
- Use `thiserror` for error types
- Use `async_trait` for async trait definitions

## Testing

- Unit tests go in `#[cfg(test)] mod tests` blocks within source files
- Use in-memory SQLite (`DatabasePool::new_sqlite_memory()`) for database tests
- Use `wiremock` for HTTP mocking
- Target 100% test pass rate

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
