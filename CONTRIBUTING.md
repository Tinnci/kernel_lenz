# Contributing to KernelLens

Welcome! As a 2026-era Rust project, we prioritize **reliability, security (Fuzzing-first), and extreme performance**.

## Development Workflow

1. **Standard**: Follow our [Coding Style & Best Practices](./docs/STYLE_GUIDE.md).
2. **Architecture**: Understand the [Project Architecture](./docs/ARCHITECTURE.md).
3. **Safety**: Ensure all parsing logic is covered by a Fuzzer in `crates/kernel_core/fuzz`.
4. **Validation**: Run `cargo xtask lint` and `cargo xtask test` before submitting a PR.

## Toolchain Required

- Rust **Stable** (for building)
- Rust **Nightly** (for running Fuzzers)
- `cargo-fuzz` (install via `cargo install cargo-fuzz`)

## Documentation

To generate and view the full developer documentation (including internal design notes):
```bash
cargo xtask doc --open
```
