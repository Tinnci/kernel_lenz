# KernelLens Coding Style Guide

This guide ensures the codebase remains maintainable, performant, and safe.

## 1. Safety & Error Handling

We avoid `panic!`, `unwrap()`, and `expect()` in library code (`kernel_core`). Use the `Result` pattern.

### ❌ Bad
```rust
let addr = data.pread::<u64>(offset).unwrap();
```

### ✅ Good
```rust
let addr = data.pread::<u64>(offset)
    .map_err(|e| Error::SymbolParseError { offset, message: e.to_string() })?;
```

## 2. Zero-Copy & Performance

Kernel analysis involves large binaries. Avoid unnecessary clones.

### ❌ Bad
```rust
fn process_name(name: Vec<u8>) { ... }
```

### ✅ Good
```rust
fn process_name(name: &[u8]) { ... }
```

## 3. Fuzzing-First Development

Every new parser in `kernel_core` **must** have a corresponding fuzzer in `fuzz/fuzz_targets/`.

## 4. Documentation

All public APIs and complex internal modules require documentation.

### ❌ Bad
```rust
// Parse kallsyms
pub fn parse_kallsyms(data: &[u8]) -> Result<Result> { ... }
```

### ✅ Good
```rust
/// Locates and recovers the `kallsyms` symbol table from a raw binary.
///
/// This uses heuristic pattern matching to find addresses and token tables.
/// For performance notes, see the module-level documentation (`//!`).
pub fn parse_kallsyms(data: &[u8]) -> Result<KallsymsResult> { ... }
```
