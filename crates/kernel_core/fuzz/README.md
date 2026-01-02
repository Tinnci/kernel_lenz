# Fuzz Testing Guide

This directory contains fuzz tests for `kernel_core` using [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).

## Prerequisites

1. **Install Rust nightly**:
   ```bash
   rustup install nightly
   ```

2. **Install cargo-fuzz**:
   ```bash
   cargo +nightly install cargo-fuzz
   ```

## Running Fuzz Tests

### Via xtask (recommended)

```bash
# Run for 60 seconds (default)
cargo xtask fuzz kallsyms_scanner

# Run for 5 minutes
cargo xtask fuzz kallsyms_decoder -m 300

# Available targets:
#   - kallsyms_scanner  (pattern matching)
#   - kallsyms_decoder  (token decompression)
#   - boot_image        (nom parsers)
#   - decompressor      (LZ4/Gzip/Zstd)
```

### Direct cargo-fuzz

```bash
cd crates/kernel_core/fuzz

# List available targets
cargo +nightly fuzz list

# Run a specific target
cargo +nightly fuzz run fuzz_kallsyms_scanner

# Run with time limit (seconds)
cargo +nightly fuzz run fuzz_boot_image -- -max_total_time=120

# Run with specific number of iterations
cargo +nightly fuzz run fuzz_decompressor -- -runs=10000
```

## Fuzz Targets

| Target | Tests | Focus |
|--------|-------|-------|
| `fuzz_kallsyms_scanner` | `KallsymsFinder::new()` | Pattern matching, architecture detection |
| `fuzz_kallsyms_decoder` | Token table parsing | Bounds checking, UTF-8 handling |
| `fuzz_boot_image` | `BootImage::from_bytes()` | nom parsers, extraction |
| `fuzz_decompressor` | `Decompressor::decompress()` | Compression bombs, malformed data |

## Corpus Management

Initial seed files are in `corpus/<target>/`:

```
corpus/
├── fuzz_boot_image/
│   └── seed_android_magic     # Valid ANDROID! magic bytes
├── fuzz_decompressor/         # Add LZ4/Gzip samples here
└── fuzz_kallsyms/             # Add kernel fragments here
```

**Tip**: Add real kernel binary fragments to the corpus for better coverage.

## Analyzing Crashes

When a crash is found, cargo-fuzz saves it to `artifacts/<target>/`:

```bash
# Reproduce a crash
cargo +nightly fuzz run fuzz_boot_image artifacts/fuzz_boot_image/crash-xxxxx

# Minimize the crash input
cargo +nightly fuzz tmin fuzz_boot_image artifacts/fuzz_boot_image/crash-xxxxx
```

## CI Integration

For continuous fuzzing in CI, consider using [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/):

```yaml
# .github/workflows/fuzz.yml
name: Fuzz
on:
  schedule:
    - cron: '0 0 * * *'  # Daily
jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: google/clusterfuzzlite/actions/build_fuzzers@v1
        with:
          language: rust
      - uses: google/clusterfuzzlite/actions/run_fuzzers@v1
        with:
          fuzz-seconds: 600
```

## Security Policy

If you discover a security vulnerability through fuzzing:

1. **Do not** open a public issue
2. Email the maintainers privately
3. Include the crash input and reproduction steps
