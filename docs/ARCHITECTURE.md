# KernelLens Architecture

## Overview

KernelLens is a Windows-native Linux kernel analysis suite built with:
- **Rust** for high-performance backend processing
- **Flutter/Dart** for cross-platform GUI

## Project Structure

```
kernel_lenz/
├── Cargo.toml              # Workspace configuration
├── crates/                 # Rust backend
│   ├── kernel_core/        # Core algorithms (parsing, symbols, ELF)
│   ├── kernel_cli/         # Command-line interface
│   ├── kernel_ffi/         # Flutter FFI bridge
│   ├── xtask/              # Build automation
│   └── test_utils/         # Shared test infrastructure
├── app/                    # Flutter GUI (initialized separately)
└── docs/                   # Documentation
```

## Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         User Input                                  │
│                      (boot.img / kernel)                           │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Stage 1: Unpack                                │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│  │ Magic Check │───▶│ Parse Header│───▶│ Extract     │            │
│  │ ANDROID!    │    │ V0/V1/V2/V3 │    │ Kernel Data │            │
│  └─────────────┘    └─────────────┘    └─────────────┘            │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Stage 2: Decompress                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│  │ Format      │───▶│ LZ4/Gzip/   │───▶│ Raw Kernel  │            │
│  │ Detection   │    │ Zstd Decode │    │ Binary      │            │
│  └─────────────┘    └─────────────┘    └─────────────┘            │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 Stage 3: Symbol Recovery                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│  │ Find Token  │───▶│ Decompress  │───▶│ Build       │            │
│  │ Table       │    │ Names       │    │ Symbol List │            │
│  └─────────────┘    └─────────────┘    └─────────────┘            │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Stage 4: ELF Generation                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│  │ Create      │───▶│ Add Symbol  │───▶│ Write       │            │
│  │ Sections    │    │ Table       │    │ vmlinux.elf │            │
│  └─────────────┘    └─────────────┘    └─────────────┘            │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Stage 5: Visualize                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│  │ Size        │    │ Call Graph  │    │ Treemap     │            │
│  │ Analysis    │    │ Analysis    │    │ Rendering   │            │
│  └─────────────┘    └─────────────┘    └─────────────┘            │
└─────────────────────────────────────────────────────────────────────┘
```

## Crate Dependencies

```
kernel_cli ─────┬──────▶ kernel_core
                │
kernel_ffi ─────┘
                │
test_utils ─────┘

xtask (standalone, no deps on kernel_*)
```

## Key Design Decisions

### 1. Workspace Inheritance

All version and dependency management is centralized in the root `Cargo.toml`.
Child crates use `version.workspace = true` to inherit settings.

### 2. Error Handling Strategy

- `kernel_core`: Uses `thiserror` for typed, composable errors
- `kernel_cli`: Uses `anyhow` for ergonomic error reporting
- `kernel_ffi`: Converts errors to JSON-serializable format for Flutter

### 3. No C Dependencies (Almost)

We deliberately avoid C library dependencies where possible:
- `lz4_flex` instead of `lz4` (pure Rust)
- `object` instead of `libelf` (pure Rust)

This makes Windows builds trivial without MSVC or MinGW.

### 4. FFI Strategy

The `kernel_ffi` crate will use `flutter_rust_bridge` to auto-generate
Dart bindings. This avoids manual FFI boilerplate and provides
type-safe async communication.

## Development Workflow

1. **Algorithm Development**: Work in `kernel_core` with unit tests
2. **CLI Testing**: Use `kernel_cli` for integration testing
3. **GUI Development**: Work in `app/` with hot reload
4. **Build Automation**: Use `cargo xtask <task>` for common operations

## Future Enhancements

- [ ] Parallel kallsyms search using Rayon
- [ ] Memory-mapped file I/O for large images
- [ ] ARM instruction disassembly for base address detection
- [ ] Plugin system for custom visualizations
