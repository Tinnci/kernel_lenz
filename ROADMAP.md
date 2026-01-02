---
status: active
current_version: v0.2.0
next_milestone: v0.3.0 (Flutter UI Integration)
priority_themes: ["FFI Performance", "Interactive Visualization", "Stability"]
---

# KernelLens Roadmap

## Phase 1: Foundation (Completed 🦀)
- [x] Project scaffolding & Workspace setup
- [x] Android Boot Image (V1-V4) parser
- [x] Multi-format decompression (LZ4, Gzip, Zstd)

## Phase 2: Core Analysis Engine (Completed 🦀)
- [x] Modular Kallsyms recovery engine
- [x] Heuristic table scanning
- [x] Token-based name decompression
- [x] Parallel symbol processing
- [x] Fuzz testing & 2026 Engineering Standards

## Phase 3: Flutter UI Integration (Ongoing 🚀)
- [x] Flutter V2 integration via `flutter_rust_bridge`
- [x] Desktop-first UI with Glassmorphism aesthetics
- [x] Real-time analysis progress visualization (StreamSink)
- [x] Symbol search & filtering interface (Backend + Infinite Scroll UI)
- [x] **Sorting Controls**: Address/Name/Type sorting with direction toggle
- [ ] Integrated HEX viewer for kernel exploration (API ready, UI pending)
- [x] **Stability & Build Hardening**: 
    - [x] Cross-platform line-ending normalization (.gitattributes)
    - [x] `xtask verify-paths` for auto-healing build scripts
    - [x] FFI race condition guards (`isLoadingMore` lock)
- [x] **FFI V2 Upgrade (2026 Spec)**: 
    - [x] `StreamSink` for real-time progress updates
    - [x] **Zero-Copy**: Rust-side sorting/filtering/pagination
    - [x] **xtask doctor**: Automated environment validation
    - [x] **Binary Diet**: `cargo-bloat` integrated into `xtask bloat`

## Phase 4: Advanced Tools (Planned 📅)
- [ ] IDA/Ghidra script export
- [ ] Kernel structure auto-definition
- [ ] Patching & Minimalist Re-packaging

## Phase 5: Ecosystem & Community (Strategic 🌐)
- [ ] Plugin system for vendor-specific offsets
- [ ] Cloud-based symbol signature sharing
