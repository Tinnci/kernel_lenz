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
- [ ] Real-time analysis progress visualization
- [/] Symbol search & filtering interface (Backend logic implemented 🦀)
- [ ] Integrated HEX viewer for kernel exploration
- [x] **Stability & Build Hardening**: 
    - [x] Cross-platform line-ending normalization (.gitattributes)
    - [x] `xtask verify-paths` for auto-healing build scripts
- [ ] **FFI V2 Upgrade (2026 Spec)**: 
    - [ ] `StreamSink` for streaming symbol tables
    - [x] **Zero-Copy**: Implement Rust-side sorting/filtering/search to minimize dart object creation
    - [x] **xtask doctor**: Automated environment validation (NDK, LLVM, Flutter)
    - [ ] **Binary Diet**: CI integration with `cargo-bloat` & `panic="abort"` optimization

## Phase 4: Advanced Tools (Planned 📅)
- [ ] IDA/Ghidra script export
- [ ] Kernel structure auto-definition
- [ ] Patching & Minimalist Re-packaging

## Phase 5: Ecosystem & Community (Strategic 🌐)
- [ ] Plugin system for vendor-specific offsets
- [ ] Cloud-based symbol signature sharing
