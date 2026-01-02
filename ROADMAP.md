---
status: active
current_version: v0.2.1
next_milestone: v0.3.0 (Advanced Tools & Export)
priority_themes: ["Zero-Latency UI", "Semantic Diagnostics", "Kernel Reconstruction"]
---

# KernelLens Roadmap

## Phase 1: Foundation (Completed 🦀)
- [x] Project scaffolding & Workspace setup
- [x] Android Boot Image (V1-V4) parser
- [x] Multi-format decompression (LZ4, Gzip, Zstd)

## Phase 2: Core Analysis Engine (Refining 🛠️)
- [x] Modular Kallsyms recovery engine
- [x] Heuristic table scanning (V2 implementation)
- [x] Token-based name decompression
- [x] Parallel symbol processing
- [x] **Advanced Heuristics (vmlinux-to-elf port)**:
    - [x] Robust token-table anchoring
    - [x] Dynamic endianness detection via token-index pattern
    - [x] Backtracking markers & names recovery
    - [x] Automated relative base discovery (4.6+ kernels)
- [x] Fuzz testing & 2026 Engineering Standards

## Phase 3: Flutter UI Integration (Completed 🚀)
- [x] **Core UI Framework**:
    - [x] Flutter V2 integration via `flutter_rust_bridge`
    - [x] Desktop-first Glassmorphism aesthetic (Radical 2026 Design)
    - [x] **Background Task Tray**: Persistent non-blocking analysis progress

## Phase 4: Advanced Tools (Ongoing 📅)
- [ ] **ELF Reconstruction Engine**: 
    - [ ] Dynamic section mapping for non-standard kernels
    - [ ] Symbol table injection for external tool compatibility
- [ ] **Kernel Re-packaging**: Minimalist rebuild for rapid testing

## Phase 5: Ecosystem & Strategic (Strategic 🌐)
- [ ] Plugin system for vendor-specific offsets
- [ ] Cloud-based symbol signature sharing
- [ ] Multi-arch support expansion (RISC-V, x86_64)
