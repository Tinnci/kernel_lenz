# 🔬 KernelLens

> **Windows-native Linux Kernel Analysis & Visualization Suite**

A high-performance toolkit for analyzing compiled Linux kernels (especially Android production kernels) without requiring WSL or Cygwin.

## 🎯 Project Goals

Transform the Linux kernel analysis workflow from Python/Shell-based tools to a modern, Windows-native experience using:

- **Rust** - Backend core logic (binary parsing, symbol recovery, ELF reconstruction)
- **Dart/Flutter** - Cross-platform GUI for visualization

## 📦 Architecture

```
kernel_lenz/
├── crates/
│   ├── kernel_core/     # Core algorithms (parsing, decompression, kallsyms)
│   ├── kernel_cli/      # Command-line interface
│   ├── kernel_ffi/      # Flutter FFI bridge
│   ├── xtask/           # Build automation (replaces Makefiles)
│   └── test_utils/      # Shared test fixtures
├── app/                 # Flutter GUI application
└── docs/                # Documentation
```

## 🔧 Core Capabilities

| Stage | Capability | Status |
|-------|-----------|--------|
| **Unpack** | Parse Android boot.img (V1-V4) | 🚧 Planned |
| **Decompress** | LZ4/Gzip/Zstd kernel extraction | 🚧 Planned |
| **Recover** | Kallsyms symbol table extraction | 🚧 Planned |
| **Reconstruct** | Generate debuggable vmlinux ELF | 🚧 Planned |
| **Visualize** | Interactive size treemap & analysis | 🚧 Planned |

## 🚀 Quick Start

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs))
- Flutter 3.16+ (for GUI, optional)

### Build CLI Tool

```powershell
# Build the command-line tool
cargo build --release -p kernel_cli

# Run analysis
./target/release/kernel_cli.exe analyze boot.img -o vmlinux.elf
```

### Development

```powershell
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p kernel_core

# Format code
cargo fmt --all

# Lint check
cargo clippy --workspace

# Run automation tasks
cargo xtask --help
```

## 📚 References

This project is inspired by and aims to replace:

- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) (Python)
- [Android Image Kitchen](https://github.com/osm0sis/Android-Image-Kitchen) (Shell/Batch)
- [Binwalk](https://github.com/ReFirmLabs/binwalk) (Python)
- [Bloaty McBloatface](https://github.com/google/bloaty) (C++)

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.
