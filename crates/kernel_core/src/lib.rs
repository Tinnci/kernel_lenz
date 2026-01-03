//! # KernelLens Core Library
//!
//! This crate provides the core functionality for analyzing Linux kernel binaries:
//!
//! - **Boot Image Parsing**: Extract kernel from Android boot.img formats (V1-V4)
//! - **Decompression**: Handle LZ4, Gzip, and Zstd compressed kernels
//! - **Symbol Recovery**: Extract kallsyms symbol tables from stripped binaries
//! - **ELF Reconstruction**: Generate debuggable ELF files with recovered symbols
//!
//! ## Architecture
//!
//! ```text
//! boot.img -> [Unpacker] -> compressed_kernel -> [Decompressor] -> raw_binary
//!     -> [KallsymsFinder] -> symbols -> [ElfBuilder] -> vmlinux.elf
//! ```
//!
//! ## Design Principles
//!
//! - **Performance**: Uses zero-copy parsing (via `scroll`) and parallel symbol recovery (via `rayon`).
//! - **Safety**: All parser logic is continuously fuzzed. We avoid `unsafe` code unless strictly necessary for performance.
//! - **Robustness**: Handles malformed or partial kernel images without crashing.
//!
//! ## Example
//!
//! ```rust,ignore
//! use kernel_core::{BootImage, KallsymsFinder};
//!
//! let boot_img = BootImage::from_file("boot.img")?;
//! let kernel = boot_img.extract_kernel()?;
//! let symbols = KernelAnalyzer::find_kallsyms(&kernel)?;
//! let elf = ElfBuilder::new(&kernel, &symbols).build()?;
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod boot_image;
pub mod compression;
pub mod elf_builder;
pub mod error;
pub mod kallsyms;

// Re-export main types for convenience
pub use boot_image::BootImage;
pub use compression::Decompressor;
pub use elf_builder::ElfBuilder;
pub use error::{Error, Result};
pub use kallsyms::{KallsymsFinder, ScanOptions};
