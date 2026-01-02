//! # KernelLens FFI Layer
//!
//! This crate provides the Foreign Function Interface (FFI) for
//! exposing kernel_core functionality to Flutter/Dart.
//!
//! ## Architecture
//!
//! ```text
//! Flutter (Dart) <--FFI--> kernel_ffi (Rust) --> kernel_core (Rust)
//! ```
//!
//! ## Usage with flutter_rust_bridge
//!
//! After configuring flutter_rust_bridge, the generated Dart bindings
//! will appear in `app/lib/bridge_generated/`.

// Re-export types that Flutter needs to access
pub use kernel_core::boot_image::{BootImageHeader, BootImageVersion};
pub use kernel_core::compression::CompressionFormat;
pub use kernel_core::kallsyms::{KallsymsResult, KernelArch, KernelSymbol};

use anyhow::Result;
use kernel_core::{BootImage, Decompressor, ElfBuilder, KallsymsFinder};

// ============================================================
// FFI-friendly wrapper functions
// ============================================================

/// Analyze a boot image file and return header information.
///
/// This is a simplified interface for Flutter to quickly get
/// boot image metadata without full processing.
pub fn get_boot_info(path: String) -> Result<BootImageHeader> {
    let boot_img = BootImage::from_file(path)?;
    Ok(boot_img.header)
}

/// Full analysis pipeline: parse -> decompress -> analyze -> build ELF.
///
/// Returns the ELF bytes that can be saved by Flutter.
pub fn analyze_kernel(input_path: String) -> Result<AnalysisResult> {
    // Load input
    let raw_data = std::fs::read(&input_path)?;

    // Parse boot image if applicable
    let kernel_data = if raw_data.starts_with(b"ANDROID!") {
        let boot_img = BootImage::from_bytes(raw_data)?;
        let kernel = boot_img.extract_kernel()?;
        Decompressor::decompress(kernel)?
    } else {
        Decompressor::decompress(&raw_data)?
    };

    // Find symbols
    let kallsyms = KallsymsFinder::new(&kernel_data)?.into_result();

    // Build ELF
    let elf_bytes = ElfBuilder::new(&kernel_data, &kallsyms).build()?;

    Ok(AnalysisResult {
        kernel_size: kernel_data.len(),
        arch: kallsyms.arch,
        kernel_base: kallsyms.kernel_base,
        symbol_count: kallsyms.symbol_count,
        symbols: kallsyms.symbols,
        elf_bytes,
    })
}

/// Detect compression format of a file.
pub fn detect_compression(path: String) -> Result<CompressionFormat> {
    let data = std::fs::read(path)?;
    if data.len() < 4 {
        return Ok(CompressionFormat::None);
    }
    Ok(CompressionFormat::detect(&data))
}

// ============================================================
// Data Structures for FFI
// ============================================================

/// Complete analysis result for Flutter.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Size of decompressed kernel.
    pub kernel_size: usize,
    /// Detected architecture.
    pub arch: KernelArch,
    /// Kernel base address.
    pub kernel_base: u64,
    /// Number of recovered symbols.
    pub symbol_count: usize,
    /// All recovered symbols.
    pub symbols: Vec<KernelSymbol>,
    /// Generated ELF file bytes.
    pub elf_bytes: Vec<u8>,
}

// ============================================================
// Placeholder for flutter_rust_bridge
// ============================================================

// When flutter_rust_bridge is configured, add:
// #[flutter_rust_bridge::frb(init)]
// pub fn init_app() {
//     flutter_rust_bridge::setup_default_user_utils();
// }
