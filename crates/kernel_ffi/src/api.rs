use anyhow::Result;
use serde::{Deserialize, Serialize};

pub use kernel_core::boot_image::{BootImageHeader, BootImageVersion};
pub use kernel_core::compression::CompressionFormat;
use kernel_core::{BootImage, Decompressor, ElfBuilder, KallsymsFinder};

/// A Flutter-friendly version of KernelSymbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrbKernelSymbol {
    /// Symbol virtual address.
    pub addr: u64,
    /// Symbol name.
    pub name: String,
    /// Symbol type string (e.g., "T", "t", "D").
    pub stype: String,
}

/// Complete analysis result for Flutter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Size of decompressed kernel.
    pub kernel_size: usize,
    /// Detected architecture.
    pub arch: String,
    /// Kernel base address.
    pub kernel_base: u64,
    /// Number of recovered symbols.
    pub symbol_count: usize,
    /// All recovered symbols.
    pub symbols: Vec<FrbKernelSymbol>,
    /// Generated ELF file bytes.
    pub elf_bytes: Vec<u8>,
}

/// Initialize the Rust API.
#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    // Default utilities like logging setup
    flutter_rust_bridge::setup_default_user_utils();
}

/// Analyze a boot image file and return header information.
pub fn get_boot_info(path: String) -> Result<BootImageHeader> {
    let boot_img = BootImage::from_file(path)?;
    Ok(boot_img.header)
}

/// Full analysis pipeline: parse -> decompress -> analyze -> build ELF.
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
        arch: format!("{:?}", kallsyms.arch),
        kernel_base: kallsyms.kernel_base,
        symbol_count: kallsyms.symbol_count,
        symbols: kallsyms.symbols
            .into_iter()
            .map(|s| FrbKernelSymbol {
                addr: s.address,
                name: s.name,
                stype: s.sym_type.to_string(),
            })
            .collect(),
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
