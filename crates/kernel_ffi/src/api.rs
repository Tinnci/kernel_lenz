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

/// Column to sort by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    /// Sort by virtual address.
    Address,
    /// Sort by symbol name.
    Name,
    /// Sort by symbol type.
    Type,
}

/// Lightweight summary of the analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    /// Size of decomrpessed kernel bytes.
    pub kernel_size: usize,
    /// CPU architecture (e.g., AArch64).
    pub arch: String,
    /// Base address of the kernel code.
    pub kernel_base: u64,
    /// Total number of symbols found.
    pub symbol_count: usize,
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

/// Stateful session that holds the analysis data in Rust memory.
///
/// This avoids passing the entire symbol table (10MB+) to Dart.
/// Dart can query this session using `query_symbols` for pagination/filtering.
#[flutter_rust_bridge::frb(opaque)]
pub struct AnalysisSession {
    symbols: Vec<FrbKernelSymbol>,
    /// Summary of the analysis.
    pub summary: AnalysisSummary,
    /// Underlying uncompressed ELF bytes.
    pub elf_bytes: Vec<u8>,
}

impl AnalysisSession {
    /// Start a new analysis session.
    pub fn new(input_path: String) -> Result<AnalysisSession> {
        let raw_data = std::fs::read(&input_path)?;

        let kernel_data = if raw_data.starts_with(b"ANDROID!") {
            let boot_img = BootImage::from_bytes(raw_data)?;
            let kernel = boot_img.extract_kernel()?;
            Decompressor::decompress(kernel)?
        } else {
            Decompressor::decompress(&raw_data)?
        };

        let kallsyms = KallsymsFinder::new(&kernel_data)?.into_result();
        let elf_bytes = ElfBuilder::new(&kernel_data, &kallsyms).build()?;

        let symbols: Vec<FrbKernelSymbol> = kallsyms
            .symbols
            .into_iter()
            .map(|s| FrbKernelSymbol {
                addr: s.address,
                name: s.name,
                stype: s.sym_type.to_string(),
            })
            .collect();

        Ok(AnalysisSession {
            summary: AnalysisSummary {
                kernel_size: kernel_data.len(),
                arch: format!("{:?}", kallsyms.arch),
                kernel_base: kallsyms.kernel_base,
                symbol_count: kallsyms.symbol_count,
            },
            symbols,
            elf_bytes,
        })
    }

    /// Query symbols using server-side filtering and sorting.
    ///
    /// This is a "Zero-Copy" operation effectively, as we only return
    /// the small subset of data requested by the UI view.
    pub fn query_symbols(
        &self,
        filter: String,
        sort_by: SortColumn,
        ascending: bool,
        page: usize,
        page_size: usize,
    ) -> Vec<FrbKernelSymbol> {
        // 1. Filter
        let mut filtered: Vec<&FrbKernelSymbol> = if filter.is_empty() {
            self.symbols.iter().collect()
        } else {
            let lower_filter = filter.to_lowercase();
            self.symbols.iter().filter(|s| s.name.to_lowercase().contains(&lower_filter)).collect()
        };

        // 2. Sort
        filtered.sort_by(|a, b| {
            let cmp = match sort_by {
                SortColumn::Address => a.addr.cmp(&b.addr),
                SortColumn::Name => a.name.cmp(&b.name),
                SortColumn::Type => a.stype.cmp(&b.stype),
            };
            if ascending {
                cmp
            } else {
                cmp.reverse()
            }
        });

        // 3. Paginate
        let start = page * page_size;
        if start >= filtered.len() {
            return Vec::new();
        }
        let end = (start + page_size).min(filtered.len());

        // Clone only the visible page (cheap)
        filtered[start..end].iter().map(|&s| s.clone()).collect()
    }

    /// Get the total count of symbols after filtering (for pagination).
    pub fn count_filtered(&self, filter: String) -> usize {
        if filter.is_empty() {
            self.symbols.len()
        } else {
            let lower_filter = filter.to_lowercase();
            self.symbols.iter().filter(|s| s.name.to_lowercase().contains(&lower_filter)).count()
        }
    }

    /// Read a chunk of the kernel for hex viewing.
    pub fn get_hex_chunk(&self, offset: usize, length: usize) -> HexChunk {
        let start = offset.min(self.elf_bytes.len());
        let end = (offset + length).min(self.elf_bytes.len());

        HexChunk {
            content: self.elf_bytes[start..end].to_vec(),
            offset: start as u64,
            total_size: self.elf_bytes.len() as u64,
        }
    }
}

/// A chunk of hex data for the viewer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexChunk {
    /// Raw byte content.
    pub content: Vec<u8>,
    /// Starting offset in the file/memory.
    pub offset: u64,
    /// Total size of the underlying data (for scrollbar calculation).
    pub total_size: u64,
}

/// Detect compression format of a file.
pub fn detect_compression(path: String) -> Result<CompressionFormat> {
    let data = std::fs::read(path)?;
    if data.len() < 4 {
        return Ok(CompressionFormat::None);
    }
    Ok(CompressionFormat::detect(&data))
}
