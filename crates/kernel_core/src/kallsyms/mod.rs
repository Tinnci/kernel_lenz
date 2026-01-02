//! # Kallsyms Symbol Recovery Module
//!
//! This module implements heuristic-based recovery of kernel symbols from the
//! `kallsyms` data structure embedded in stripped Linux kernel binaries.
//!
//! ## Architecture
//!
//! The module is split into sub-modules following the task flow:
//!
//! ```text
//! Raw Image
//!     │
//!     ▼
//! ┌─────────────────┐
//! │  Scanner        │  ← Locate signature patterns in binary
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Config         │  ← Infer format: 32/64-bit, relative offset
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Token Recovery │  ← Parse token_table and token_index
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Decoder        │  ← Stream decompress symbol names
//! └────────┬────────┘
//!          ▼
//!   Vec<KernelSymbol>
//! ```
//!
//! ## Supported Formats
//!
//! - 32-bit absolute addresses
//! - 64-bit absolute addresses  
//! - Relative offset format (modern kernels with `kallsyms_relative_base`)

mod arch;
mod decoder;
mod scanner;
mod traits;
mod types;

// Re-export public API
pub use decoder::SymbolIterator;
pub use traits::AddressParser;
pub use types::{
    KallsymsConfig, KallsymsError, KallsymsResult, KernelArch, KernelSymbol, SymbolType,
};

use crate::Result;
use rayon::prelude::*;

// ============================================================
// Main Entry Point: KallsymsFinder
// ============================================================

/// High-level interface for Kallsyms symbol recovery.
///
/// This struct orchestrates the full recovery pipeline:
/// scanning → configuration → token recovery → symbol decoding.
///
/// # Example
///
/// ```rust,ignore
/// use kernel_core::kallsyms::KallsymsFinder;
///
/// let kernel_data = std::fs::read("kernel.img")?;
/// let finder = KallsymsFinder::new(&kernel_data)?;
///
/// // Lazy iteration (recommended for CLI tools)
/// for symbol in finder.symbols() {
///     println!("{:#x} {} {}", symbol.address, symbol.sym_type, symbol.name);
/// }
///
/// // Or collect all at once (with parallel decoding)
/// let all_symbols = finder.collect_all_parallel();
/// ```
pub struct KallsymsFinder<'a> {
    /// Raw kernel binary data (zero-copy reference).
    data: &'a [u8],
    /// Detected configuration.
    config: KallsymsConfig,
    /// Parsed token table for name decompression.
    tokens: decoder::TokenTable<'a>,
    /// Parsed addresses table.
    addresses: Vec<u64>,
    /// Offset to names table in data.
    names_offset: usize,
    /// Number of symbols.
    num_symbols: usize,
}

impl<'a> KallsymsFinder<'a> {
    /// Create a new finder and perform initial scanning.
    ///
    /// This will:
    /// 1. Scan for kallsyms tables in the binary
    /// 2. Detect the address format (32/64-bit, relative)
    /// 3. Parse the token table
    ///
    /// # Errors
    ///
    /// Returns an error if kallsyms tables cannot be found or parsed.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        tracing::info!("Starting kallsyms analysis on {} byte kernel", data.len());

        // Step 1: Detect kernel architecture
        let arch = scanner::detect_architecture(data);
        tracing::debug!("Detected architecture: {:?}", arch);

        // Step 2: Scan for kallsyms tables
        let scan_result = scanner::scan_for_kallsyms(data, arch)?;
        tracing::debug!(
            "Found kallsyms tables: addresses@{:#x}, names@{:#x}, tokens@{:#x}, markers@{:#x}",
            scan_result.addresses_offset,
            scan_result.names_offset,
            scan_result.token_table_offset,
            scan_result.markers_offset
        );

        // Step 3: Infer configuration (32/64-bit, relative)
        let config = scanner::infer_config(&scan_result)?;
        tracing::info!("Kallsyms config: {:?}", config);

        // Step 4: Parse addresses table
        let addresses = Self::parse_addresses(data, &scan_result, &config)?;
        tracing::debug!("Parsed {} addresses", addresses.len());

        // Step 5: Parse token table
        let tokens = decoder::TokenTable::parse(
            data,
            scan_result.token_table_offset,
            scan_result.token_index_offset,
        )?;
        tracing::debug!("Parsed token table with {} entries", tokens.len());

        Ok(Self {
            data,
            config,
            tokens,
            addresses,
            names_offset: scan_result.names_offset,
            num_symbols: scan_result.num_symbols,
        })
    }

    /// Get the detected configuration.
    pub fn config(&self) -> &KallsymsConfig {
        &self.config
    }

    /// Get the number of symbols found.
    pub fn symbol_count(&self) -> usize {
        self.num_symbols
    }

    /// Get the kernel base address.
    pub fn kernel_base(&self) -> u64 {
        self.config.kernel_base
    }

    /// Get detected architecture.
    pub fn arch(&self) -> KernelArch {
        self.config.arch
    }

    /// Returns a lazy iterator over symbols.
    ///
    /// This is memory-efficient as it decodes symbols on-demand.
    /// Ideal for CLI tools that may stop early (e.g., searching for a specific symbol).
    pub fn symbols(&'a self) -> SymbolIterator<'a> {
        SymbolIterator::new(self.data, &self.addresses, self.names_offset, &self.tokens)
    }

    /// Collect all symbols using parallel decoding.
    ///
    /// Uses Rayon to decode symbol names in parallel.
    /// Faster for bulk operations but uses more memory.
    pub fn collect_all_parallel(&self) -> Vec<KernelSymbol> {
        (0..self.num_symbols)
            .into_par_iter()
            .filter_map(|i| self.decode_symbol_at(i).ok())
            .collect()
    }

    /// Collect all symbols into a result struct.
    pub fn into_result(self) -> KallsymsResult {
        let symbols = self.collect_all_parallel();
        KallsymsResult {
            symbol_count: symbols.len(),
            symbols,
            kernel_base: self.config.kernel_base,
            arch: self.config.arch,
        }
    }

    /// Find a symbol by address.
    pub fn find_by_address(&self, addr: u64) -> Option<KernelSymbol> {
        self.symbols().find(|s| s.address == addr)
    }

    /// Find symbols matching a name prefix.
    pub fn find_by_prefix(&self, prefix: &str) -> Vec<KernelSymbol> {
        self.symbols().filter(|s| s.name.starts_with(prefix)).collect()
    }

    // --------------------------------------------------------
    // Private helpers
    // --------------------------------------------------------

    fn parse_addresses(
        data: &[u8],
        scan: &scanner::ScanResult,
        config: &KallsymsConfig,
    ) -> Result<Vec<u64>> {
        use traits::{AddressParser, RelativeAddressParser};

        match config.format {
            types::AddressFormat::Absolute32 => {
                arch::Bin32Parser::parse_addresses(data, scan.addresses_offset, scan.num_symbols)
            },
            types::AddressFormat::Absolute64 => {
                arch::Bin64Parser::parse_addresses(data, scan.addresses_offset, scan.num_symbols)
            },
            types::AddressFormat::Relative32 => arch::RelativeParser::parse_addresses_with_base(
                data,
                scan.addresses_offset,
                scan.num_symbols,
                config.relative_base.unwrap_or(0),
            ),
        }
    }

    fn decode_symbol_at(&self, index: usize) -> Result<KernelSymbol> {
        if index >= self.num_symbols {
            return Err(KallsymsError::IndexOutOfBounds { index, max: self.num_symbols }.into());
        }

        let address = self.addresses.get(index).copied().unwrap_or(0);
        let (name, sym_type) =
            decoder::decode_symbol_name(self.data, self.names_offset, index, &self.tokens)?;

        // Calculate size (distance to next symbol)
        let size = if index + 1 < self.addresses.len() {
            self.addresses.get(index + 1).map(|next| next.saturating_sub(address))
        } else {
            None
        };

        Ok(KernelSymbol { address, name, sym_type, size })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_arch_pointer_size() {
        assert_eq!(KernelArch::Arm64.pointer_size(), 8);
        assert_eq!(KernelArch::X86_64.pointer_size(), 8);
        assert_eq!(KernelArch::Arm32.pointer_size(), 4);
    }

    #[test]
    fn test_symbol_type_classification() {
        assert!(SymbolType::Text.is_code());
        assert!(SymbolType::Data.is_data());
        assert!(!SymbolType::Text.is_data());
    }
}
