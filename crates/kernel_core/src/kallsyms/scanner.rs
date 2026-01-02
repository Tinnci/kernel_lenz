//! Kallsyms Scanner Module
//!
//! This module implements the heuristic search logic to locate kallsyms tables
//! within a raw kernel binary. It uses pattern matching to find monatonic
//! address sequences and known token table markers.

use super::types::{AddressFormat, KallsymsConfig, KallsymsError, KernelArch};
use crate::Result;
use scroll::{Pread, LE};

/// Results of the initial kallsyms scan.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Offset to kallsyms_addresses table.
    pub addresses_offset: usize,
    /// Offset to kallsyms_names table.
    pub names_offset: usize,
    /// Offset to kallsyms_token_table.
    pub token_table_offset: usize,
    /// Offset to kallsyms_token_index.
    pub token_index_offset: usize,
    /// Number of symbols found.
    pub num_symbols: usize,
}

/// Detect kernel architecture from binary patterns.
pub fn detect_architecture(data: &[u8]) -> KernelArch {
    // ARM64 magic "ARM\x64" at offset 0x38
    if data.len() > 0x40 && &data[0x38..0x3C] == b"ARM\x64" {
        return KernelArch::Arm64;
    }

    // x86_64 bzImage magic 0x55AA at 0x1FE
    if data.len() > 0x200 && data[0x1FE..0x200] == [0x55, 0xAA] {
        return KernelArch::X86_64;
    }

    // Default to a sane guess if possible, or Unknown
    KernelArch::Unknown
}

/// Perform a heuristic scan to find kallsyms table offsets.
pub fn scan_for_kallsyms(data: &[u8], arch: KernelArch) -> Result<ScanResult> {
    tracing::info!("Starting kallsyms scan for arch: {:?}", arch);

    // 1. Find kallsyms_names by searching for token table markers
    let token_table_offset = find_token_table(data)?;
    tracing::info!("Found token table at offset: 0x{:x}", token_table_offset);

    // 2. Find token_index (follows token_table)
    let token_index_offset = find_token_index(data, token_table_offset)?;

    // 3. Find kallsyms_names and kallsyms_markers
    tracing::info!("Searching for addresses table...");
    let (addresses_offset, num_symbols, ptr_size) = find_addresses_table(data, arch)?;
    tracing::info!("Found address table at 0x{:x} with {} symbols", addresses_offset, num_symbols);

    // 4. Locate names table
    let names_offset = find_names_offset(data, addresses_offset, num_symbols, ptr_size)?;
    tracing::info!("Located names table at offset 0x{:x}", names_offset);

    Ok(ScanResult {
        addresses_offset,
        names_offset,
        token_table_offset,
        token_index_offset,
        num_symbols,
    })
}

/// Infer the kallsyms configuration (address format, base, etc.)
pub fn infer_config(data: &[u8], scan: &ScanResult, arch: KernelArch) -> Result<KallsymsConfig> {
    let mut config = KallsymsConfig { arch, ..Default::default() };

    // Check for kallsyms_relative_base
    if let Some(rel_base) = find_relative_base(data, scan) {
        config.format = AddressFormat::Relative32;
        config.relative_base = Some(rel_base);
    } else {
        config.format =
            if arch.is_64bit() { AddressFormat::Absolute64 } else { AddressFormat::Absolute32 };
    }

    // Peek at the first address to set kernel_base
    let first_addr: u64 = match config.format {
        AddressFormat::Absolute64 => data.pread_with(scan.addresses_offset, LE).unwrap_or(0),
        AddressFormat::Absolute32 | AddressFormat::Relative32 => {
            let val: u32 = data.pread_with(scan.addresses_offset, LE).unwrap_or(0);
            if config.format == AddressFormat::Relative32 {
                config.relative_base.unwrap_or(0).wrapping_add(val as i32 as u64)
            } else {
                val as u64
            }
        },
    };

    config.kernel_base = first_addr;

    Ok(config)
}

fn find_token_table(data: &[u8]) -> Result<usize> {
    let patterns: &[&[u8]] = &[b"__cfi_", b"__kstrtab_", b"__initcall_"];

    for pat in patterns {
        if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
            let mut start = pos;
            while start > 0 && (data[start - 1] != 0 || data[start] != 0) {
                start -= 1;
            }
            return Ok(start);
        }
    }

    Err(KallsymsError::TokenTableNotFound.into())
}

fn find_token_index(data: &[u8], token_table_start: usize) -> Result<usize> {
    let mut pos = token_table_start;
    let mut count = 0;
    while count < 256 && pos < data.len() {
        if data[pos] == 0 {
            count += 1;
        }
        pos += 1;
    }
    pos = (pos + 3) & !3;

    if pos < data.len() {
        Ok(pos)
    } else {
        Err(KallsymsError::TokenIndexNotFound.into())
    }
}

fn find_addresses_table(data: &[u8], arch: KernelArch) -> Result<(usize, usize, usize)> {
    let ptr_size = arch.pointer_size();
    let step = ptr_size;
    let total = data.len() - ptr_size;
    let log_interval = total / 10;

    let mut count = 0;
    let mut last_addr = 0u64;
    let mut start_pos = 0;

    for i in (0..total).step_by(step) {
        if i % log_interval == 0 && i > 0 {
            tracing::debug!("Address scan progress: {}%", (i * 100) / total);
        }

        let addr: u64 = if ptr_size == 8 {
            data.pread_with(i, LE).unwrap_or(0)
        } else {
            data.pread_with::<u32>(i, LE).unwrap_or(0) as u64
        };

        let is_kernel =
            if ptr_size == 8 { addr >= 0xFFFF_0000_0000_0000 } else { addr >= 0x8000_0000 };

        if is_kernel && addr >= last_addr {
            if count == 0 {
                start_pos = i;
            }
            count += 1;
            last_addr = addr;

            if count > 200 {
                return Ok((start_pos, estimate_num_symbols(data, start_pos, ptr_size), ptr_size));
            }
        } else {
            count = 0;
            last_addr = 0;
        }
    }

    Err(KallsymsError::AddressesNotFound.into())
}

fn estimate_num_symbols(data: &[u8], start: usize, ptr_size: usize) -> usize {
    let mut count = 0;
    let mut last_addr = 0u64;
    let mut pos = start;

    while pos + ptr_size <= data.len() {
        let addr: u64 = if ptr_size == 8 {
            data.pread_with(pos, LE).unwrap_or(0)
        } else {
            data.pread_with::<u32>(pos, LE).unwrap_or(0) as u64
        };

        if addr < last_addr {
            break;
        }

        last_addr = addr;
        count += 1;
        pos += ptr_size;
    }
    count
}

fn find_names_offset(
    data: &[u8],
    addr_offset: usize,
    num_syms: usize,
    ptr_size: usize,
) -> Result<usize> {
    let mut pos = addr_offset + (num_syms * ptr_size);
    pos = (pos + ptr_size - 1) & !(ptr_size - 1);

    let detected_count: u64 = if ptr_size == 8 {
        data.pread_with(pos, LE).unwrap_or(0)
    } else {
        data.pread_with::<u32>(pos, LE).unwrap_or(0) as u64
    };

    if detected_count == num_syms as u64 {
        Ok(pos + ptr_size)
    } else {
        Ok(pos + ptr_size)
    }
}

fn find_relative_base(_data: &[u8], _scan: &ScanResult) -> Option<u64> {
    None
}
