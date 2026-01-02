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
    if data.len() > 0x200 && &data[0x1FE..0x200] == &[0x55, 0xAA] {
        return KernelArch::X86_64;
    }

    // Default to a sane guess if possible, or Unknown
    KernelArch::Unknown
}

/// Perform a heuristic scan to find kallsyms table offsets.
pub fn scan_for_kallsyms(data: &[u8], arch: KernelArch) -> Result<ScanResult> {
    // 1. Find kallsyms_names by searching for token table markers
    // The token table usually follows the names and markers tables.
    let token_table_offset = find_token_table(data)?;

    // 2. Find token_index (follows token_table)
    let token_index_offset = find_token_index(data, token_table_offset)?;

    // 3. Find kallsyms_names and kallsyms_markers
    // This is often harder and requires walking backwards or searching for density.
    // For now, let's use a simplified approach of searching for the 'addresses' table first.
    let (addresses_offset, num_symbols, ptr_size) = find_addresses_table(data, arch)?;

    // 4. Locate names table (usually follows markers which follow addresses)
    // In many kernels: [addresses] -> [num_syms] -> [names]
    let names_offset = find_names_offset(data, addresses_offset, num_symbols, ptr_size)?;

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
    // This is usually a pointer-sized value near the tables.
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
        }
    };

    config.kernel_base = first_addr;

    Ok(config)
}

// ----------------------------------------------------------------------------
// Internal Search Heuristics
// ----------------------------------------------------------------------------

fn find_token_table(data: &[u8]) -> Result<usize> {
    // Search for common prefixes in the token table (e.g., "__", "init", "subsys")
    // The token table starts after a series of null-terminated strings.
    // Heuristic: search for a high density of printable ASCII followed by nulls.

    // Pattern: "__cfi_" is a very common token in modern Android kernels
    let patterns: &[&[u8]] = &[b"__cfi_", b"__kstrtab_", b"__initcall_"];

    for pat in patterns {
        if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
            // Walk backwards to the start of the token table
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
    // token_index follows token_table after 256 null-terminated strings.
    let mut pos = token_table_start;
    let mut count = 0;
    while count < 256 && pos < data.len() {
        if data[pos] == 0 {
            count += 1;
        }
        pos += 1;
    }

    // Align to 2 or 4 bytes
    pos = (pos + 3) & !3;

    if pos < data.len() {
        Ok(pos)
    } else {
        Err(KallsymsError::TokenIndexNotFound.into())
    }
}

fn find_addresses_table(data: &[u8], arch: KernelArch) -> Result<(usize, usize, usize)> {
    // Look for a sequence of addresses in kernel space
    // 64-bit: 0xFFFFFF80... or 0xFFFFFFFF8...
    // 32-bit: 0xC0...

    let ptr_size = arch.pointer_size();
    let step = ptr_size;

    // Scanning the whole image for a sequence of at least 100 monotonic pointers
    let mut count = 0;
    let mut last_addr = 0u64;
    let mut start_pos = 0;

    for i in (0..(data.len() - ptr_size)).step_by(step) {
        let addr: u64 = if ptr_size == 8 {
            data.pread_with(i, LE).unwrap_or(0)
        } else {
            data.pread_with::<u32>(i, LE).unwrap_or(0) as u64
        };

        // Heuristic for kernel space address
        let is_kernel =
            if ptr_size == 8 { addr >= 0xFFFF_0000_0000_0000 } else { addr >= 0x8000_0000 };

        if is_kernel && addr >= last_addr {
            if count == 0 {
                start_pos = i;
            }
            count += 1;
            last_addr = addr;

            if count > 200 {
                // Found a candidate. Now find the exact start by walking back.
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
    // Walk forward until the sequence of addresses breaks
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
    // Immediately after addresses, there is usually kallsyms_num_syms (4 or 8 bytes)
    // then kallsyms_names.
    let mut pos = addr_offset + (num_syms * ptr_size);

    // Align?
    pos = (pos + ptr_size - 1) & !(ptr_size - 1);

    // Often there's a 4 or 8 byte 'count' here that matches num_syms
    let detected_count: u64 = if ptr_size == 8 {
        data.pread_with(pos, LE).unwrap_or(0)
    } else {
        data.pread_with::<u32>(pos, LE).unwrap_or(0) as u64
    };

    if detected_count == num_syms as u64 {
        Ok(pos + ptr_size)
    } else {
        // Fallback: just skipping potential markers/counts
        Ok(pos + ptr_size)
    }
}

fn find_relative_base(_data: &[u8], _scan: &ScanResult) -> Option<u64> {
    // Relative base is often just before or after the addresses table.
    // For now, returning None as relative support requires more careful signature matching.
    None
}
