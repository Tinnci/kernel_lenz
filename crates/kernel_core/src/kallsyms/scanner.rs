//! Kallsyms Scanner Module (V2 - Robust Edition)
//!
//! Implementation based on the proven discovery algorithms from vmlinux-to-elf.
//! Orchestrates the anchor-based discovery of token tables, markers, names and addresses.

use super::types::{AddressFormat, KallsymsConfig, KallsymsError, KernelArch};
use crate::Result;
use scroll::{Pread, BE, LE};

/// Results of the initial kallsyms scan.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Offset to kallsyms_addresses table (or offsets table).
    pub addresses_offset: usize,
    /// Offset to kallsyms_names table.
    pub names_offset: usize,
    /// Offset to kallsyms_token_table.
    pub token_table_offset: usize,
    /// Offset to kallsyms_token_index.
    pub token_index_offset: usize,
    /// Start of kallsyms_markers table.
    pub markers_offset: usize,
    /// Number of symbols found.
    pub num_symbols: usize,
    /// Detected or confirmed architecture.
    pub arch: KernelArch,
    /// Detected endianness (true for big-endian).
    pub big_endian: bool,
    /// Detected relative base (if any).
    pub relative_base_address: Option<u64>,
}

/// Detect kernel architecture using function prologue patterns.
pub fn detect_architecture(data: &[u8]) -> KernelArch {
    if data.len() > 0x40 && &data[0x38..0x3C] == b"ARM\x64" {
        return KernelArch::Arm64;
    }
    if data.len() > 0x200 && data[0x1FE..0x200] == [0x55, 0xAA] {
        return KernelArch::X86_64;
    }

    let scan_limit = std::cmp::min(data.len(), 512 * 1024);
    let window = &data[..scan_limit];

    // Check for AArch64 'ret' instruction (0xd65f03c0)
    let mut arm64_ret_count = 0;
    for chunk in window.chunks_exact(4) {
        if chunk == b"\xc0\x03\x5f\xd6" {
            arm64_ret_count += 1;
        }
    }
    if arm64_ret_count > 10 {
        return KernelArch::Arm64;
    }

    // x86_64 prologue: push rbp; mov rbp, rsp
    let mut x86_64_prologue_count = 0;
    for i in 0..window.len().saturating_sub(4) {
        if &window[i..i + 4] == b"\x55\x48\x89\xE5" {
            x86_64_prologue_count += 1;
        }
    }
    if x86_64_prologue_count > 10 {
        return KernelArch::X86_64;
    }

    KernelArch::Unknown
}

/// Perform a robust scan to find kallsyms table offsets.
pub fn scan_for_kallsyms(data: &[u8], hint_arch: KernelArch) -> Result<ScanResult> {
    tracing::info!("Starting robust kallsyms scanning (Anchor flow)...");

    // 1. Find Token Table (The Anchor)
    let token_table_offset = find_token_table(data)?;
    tracing::info!("[+] Token table anchor: 0x{:x}", token_table_offset);

    // 2. Find Token Index & Endianness
    let (token_index_offset, big_endian) =
        find_token_index_and_endianness(data, token_table_offset)?;
    tracing::info!("[+] Token index: 0x{:x} (BE: {})", token_index_offset, big_endian);

    // 3. Find Markers (Backwards from Token Table)
    let (markers_offset, element_size) = find_markers(data, token_table_offset, big_endian)?;
    tracing::info!("[+] Markers found at 0x{:x} (element size: {})", markers_offset, element_size);

    // 4. Find Names offset (Backwards from Markers)
    let names_offset = find_names_offset(data, markers_offset, element_size, big_endian)?;
    tracing::info!("[+] Names start calculated at 0x{:x}", names_offset);

    // 5. Find Num Symbols
    let (num_syms_offset, num_symbols) = find_num_symbols(data, names_offset, big_endian)?;
    tracing::info!("[+] Found {} symbols (marker at 0x{:x})", num_symbols, num_syms_offset);

    // 6. Find Addresses or Offsets (The most variant part)
    let (addresses_offset, relative_base, final_arch) =
        find_addresses_table(data, num_syms_offset, num_symbols, hint_arch, big_endian)?;

    Ok(ScanResult {
        addresses_offset,
        names_offset,
        token_table_offset,
        token_index_offset,
        markers_offset,
        num_symbols,
        arch: final_arch,
        big_endian,
        relative_base_address: relative_base,
    })
}

pub fn infer_config(scan: &ScanResult) -> Result<KallsymsConfig> {
    let mut config =
        KallsymsConfig { arch: scan.arch, big_endian: scan.big_endian, ..Default::default() };

    if let Some(rel_base) = scan.relative_base_address {
        config.format = AddressFormat::Relative32;
        config.relative_base = Some(rel_base);
        config.kernel_base = rel_base;
    } else {
        config.format = if scan.arch.is_64bit() {
            AddressFormat::Absolute64
        } else {
            AddressFormat::Absolute32
        };
    }

    Ok(config)
}

// --- Implementation Logic ---

fn find_token_table(data: &[u8]) -> Result<usize> {
    // Search for "0\01\0...9\0"
    let mut seq = Vec::with_capacity(20);
    for i in b'0'..=b'9' {
        seq.push(i);
        seq.push(0);
    }

    let mut pos = 0;
    while let Some(found_pos) = data[pos..].windows(seq.len()).position(|w| w == seq) {
        let abs_pos = pos + found_pos;

        // Backtrack to token 0
        let mut table_start = abs_pos;
        let token_count = b'0' as usize;
        let mut failed = false;

        for _ in 0..token_count {
            // Each token is null-terminated string.
            // Search back for previous null.
            if table_start == 0 {
                failed = true;
                break;
            }
            table_start -= 1;
            let mut len = 0;
            while table_start > 0 && data[table_start - 1] != 0 {
                table_start -= 1;
                len += 1;
                if len > 64 {
                    failed = true;
                    break;
                }
            }
            if failed {
                break;
            }
        }

        if !failed {
            // Align to 4
            table_start = (table_start + 3) & !3;
            // Verify forward a bit?
            // If it looks okay, return.
            return Ok(table_start);
        }
        pos = abs_pos + 1;
    }

    Err(KallsymsError::TokenTableNotFound.into())
}

fn find_token_index_and_endianness(
    data: &[u8],
    token_table_offset: usize,
) -> Result<(usize, bool)> {
    // 1. Calculate token offsets
    let mut offsets = Vec::with_capacity(256);
    let mut curr = token_table_offset;
    for _ in 0..256 {
        offsets.push((curr - token_table_offset) as u16);
        while curr < data.len() && data[curr] != 0 {
            curr += 1;
        }
        curr += 1;
    }

    // 2. Build LE and BE patterns
    let mut le_pat = Vec::with_capacity(512);
    let mut be_pat = Vec::with_capacity(512);
    for &off in &offsets {
        le_pat.extend_from_slice(&off.to_le_bytes());
        be_pat.extend_from_slice(&off.to_be_bytes());
    }

    // 3. Search restricted window after token_table
    let window_start = curr;
    let window_end = std::cmp::min(curr + 512 + 1024, data.len());
    let window = &data[window_start..window_end];

    let le_pos = window.windows(le_pat.len()).position(|w| w == le_pat);
    let be_pos = window.windows(be_pat.len()).position(|w| w == be_pat);

    match (le_pos, be_pos) {
        (Some(p), _) => Ok((window_start + p, false)),
        (None, Some(p)) => Ok((window_start + p, true)),
        _ => Err(KallsymsError::TokenIndexNotFound.into()),
    }
}

fn find_markers(
    data: &[u8],
    token_table_offset: usize,
    big_endian: bool,
) -> Result<(usize, usize)> {
    // Markers contain offsets in names for every 256 symbols.
    // markers[0] == 0, markers[i] > markers[i-1].
    // Increments are usually between 0x200 and 0x4000 (heuristic).

    for element_size in [8, 4, 2] {
        let mut pos = token_table_offset;
        let null_pattern = vec![0u8; element_size];

        // Search backwards for the first element (which is 0)
        while pos >= element_size {
            pos = match data[..pos].windows(element_size).rposition(|w| w == null_pattern) {
                Some(p) => p,
                None => break,
            };

            // Align
            if !pos.is_multiple_of(element_size) {
                // Not a great candidate if not aligned
                if pos > 0 {
                    pos -= 1;
                    continue;
                } else {
                    break;
                }
            }

            // Verify a few elements
            let mut valid = true;
            let mut last_val = 0u64;
            for i in 1..4 {
                let off = pos + (i * element_size);
                if off + element_size > data.len() {
                    valid = false;
                    break;
                }

                let val: u64 = if big_endian {
                    match element_size {
                        8 => data.pread_with::<u64>(off, BE).unwrap_or(0),
                        4 => data.pread_with::<u32>(off, BE).unwrap_or(0) as u64,
                        _ => data.pread_with::<u16>(off, BE).unwrap_or(0) as u64,
                    }
                } else {
                    match element_size {
                        8 => data.pread_with::<u64>(off, LE).unwrap_or(0),
                        4 => data.pread_with::<u32>(off, LE).unwrap_or(0) as u64,
                        _ => data.pread_with::<u16>(off, LE).unwrap_or(0) as u64,
                    }
                };

                if val <= last_val || val < last_val + 0x200 || val > last_val + 0x8000 {
                    valid = false;
                    break;
                }
                last_val = val;
            }

            if valid {
                return Ok((pos, element_size));
            }

            if pos > 0 {
                pos -= 1;
            } else {
                break;
            }
        }
    }

    Err(KallsymsError::ParseError("Could not find kallsyms_markers".to_string()).into())
}

fn find_names_offset(
    data: &[u8],
    markers_offset: usize,
    element_size: usize,
    big_endian: bool,
) -> Result<usize> {
    // Read markers to find the last entry
    let mut last_entry = 0u64;
    let mut count = 0;
    while count < 3000 {
        let off = markers_offset + (count * element_size);
        if off + element_size > data.len() {
            break;
        }

        let val: u64 = if big_endian {
            match element_size {
                8 => data.pread_with::<u64>(off, BE).unwrap_or(0),
                4 => data.pread_with::<u32>(off, BE).unwrap_or(0) as u64,
                _ => data.pread_with::<u16>(off, BE).unwrap_or(0) as u64,
            }
        } else {
            match element_size {
                8 => data.pread_with::<u64>(off, LE).unwrap_or(0),
                4 => data.pread_with::<u32>(off, LE).unwrap_or(0) as u64,
                _ => data.pread_with::<u16>(off, LE).unwrap_or(0) as u64,
            }
        };

        if count > 0 && val <= last_entry {
            break;
        }
        if count > 0 && val > last_entry + 0x8000 {
            break;
        }

        last_entry = val;
        count += 1;
    }

    if count == 0 {
        return Err(KallsymsError::NamesNotFound.into());
    }

    // names_offset = markers_offset - last_entry (approx, with alignment)
    let mut names_start = (markers_offset as i64 - last_entry as i64) as usize;
    names_start &= !(element_size - 1);

    Ok(names_start)
}

fn find_num_symbols(data: &[u8], names_offset: usize, big_endian: bool) -> Result<(usize, usize)> {
    // num_symbols is typically a long/long long before names_offset
    for size in [8, 4] {
        let pos = names_offset.saturating_sub(size);
        let val: u64 = if big_endian {
            if size == 8 {
                data.pread_with::<u64>(pos, BE).unwrap_or(0)
            } else {
                data.pread_with::<u32>(pos, BE).unwrap_or(0) as u64
            }
        } else if size == 8 {
            data.pread_with::<u64>(pos, LE).unwrap_or(0)
        } else {
            data.pread_with::<u32>(pos, LE).unwrap_or(0) as u64
        };

        // Heuristic: symbol count is usually 10k - 200k
        if val > 1000 && val < 500000 {
            // Check if names[0] looks like a length byte
            let first_len: u8 = data.pread_with(names_offset, LE).unwrap_or(0);
            if first_len > 0 && first_len < 128 {
                return Ok((pos, val as usize));
            }
        }
    }

    Err(KallsymsError::ParseError("Could not find num_symbols anchor".to_string()).into())
}

fn find_addresses_table(
    data: &[u8],
    num_syms_offset: usize,
    num_symbols: usize,
    hint_arch: KernelArch,
    big_endian: bool,
) -> Result<(usize, Option<u64>, KernelArch)> {
    // 1. Check for Absolute Addresses
    // Usually immediately before num_syms_offset
    let ptr_size = hint_arch.pointer_size();
    let addr_table_size = num_symbols * ptr_size;

    if num_syms_offset >= addr_table_size {
        let table_start = (num_syms_offset - addr_table_size) & !(ptr_size - 1);
        let a1: u64 = if big_endian {
            if ptr_size == 8 {
                data.pread_with::<u64>(table_start, BE).unwrap_or(0)
            } else {
                data.pread_with::<u32>(table_start, BE).unwrap_or(0) as u64
            }
        } else if ptr_size == 8 {
            data.pread_with::<u64>(table_start, LE).unwrap_or(0)
        } else {
            data.pread_with::<u32>(table_start, LE).unwrap_or(0) as u64
        };

        // Heuristic: kernel address
        if (ptr_size == 8 && a1 >= 0xFFFF_0000_0000_0000) || (ptr_size == 4 && a1 >= 0x8000_0000) {
            return Ok((table_start, None, hint_arch));
        }
    }

    // 2. Check for Relative Offsets (modern kernels)
    // Structure: [relative_base (8)] [offsets (4 * num_symbols)]
    let offsets_size = num_symbols * 4;
    if num_syms_offset >= (offsets_size + 8) {
        let offsets_end = num_syms_offset;
        let mut pos = offsets_end.saturating_sub(offsets_size);
        pos &= !3;

        // Scan backwards for the 64-bit base address
        let base_pos = pos.saturating_sub(8);
        let base_val: u64 = if big_endian {
            data.pread_with::<u64>(base_pos, BE).unwrap_or(0)
        } else {
            data.pread_with::<u64>(base_pos, LE).unwrap_or(0)
        };

        if base_val >= 0xFFFF_0000_0000_0000 || (base_val >= 0x8000_0000 && !hint_arch.is_64bit()) {
            return Ok((pos, Some(base_val), hint_arch));
        }
    }

    Err(KallsymsError::AddressesNotFound.into())
}
