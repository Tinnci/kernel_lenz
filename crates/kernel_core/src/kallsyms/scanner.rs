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

/// Options for kallsyms scanning.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Force treating offsets as absolute addresses, ignoring relative base detection.
    /// Useful when automatic detection incorrectly identifies a kernel as using relative addressing.
    /// (Equivalent to vmlinux-to-elf's `--override-relative` flag)
    pub override_relative: bool,
}

/// Detect kernel architecture using function prologue patterns.
pub fn detect_architecture(data: &[u8]) -> KernelArch {
    if data.len() > 0x40 && &data[0x38..0x3C] == b"ARM\x64" {
        return KernelArch::Arm64;
    }
    if data.len() > 0x200 && data[0x1FE..0x200] == [0x55, 0xAA] {
        return KernelArch::X86_64;
    }

    let scan_limit = std::cmp::min(data.len(), 1024 * 1024);
    let window = &data[..scan_limit];

    // Check for AArch64 'ret' instruction (0xd65f03c0)
    let mut arm64_ret_count = 0;
    for chunk in window.chunks_exact(4) {
        if chunk == b"\xc0\x03\x5f\xd6" || chunk == b"\xd6\x5f\x03\xc0" {
            arm64_ret_count += 1;
        }
    }
    if arm64_ret_count > 20 {
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

    // ARM32: push {..., lr}; add r11, sp, #...
    let mut arm32_count = 0;
    for i in 0..window.len().saturating_sub(4) {
        let chunk = &window[i..i+4];
        // stmfd sp!, {..., lr} (0xe92d4...)
        if chunk[3] == 0xe9 && chunk[2] == 0x2d && (chunk[1] & 0x40) != 0 {
            arm32_count += 1;
        }
    }
    if arm32_count > 20 {
        return KernelArch::Arm32;
    }

    KernelArch::Unknown
}

/// Perform a robust scan to find kallsyms table offsets.
/// 
/// This is a convenience wrapper around [`scan_for_kallsyms_with_options`] with default options.
#[allow(dead_code)]
pub fn scan_for_kallsyms(data: &[u8], hint_arch: KernelArch) -> Result<ScanResult> {
    scan_for_kallsyms_with_options(data, hint_arch, &ScanOptions::default())
}

/// Perform a robust scan with configurable options.
/// 
/// Use this variant when you need to override automatic detection behavior,
/// e.g., forcing absolute address mode with `override_relative: true`.
pub fn scan_for_kallsyms_with_options(
    data: &[u8],
    hint_arch: KernelArch,
    options: &ScanOptions,
) -> Result<ScanResult> {
    tracing::info!("Starting robust kallsyms scanning (Anchor flow)...");
    if options.override_relative {
        tracing::info!("[!] Override mode: forcing absolute addresses");
    }

    // 1 & 2. Find Token Table and Index (The Anchors)
    let (token_table_offset, token_index_offset, big_endian) = find_token_anchors(data)?;
    tracing::info!("[+] Token table anchor: 0x{:x}", token_table_offset);
    tracing::info!("[+] Token index: 0x{:x} (BE: {})", token_index_offset, big_endian);

    // 3. Find Markers (Backwards from Token Table)
    let (markers_offset, element_size, marker_count, last_marker_val) = find_markers(data, token_table_offset, big_endian)?;
    tracing::info!("[+] Markers found at 0x{:x} (element size: {}, count: {})", markers_offset, element_size, marker_count);

    // 4 & 5. Find Num Symbols and Names Offset (Robust combined discovery)
    let (num_syms_offset, num_symbols, names_offset) = find_num_symbols_and_names(data, markers_offset, marker_count, last_marker_val, big_endian)?;
    tracing::info!("[+] Found {} symbols (anchor at 0x{:x}, names at 0x{:x})", num_symbols, num_syms_offset, names_offset);

    // 6. Find Addresses or Offsets (The most variant part)
    let (addresses_offset, relative_base, final_arch) =
        find_addresses_table(data, num_syms_offset, num_symbols, hint_arch, big_endian)?;

    // Apply override if requested
    let final_relative_base = if options.override_relative {
        tracing::info!("[!] Ignoring relative_base due to --override-relative");
        None
    } else {
        relative_base
    };

    Ok(ScanResult {
        addresses_offset,
        names_offset,
        token_table_offset,
        token_index_offset,
        markers_offset,
        num_symbols,
        arch: final_arch,
        big_endian,
        relative_base_address: final_relative_base,
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

/// Patterns to avoid when searching for token table (vmlinux-to-elf inspired)
/// These patterns after "0123456789" indicate false positives
const TOKEN_TABLE_AVOID_PATTERNS: &[&[u8]] = &[
    b":\0",      // ':' comes after '9' in ASCII but shouldn't be in token table
    b"\0\0",     // Double null might indicate data boundary
    b"\0\x01",   // Control characters
    b"\0\x02",
    b"ASCII\0",  // String literal marker
];

fn find_token_anchors(data: &[u8]) -> Result<(usize, usize, bool)> {
    // Search for "0\01\0...9\0"
    let mut seq = Vec::with_capacity(20);
    for i in b'0'..=b'9' {
        seq.push(i);
        seq.push(0);
    }

    let mut candidates: Vec<usize> = Vec::new();
    let mut candidates_with_ascii_follow: Vec<usize> = Vec::new();

    let mut pos = 0;
    while let Some(found_pos) = data[pos..].windows(seq.len()).position(|w| w == seq) {
        let abs_pos = pos + found_pos;
        
        // Check for avoidance patterns after the sequence
        let after_seq = abs_pos + seq.len();
        let mut should_avoid = false;
        
        for pattern in TOKEN_TABLE_AVOID_PATTERNS {
            if after_seq + pattern.len() <= data.len() 
               && &data[after_seq..after_seq + pattern.len()] == *pattern {
                should_avoid = true;
                tracing::debug!("Token table candidate at 0x{:x} avoided due to pattern", abs_pos);
                break;
            }
        }
        
        if !should_avoid {
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
                candidates.push(table_start);
                
                // Check if followed by ASCII character (higher confidence)
                if after_seq < data.len() && data[after_seq].is_ascii_alphanumeric() {
                    candidates_with_ascii_follow.push(table_start);
                }
            }
        }
        pos = abs_pos + 1;
    }
    
    // Prefer candidates followed by ASCII, fall back to all candidates
    let final_candidates = if candidates_with_ascii_follow.len() == 1 {
        candidates_with_ascii_follow
    } else if !candidates.is_empty() {
        candidates
    } else {
        return Err(KallsymsError::TokenTableNotFound.into());
    };
    
    // Try each candidate until one validates
    for table_start in final_candidates {
        if let Ok((index_offset, be)) = find_token_index_and_endianness(data, table_start) {
            println!("[Rust] Token table validated at 0x{:x}", table_start);
            return Ok((table_start, index_offset, be));
        }
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
        let off = (curr - token_table_offset) as u64;
        if off > 0xFFFF {
            // If token table is too large, it might use u32 index, but that's rare.
            return Err(KallsymsError::TokenIndexNotFound.into());
        }
        offsets.push(off as u16);
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
    // 2026-01-02: Increased window size to 16KB to handle kernels with padding/data between tables.
    let window_start = curr;
    let window_end = std::cmp::min(curr + 16384, data.len());
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
) -> Result<(usize, usize, usize, u64)> {
    // Markers contain offsets in names for every 256 symbols.
    // markers[0] == 0, markers[i] > markers[i-1].
    // vmlinux-to-elf uses: increments between 0x200 and 0x4000

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
                if pos > 0 { pos -= 1; continue; } else { break; }
            }

            // Verify a few elements and count them
            let mut valid = true;
            let mut last_val = 0u64;
            let mut count = 1;
            
            // Verify at least 2 markers (0 and 1) to be a candidate
            let verify_count = std::cmp::min(4, (data.len() - pos) / element_size);
            if verify_count < 2 {
                if pos > 0 { pos -= 1; continue; } else { break; }
            }

            for i in 1..verify_count {
                let off = pos + (i * element_size);
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

                // Tighter increment check (vmlinux-to-elf style): 0x200 to 0x4000
                if val <= last_val || val < last_val + 0x200 || val > last_val + 0x4000 {
                    valid = false;
                    break;
                }
                last_val = val;
                count += 1;
            }

            if valid {
                // Count all markers until they stop looking like markers
                let mut current_pos = pos + (count * element_size);
                loop {
                    if current_pos + element_size > data.len() { break; }
                    let val: u64 = if big_endian {
                        match element_size {
                            8 => data.pread_with::<u64>(current_pos, BE).unwrap_or(0),
                            4 => data.pread_with::<u32>(current_pos, BE).unwrap_or(0) as u64,
                            _ => data.pread_with::<u16>(current_pos, BE).unwrap_or(0) as u64,
                        }
                    } else {
                        match element_size {
                            8 => data.pread_with::<u64>(current_pos, LE).unwrap_or(0),
                            4 => data.pread_with::<u32>(current_pos, LE).unwrap_or(0) as u64,
                            _ => data.pread_with::<u16>(current_pos, LE).unwrap_or(0) as u64,
                        }
                    };
                    
                    if val <= last_val || val > last_val + 0x4000 { break; }
                    last_val = val;
                    count += 1;
                    current_pos += element_size;
                }
                return Ok((pos, element_size, count, last_val));
            }

            if pos > 0 { pos -= 1; } else { break; }
        }
    }

    Err(KallsymsError::ParseError("Could not find kallsyms_markers".to_string()).into())
}

/// Validate names table structure using dynamic programming approach (vmlinux-to-elf inspired).
/// 
/// The names table format is: [length: u8, type: u8, token_indices: u8*]
/// This function iterates through entries to count how many are valid.
fn validate_names_dp(data: &[u8], names_offset: usize, claimed_count: usize) -> (usize, bool) {
    let mut pos = names_offset;
    let mut valid_count = 0;
    let max_check = claimed_count.min(2000); // Don't check more than 2000 symbols
    
    for _ in 0..max_check {
        if pos + 1 >= data.len() {
            break;
        }
        
        // Read length byte
        let len = data[pos] as usize;
        
        // Validate length: must be >= 1 (at least type byte) and < 128 (reasonable)
        if len == 0 || len > 127 {
            break;
        }
        
        // Check if we have enough data for this entry
        if pos + 1 + len > data.len() {
            break;
        }
        
        // Note: For compressed kallsyms, data[pos + 1] is a token_id, 
        // not necessarily an ASCII character. We shouldn't check it here
        // unless we have the token table. 
        // 
        // Instead, we just check if the sequence of lengths is consistent.

        valid_count += 1;
        pos += 1 + len; // Move to next entry
    }
    
    // Success if we reached at least 50 entries or 50% of claimed (whichever is smaller)
    let threshold = if max_check < 50 { max_check / 2 } else { 50 };
    let success = valid_count >= threshold;
    
    if !success && valid_count > 0 {
        println!("[Rust] validate_names_dp failed: only {} of {} entries look valid at 0x{:x}", 
                 valid_count, max_check, names_offset);
    }
    
    (valid_count, success)
}

fn find_num_symbols_and_names(
    data: &[u8],
    markers_offset: usize,
    marker_count: usize,
    last_marker_val: u64,
    big_endian: bool,
) -> Result<(usize, usize, usize)> {
    // num_symbols should be in range [(marker_count-1)*256 + 1, marker_count*256]
    let min_syms = (marker_count.saturating_sub(1)) * 256;
    let max_syms = marker_count * 256;
    
    println!("[Rust] Searching for num_symbols in range [{}, {}] around markers@0x{:x}", min_syms, max_syms, markers_offset);

    // =========================================================================================
    // Strategy 3: Layout-Aware / Marker-Guided Discovery (Most Robust)
    // =========================================================================================
    // We know where markers are. We know the last marker value (which is roughly the size of names table).
    // So: names_offset ≈ markers_offset - last_marker_val
    // And num_symbols is usually immediately preceding names_offset (or separated by addresses).
    
    // Let's deduce likely names_offset candidates first.
    let estimated_names_size = last_marker_val as usize;
    let base_names_offset = markers_offset.saturating_sub(estimated_names_size);
    
    // We'll search for num_symbols in a window BEFORE the estimated names offset.
    // The window covers potential padding and the possibility of addresses table being in between.
    println!("[Rust] Strategy 3: derived base_names_offset=0x{:x} from last_marker={}", base_names_offset, last_marker_val);

    // Candidates for num_symbols position:
    // 1. Immediately before names ( [num_symbols] [names] )
    // 2. Before addresses ( [num_symbols] [addresses] [names] )
    // 3. Just brute force scan a reasonable range around the base_names_offset.

    let scan_start = base_names_offset.saturating_sub(16 * 1024 * 1024); // Look back 16MB (generous)
    let scan_end = base_names_offset.saturating_add(4096);   // Look forward a bit (padding)
    let mut best_candidate: Option<(usize, usize, usize, usize)> = None; // (pos, num, names_off, score)

    let mut pos = scan_end; 
    while pos >= scan_start {
        // Alignment optimization: num_symbols is typically 4-byte or 8-byte aligned
        if pos % 4 != 0 {
            pos -= 1;
            continue;
        }

        for size in [4, 8] {
            if pos + size > data.len() { continue; }
            
            let val = if big_endian {
                if size == 8 { data.pread_with::<u64>(pos, BE).unwrap_or(0) }
                else { data.pread_with::<u32>(pos, BE).unwrap_or(0) as u64 }
            } else {
                if size == 8 { data.pread_with::<u64>(pos, LE).unwrap_or(0) }
                else { data.pread_with::<u32>(pos, LE).unwrap_or(0) as u64 }
            };

            if val >= min_syms as u64 && val <= max_syms as u64 {
                let num_syms = val as usize;
                
                // Hypothesis A: names start immediately after num_symbols
                let names_off_a = pos + size;
                
                // Hypothesis B: addresses are between num_symbols and names
                // This requires knowing pointer size. Let's try both 4 and 8.
                let names_off_b4 = pos + size + num_syms * 4;
                let names_off_b8 = pos + size + num_syms * 8;
                
                // Hypothesis C: names are at base_names_offset (derived from markers)
                // We assume there might be some padding/alignment between num_symbols and names.
                // Or padding between addresses and names.
                
                let candidates = [names_off_a, names_off_b4, names_off_b8];
                
                for &names_off in &candidates {
                    // Quick bounds check
                    if names_off >= data.len() || names_off < 8 { continue; }
                    
                    // Does this names_offset make sense with markers?
                    // The distance (markers_offset - names_offset) should be close to last_marker_val.
                    // Allow for some padding (e.g., 0-4096 bytes).
                    let check_dist = markers_offset.saturating_sub(names_off);
                    // last_marker_val IS the offset of the start of the last block relative to names_offset.
                    // So real size of names table is last_marker_val + last_block_len.
                    // Therefore markers_offset - names_offset should be >= last_marker_val.
                    
                    if check_dist < estimated_names_size { 
                        // names_offset is too close to markers, impossible given the last marker value.
                        continue; 
                    }
                    
                    // Check if the gap is reasonable (e.g., < 64KB padding/alignment + last block)
                    if check_dist > estimated_names_size + 65536 {
                        continue; // Too far away
                    }
                    
                    // DP Validation
                    // Only run expensive DP if we pass the distance check
                    let (valid_count, is_valid) = validate_names_dp(data, names_off, num_syms);
                    
                    if is_valid {
                        // Found a strong candidate!
                        // Rank by valid count
                        if best_candidate.is_none() || valid_count > best_candidate.unwrap().3 {
                            println!("[Rust] Strategy 3 Candidate: num={} @ 0x{:x}, names @ 0x{:x}, score={}", 
                                     num_syms, pos, names_off, valid_count);
                            best_candidate = Some((pos, num_syms, names_off, valid_count));
                        }
                    }
                }
            }
        }
        
        if pos < 4 { break; }
        pos -= 4; // Skip 4 bytes at a time for speed, since we align check.
    }
    
    if let Some((pos, num, names, score)) = best_candidate {
        println!("[Rust] Selected best candidate: num={} @ 0x{:x}, names @ 0x{:x} (score={})", num, pos, names, score);
        return Ok((pos, num, names));
    }

    // Fallback: If Strategy 3 failed, try the old Brute Force (Strategy 2) but with the relaxed validation
    // This is useful if markers logic is somehow flawed or layout is very weird.
    println!("[Rust] Strategy 3 failed. Trying fallback Strategy 2 (Brute Force)...");
    
    let scan_limit = markers_offset.saturating_sub(4 * 1024 * 1024);
    let mut pos = markers_offset.saturating_sub(4);
    while pos >= scan_limit {
        for size in [8, 4] {
            if pos + size > data.len() { continue; }
            let val = if big_endian {
                if size == 8 { data.pread_with::<u64>(pos, BE).unwrap_or(0) }
                else { data.pread_with::<u32>(pos, BE).unwrap_or(0) as u64 }
            } else {
                if size == 8 { data.pread_with::<u64>(pos, LE).unwrap_or(0) }
                else { data.pread_with::<u32>(pos, LE).unwrap_or(0) as u64 }
            };

            if val >= min_syms as u64 && val <= max_syms as u64 {
                let names_offset = pos + size;
                 // Quick check
                if names_offset < data.len() && data[names_offset] > 0 && data[names_offset] < 128 {
                    let (valid_count, is_valid) = validate_names_dp(data, names_offset, val as usize);
                    if is_valid {
                        println!("[Rust] Found num_symbols {} at 0x{:x} via Strategy 2 fallback", val, pos);
                        return Ok((pos, val as usize, names_offset));
                    }
                }
            }
        }
        if pos < 1 { break; }
        pos -= 1;
    }

    println!("[Rust] Failed to find num_symbols anchor. Marker count: {}, Last marker val: {}", marker_count, last_marker_val);
    Err(KallsymsError::ParseError("Could not find num_symbols anchor".to_string()).into())
}

fn find_addresses_table(
    data: &[u8],
    num_syms_offset: usize,
    num_symbols: usize,
    hint_arch: KernelArch,
    big_endian: bool,
) -> Result<(usize, Option<u64>, KernelArch)> {
    println!("[Rust] Searching for addresses table for {} symbols before 0x{:x}", num_symbols, num_syms_offset);

    // Try different pointer sizes if arch is unknown
    let archs_to_try = if hint_arch == KernelArch::Unknown {
        vec![KernelArch::Arm64, KernelArch::Arm32]
    } else {
        vec![hint_arch]
    };

    for arch in archs_to_try {
        let ptr_size = arch.pointer_size();
        println!("[Rust] Trying arch {:?} (ptr_size={})", arch, ptr_size);
        
        // Strategy 1: Absolute Addresses
        // Scan backwards from num_syms_offset for a table of addresses
        let addr_table_size = num_symbols * ptr_size;
        // We allow some padding/gap between addresses and num_syms
        let scan_limit = num_syms_offset.saturating_sub(addr_table_size + 16384);
        let mut pos = num_syms_offset.saturating_sub(addr_table_size);
        pos &= !(ptr_size - 1);

        while pos >= scan_limit {
            if pos + ptr_size * 4 > data.len() { 
                if pos < ptr_size { break; }
                pos -= ptr_size;
                continue; 
            }

            let a1: u64 = if big_endian {
                if ptr_size == 8 { data.pread_with::<u64>(pos, BE).unwrap_or(0) }
                else { data.pread_with::<u32>(pos, BE).unwrap_or(0) as u64 }
            } else {
                if ptr_size == 8 { data.pread_with::<u64>(pos, LE).unwrap_or(0) }
                else { data.pread_with::<u32>(pos, LE).unwrap_or(0) as u64 }
            };

            // Heuristic: kernel address
            if (ptr_size == 8 && a1 >= 0xFFFF_0000_0000_0000) || (ptr_size == 4 && a1 >= 0x8000_0000) {
                // Verify a few more (at least 4)
                let mut valid = true;
                let mut prev = a1;
                for i in 1..4 {
                    let next_pos = pos + i * ptr_size;
                    let next_val: u64 = if big_endian {
                        if ptr_size == 8 { data.pread_with::<u64>(next_pos, BE).unwrap_or(0) }
                        else { data.pread_with::<u32>(next_pos, BE).unwrap_or(0) as u64 }
                    } else {
                        if ptr_size == 8 { data.pread_with::<u64>(next_pos, LE).unwrap_or(0) }
                        else { data.pread_with::<u32>(next_pos, LE).unwrap_or(0) as u64 }
                    };
                    if next_val < prev {
                        valid = false;
                        break;
                    }
                    prev = next_val;
                }
                
                if valid {
                    println!("[Rust] Found absolute addresses table at 0x{:x} for {:?}", pos, arch);
                    return Ok((pos, None, arch));
                }
            }
            if pos < ptr_size { break; }
            pos -= ptr_size;
        }

        // Strategy 2: Relative Offsets (modern kernels)
        // Structure: [offsets (4 * num_symbols)] [padding?] [relative_base (8)] [padding?] [num_syms]
        println!("[Rust] Trying Strategy 2 (Relative Offsets) for {:?}", arch);
        let offsets_size = num_symbols * 4;
        // The offsets table ends somewhere before num_syms_offset
        let max_offsets_end = num_syms_offset;
        let min_offsets_end = num_syms_offset.saturating_sub(4096);
        
        // Collect all candidates with quality scores
        let mut candidates: Vec<(usize, u64, usize, f32)> = Vec::new(); // (pos, base, base_pos, quality)
        
        let mut offsets_end = max_offsets_end;
        while offsets_end >= min_offsets_end {
            let pos = offsets_end.saturating_sub(offsets_size);
            if pos + offsets_size > data.len() { 
                if offsets_end < 4 { break; }
                offsets_end -= 4;
                continue; 
            }

            // In relative mode, kallsyms_relative_base is usually between offsets and num_syms
            // or sometimes just before offsets.
            // Let's look for a base address in the gap.
            let gap_start = offsets_end;
            let gap_end = num_syms_offset;
            
            // Scan for base address in the gap first
            let mut base_pos = gap_start;
            base_pos &= !7; // 8-aligned
            while base_pos + 8 <= gap_end {
                let base_val: u64 = if big_endian {
                    data.pread_with::<u64>(base_pos, BE).unwrap_or(0)
                } else {
                    data.pread_with::<u64>(base_pos, LE).unwrap_or(0)
                };

                // Check if this looks like a valid kernel base address
                if is_valid_kernel_base(base_val, arch) {
                    // Validate the offsets table quality
                    if let Some(quality) = validate_relative_offsets(data, pos, num_symbols, base_val, big_endian) {
                        println!("[Rust] Candidate: base=0x{:x} at 0x{:x}, offsets at 0x{:x}, quality={:.2}%", 
                                 base_val, base_pos, pos, quality * 100.0);
                        candidates.push((pos, base_val, base_pos, quality));
                    }
                }
                base_pos += 8;
            }

            // Also try looking for base address BEFORE offsets (less common but possible)
            let pre_gap_limit = pos.saturating_sub(128);
            let mut pre_base_pos = pos.saturating_sub(8);
            pre_base_pos &= !7;
            while pre_base_pos >= pre_gap_limit {
                let base_val: u64 = if big_endian {
                    data.pread_with::<u64>(pre_base_pos, BE).unwrap_or(0)
                } else {
                    data.pread_with::<u64>(pre_base_pos, LE).unwrap_or(0)
                };

                if is_valid_kernel_base(base_val, arch) {
                    if let Some(quality) = validate_relative_offsets(data, pos, num_symbols, base_val, big_endian) {
                        println!("[Rust] Candidate (pre): base=0x{:x} at 0x{:x}, offsets at 0x{:x}, quality={:.2}%", 
                                 base_val, pre_base_pos, pos, quality * 100.0);
                        candidates.push((pos, base_val, pre_base_pos, quality));
                    }
                }
                if pre_base_pos < 8 { break; }
                pre_base_pos -= 8;
            }

            if offsets_end < 4 { break; }
            offsets_end -= 4;
        }
        
        // Select the best candidate (highest quality score)
        if !candidates.is_empty() {
            println!("[Rust] Found {} candidates for {:?}", candidates.len(), arch);
        }
        
        if let Some(&(best_pos, best_base, best_base_pos, best_quality)) = 
            candidates.iter().max_by(|a, b| a.3.partial_cmp(&b.3).unwrap()) 
        {
            // Lower threshold to 20% - we rely on quality scoring, not hard rejection
            if best_quality >= 0.2 {
                println!("[Rust] Selected best candidate: base=0x{:x} at 0x{:x}, quality={:.2}%", 
                         best_base, best_base_pos, best_quality * 100.0);
                return Ok((best_pos, Some(best_base), arch));
            } else {
                println!("[Rust] Best candidate quality too low ({:.2}%), rejecting", best_quality * 100.0);
            }
        }
    }

    println!("[Rust] Failed to find addresses table for any arch");
    Err(KallsymsError::AddressesNotFound.into())
}

/// Validate that a kernel base address looks reasonable.
/// Based on vmlinux-to-elf heuristics.
/// NOTE: kallsyms_relative_base does NOT need to be page-aligned!
fn is_valid_kernel_base(base: u64, arch: KernelArch) -> bool {
    if arch.is_64bit() {
        // 1. Must be in kernel address space (high bits set)
        if base < 0xFFFF_0000_0000_0000 {
            return false;
        }
        
        // 2. Page alignment is NOT required for kallsyms_relative_base
        //    It's just a calculation base, not an actual loadable address
        
        // 3. Check for common AArch64/x86_64 kernel base patterns
        // AArch64 typical: 0xffffffc0_xxxxxxxx, 0xffff8000_xxxxxxxx
        // x86_64 typical:  0xffffffff_8xxxxxxx, 0xffffffff_axxxxxxx
        let high_nibbles = base >> 48;
        matches!(high_nibbles, 
            0xFFFF | // Standard kernel VA
            0xFFFE | // Some KASLR configurations
            0xFFFD   // Less common but valid
        )
    } else {
        // 32-bit: typically >= 0x80000000 (TASK_SIZE), page-aligned
        base >= 0x8000_0000 && (base & 0xFFF) == 0
    }
}

/// Validate relative offsets table quality using vmlinux-to-elf heuristics.
/// Returns a quality score (0.0 - 1.0) or None if completely invalid.
fn validate_relative_offsets(
    data: &[u8],
    offsets_pos: usize,
    num_symbols: usize,
    base: u64,
    big_endian: bool,
) -> Option<f32> {
    let sample_size = std::cmp::min(num_symbols, 1000);
    let step = if num_symbols > 1000 { num_symbols / 1000 } else { 1 };
    
    let mut null_count = 0;
    let mut negative_count = 0;
    let mut valid_kernel_addr_count = 0;
    let mut ascending_pairs = 0;
    let mut total_pairs = 0;
    
    // Masks for negative offset heuristic (top 3 nibbles)
    let negative_mask: i32 = 0xFFF << 20; // 0xFFF00000
    
    let mut prev_addr: Option<u64> = None;
    
    for i in (0..num_symbols).step_by(step).take(sample_size) {
        let off_pos = offsets_pos + i * 4;
        if off_pos + 4 > data.len() {
            break;
        }
        
        let offset: i32 = if big_endian {
            data.pread_with::<i32>(off_pos, BE).unwrap_or(0)
        } else {
            data.pread_with::<i32>(off_pos, LE).unwrap_or(0)
        };
        
        // Convert to absolute address (this is the KEY fix!)
        let addr = (base as i64).wrapping_add(offset as i64) as u64;
        
        // Count null ADDRESSES (not offsets!) - vmlinux-to-elf checks addresses, not offsets
        // offset == 0 is valid (symbol at base), but address == 0 is invalid
        if addr == 0 {
            null_count += 1;
        }
        
        // Count "looks like negative" using bitmask heuristic
        if (offset & negative_mask) == negative_mask || offset < 0 {
            negative_count += 1;
        }
        
        // Count valid kernel addresses (symbol addresses don't need to be page-aligned)
        // Just check if they're in kernel space
        if addr >= 0xFFFF_0000_0000_0000 {
            valid_kernel_addr_count += 1;
        }
        
        // Check ascending order
        if let Some(prev) = prev_addr {
            total_pairs += 1;
            if addr >= prev {
                ascending_pairs += 1;
            }
        }
        prev_addr = Some(addr);
    }
    
    let sample_count = sample_size as f32;
    let null_ratio = null_count as f32 / sample_count;
    let negative_ratio = negative_count as f32 / sample_count;
    let valid_ratio = valid_kernel_addr_count as f32 / sample_count;
    let ascending_ratio = if total_pairs > 0 { 
        ascending_pairs as f32 / total_pairs as f32 
    } else { 
        0.0 
    };
    
    // Log stats for debugging
    println!("[Rust] Validation stats: null_addr={:.1}%, negative={:.1}%, valid_kernel={:.1}%, ascending={:.1}%",
             null_ratio * 100.0, negative_ratio * 100.0, valid_ratio * 100.0, ascending_ratio * 100.0);
    
    // Reject if too many null addresses (> 20%)
    // Note: This should rarely happen with correct base, as address=0 means offset=-base
    if null_ratio >= 0.2 {
        println!("[Rust] Rejecting: too many null addresses ({:.1}%)", null_ratio * 100.0);
        return None;
    }
    
    // Compute quality score
    // Weight: valid kernel addresses matter most, then ascending order
    let quality = (valid_ratio * 0.5) + (ascending_ratio * 0.4) + (negative_ratio * 0.1);
    
    Some(quality)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Test detect_architecture ---
    
    #[test]
    fn test_detect_architecture_arm64_magic() {
        // ARM64 kernel has "ARM\x64" at offset 0x38
        let mut data = vec![0u8; 0x100];
        data[0x38..0x3C].copy_from_slice(b"ARM\x64");
        
        assert_eq!(detect_architecture(&data), KernelArch::Arm64);
    }
    
    #[test]
    fn test_detect_architecture_unknown_empty() {
        let data = vec![0u8; 100];
        assert_eq!(detect_architecture(&data), KernelArch::Unknown);
    }
    
    #[test]
    fn test_detect_architecture_too_small() {
        let data = vec![0u8; 10];
        assert_eq!(detect_architecture(&data), KernelArch::Unknown);
    }

    // --- Test ScanOptions ---
    
    #[test]
    fn test_scan_options_default() {
        let options = ScanOptions::default();
        assert!(!options.override_relative);
    }
    
    #[test]
    fn test_scan_options_override() {
        let options = ScanOptions { override_relative: true };
        assert!(options.override_relative);
    }

    // --- Test is_valid_kernel_base ---
    
    #[test]
    fn test_valid_kernel_base_arm64() {
        // Typical ARM64 kernel base
        assert!(is_valid_kernel_base(0xFFFF_8000_0000_0000, KernelArch::Arm64));
        assert!(is_valid_kernel_base(0xFFFF_FFFF_8000_0000, KernelArch::Arm64));
    }
    
    #[test]
    fn test_valid_kernel_base_x86_64() {
        // Typical x86_64 kernel base
        assert!(is_valid_kernel_base(0xFFFF_FFFF_8000_0000, KernelArch::X86_64));
        assert!(is_valid_kernel_base(0xFFFF_8880_0000_0000, KernelArch::X86_64));
    }
    
    #[test]
    fn test_invalid_kernel_base_userspace() {
        // Userspace addresses should be invalid
        assert!(!is_valid_kernel_base(0x0000_0000_0040_0000, KernelArch::Arm64));
        assert!(!is_valid_kernel_base(0x0000_7FFF_FFFF_FFFF, KernelArch::X86_64));
    }
    
    #[test]
    fn test_invalid_kernel_base_zero() {
        assert!(!is_valid_kernel_base(0, KernelArch::Arm64));
        assert!(!is_valid_kernel_base(0, KernelArch::X86_64));
    }
    
    #[test]
    fn test_valid_kernel_base_arm32() {
        // ARM32 kernel bases are typically 0xC0000000+
        assert!(is_valid_kernel_base(0xC000_0000, KernelArch::Arm32));
        assert!(is_valid_kernel_base(0xC010_0000, KernelArch::Arm32));
    }

    // --- Test validate_names_dp ---
    
    #[test]
    fn test_validate_names_dp_valid_entries() {
        // Format: [len, token_id_1, token_id_2...]
        // Create 60 valid entries: len=2, first byte is token_id (not necessarily ASCII)
        let mut data = Vec::new();
        for i in 0..60 {
            data.push(2);    // length = 2
            data.push(i as u8); // token_id = i (could be anything)
            data.push(0);    // token index
        }
        
        let (valid_count, is_valid) = validate_names_dp(&data, 0, 60);
        assert_eq!(valid_count, 60);
        assert!(is_valid);
    }
    
    #[test]
    fn test_validate_names_dp_zero_length() {
        // Zero length should fail immediately
        let data = vec![0u8, 0, 0];
        
        let (valid_count, _) = validate_names_dp(&data, 0, 10);
        assert_eq!(valid_count, 0);
    }
    
    #[test]
    fn test_validate_names_dp_invalid_length() {
        // Length > 127 should fail
        let data = vec![255, 0, 0];
        
        let (valid_count, _) = validate_names_dp(&data, 0, 10);
        assert_eq!(valid_count, 0);
    }

    // --- Test validate_relative_offsets ---
    
    #[test]
    fn test_validate_relative_offsets_valid() {
        // Create valid relative offset table
        // Base: 0xFFFF_8000_1000_0000, offsets: 0, 0x100, 0x200, 0x300...
        let base: u64 = 0xFFFF_8000_1000_0000;
        let num_symbols = 100;
        
        let mut data = vec![0u8; num_symbols * 4 + 8]; // Extra space
        for i in 0..num_symbols {
            let offset: i32 = (i * 0x100) as i32;
            let pos = i * 4;
            data[pos..pos + 4].copy_from_slice(&offset.to_le_bytes());
        }
        
        let result = validate_relative_offsets(&data, 0, num_symbols, base, false);
        assert!(result.is_some());
        
        let quality = result.unwrap();
        assert!(quality > 0.5, "Quality should be > 0.5 for valid data, got {}", quality);
    }
    
    #[test]
    fn test_validate_relative_offsets_too_many_nulls() {
        // All offsets result in address 0 (offset = -base)
        let base: u64 = 0x1000;
        let num_symbols = 100;
        let offset: i32 = -(base as i32);
        
        let mut data = vec![0u8; num_symbols * 4];
        for i in 0..num_symbols {
            let pos = i * 4;
            data[pos..pos + 4].copy_from_slice(&offset.to_le_bytes());
        }
        
        // This should fail due to >20% null addresses
        let result = validate_relative_offsets(&data, 0, num_symbols, base, false);
        assert!(result.is_none());
    }
    
    #[test]
    fn test_validate_relative_offsets_ascending() {
        // Strictly ascending offsets should have high quality
        let base: u64 = 0xFFFF_8000_0000_0000;
        let num_symbols = 50;
        
        let mut data = vec![0u8; num_symbols * 4];
        for i in 0..num_symbols {
            let offset: i32 = (i * 0x1000) as i32; // Each symbol 4KB apart
            let pos = i * 4;
            data[pos..pos + 4].copy_from_slice(&offset.to_le_bytes());
        }
        
        let result = validate_relative_offsets(&data, 0, num_symbols, base, false);
        assert!(result.is_some());
        
        let quality = result.unwrap();
        assert!(quality > 0.7, "Ascending sequence should have quality > 0.7, got {}", quality);
    }

    // --- Test TOKEN_TABLE_AVOID_PATTERNS ---
    
    #[test]
    fn test_token_table_avoid_patterns_exist() {
        // Verify the avoid patterns are defined correctly
        assert!(TOKEN_TABLE_AVOID_PATTERNS.contains(&b":\0".as_slice()));
        assert!(TOKEN_TABLE_AVOID_PATTERNS.contains(&b"\0\0".as_slice()));
        assert!(TOKEN_TABLE_AVOID_PATTERNS.contains(&b"ASCII\0".as_slice()));
    }
}
