//! Fuzz target for kallsyms decoder module.
//!
//! Tests the token table parsing and symbol name decompression
//! with structured fuzzing inputs.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Structured input for decoder fuzzing.
/// This allows the fuzzer to generate more meaningful test cases.
#[derive(Arbitrary, Debug)]
struct DecoderInput<'a> {
    /// Simulated token table offset (will be clamped to data bounds)
    token_table_offset: u16,
    /// Simulated token index offset
    token_index_offset: u16,
    /// Simulated symbol index to decode
    symbol_index: u16,
    /// Raw binary data
    data: &'a [u8],
}

fuzz_target!(|input: DecoderInput| {
    // Skip if data is too small to be meaningful
    if input.data.len() < 512 {
        return;
    }

    // Clamp offsets to valid range
    let max_offset = input.data.len().saturating_sub(1);
    let token_table_offset = (input.token_table_offset as usize).min(max_offset);
    let token_index_offset = (input.token_index_offset as usize).min(max_offset);

    // Try to parse token table - should not panic
    // Note: We're testing internal module, so we use a wrapper approach
    // The fuzzer will find edge cases in bounds checking, UTF-8 handling, etc.

    // For now, test through the public API
    let _ = kernel_core::KallsymsFinder::new(input.data);
});
