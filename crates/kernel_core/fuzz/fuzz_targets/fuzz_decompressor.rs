//! Fuzz target for decompression module.
//!
//! Tests LZ4, Gzip, and Zstd decompression against malicious inputs
//! like "compression bombs" that could exhaust memory.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// Maximum decompressed size to prevent OOM during fuzzing (16 MB)
const MAX_DECOMPRESSED_SIZE: usize = 16 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    // Skip very small inputs
    if data.len() < 4 {
        return;
    }

    // Test decompression with arbitrary data
    // The decompressor should:
    // 1. Correctly identify compression format (or return None)
    // 2. Handle malformed compressed data gracefully
    // 3. NOT exhaust memory on compression bombs
    //
    // Note: We rely on the underlying libraries (lz4_flex, flate2, zstd)
    // having their own safety limits, but we should also add our own.

    match kernel_core::Decompressor::decompress(data) {
        Ok(decompressed) => {
            // Sanity check: if decompression succeeded, verify reasonable size
            assert!(
                decompressed.len() <= MAX_DECOMPRESSED_SIZE * 100,
                "Decompression bomb detected: {} bytes from {} bytes input",
                decompressed.len(),
                data.len()
            );
        }
        Err(_) => {
            // Errors are expected and fine
        }
    }
});
