//! Fuzz target for boot image parsing.
//!
//! Tests the nom-based parsers against malformed boot images
//! to find crashes, hangs, or memory issues.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test boot image parsing with arbitrary data
    // The parser should gracefully reject invalid magic without panicking
    if let Ok(boot_img) = kernel_core::BootImage::from_bytes(data.to_vec()) {
        // If parsing succeeded, try extraction
        // These should also handle edge cases gracefully
        let _ = boot_img.extract_kernel();
        let _ = boot_img.extract_ramdisk();
    }
});
