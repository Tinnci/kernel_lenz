//! Fuzz target for kallsyms scanner module.
//!
//! Tests the pattern matching logic that locates kallsyms tables
//! in arbitrary binary data.

#![no_main]

use libfuzzer_sys::fuzz_target;

// We directly test the internal scanning functions to maximize coverage
fuzz_target!(|data: &[u8]| {
    // Fuzz the high-level KallsymsFinder::new which orchestrates scanning
    // This will exercise:
    // - Architecture detection
    // - Address table scanning
    // - Token table detection
    // - Names offset calculation
    //
    // We expect errors on random data, but we should NEVER panic or crash.
    let _ = kernel_core::KallsymsFinder::new(data);
});
