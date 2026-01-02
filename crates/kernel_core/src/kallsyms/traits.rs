//! Trait definitions for architecture-specific address parsing.
//!
//! This module defines the common interface that different address
//! format implementations must provide.

use crate::Result;

/// Trait for parsing addresses from kallsyms tables.
///
/// Different kernel versions and architectures store addresses differently:
/// - 32-bit absolute addresses
/// - 64-bit absolute addresses
/// - 32-bit relative offsets (with a separate base address)
///
/// Implementations of this trait handle these variations.
pub trait AddressParser {
    /// Parse addresses from the binary data.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw kernel binary data
    /// * `offset` - Offset to the start of the addresses table
    /// * `count` - Number of addresses to parse
    ///
    /// # Returns
    ///
    /// Vector of 64-bit virtual addresses.
    fn parse_addresses(data: &[u8], offset: usize, count: usize) -> Result<Vec<u64>>;

    /// Get the size of each address entry in bytes.
    fn entry_size() -> usize;

    /// Check if this parser can handle the given data.
    ///
    /// This is used for auto-detection of the address format.
    fn can_parse(data: &[u8], offset: usize, sample_count: usize) -> bool;
}

/// Extended trait for relative address parsing.
///
/// Modern kernels (since ~4.6) use relative offsets to save space.
/// This trait extends `AddressParser` with base address support.
pub trait RelativeAddressParser: AddressParser {
    /// Parse addresses with a known base address.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw kernel binary data
    /// * `offset` - Offset to the start of the offsets table
    /// * `count` - Number of addresses to parse
    /// * `base` - The `kallsyms_relative_base` value
    fn parse_addresses_with_base(
        data: &[u8],
        offset: usize,
        count: usize,
        base: u64,
    ) -> Result<Vec<u64>>;
}
