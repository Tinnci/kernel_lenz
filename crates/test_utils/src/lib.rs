//! # Test Utilities for KernelLens
//!
//! This crate provides shared testing infrastructure:
//!
//! - Mock boot images for unit testing
//! - Test fixture management
//! - Common assertion helpers

use std::path::PathBuf;

use kernel_core::boot_image::BOOT_MAGIC;

// ============================================================
// Mock Data Generators
// ============================================================

/// Generate a minimal valid boot.img for testing.
///
/// This creates a fake boot image with valid headers but
/// placeholder kernel/ramdisk data.
pub fn create_mock_boot_image(kernel_size: u32, ramdisk_size: u32) -> Vec<u8> {
    let page_size: u32 = 2048;

    // Calculate total size
    let header_pages = 1;
    let kernel_pages = (kernel_size + page_size - 1) / page_size;
    let ramdisk_pages = (ramdisk_size + page_size - 1) / page_size;
    let total_size = (header_pages + kernel_pages + ramdisk_pages) as usize * page_size as usize;

    let mut data = vec![0u8; total_size];

    // Write header
    data[0..8].copy_from_slice(BOOT_MAGIC);

    // Kernel size (offset 8)
    data[8..12].copy_from_slice(&kernel_size.to_le_bytes());

    // Kernel addr (offset 12)
    data[12..16].copy_from_slice(&0x10008000u32.to_le_bytes());

    // Ramdisk size (offset 16)
    data[16..20].copy_from_slice(&ramdisk_size.to_le_bytes());

    // Ramdisk addr (offset 20)
    data[20..24].copy_from_slice(&0x11000000u32.to_le_bytes());

    // Second size (offset 24) - 0
    // Second addr (offset 28)
    // Tags addr (offset 32)
    data[32..36].copy_from_slice(&0x10000100u32.to_le_bytes());

    // Page size (offset 36)
    data[36..40].copy_from_slice(&page_size.to_le_bytes());

    // Header version (offset 40) - V1
    data[40..44].copy_from_slice(&1u32.to_le_bytes());

    // OS version (offset 44)
    data[44..48].copy_from_slice(&0u32.to_le_bytes());

    // Fill kernel area with pattern
    let kernel_start = page_size as usize;
    let kernel_end = kernel_start + kernel_size as usize;
    for (i, byte) in data[kernel_start..kernel_end].iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    // Fill ramdisk area with different pattern
    let ramdisk_start = kernel_start + kernel_pages as usize * page_size as usize;
    let ramdisk_end = ramdisk_start + ramdisk_size as usize;
    for (i, byte) in data[ramdisk_start..ramdisk_end].iter_mut().enumerate() {
        *byte = (255 - i % 256) as u8;
    }

    data
}

/// Create a mock ARM64 kernel binary.
///
/// Includes the ARM64 magic header at the correct offset.
pub fn create_mock_arm64_kernel(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size.max(0x50)];

    // ARM64 kernel magic at offset 0x38
    data[0x38..0x3C].copy_from_slice(b"ARM\x64");

    // Fill with pattern
    for (i, byte) in data[0x40..].iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    data
}

/// Create LZ4-compressed data for testing.
pub fn create_lz4_compressed(data: &[u8]) -> Vec<u8> {
    // LZ4 legacy format: magic + uncompressed_size + compressed_data
    let compressed = lz4_flex::compress(data);

    let mut result = Vec::with_capacity(8 + compressed.len());

    // Magic: 0x02214C18 (LE)
    result.extend_from_slice(&[0x02, 0x21, 0x4C, 0x18]);

    // Uncompressed size (LE)
    result.extend_from_slice(&(data.len() as u32).to_le_bytes());

    // Compressed data
    result.extend_from_slice(&compressed);

    result
}

// ============================================================
// Fixture Management
// ============================================================

/// Get the path to the test fixtures directory.
pub fn fixtures_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("fixtures")
}

/// Ensure fixtures directory exists and return path.
pub fn ensure_fixtures_dir() -> std::io::Result<PathBuf> {
    let dir = fixtures_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

// ============================================================
// Temporary Test Files
// ============================================================

/// Create a temporary file with the given contents.
pub fn temp_file_with_contents(contents: &[u8]) -> tempfile::NamedTempFile {
    use std::io::Write;

    let mut file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
    file.write_all(contents).expect("Failed to write temp file");
    file.flush().expect("Failed to flush temp file");
    file
}

// ============================================================
// Assertion Helpers
// ============================================================

/// Assert that two byte slices are equal, with nice diff output.
#[track_caller]
pub fn assert_bytes_eq(expected: &[u8], actual: &[u8]) {
    if expected != actual {
        let max_show = 100;
        let exp_preview: Vec<_> = expected.iter().take(max_show).copied().collect();
        let act_preview: Vec<_> = actual.iter().take(max_show).copied().collect();

        panic!(
            "Byte slices not equal:\n  Expected ({} bytes): {:?}...\n  Actual ({} bytes): {:?}...",
            expected.len(),
            exp_preview,
            actual.len(),
            act_preview
        );
    }
}

// ============================================================
// Tests for test utils (meta!)
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_boot_image_has_magic() {
        let img = create_mock_boot_image(4096, 1024);
        assert!(img.starts_with(BOOT_MAGIC));
    }

    #[test]
    fn test_mock_arm64_kernel_has_magic() {
        let kernel = create_mock_arm64_kernel(1024);
        assert_eq!(&kernel[0x38..0x3C], b"ARM\x64");
    }

    #[test]
    fn test_lz4_roundtrip() {
        let original = b"Hello, World! This is test data for compression.";
        let compressed = create_lz4_compressed(original);

        // Verify magic
        assert_eq!(&compressed[0..4], &[0x02, 0x21, 0x4C, 0x18]);

        // Verify size field
        let size = u32::from_le_bytes([compressed[4], compressed[5], compressed[6], compressed[7]]);
        assert_eq!(size as usize, original.len());
    }
}
