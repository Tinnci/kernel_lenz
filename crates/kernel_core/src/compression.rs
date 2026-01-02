//! Kernel Decompression Module
//!
//! Handles decompression of Linux kernel images that may be compressed with:
//! - LZ4 (most common for Android/Rockchip kernels)
//! - Gzip
//! - Zstd (newer kernels)
//! - Uncompressed (raw Image)

use std::io::{Cursor, Read};

use crate::{Error, Result};

// ============================================================
// Compression Format Detection
// ============================================================

/// Supported kernel compression formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionFormat {
    /// LZ4 legacy format (common in Android).
    Lz4Legacy,
    /// LZ4 frame format.
    Lz4Frame,
    /// Gzip compression.
    Gzip,
    /// Zstandard compression.
    Zstd,
    /// Uncompressed kernel.
    None,
}

impl CompressionFormat {
    /// Detect compression format from magic bytes.
    pub fn detect(data: &[u8]) -> Self {
        if data.len() < 4 {
            return Self::None;
        }

        match &data[..4] {
            // LZ4 legacy magic: 0x02214C18
            [0x02, 0x21, 0x4C, 0x18] => Self::Lz4Legacy,
            // LZ4 frame magic: 0x184D2204
            [0x04, 0x22, 0x4D, 0x18] => Self::Lz4Frame,
            // Gzip magic: 1f 8b
            [0x1f, 0x8b, ..] => Self::Gzip,
            // Zstd magic: 0x28B52FFD
            [0x28, 0xB5, 0x2F, 0xFD] => Self::Zstd,
            // ARM64 kernel magic at offset 0x38: "ARM\x64"
            _ if data.len() > 0x40 && &data[0x38..0x3C] == b"ARM\x64" => Self::None,
            _ => Self::None,
        }
    }

    /// Get human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Lz4Legacy => "LZ4 (Legacy)",
            Self::Lz4Frame => "LZ4 (Frame)",
            Self::Gzip => "Gzip",
            Self::Zstd => "Zstandard",
            Self::None => "Uncompressed",
        }
    }
}

// ============================================================
// Decompressor
// ============================================================

/// Kernel decompressor that auto-detects and handles various formats.
pub struct Decompressor;

impl Decompressor {
    /// Decompress kernel data, auto-detecting the format.
    ///
    /// # Arguments
    ///
    /// * `data` - Potentially compressed kernel data
    ///
    /// # Returns
    ///
    /// Decompressed kernel bytes (or original if uncompressed).
    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        let format = CompressionFormat::detect(data);
        tracing::info!("Detected compression format: {}", format.name());

        match format {
            CompressionFormat::Lz4Legacy => Self::decompress_lz4_legacy(data),
            CompressionFormat::Lz4Frame => Self::decompress_lz4_frame(data),
            CompressionFormat::Gzip => Self::decompress_gzip(data),
            CompressionFormat::Zstd => Self::decompress_zstd(data),
            CompressionFormat::None => Ok(data.to_vec()),
        }
    }

    /// Decompress LZ4 legacy format (Android-style).
    ///
    /// The legacy format uses raw LZ4 blocks without frame headers.
    fn decompress_lz4_legacy(data: &[u8]) -> Result<Vec<u8>> {
        // Skip magic (4 bytes) and get uncompressed size (4 bytes LE)
        if data.len() < 8 {
            return Err(Error::Lz4Error("Data too short for LZ4 header".into()));
        }

        // Legacy format: magic (4) + uncompressed_size (4) + compressed_data
        let uncompressed_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

        tracing::debug!(
            "LZ4 legacy: compressed={}, uncompressed={}",
            data.len() - 8,
            uncompressed_size
        );

        // Decompress using lz4_flex
        let decompressed = lz4_flex::decompress(&data[8..], uncompressed_size)?;

        Ok(decompressed)
    }

    /// Decompress LZ4 frame format.
    fn decompress_lz4_frame(data: &[u8]) -> Result<Vec<u8>> {
        // Use lz4_flex frame decoder
        let mut decoder = lz4_flex::frame::FrameDecoder::new(Cursor::new(data));
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)?;
        Ok(output)
    }

    /// Decompress Gzip format.
    fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = flate2::read::GzDecoder::new(Cursor::new(data));
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)?;
        Ok(output)
    }

    /// Decompress Zstandard format.
    fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
        let output = zstd::decode_all(Cursor::new(data))
            .map_err(|e| Error::DecompressionError(format!("Zstd: {}", e)))?;
        Ok(output)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection_gzip() {
        let data = [0x1f, 0x8b, 0x08, 0x00];
        assert_eq!(CompressionFormat::detect(&data), CompressionFormat::Gzip);
    }

    #[test]
    fn test_format_detection_lz4_legacy() {
        let data = [0x02, 0x21, 0x4C, 0x18];
        assert_eq!(CompressionFormat::detect(&data), CompressionFormat::Lz4Legacy);
    }

    #[test]
    fn test_format_detection_unknown() {
        let data = [0x00, 0x00, 0x00, 0x00];
        assert_eq!(CompressionFormat::detect(&data), CompressionFormat::None);
    }
}
