//! Android Boot Image Parser
//!
//! Supports parsing Android boot image formats:
//! - V0/V1/V2: Traditional format with `ANDROID!` magic
//! - V3/V4: Vendor boot format with `VNDRBOOT` magic
//!
//! Reference: https://source.android.com/docs/core/architecture/bootloader/boot-image-header

use nom::{
    bytes::complete::{tag, take},
    number::complete::le_u32,
    IResult,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::{Error, Result};

// ============================================================
// Constants
// ============================================================

/// Magic bytes for Android boot image V0-V2.
pub const BOOT_MAGIC: &[u8] = b"ANDROID!";

/// Magic bytes for Vendor boot image V3+.
pub const VENDOR_BOOT_MAGIC: &[u8] = b"VNDRBOOT";

/// Size of the boot image magic field.
pub const BOOT_MAGIC_SIZE: usize = 8;

// ============================================================
// Boot Image Header Structures
// ============================================================

/// Detected boot image version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootImageVersion {
    /// Legacy format (V0-V2).
    V0,
    /// Traditional format V1.
    V1,
    /// Traditional format V2.
    V2,
    /// Modern GKI format (V3+).
    V3,
    /// GKI format V4.
    V4,
    /// Unknown or unsupported.
    Unknown(u32),
}

impl From<u32> for BootImageVersion {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::V0,
            1 => Self::V1,
            2 => Self::V2,
            3 => Self::V3,
            4 => Self::V4,
            v => Self::Unknown(v),
        }
    }
}

/// Parsed boot image header (common fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootImageHeader {
    /// Boot image format version.
    pub version: BootImageVersion,
    /// Kernel size in bytes.
    pub kernel_size: u32,
    /// Kernel load address.
    pub kernel_addr: u32,
    /// Ramdisk size in bytes.
    pub ramdisk_size: u32,
    /// Ramdisk load address.
    pub ramdisk_addr: u32,
    /// Second stage bootloader size (V0-V2 only).
    pub second_size: u32,
    /// Page size (typically 2048 or 4096).
    pub page_size: u32,
    /// OS version (packed format).
    pub os_version: u32,
    /// Command line (null-terminated).
    pub cmdline: String,
    /// Offset to kernel data within the image.
    pub kernel_offset: usize,
    /// Offset to ramdisk data within the image.
    pub ramdisk_offset: usize,
}

/// Represents a parsed Android boot image.
#[derive(Debug)]
pub struct BootImage {
    /// Parsed header information.
    pub header: BootImageHeader,
    /// Raw file data (memory-mapped for large files).
    data: Vec<u8>,
}

impl BootImage {
    /// Load and parse a boot image from a file path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the boot.img file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the format is invalid.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let data = std::fs::read(path)
            .map_err(|e| Error::FileError { path: path.display().to_string(), source: e })?;

        Self::from_bytes(data)
    }

    /// Parse a boot image from raw bytes.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.len() < BOOT_MAGIC_SIZE {
            return Err(Error::InvalidBootImage("File too small".into()));
        }

        // Detect format by magic
        let header = if data.starts_with(BOOT_MAGIC) {
            Self::parse_android_header(&data)?
        } else if data.starts_with(VENDOR_BOOT_MAGIC) {
            Self::parse_vendor_header(&data)?
        } else {
            return Err(Error::MagicMismatch {
                expected: "ANDROID! or VNDRBOOT".into(),
                found: format!("{:?}", &data[..8.min(data.len())]),
            });
        };

        Ok(Self { header, data })
    }

    /// Extract the raw kernel binary from the boot image.
    ///
    /// Note: The kernel may still be compressed (LZ4/Gzip).
    /// Use [`crate::Decompressor`] to decompress if needed.
    pub fn extract_kernel(&self) -> Result<&[u8]> {
        let start = self.header.kernel_offset;
        let end = start + self.header.kernel_size as usize;

        if end > self.data.len() {
            return Err(Error::InvalidBootImage(format!(
                "Kernel extends beyond file: offset={}, size={}, file_len={}",
                start,
                self.header.kernel_size,
                self.data.len()
            )));
        }

        Ok(&self.data[start..end])
    }

    /// Extract the ramdisk from the boot image.
    pub fn extract_ramdisk(&self) -> Result<&[u8]> {
        let start = self.header.ramdisk_offset;
        let end = start + self.header.ramdisk_size as usize;

        if end > self.data.len() {
            return Err(Error::InvalidBootImage(format!(
                "Ramdisk extends beyond file: offset={}, size={}, file_len={}",
                start,
                self.header.ramdisk_size,
                self.data.len()
            )));
        }

        Ok(&self.data[start..end])
    }

    // --------------------------------------------------------
    // Private parsing helpers
    // --------------------------------------------------------

    fn parse_android_header(data: &[u8]) -> Result<BootImageHeader> {
        let (_remaining, header) =
            parse_boot_header_v0(data).map_err(|e| Error::ParseError(format!("{:?}", e)))?;

        // Calculate offsets based on page alignment
        let page_size = header.page_size as usize;
        let kernel_offset = page_size; // Kernel starts after header page
        let kernel_pages = (header.kernel_size as usize).div_ceil(page_size);
        let ramdisk_offset = kernel_offset + kernel_pages * page_size;

        Ok(BootImageHeader {
            version: header.version,
            kernel_size: header.kernel_size,
            kernel_addr: header.kernel_addr,
            ramdisk_size: header.ramdisk_size,
            ramdisk_addr: header.ramdisk_addr,
            second_size: header.second_size,
            page_size: header.page_size,
            os_version: header.os_version,
            cmdline: header.cmdline,
            kernel_offset,
            ramdisk_offset,
        })
    }

    fn parse_vendor_header(_data: &[u8]) -> Result<BootImageHeader> {
        // V3/V4 vendor boot parsing - simplified for now
        todo!("Vendor boot image parsing not yet implemented")
    }
}

// ============================================================
// nom Parsers for Binary Structures
// ============================================================

/// Intermediate struct for nom parsing.
#[allow(dead_code)]
struct RawBootHeader {
    version: BootImageVersion,
    kernel_size: u32,
    kernel_addr: u32,
    ramdisk_size: u32,
    ramdisk_addr: u32,
    second_size: u32,
    second_addr: u32,
    tags_addr: u32,
    page_size: u32,
    header_version: u32,
    os_version: u32,
    cmdline: String,
}

/// Parse Android boot image header (V0-V2 format).
fn parse_boot_header_v0(input: &[u8]) -> IResult<&[u8], RawBootHeader> {
    let (input, _magic) = tag(BOOT_MAGIC)(input)?;
    let (input, kernel_size) = le_u32(input)?;
    let (input, kernel_addr) = le_u32(input)?;
    let (input, ramdisk_size) = le_u32(input)?;
    let (input, ramdisk_addr) = le_u32(input)?;
    let (input, second_size) = le_u32(input)?;
    let (input, second_addr) = le_u32(input)?;
    let (input, tags_addr) = le_u32(input)?;
    let (input, page_size) = le_u32(input)?;
    let (input, header_version) = le_u32(input)?;
    let (input, os_version) = le_u32(input)?;

    // Read command line (512 bytes, null-terminated)
    let (input, cmdline_bytes) = take(512usize)(input)?;
    let cmdline =
        String::from_utf8_lossy(cmdline_bytes.split(|&b| b == 0).next().unwrap_or(cmdline_bytes))
            .into_owned();

    Ok((
        input,
        RawBootHeader {
            version: header_version.into(),
            kernel_size,
            kernel_addr,
            ramdisk_size,
            ramdisk_addr,
            second_size,
            second_addr,
            tags_addr,
            page_size,
            header_version,
            os_version,
            cmdline,
        },
    ))
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_detection() {
        // Valid ANDROID! magic
        let mut data = vec![0u8; 4096];
        data[..8].copy_from_slice(BOOT_MAGIC);

        assert!(data.starts_with(BOOT_MAGIC));
    }

    #[test]
    fn test_invalid_magic() {
        let data = vec![0u8; 100];
        let result = BootImage::from_bytes(data);

        assert!(matches!(result, Err(Error::MagicMismatch { .. })));
    }
}
