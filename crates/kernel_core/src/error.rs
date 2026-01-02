//! Error types for the kernel_core library.
//!
//! Uses `thiserror` for library-style error handling that can be composed
//! by upstream consumers (CLI, FFI).

use thiserror::Error;

/// The main error type for kernel analysis operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid or unsupported boot image format.
    #[error("Invalid boot image format: {0}")]
    InvalidBootImage(String),

    /// Magic number mismatch when parsing headers.
    #[error("Magic number mismatch: expected {expected}, found {found}")]
    MagicMismatch { expected: String, found: String },

    /// Decompression failed.
    #[error("Decompression failed: {0}")]
    DecompressionError(String),

    /// LZ4 specific decompression error.
    #[error("LZ4 decompression error: {0}")]
    Lz4Error(String),

    /// Gzip specific decompression error.
    #[error("Gzip decompression error: {0}")]
    GzipError(#[from] std::io::Error),

    /// Failed to locate kallsyms in the binary.
    #[error("Kallsyms not found: {0}")]
    KallsymsNotFound(String),

    /// Symbol table parsing failed.
    #[error("Symbol table parse error at offset {offset:#x}: {message}")]
    SymbolParseError { offset: usize, message: String },

    /// ELF generation failed.
    #[error("ELF building error: {0}")]
    ElfBuildError(String),

    /// Binary parsing error from nom.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Memory mapping failed.
    #[error("Memory map error: {0}")]
    MmapError(String),

    /// File not found or access denied.
    #[error("File access error for '{path}': {source}")]
    FileError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Unsupported architecture.
    #[error("Unsupported architecture: {0}")]
    UnsupportedArch(String),

    /// Generic internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Convenience Result type alias.
pub type Result<T> = std::result::Result<T, Error>;

// ============================================================
// Conversion implementations for error interop
// ============================================================

impl From<lz4_flex::block::DecompressError> for Error {
    fn from(err: lz4_flex::block::DecompressError) -> Self {
        Error::Lz4Error(err.to_string())
    }
}

impl From<object::write::Error> for Error {
    fn from(err: object::write::Error) -> Self {
        Error::ElfBuildError(err.to_string())
    }
}

impl<E: std::fmt::Debug> From<nom::Err<E>> for Error {
    fn from(err: nom::Err<E>) -> Self {
        Error::ParseError(format!("{:?}", err))
    }
}
