//! Core type definitions for Kallsyms recovery.
//!
//! This module defines the fundamental data structures used throughout
//! the kallsyms recovery pipeline.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================
// Error Types (精确定义，便于上层精细化处理)
// ============================================================

/// Errors that can occur during Kallsyms recovery.
#[derive(Error, Debug)]
pub enum KallsymsError {
    /// Failed to locate the addresses table.
    #[error("Could not locate kallsyms_addresses table")]
    AddressesNotFound,

    /// Failed to locate the names table.
    #[error("Could not locate kallsyms_names table")]
    NamesNotFound,

    /// Failed to locate the token table.
    #[error("Could not locate kallsyms_token_table")]
    TokenTableNotFound,

    /// Failed to locate the token index.
    #[error("Could not locate kallsyms_token_index")]
    TokenIndexNotFound,

    /// Invalid relative offset encountered.
    #[error("Invalid relative offset at position {offset:#x}: {message}")]
    InvalidRelativeOffset {
        /// Byte offset in the data.
        offset: usize,
        /// Description of the issue.
        message: String,
    },

    /// Token recursion depth exceeded (防止恶意构造导致栈溢出).
    #[error("Token expansion exceeded max depth ({max_depth}) at token {token_id}")]
    TokenRecursionLimit {
        /// Token that caused the overflow.
        token_id: usize,
        /// Maximum allowed depth.
        max_depth: usize,
    },

    /// Index out of bounds during parsing.
    #[error("Index {index} out of bounds (max: {max})")]
    IndexOutOfBounds {
        /// Requested index.
        index: usize,
        /// Maximum valid index.
        max: usize,
    },

    /// Unexpected end of data while parsing.
    #[error("Unexpected end of data at offset {offset:#x}, needed {needed} bytes")]
    UnexpectedEof {
        /// Current offset.
        offset: usize,
        /// Bytes needed.
        needed: usize,
    },

    /// Invalid UTF-8 in symbol name.
    #[error("Invalid UTF-8 in symbol name at index {index}")]
    InvalidUtf8 {
        /// Symbol index.
        index: usize,
    },

    /// Generic parse error.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Unsupported kernel format.
    #[error("Unsupported kernel format: {0}")]
    UnsupportedFormat(String),
}

impl From<KallsymsError> for crate::Error {
    fn from(err: KallsymsError) -> Self {
        crate::Error::KallsymsNotFound(err.to_string())
    }
}

// ============================================================
// Configuration Types
// ============================================================

/// Detected kernel architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelArch {
    /// ARM 64-bit (AArch64).
    Arm64,
    /// x86 64-bit.
    X86_64,
    /// ARM 32-bit.
    Arm32,
    /// x86 32-bit.
    X86,
    /// RISC-V 64-bit.
    RiscV64,
    /// Unknown architecture.
    Unknown,
}

impl KernelArch {
    /// Get the pointer size for this architecture in bytes.
    pub const fn pointer_size(&self) -> usize {
        match self {
            Self::Arm64 | Self::X86_64 | Self::RiscV64 => 8,
            Self::Arm32 | Self::X86 => 4,
            Self::Unknown => 8, // Default to 64-bit
        }
    }

    /// Check if this is a 64-bit architecture.
    pub const fn is_64bit(&self) -> bool {
        matches!(self, Self::Arm64 | Self::X86_64 | Self::RiscV64)
    }
}

/// Address storage format in the kallsyms tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressFormat {
    /// 32-bit absolute addresses (legacy kernels).
    Absolute32,
    /// 64-bit absolute addresses.
    Absolute64,
    /// 32-bit relative offsets (modern kernels since ~4.6).
    /// Addresses are stored as: `relative_base + (i32 offset)`.
    Relative32,
}

impl AddressFormat {
    /// Get the size of each address entry in bytes.
    pub const fn entry_size(&self) -> usize {
        match self {
            Self::Absolute32 | Self::Relative32 => 4,
            Self::Absolute64 => 8,
        }
    }
}

/// Complete kallsyms configuration detected from the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KallsymsConfig {
    /// Detected kernel architecture.
    pub arch: KernelArch,
    /// Address storage format.
    pub format: AddressFormat,
    /// Kernel base address (first symbol address).
    pub kernel_base: u64,
    /// Relative base address (only for Relative32 format).
    pub relative_base: Option<u64>,
    /// Whether big-endian encoding is used.
    pub big_endian: bool,
}

impl Default for KallsymsConfig {
    fn default() -> Self {
        Self {
            arch: KernelArch::Unknown,
            format: AddressFormat::Absolute64,
            kernel_base: 0,
            relative_base: None,
            big_endian: false,
        }
    }
}

// ============================================================
// Symbol Types
// ============================================================

/// Linux kernel symbol type (from nm output).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolType {
    /// Text (code) section, global.
    Text,
    /// Text section, local.
    TextLocal,
    /// Data section, global.
    Data,
    /// Data section, local.
    DataLocal,
    /// BSS (uninitialized data), global.
    Bss,
    /// BSS, local.
    BssLocal,
    /// Read-only data, global.
    Rodata,
    /// Read-only data, local.
    RodataLocal,
    /// Weak symbol.
    Weak,
    /// Weak symbol, local.
    WeakLocal,
    /// Absolute symbol.
    Absolute,
    /// Unknown type.
    Unknown(char),
}

impl SymbolType {
    /// Parse from the single-character type used in kallsyms.
    pub fn from_char(c: char) -> Self {
        match c {
            'T' => Self::Text,
            't' => Self::TextLocal,
            'D' => Self::Data,
            'd' => Self::DataLocal,
            'B' => Self::Bss,
            'b' => Self::BssLocal,
            'R' => Self::Rodata,
            'r' => Self::RodataLocal,
            'W' | 'V' => Self::Weak,
            'w' | 'v' => Self::WeakLocal,
            'A' => Self::Absolute,
            _ => Self::Unknown(c),
        }
    }

    /// Convert back to character representation.
    pub fn to_char(self) -> char {
        match self {
            Self::Text => 'T',
            Self::TextLocal => 't',
            Self::Data => 'D',
            Self::DataLocal => 'd',
            Self::Bss => 'B',
            Self::BssLocal => 'b',
            Self::Rodata => 'R',
            Self::RodataLocal => 'r',
            Self::Weak => 'W',
            Self::WeakLocal => 'w',
            Self::Absolute => 'A',
            Self::Unknown(c) => c,
        }
    }

    /// Check if this symbol is in a code section.
    pub fn is_code(&self) -> bool {
        matches!(self, Self::Text | Self::TextLocal | Self::Weak | Self::WeakLocal)
    }

    /// Check if this symbol is in a data section.
    pub fn is_data(&self) -> bool {
        matches!(
            self,
            Self::Data
                | Self::DataLocal
                | Self::Bss
                | Self::BssLocal
                | Self::Rodata
                | Self::RodataLocal
        )
    }

    /// Check if this is a global symbol.
    pub fn is_global(&self) -> bool {
        matches!(
            self,
            Self::Text | Self::Data | Self::Bss | Self::Rodata | Self::Weak | Self::Absolute
        )
    }
}

impl std::fmt::Display for SymbolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_char())
    }
}

// ============================================================
// Symbol Data
// ============================================================

/// A recovered kernel symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSymbol {
    /// Symbol virtual address.
    pub address: u64,
    /// Symbol name (decompressed).
    pub name: String,
    /// Symbol type.
    pub sym_type: SymbolType,
    /// Size in bytes (calculated from distance to next symbol).
    pub size: Option<u64>,
}

impl KernelSymbol {
    /// Check if this symbol is likely a function.
    pub fn is_function(&self) -> bool {
        self.sym_type.is_code()
    }

    /// Check if this symbol is likely a variable.
    pub fn is_variable(&self) -> bool {
        self.sym_type.is_data()
    }
}

impl std::fmt::Display for KernelSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x} {} {}", self.address, self.sym_type, self.name)
    }
}

// ============================================================
// Result Type
// ============================================================

/// Complete result of kallsyms extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KallsymsResult {
    /// All recovered symbols.
    pub symbols: Vec<KernelSymbol>,
    /// Detected kernel base address.
    pub kernel_base: u64,
    /// Detected architecture.
    pub arch: KernelArch,
    /// Number of symbols found.
    pub symbol_count: usize,
}

impl KallsymsResult {
    /// Find a symbol by exact name.
    pub fn find_by_name(&self, name: &str) -> Option<&KernelSymbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// Find symbols containing a substring.
    pub fn search(&self, query: &str) -> Vec<&KernelSymbol> {
        self.symbols.iter().filter(|s| s.name.contains(query)).collect()
    }
}
