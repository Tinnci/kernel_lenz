//! ELF File Builder
//!
//! Reconstructs a debuggable ELF file from the raw kernel binary
//! and recovered kallsyms symbols.
//!
//! The generated ELF can be loaded into IDA Pro, Ghidra, or other
//! reverse engineering tools for further analysis.

use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

use crate::kallsyms::{KallsymsResult, KernelArch, KernelSymbol};
use crate::{Error, Result};

// ============================================================
// ELF Builder
// ============================================================

/// Builder for generating ELF files with recovered symbols.
pub struct ElfBuilder<'a> {
    /// Raw kernel binary.
    kernel_data: &'a [u8],
    /// Recovered symbols.
    symbols: &'a KallsymsResult,
}

impl<'a> ElfBuilder<'a> {
    /// Create a new ELF builder.
    ///
    /// # Arguments
    ///
    /// * `kernel_data` - Raw (decompressed) kernel binary
    /// * `symbols` - Recovered kallsyms data
    pub fn new(kernel_data: &'a [u8], symbols: &'a KallsymsResult) -> Self {
        Self { kernel_data, symbols }
    }

    /// Build the ELF file and return the bytes.
    pub fn build(&self) -> Result<Vec<u8>> {
        let (arch, endian) = self.get_elf_params()?;

        let mut obj = Object::new(BinaryFormat::Elf, arch, endian);

        // Add kernel code section
        let text_section = obj.section_id(StandardSection::Text);
        obj.append_section_data(text_section, self.kernel_data, 4096);

        // Add symbols
        for sym in &self.symbols.symbols {
            self.add_symbol(&mut obj, sym, text_section)?;
        }

        // Generate ELF bytes
        let bytes = obj.write().map_err(|e| Error::ElfBuildError(e.to_string()))?;

        tracing::info!(
            "Generated ELF: {} bytes, {} symbols",
            bytes.len(),
            self.symbols.symbol_count
        );

        Ok(bytes)
    }

    /// Get ELF architecture and endianness from kernel arch.
    fn get_elf_params(&self) -> Result<(Architecture, Endianness)> {
        match self.symbols.arch {
            KernelArch::Arm64 => Ok((Architecture::Aarch64, Endianness::Little)),
            KernelArch::X86_64 => Ok((Architecture::X86_64, Endianness::Little)),
            KernelArch::Arm32 => Ok((Architecture::Arm, Endianness::Little)),
            KernelArch::Unknown => {
                Err(Error::UnsupportedArch("Cannot determine ELF architecture".into()))
            }
        }
    }

    /// Add a kernel symbol to the ELF object.
    fn add_symbol(
        &self,
        obj: &mut Object,
        sym: &KernelSymbol,
        section: object::write::SectionId,
    ) -> Result<()> {
        let kind = if sym.is_code() {
            SymbolKind::Text
        } else if sym.is_data() {
            SymbolKind::Data
        } else {
            SymbolKind::Unknown
        };

        let scope = if sym.sym_type.is_uppercase() {
            SymbolScope::Dynamic
        } else {
            SymbolScope::Compilation
        };

        // Calculate offset within section
        let offset = sym.address.saturating_sub(self.symbols.kernel_base) as u64;

        obj.add_symbol(Symbol {
            name: sym.name.as_bytes().to_vec(),
            value: offset,
            size: sym.size.unwrap_or(0),
            kind,
            scope,
            weak: sym.sym_type == 'W' || sym.sym_type == 'w',
            section: SymbolSection::Section(section),
            flags: SymbolFlags::None,
        });

        Ok(())
    }
}

// ============================================================
// Convenience Functions
// ============================================================

/// Quick function to generate an ELF from kernel data and symbols.
pub fn build_elf(kernel_data: &[u8], symbols: &KallsymsResult) -> Result<Vec<u8>> {
    ElfBuilder::new(kernel_data, symbols).build()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kallsyms::KernelArch;

    #[test]
    fn test_elf_params_arm64() {
        let symbols = KallsymsResult {
            symbols: vec![],
            kernel_base: 0xFFFF_8000_0000_0000,
            arch: KernelArch::Arm64,
            symbol_count: 0,
        };

        let builder = ElfBuilder::new(&[], &symbols);
        let (arch, endian) = builder.get_elf_params().unwrap();

        assert_eq!(arch, Architecture::Aarch64);
        assert_eq!(endian, Endianness::Little);
    }
}
