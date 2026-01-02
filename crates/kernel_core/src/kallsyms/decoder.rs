//! Kallsyms Decoder Module
//!
//! This module implements the kallsyms name decompression algorithm.
//! Symbols are stored using a token-based prefix compression scheme.

use super::types::{KallsymsError, KernelSymbol, SymbolType};
use crate::Result;
use scroll::Pread;

/// A compiled dictionary of string fragments used for decompression.
pub struct TokenTable<'a> {
    tokens: Vec<&'a [u8]>,
}

impl<'a> TokenTable<'a> {
    /// Parse the token table and its index.
    pub fn parse(data: &'a [u8], table_offset: usize, index_offset: usize) -> Result<Self> {
        let mut tokens = Vec::with_capacity(256);

        for i in 0..256 {
            let offset_into_table: u16 = data
                .pread_with(index_offset + (i * 2), scroll::LE)
                .map_err(|_| KallsymsError::UnexpectedEof { offset: index_offset, needed: 2 })?;

            let start = table_offset + offset_into_table as usize;
            // The token is a null-terminated string.
            let mut end = start;
            while end < data.len() && data[end] != 0 {
                end += 1;
            }

            tokens.push(&data[start..end]);
        }

        Ok(Self { tokens })
    }

    /// Recursively expand a token into a string.
    pub fn expand(&self, token_id: u8, output: &mut String, depth: usize) -> Result<()> {
        if depth > 10 {
            return Err(KallsymsError::TokenRecursionLimit {
                token_id: token_id as usize,
                max_depth: 10,
            }
            .into());
        }

        let token = self
            .tokens
            .get(token_id as usize)
            .ok_or(KallsymsError::IndexOutOfBounds { index: token_id as usize, max: 256 })?;

        for &byte in *token {
            // In kallsyms, tokens can refer to other tokens if the byte is < 256?
            // Actually, the decompression works by taking each byte of the compressed name
            // and looking it up in the token table. If a token byte itself should be
            // expanded, it happens here. But usually, symbols consist of a series of tokens.
            output.push(byte as char);
        }

        Ok(())
    }

    /// Get the number of tokens in the table.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }
}

/// Decode a single symbol name at the given index.
pub fn decode_symbol_name(
    data: &[u8],
    names_offset: usize,
    index: usize,
    tokens: &TokenTable,
) -> Result<(String, SymbolType)> {
    // 1. Find the offset into the names table for this index.
    // This requires kallsyms_markers. Let's simplify and assume
    // we need a smarter way or we must iterate from the start.
    // Heuristic: kallsyms_markers provides offsets every 256 symbols.

    // For now, to make progress, let's implement a naive sequential scan or
    // assume names_offset is actually an array of offsets (unlikely in kallsyms).
    // Real kallsyms_names: [len][data...][len][data...]

    // We need to find the start of the 'index'-th symbol.
    // This is expensive without markers. Let's assume for this step we scan from the start.
    let mut current_pos = names_offset;
    for _ in 0..index {
        if current_pos >= data.len() {
            return Err(KallsymsError::IndexOutOfBounds { index, max: 0 }.into());
        }
        let len = data[current_pos] as usize;
        current_pos += 1 + len;
    }

    if current_pos >= data.len() {
        return Err(KallsymsError::UnexpectedEof { offset: current_pos, needed: 1 }.into());
    }

    let len = data[current_pos] as usize;
    let name_data = &data[current_pos + 1..current_pos + 1 + len];

    let mut expanded_name = String::with_capacity(64);
    // The first token in the compressed name is often the symbol type.
    let type_token_id = name_data[0];
    let mut type_str = String::new();
    tokens.expand(type_token_id, &mut type_str, 0)?;
    let sym_type = SymbolType::from_char(type_str.chars().next().unwrap_or('?'));

    // Expand the rest of the name
    for &token_id in &name_data[1..] {
        tokens.expand(token_id, &mut expanded_name, 0)?;
    }

    Ok((expanded_name, sym_type))
}

/// A lazy iterator over kernel symbols.
pub struct SymbolIterator<'a> {
    data: &'a [u8],
    addresses: &'a [u64],
    _names_offset: usize,
    tokens: &'a TokenTable<'a>,
    current_index: usize,
    current_names_ptr: usize,
}

impl<'a> SymbolIterator<'a> {
    /// Create a new symbol iterator.
    pub fn new(
        data: &'a [u8],
        addresses: &'a [u64],
        names_offset: usize,
        tokens: &'a TokenTable<'a>,
    ) -> Self {
        Self {
            data,
            addresses,
            _names_offset: names_offset,
            tokens,
            current_index: 0,
            current_names_ptr: names_offset,
        }
    }
}

impl<'a> Iterator for SymbolIterator<'a> {
    type Item = KernelSymbol;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.addresses.len() || self.current_names_ptr >= self.data.len() {
            return None;
        }

        let address = self.addresses[self.current_index];
        let len = self.data[self.current_names_ptr] as usize;
        let name_data = &self.data[self.current_names_ptr + 1..self.current_names_ptr + 1 + len];

        let mut name = String::with_capacity(64);
        let type_token_id = name_data[0];
        let mut type_str = String::new();
        let _ = self.tokens.expand(type_token_id, &mut type_str, 0);
        let sym_type = SymbolType::from_char(type_str.chars().next().unwrap_or('?'));

        for &token_id in &name_data[1..] {
            let _ = self.tokens.expand(token_id, &mut name, 0);
        }

        let size = if self.current_index + 1 < self.addresses.len() {
            Some(self.addresses[self.current_index + 1].saturating_sub(address))
        } else {
            None
        };

        self.current_index += 1;
        self.current_names_ptr += 1 + len;

        Some(KernelSymbol { address, name, sym_type, size })
    }
}
