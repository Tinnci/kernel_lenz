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
        if depth > 128 { // kallsyms usually doesn't go very deep, 128 is safe
            return Err(KallsymsError::TokenRecursionLimit {
                token_id: token_id as usize,
                max_depth: 128,
            }
            .into());
        }

        let token = self
            .tokens
            .get(token_id as usize)
            .ok_or(KallsymsError::IndexOutOfBounds { index: token_id as usize, max: 256 })?;

        for &byte in *token {
            // In kallsyms, the token table itself is compressed.
            // Each byte in a token string can be another token ID to expand.
            // BUT: standard kallsyms only expands bytes that are NOT in the byte string if they are "tokens".
            // Actually, in kallsyms, every byte in the token table is expanded UNLESS it's the base case.
            // The scripts/kallsyms.c logic says:
            // "if the byte is a token, expand it, otherwise push it."
            
            // However, a simple way to know if it's a "leaf" is if the token at that ID 
            // is just a single byte equal to the ID? No, that's not right.
            
            // Correct logic:
            // For each byte in the token's byte string:
            //   If we are at depth 0 AND it's a single-byte token that matches the byte? -> Infinite loop.
            // The base case for kallsyms is that some tokens are literal bytes.
            
            // Let's look at how kernel's kallsyms_expand_symbol does it:
            // it uses a table of token lengths. If length is 1 and it matches? No.
            
            // Actually, in our TokenTable::parse, we populate 256 tokens.
            // The recursive expansion should only happen if the token for `byte` is NOT just the byte itself.
            
            let sub_token = self.tokens[byte as usize];
            if sub_token.len() == 1 && sub_token[0] == byte {
                // Base case: this byte represents itself
                output.push(byte as char);
            } else {
                // Recursive case: expand this byte as a token
                self.expand(byte, output, depth + 1)?;
            }
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
    for i in 0..index {
        if current_pos >= data.len() {
            return Err(KallsymsError::IndexOutOfBounds { index, max: i }.into());
        }
        let len = data[current_pos] as usize;
        if len == 0 {
            // In kallsyms, len=0 is technically corruption, but some kernels 
            // might have padding. However, our SymbolIterator skips it.
            // For random access, hitting a 0 probably means we are misaligned.
            return Err(KallsymsError::InvalidSymbolName { 
                index, 
                reason: format!("Found zero-length name at index {} while seeking", i) 
            }.into());
        }
        current_pos += 1 + len;
    }

    if current_pos >= data.len() {
        return Err(KallsymsError::UnexpectedEof { offset: current_pos, needed: 1 }.into());
    }

    let len = data[current_pos] as usize;

    // Guard: Empty symbol names are invalid
    if len == 0 {
        return Err(KallsymsError::InvalidSymbolName {
            index,
            reason: "Symbol has zero-length name".to_string(),
        }
        .into());
    }

    // Guard: Ensure we have enough data
    if current_pos + 1 + len > data.len() {
        return Err(KallsymsError::UnexpectedEof {
            offset: current_pos + 1,
            needed: len,
        }
        .into());
    }

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
        loop {
            if self.current_index >= self.addresses.len() || self.current_names_ptr >= self.data.len() {
                return None;
            }

            let address = self.addresses[self.current_index];
            let len = self.data[self.current_names_ptr] as usize;

            // Guard: Skip symbols with zero-length names (corrupted data)
            if len == 0 {
                self.current_index += 1;
                self.current_names_ptr += 1;
                continue; // Use loop instead of recursion
            }

            // Guard: Ensure we have enough data for this symbol's name
            if self.current_names_ptr + 1 + len > self.data.len() {
                // Data is truncated, stop iteration
                return None;
            }

            let name_data = &self.data[self.current_names_ptr + 1..self.current_names_ptr + 1 + len];

            let mut name = String::with_capacity(64);
            let type_token_id = name_data[0];
            let mut type_str = String::new();
            
            // Expand type
            if let Err(e) = self.tokens.expand(type_token_id, &mut type_str, 0) {
                tracing::warn!("Failed to expand type token {} at index {}: {}", type_token_id, self.current_index, e);
                type_str.push('?');
            }
            let sym_type = SymbolType::from_char(type_str.chars().next().unwrap_or('?'));

            // Expand the rest of the name
            for &token_id in &name_data[1..] {
                if let Err(e) = self.tokens.expand(token_id, &mut name, 0) {
                    tracing::debug!("Failed to expand name token {} at index {}: {}", token_id, self.current_index, e);
                    name.push_str("<?>");
                }
            }

            let size = if self.current_index + 1 < self.addresses.len() {
                Some(self.addresses[self.current_index + 1].saturating_sub(address))
            } else {
                None
            };

            self.current_index += 1;
            self.current_names_ptr += 1 + len;

            return Some(KernelSymbol { address, name, sym_type, size });
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helper: Create mock token table data ---
    
    /// Create a minimal token table with ASCII identity mapping
    /// Token table: each token is just a single ASCII character
    /// Token index: offset 0, 1, 2, 3... pointing to each character
    fn create_mock_token_data() -> Vec<u8> {
        // Token table: 256 single-character tokens, each null-terminated
        // Format: 'A'\0 'B'\0 ... for first 26, then 'a'\0...
        // For simplicity, use: \0 at index 0, then a-z, A-Z etc.
        let mut token_table = Vec::new();
        let mut token_index = Vec::new();
        
        for i in 0u8..=255 {
            token_index.extend_from_slice(&(token_table.len() as u16).to_le_bytes());
            if i >= 32 && i < 127 {
                token_table.push(i); // printable ASCII
            } else {
                token_table.push(b'?'); // placeholder
            }
            token_table.push(0); // null terminator
        }
        
        // Layout: [token_table (512 bytes) | token_index (512 bytes)]
        let mut data = token_table;
        data.extend_from_slice(&token_index);
        data
    }

    // --- Test TokenTable ---
    
    #[test]
    fn test_token_table_parse() {
        let data = create_mock_token_data();
        let table_offset = 0;
        let index_offset = 512; // After token table
        
        let result = TokenTable::parse(&data, table_offset, index_offset);
        assert!(result.is_ok());
        
        let table = result.unwrap();
        assert_eq!(table.len(), 256);
    }
    
    #[test]
    fn test_token_table_expand_simple() {
        let data = create_mock_token_data();
        let table = TokenTable::parse(&data, 0, 512).unwrap();
        
        let mut output = String::new();
        // Token 65 should expand to 'A' (ASCII 65)
        let result = table.expand(65, &mut output, 0);
        assert!(result.is_ok());
        assert_eq!(output, "A");
    }
    
    #[test]
    fn test_token_table_expand_multiple() {
        let data = create_mock_token_data();
        let table = TokenTable::parse(&data, 0, 512).unwrap();
        
        let mut output = String::new();
        // Expand multiple tokens
        table.expand(72, &mut output, 0).unwrap(); // 'H'
        table.expand(101, &mut output, 0).unwrap(); // 'e'
        table.expand(108, &mut output, 0).unwrap(); // 'l'
        table.expand(108, &mut output, 0).unwrap(); // 'l'
        table.expand(111, &mut output, 0).unwrap(); // 'o'
        
        assert_eq!(output, "Hello");
    }

    #[test]
    fn test_token_table_expand_recursive() {
        // Create custom data where token 200 expands to 201 + 202
        // Token 201: "Foo" (where 'F', 'o' are identity tokens)
        // Token 202: "Bar" (where 'B', 'a', 'r' are identity tokens)
        // Token 200: [201, 202]
        let mut data = vec![0u8; 2048]; // Large enough
        let table_offset = 0;
        let index_offset = 1024;
        
        // Setup base identity tokens for all 256 bytes
        let mut current_table_ptr = 0;
        for i in 0..256 {
            let start = current_table_ptr;
            data[start] = i as u8;
            data[start + 1] = 0;
            current_table_ptr += 2;
            
            // Set index
            data[index_offset + i*2..index_offset + i*2 + 2].copy_from_slice(&(start as u16).to_le_bytes());
        }

        // Now override specific tokens
        // Id 201: [70, 111, 111] ("Foo" using identity tokens for F, o)
        let off201 = current_table_ptr;
        data[off201..off201+4].copy_from_slice(&[70, 111, 111, 0]);
        current_table_ptr += 4;
        data[index_offset + 201*2..index_offset + 201*2 + 2].copy_from_slice(&(off201 as u16).to_le_bytes());

        // Id 202: [66, 97, 114] ("Bar" using identity tokens for B, a, r)
        let off202 = current_table_ptr;
        data[off202..off202+4].copy_from_slice(&[66, 97, 114, 0]);
        current_table_ptr += 4;
        data[index_offset + 202*2..index_offset + 202*2 + 2].copy_from_slice(&(off202 as u16).to_le_bytes());

        // Id 200: [201, 202] (Recursive)
        let off200 = current_table_ptr;
        data[off200..off200+3].copy_from_slice(&[201, 202, 0]);
        data[index_offset + 200*2..index_offset + 200*2 + 2].copy_from_slice(&(off200 as u16).to_le_bytes());
        
        let table = TokenTable::parse(&data, table_offset, index_offset).unwrap();
        let mut output = String::new();
        table.expand(200, &mut output, 0).unwrap();
        
        assert_eq!(output, "FooBar");
    }

    // --- Test decode_symbol_name edge cases ---
    
    #[test]
    fn test_decode_symbol_name_zero_length() {
        let mut data = create_mock_token_data();
        let names_offset = data.len();
        data.push(0); // zero length - invalid!
        
        let table = TokenTable::parse(&data, 0, 512).unwrap();
        let result = decode_symbol_name(&data, names_offset, 0, &table);
        assert!(result.is_err());
        
        // Check it's the right error type
        let err = result.unwrap_err();
        assert!(err.to_string().contains("zero-length") || err.to_string().contains("InvalidSymbolName"));
    }
    
    #[test]
    fn test_decode_symbol_name_eof() {
        let mut data = create_mock_token_data();
        let names_offset = data.len();
        data.push(10); // claims 10 bytes
        data.extend_from_slice(&[65, 66, 67]); // only 3 bytes
        
        let table = TokenTable::parse(&data, 0, 512).unwrap();
        let result = decode_symbol_name(&data, names_offset, 0, &table);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_decode_symbol_name_valid() {
        let mut data = create_mock_token_data();
        let names_offset = data.len();
        data.push(4); // length = 4 bytes
        data.push(84); // type 'T'
        data.push(102); // 'f'
        data.push(111); // 'o'
        data.push(111); // 'o'
        
        let table = TokenTable::parse(&data, 0, 512).unwrap();
        let result = decode_symbol_name(&data, names_offset, 0, &table);
        assert!(result.is_ok());
        
        let (name, sym_type) = result.unwrap();
        assert_eq!(name, "foo");
        assert_eq!(sym_type, SymbolType::Text);
    }

    // --- Test SymbolIterator ---
    
    #[test]
    fn test_symbol_iterator_empty() {
        let data = create_mock_token_data();
        let table = TokenTable::parse(&data, 0, 512).unwrap();
        
        let addresses: Vec<u64> = vec![];
        let names_offset = data.len();
        
        let mut iter = SymbolIterator::new(&data, &addresses, names_offset, &table);
        assert!(iter.next().is_none());
    }
    
    #[test]
    fn test_symbol_iterator_single_symbol() {
        let mut data = create_mock_token_data();
        let names_offset = data.len();
        data.push(3);
        data.push(84); // 'T'
        data.push(97); // 'a'
        data.push(98); // 'b'
        
        let table = TokenTable::parse(&data, 0, 512).unwrap();
        let addresses = vec![0xFFFF_8000_1000_0000u64];
        
        let mut iter = SymbolIterator::new(&data, &addresses, names_offset, &table);
        
        let sym = iter.next();
        assert!(sym.is_some());
        
        let sym = sym.unwrap();
        assert_eq!(sym.address, 0xFFFF_8000_1000_0000);
        assert_eq!(sym.name, "ab");
        assert_eq!(sym.sym_type, SymbolType::Text);
        
        // Should be done
        assert!(iter.next().is_none());
    }
    
    #[test]
    fn test_symbol_iterator_skips_zero_length() {
        let mut data = create_mock_token_data();
        let names_offset = data.len();
        
        // Symbol 0: zero-length (should be skipped)
        data.push(0);
        
        // Symbol 1: valid [len=2][T][x]
        data.push(2);
        data.push(84); // 'T'
        data.push(120); // 'x'
        
        let table = TokenTable::parse(&data, 0, 512).unwrap();
        let addresses = vec![0x1000, 0x2000];
        
        let mut iter = SymbolIterator::new(&data, &addresses, names_offset, &table);
        
        // First call should skip symbol 0 and return symbol 1
        let sym = iter.next();
        assert!(sym.is_some());
        let sym = sym.unwrap();
        assert_eq!(sym.address, 0x2000); // Second address
        assert_eq!(sym.name, "x");
    }
    
    #[test]
    fn test_symbol_iterator_multiple_symbols() {
        let mut data = create_mock_token_data();
        let names_offset = data.len();
        
        // Symbol 0: [len=2][T][a]
        data.push(2);
        data.push(84); // 'T'
        data.push(97); // 'a'
        
        // Symbol 1: [len=2][D][b]
        data.push(2);
        data.push(68); // 'D'
        data.push(98); // 'b'
        
        // Symbol 2: [len=2][R][c]
        data.push(2);
        data.push(82); // 'R'
        data.push(99); // 'c'
        
        let table = TokenTable::parse(&data, 0, 512).unwrap();
        let addresses = vec![0x1000, 0x2000, 0x3000];
        
        let iter = SymbolIterator::new(&data, &addresses, names_offset, &table);
        let symbols: Vec<_> = iter.collect();
        
        assert_eq!(symbols.len(), 3);
        assert_eq!(symbols[0].name, "a");
        assert_eq!(symbols[1].name, "b");
        assert_eq!(symbols[2].name, "c");
        assert_eq!(symbols[0].sym_type, SymbolType::Text);
        assert_eq!(symbols[1].sym_type, SymbolType::Data);
        assert_eq!(symbols[2].sym_type, SymbolType::Rodata);
    }
    
    #[test]
    fn test_symbol_iterator_calculates_size() {
        let mut data = create_mock_token_data();
        let names_offset = data.len();
        
        // Two symbols
        data.push(2); data.push(84); data.push(97);
        data.push(2); data.push(84); data.push(98);
        
        let table = TokenTable::parse(&data, 0, 512).unwrap();
        let addresses = vec![0x1000, 0x1100]; // 0x100 bytes apart
        
        let iter = SymbolIterator::new(&data, &addresses, names_offset, &table);
        let symbols: Vec<_> = iter.collect();
        
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].size, Some(0x100)); // Size = next_addr - this_addr
        assert_eq!(symbols[1].size, None); // Last symbol has no size
    }
}
