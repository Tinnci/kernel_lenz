use super::super::traits::{AddressParser, RelativeAddressParser};
use crate::Result;
use scroll::{Pread, LE};

pub struct RelativeParser;

impl AddressParser for RelativeParser {
    fn parse_addresses(_data: &[u8], _offset: usize, _count: usize) -> Result<Vec<u64>> {
        Err(crate::kallsyms::KallsymsError::UnsupportedFormat(
            "Use parse_addresses_with_base for relative format".into(),
        )
        .into())
    }

    fn entry_size() -> usize {
        4
    }

    fn can_parse(_data: &[u8], _offset: usize, _sample_count: usize) -> bool {
        true
    }
}

impl RelativeAddressParser for RelativeParser {
    fn parse_addresses_with_base(
        data: &[u8],
        offset: usize,
        count: usize,
        base: u64,
    ) -> Result<Vec<u64>> {
        let mut addrs = Vec::with_capacity(count);
        for i in 0..count {
            let rel_offset: i32 = data
                .pread_with(offset + (i * 4), LE)
                .map_err(|_| crate::kallsyms::KallsymsError::UnexpectedEof { offset, needed: 4 })?;

            // Result = base + offset (signed)
            addrs.push(base.wrapping_add(rel_offset as i64 as u64));
        }
        Ok(addrs)
    }
}
