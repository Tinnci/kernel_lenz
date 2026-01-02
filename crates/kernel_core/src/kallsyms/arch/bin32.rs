use super::super::traits::AddressParser;
use crate::Result;
use scroll::{Pread, LE};

pub struct Bin32Parser;

impl AddressParser for Bin32Parser {
    fn parse_addresses(data: &[u8], offset: usize, count: usize) -> Result<Vec<u64>> {
        let mut addrs = Vec::with_capacity(count);
        for i in 0..count {
            let addr: u32 = data
                .pread_with(offset + (i * 4), LE)
                .map_err(|_| crate::kallsyms::KallsymsError::UnexpectedEof { offset, needed: 4 })?;
            addrs.push(addr as u64);
        }
        Ok(addrs)
    }

    fn entry_size() -> usize {
        4
    }

    fn can_parse(_data: &[u8], _offset: usize, _sample_count: usize) -> bool {
        // Simple heuristic check could be added here
        true
    }
}
