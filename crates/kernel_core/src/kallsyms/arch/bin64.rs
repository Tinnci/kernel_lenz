use super::super::traits::AddressParser;
use crate::Result;
use scroll::{Pread, LE};

pub struct Bin64Parser;

impl AddressParser for Bin64Parser {
    fn parse_addresses(data: &[u8], offset: usize, count: usize) -> Result<Vec<u64>> {
        let mut addrs = Vec::with_capacity(count);
        for i in 0..count {
            let addr: u64 = data
                .pread_with(offset + (i * 8), LE)
                .map_err(|_| crate::kallsyms::KallsymsError::UnexpectedEof { offset, needed: 8 })?;
            addrs.push(addr);
        }
        Ok(addrs)
    }

    fn entry_size() -> usize {
        8
    }

    fn can_parse(_data: &[u8], _offset: usize, _sample_count: usize) -> bool {
        true
    }
}
