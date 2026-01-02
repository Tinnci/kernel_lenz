//! Architecture-specific address parsers.

pub mod bin32;
pub mod bin64;
pub mod relative;

pub use bin32::Bin32Parser;
pub use bin64::Bin64Parser;
pub use relative::RelativeParser;
