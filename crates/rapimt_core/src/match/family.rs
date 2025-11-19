//! # Match family module
//!
//! ```no_run
//! use rapimt_core::fm_ipv4_from;
//! use rapimt_core::prelude::{
//!     ipv4_to_match, Match, FieldMatch
//! };
//!
//! let fm = fm_ipv4_from!("dip", "192.168.1.0/24");
//! // fm.cond is parsed into a Match::TernaryMatch
//! assert!(matches!(fm.cond, Match::TernaryMatch { .. }));
//! ```

/// Describes a field in a match family.
#[derive(Copy, Clone, Debug)]
pub struct FieldDeclaration {
    pub name: &'static str,
    pub from: usize,
    pub to: usize,
}

/// (codegen) Decide field names and bit positions.
pub mod constant {
    use super::FieldDeclaration;
    use bitvec::order::Lsb0;

    include!(concat!(env!("OUT_DIR"), "/codegen.rs"));

    pub type HeaderBitOrder = Lsb0;
    pub type HeaderBitStore = u8;

    pub const HEADERSTORENUM: usize = MAX_POS / HeaderBitStore::BITS as usize;

    pub fn get_field_declaration(name: &str) -> Option<FieldDeclaration> {
        if let Some((field_name, (from, to))) = FIELD_MAP.get_entry(name) {
            Some(FieldDeclaration {
                name: field_name,
                from: *from,
                to: *to,
            })
        } else {
            None
        }
    }
}
