//! # Match family module
//!
//! ## What is a match family?
//! In packet processing, a match family is a set of fields that can be
//! matched against a packet. For example, in the TCP 4-tuple match family
//! [TcpT4Family](MatchFamily::TcpT4Family), the fields are (sport, dport, sip, dip).
//!
//! ## What is it used for?
//! We only need to know what fields are in a match family.
//! [MatchEncoder](crate::core::r#match::MatchEncoder) uses the match family to
//! directly encode a field value into a predicate.
//!
//! ## Example
//! ```no_run
//! use rapimt_core::{
//!     fm_ipv4_from, ipv4_to_match,
//!     r#match::{Match, FieldMatch, family::MatchFamily},
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

pub trait FamilyDecl {
    fn get_field_declaration(&self, name: &str) -> Option<FieldDeclaration>;
}

pub struct MatchFamily;

pub mod constant {
    use super::{MatchFamily, FamilyDecl, FieldDeclaration};
    use bitvec::order::Lsb0;

    include!(concat!(env!("OUT_DIR"), "/codegen.rs"));

    pub const GLOBAL_FAMILY: MatchFamily = MatchFamily;

    pub type HeaderBitOrder = Lsb0;
    pub type HeaderBitStore = u8;

    pub const HEADERSTORENUM: usize = MAX_POS / HeaderBitStore::BITS as usize;

    impl FamilyDecl for MatchFamily {
        fn get_field_declaration(&self, name: &str) -> Option<FieldDeclaration> {
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
}

