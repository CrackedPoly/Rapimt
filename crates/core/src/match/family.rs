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
use bitvec::prelude::*;

#[derive(Clone, Debug)]
pub struct FieldDeclaration {
    pub name: &'static str,
    pub from: u32,
    pub to: u32,
}

pub trait FamilyDecl {
    fn get_max_pos(&self) -> u128;
    fn get_field_declaration(&self, name: String) -> Option<&FieldDeclaration>;
}

pub type Inet4BitStore = u32;
pub const INET4STORENUM: usize = 1;
pub const INET4MAXPOS: usize = 32;

pub type TcpT4BitStore = u32;
pub const TCPT4STORENUM: usize = 3;
pub const TCPT4MAXPOS: usize = 96;

pub type HeaderBitOrder = Msb0;
// #[cfg(target_header="inet4")]
pub type HeaderBitStore = Inet4BitStore;
// #[cfg(target_header="inet4")]
pub const HEADERSTORENUM: usize = INET4STORENUM;
// #[cfg(target_header="inet4")]
pub const MAX_POS: usize = INET4MAXPOS;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum MatchFamily {
    /// # The IPv4 match family
    /// This family only contains the destination IP field.
    /// ## Field names
    /// - "dip": destination IP
    /// ## Field value formats
    /// - ExactMatch
    /// - TernaryMatch
    Inet4Family,
    /// # The TCP 4-tuple match family
    /// This family contains the source port, destination port, source IP, and
    /// destination IP fields.
    /// ## Field names
    /// - "sport": source port
    /// - "dport": destination port
    /// - "sip": source IP
    /// - "dip": destination IP
    /// ## Field value formats
    /// ### Port fields
    /// - ExactMatch
    /// - RangeMatch
    /// ### IP fields
    /// - ExactMatch: TernaryMatch(/32 prefix)
    /// - TernaryMatch
    TcpT4Family,
}

impl MatchFamily {
    const INET4_FIELDS: [FieldDeclaration; 1] = [FieldDeclaration {
        name: "dip",
        from: 0,
        to: 31,
    }];
    const INET4_MAX_POS: u128 = 32;

    const TCP_FIELDS: [FieldDeclaration; 4] = [
        FieldDeclaration {
            name: "sport",
            from: 0,
            to: 15,
        },
        FieldDeclaration {
            name: "dport",
            from: 16,
            to: 31,
        },
        FieldDeclaration {
            name: "sip",
            from: 32,
            to: 63,
        },
        FieldDeclaration {
            name: "dip",
            from: 64,
            to: 95,
        },
    ];
    const TCPT4_MAX_POS: u128 = 96;

    fn get_fields(&self) -> &'static [FieldDeclaration] {
        match self {
            MatchFamily::Inet4Family => &MatchFamily::INET4_FIELDS,
            MatchFamily::TcpT4Family => &MatchFamily::TCP_FIELDS,
        }
    }
}

impl FamilyDecl for MatchFamily {
    fn get_max_pos(&self) -> u128 {
        match self {
            MatchFamily::Inet4Family => MatchFamily::INET4_MAX_POS,
            MatchFamily::TcpT4Family => MatchFamily::TCPT4_MAX_POS,
        }
    }

    fn get_field_declaration(&self, name: String) -> Option<&FieldDeclaration> {
        let fields = self.get_fields();
        fields.iter().find(|f| f.name == name)
    }
}
