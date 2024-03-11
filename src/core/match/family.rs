//! # Match family module
//!
//! ## What is a match family?
//! In packet processing, a match family is a set of fields that can be
//! matched against a packet. For example, in the TCP 4-tuple match family
//! [TcpT4Family](MatchFamily::TcpT4Family), the fields are (s_port, d_port, s_ip, d_ip).
//! The family declares these fields and provides a method to
//! [parse](FamilyDecl::parse) a [FieldValue](FieldValue) into a [FieldMatch](FieldMatch).
//!
//! ## What is it used for?
//! We only need to know what fields are in a match family.
//! [MatchEncoder](crate::core::MatchEncoder) uses the match family to directly
//! encode a field value into a predicate.
//!
//! ## Example
//! ```no_run
//! use crate::fast_imt::core::{Match, FieldValue, MatchFamily, FamilyDecl};
//!
//! let family = MatchFamily::TcpT4Family;
//! let fv = FieldValue {
//!     field: "dip".to_string(),
//!     value: "192.168.1.0/24".to_string(),
//! };
//! let fm = family.parse(fv);
//! // fm.cond is parsed into a Match::TernaryMatch
//! assert!(matches!(fm.cond, Match::TernaryMatch { .. }));
//! ```

#[macro_export]
macro_rules! fv_from {
    ($from:expr, $to:expr) => {
        FieldValue {
            field: $from.to_string(),
            value: $to.to_string(),
        }
    };
}
#[allow(unused_imports)]
pub(crate) use fv_from;

#[derive(Clone, Debug)]
pub struct FieldValue {
    pub field: String,
    pub value: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum Match {
    ExactMatch { value: u128 },
    TernaryMatch { value: u128, mask: u128 },
    RangeMatch { low: u128, high: u128 },
}

#[derive(Clone, Debug)]
pub struct FieldMatch {
    pub field: String,
    pub cond: Match,
}

#[derive(Clone, Debug)]
pub struct FieldDeclaration {
    pub name: &'static str,
    pub from: u128,
    pub to: u128,
}

pub trait FamilyDecl {
    fn get_max_pos(&self) -> u128;
    fn get_field_declaration(&self, name: String) -> Option<FieldDeclaration>;
    fn parse(&self, fv: FieldValue) -> FieldMatch;
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum MatchFamily {
    /// # The IPv4 match family
    /// This family only contains the destination IP field.
    /// ## Field names
    /// - "dip": destination IP
    /// ## Field value formats
    /// - ExactMatch: "192.168.1.1/32" or "3232235777/32"
    /// - TernaryMatch: "192.168.1.0/24" or "3232235776/24"
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
    /// - ExactMatch: "80"
    /// ### IP fields
    /// - ExactMatch: "192.168.1.1/32" or "3232235777/32"
    /// - TernaryMatch: "192.168.1.0/24" or "3232235776/24"
    TcpT4Family,
}

impl MatchFamily {
    const INET4_FIELDS: [FieldDeclaration; 1] = [FieldDeclaration {
        name: "dip",
        from: 0,
        to: 31,
    }];
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
            MatchFamily::Inet4Family => MatchFamily::INET4_FIELDS.last().unwrap().to + 1,
            MatchFamily::TcpT4Family => MatchFamily::TCP_FIELDS.last().unwrap().to + 1,
        }
    }

    fn get_field_declaration(&self, name: String) -> Option<FieldDeclaration> {
        let fields = self.get_fields();
        for f in fields.iter() {
            if f.name == name {
                return Some(f.clone());
            }
        }
        return None;
    }

    fn parse(&self, fv: FieldValue) -> FieldMatch {
        let fields = self.get_fields();
        for f in fields.iter() {
            if f.name == fv.field {
                match f.name {
                    "dip" | "sip" => {
                        return FieldMatch {
                            field: fv.field,
                            cond: ipv4_to_match(fv.value),
                        };
                    }
                    "sport" | "dport" => {
                        return FieldMatch {
                            field: fv.field,
                            cond: Match::ExactMatch {
                                value: fv.value.parse().unwrap(),
                            },
                        };
                    }
                    _ => {
                        panic!("Unsupported field type");
                    }
                }
            }
        }
        panic!("Unsupported field type");
    }
}

const INET4_FAMILY_V4_LEN: u128 = 32;
const INET4_FAMILY_V4_MASK: u128 = (1 << INET4_FAMILY_V4_LEN) - 1;

fn ipv4_to_match(value: String) -> Match {
    let items: Vec<_> = value.split('/').collect();
    let plen: u128 = items[1].parse().expect("Wrong format of IPv4 prefix");
    let ip: u128 = if let Ok(num) = items[0].parse() {
        num
    } else {
        let octets: Vec<u128> = items[0].split('.').map(|s| s.parse().unwrap()).collect();
        (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    };
    let mask =
        (INET4_FAMILY_V4_MASK >> (INET4_FAMILY_V4_LEN - plen)) << (INET4_FAMILY_V4_LEN - plen);
    Match::TernaryMatch { value: ip, mask }
}
