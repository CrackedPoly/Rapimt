use std::{
    fmt::{Binary, Debug, Display, Formatter},
    ops::BitAnd,
};

use bitvec::{field::BitField, prelude::*};
use funty::Unsigned;

use crate::r#match::family::constant;

/// Match condition for a field.
#[derive(Copy, Clone, Debug)]
pub enum Match<U: Unsigned> {
    ExactMatch { value: U },
    TernaryMatch { value: U, mask: U },
    RangeMatch { low: U, high: U },
}

/// FieldMatch contains the name and the condition of a match in a field.
#[derive(Copy, Clone, Debug)]
pub struct FieldMatch<'a, U: Unsigned> {
    pub field: &'a str,
    pub cond: Match<U>,
}

/// Ternary bit string representing an entire header match. 
///
/// Bits are stored in little-endian. For example, fields declared as "tag: 0-16, dip: 16-32"
/// encodes dip=192.168.0.0/24, tag=2 as `0100000000000000*******000000000001010100000011`.
#[derive(Eq, PartialEq, Hash, Default, Clone, Copy)]
pub struct MaskedValue {
    pub value:
        BitArray<[constant::HeaderBitStore; constant::HEADERSTORENUM], constant::HeaderBitOrder>,
    pub mask:
        BitArray<[constant::HeaderBitStore; constant::HEADERSTORENUM], constant::HeaderBitOrder>,
}

impl MaskedValue {
    pub fn store<U: Unsigned>(value: U, mask: U, from: usize, to: usize) -> Self {
        let mut v = BitArray::ZERO;
        let mut m = BitArray::ZERO;
        v[from..to].store_le(value);
        m[from..to].store_le(mask);
        Self { value: v, mask: m }
    }
}

impl Binary for MaskedValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:b}/{:b}", self.value, self.mask)
    }
}

/// Display the MaskedValue in a human-readable (big-endian) format.
///
/// For example, fields declared as "tag: 0-16, dip: 16-32" encodes dip=192.168.0.0/24, tag=2, it
/// displays as `110000001010100000000000*******0000000000000010`.
impl Display for MaskedValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut ternary_bits_disp = [b'*'; constant::MAX_POS];
        for (i, bit) in ternary_bits_disp.iter_mut().rev().enumerate() {
            *bit = if !self.mask[i] {
                b'*'
            } else if self.value[i] {
                b'1'
            } else {
                b'0'
            };
        }
        write!(f, "{}", std::str::from_utf8(&ternary_bits_disp).unwrap())
    }
}

impl Debug for MaskedValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl BitAnd for MaskedValue {
    type Output = MaskedValue;
    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        debug_assert!(
            (self.mask & rhs.mask).not_any(),
            "{}, {} has overlap",
            self.mask,
            rhs.mask
        );
        MaskedValue {
            value: self.value | rhs.value,
            mask: self.mask | rhs.mask,
        }
    }
}

pub mod macros {
    use std::net::Ipv4Addr;

    use crate::r#match::raw_match::Match;

    const INET4_FAMILY_V4_LEN: u32 = u32::BITS;
    const INET4_FAMILY_V4_MASK: u32 = u32::MAX;

    /// Encode an IPv4 address with prefix into a ternary match.
    pub fn ipv4_to_match(value: &str) -> Match<u32> {
        let mut items = value.split('/');
        let ip_part = items.next().unwrap();
        let ip: u32 = if let Ok(num) = ip_part.parse::<u32>() {
            num
        } else {
            ip_part.parse::<Ipv4Addr>().unwrap().into()
        };
        let plen: u32 = items
            .next()
            .unwrap()
            .parse()
            .expect("Wrong format of IPv4 prefix");
        if plen == 0 {
            return Match::TernaryMatch { value: ip, mask: 0 };
        }
        let mask =
            (INET4_FAMILY_V4_MASK >> (INET4_FAMILY_V4_LEN - plen)) << (INET4_FAMILY_V4_LEN - plen);
        Match::TernaryMatch { value: ip, mask }
    }

    /// Create a FieldMatch with an IPv4 value.
    /// ```no_run
    /// use rapimt_core::{fm_ipv4_from};
    /// use rapimt_core::prelude::{ipv4_to_match, FieldMatch, Match};
    /// let _ = fm_ipv4_from!("dip", "192.168.1.0/24");
    /// let _ = fm_ipv4_from!("dip", "3232235776/32");
    /// let _ = fm_ipv4_from!("dip", "0/0");
    /// ```
    #[macro_export]
    macro_rules! fm_ipv4_from {
        ($field:expr, $value:expr) => {
            FieldMatch {
                field: $field,
                cond: ipv4_to_match($value),
            }
        };
    }

    /// Create a FieldMatch with an exact value.
    /// ```no_run
    /// use rapimt_core::{fm_exact_from, r#match::raw_match::{FieldMatch, Match}};
    /// let _ = fm_exact_from!("dport", 80u16);
    /// ```
    #[macro_export]
    macro_rules! fm_exact_from {
        ($field:expr, $value:expr) => {
            FieldMatch {
                field: $field,
                cond: Match::ExactMatch { value: $value },
            }
        };
    }

    /// Create a FieldMatch with a range value, both inclusive.
    /// ```no_run
    /// use rapimt_core::{fm_range_from, r#match::raw_match::{FieldMatch, Match}};
    /// let _ = fm_range_from!("sport", 80u16, 100u16);
    /// ```
    #[macro_export]
    macro_rules! fm_range_from {
        ($field:expr, $low:expr, $high:expr) => {
            FieldMatch {
                field: $field,
                cond: Match::RangeMatch {
                    low: $low,
                    high: $high,
                },
            }
        };
    }
}
