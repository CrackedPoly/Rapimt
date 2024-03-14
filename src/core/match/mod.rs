//! # Match
//!
//! ## Relations of important structs
//! ```text
//!                   FieldMatch
//!                       |
//!                       v
//! MatchFamily -> PredicateEngine
//!                       |
//!                       v
//!                    Predicate
//! ```
//!
//! ## Example
//! ```no_run
//! use fast_imt::core::r#match::{PredicateOp, PredicateEngine, MatchEncoder,
//! RuddyPredicateEngine, ipv4_to_match, FieldMatch};
//! use fast_imt::core::r#match::family::{MatchFamily};
//! use crate::fast_imt::fm_ipv4_from;
//!
//! // Initialize the engine
//! let mut engine = RuddyPredicateEngine::new();
//! let family = MatchFamily::TcpT4Family;
//! engine.init(1000, 100, family);
//!
//! // Encode
//! let matches1 = vec![fm_ipv4_from!("sip", "192.168.1.0/24"), fm_ipv4_from!("dip", "0.0.0.0/0")];
//! let (p1, _) = engine.encode_matches(matches1);
//! let matches2 = vec![fm_ipv4_from!("sip", "192.168.50.1/24"), fm_ipv4_from!("dip", "0.0.0.0/0")];
//! let (p2, _) = engine.encode_matches(matches2);
//!
//! // Operate
//! let p3 = p1 & p2;
//! p1.drop();
//! p2.drop();
//! ```

use family::{FamilyDecl, MatchFamily};
use rug::Integer;
use std::fmt::Display;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not, Sub, SubAssign};

pub mod engine;
pub mod family;
pub use engine::ruddy_engine::RuddyPredicateEngine;
pub use macros::ipv4_to_match;

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
pub struct MaskedValue {
  pub value: Integer,
  pub mask: Integer,
}

impl<'a> BitOr for &'a MaskedValue {
  type Output = MaskedValue;
  fn bitor(self, rhs: Self) -> Self::Output {
    MaskedValue {
      value: self.value.clone() | rhs.value.clone(),
      mask: self.mask.clone() | rhs.mask.clone(),
    }
  }
}

pub trait PredicateEngine<'a, P>: MatchEncoder<'a, P = P> + PredicateIO<'a, P = P> {}

pub trait Predicate: PredicateOp + Display {}

/// MatchEncoder parses field values and encodes them into predicates.
pub trait MatchEncoder<'a>
where
  Self: 'a,
{
  type P: Predicate + 'a;
  fn gc(&self) -> Option<usize>;
  fn one(&'a self) -> Self::P;
  fn zero(&'a self) -> Self::P;
  fn family(&self) -> &MatchFamily;
  fn _encode(&'a self, value: u128, mask: u128, from: u32, to: u32) -> Self::P;

  fn encode_match(&'a self, fm: FieldMatch) -> (Self::P, Vec<MaskedValue>) {
    let family = self.family();
    match family.get_field_declaration(fm.field) {
      Some(fdecl) => {
        let from = fdecl.from;
        let to = fdecl.to;
        return match fm.cond {
          Match::ExactMatch { value } => {
            let mask: u128 = (1 << (to - from + 1)) - 1;
            (
              self._encode(value, mask, from, to),
              vec![MaskedValue::from((value << from, mask << from))],
            )
          }
          Match::TernaryMatch { value, mask } => (
            self._encode(value, mask, from, to),
            vec![MaskedValue::from((value << from, mask << from))],
          ),
          Match::RangeMatch { mut low, high } => {
            let mask: u128 = (1 << (to - from + 1)) - 1;
            let mut vm_pairs = vec![];
            loop {
              let t_zeros = low.trailing_zeros();
              let mut inc: u128 = 1 << t_zeros;
              low = low + inc;
              while low - 1 > high {
                inc = inc >> 1;
                low = low - inc;
              }
              let t_zeros = inc.trailing_zeros();
              vm_pairs.push((low - inc, (mask >> t_zeros) << t_zeros));
              if low - 1 == high {
                break;
              }
            }
            let mut pred = self.zero();
            let mvs = vm_pairs
              .iter()
              .map(|(v, m)| {
                pred |= self._encode(*v, *m, from, to);
                MaskedValue::from((*v << from, *m << from))
              })
              .collect();
            (pred, mvs)
          }
        };
      }
      _ => (self.one(), vec![MaskedValue::from((0u32, 0u32))]),
    }
  }

  fn encode_matches(&'a self, fms: Vec<FieldMatch>) -> (Self::P, Vec<MaskedValue>) {
    let mut pred = self.zero();
    let mut mvs = vec![];
    for fm in fms {
      let (p, sub_mvs) = self.encode_match(fm);
      pred |= p;
      if mvs.is_empty() {
        mvs.extend(sub_mvs)
      } else {
        // do a cross product of mvs and sub_mvs
        let mut new_mvs = vec![];
        for mv in mvs.iter() {
          for sub_mv in sub_mvs.iter() {
            new_mvs.push(mv | sub_mv);
          }
        }
        mvs = new_mvs;
      }
    }
    (pred, mvs)
  }
}

/// PredicateIO enables serialization and deserialization of a predicate.
/// It is useful when local storing or remote transmitting predicates.
pub trait PredicateIO<'a>
where
  Self: 'a,
{
  type P: Predicate + 'a;
  /// Deserialize a predicate according to the buffer.
  fn read_buffer(&'a self, buffer: &Vec<u8>) -> Option<Self::P>;
  /// Serialize the predicate to the buffer.
  fn write_buffer(&'a self, pred: &Self::P, buffer: &mut Vec<u8>) -> Option<usize>;
}

/// [PredicateOp] is an important trait to operate on predicates.
/// # Methods
/// ## No-side-effect methods
/// - [==](PartialEq::eq) checks if two predicates are equal.
/// - [empty](PredicateOp::is_empty) checks if the predicate is empty.
/// ## Side effect methods
/// *Side effect* means the method either produces a new predicate or
/// consumes/drop existing predicates.
/// ### Logical operations
/// - [!](Not::not) returns a new predicate that is the negation of the predicate.
/// - [&](BitAnd::bitand) returns a new predicate that is the logical AND of
/// this predicate and the rhs predicate. The rhs predicate is not dropped.
/// You should drop it manually afterward.
/// - [&=](BitAndAssign::bitand_assign) updates the current predicate to be
/// the logical AND of this predicate and the rhs predicate. The rhs
/// predicate is dropped.
/// - [|](BitOr::bitor) returns a new predicate that is the logical OR of this
/// predicate and the rhs predicate. The rhs predicate is not dropped. You
/// should drop it manually afterward.
/// - [|=](BitOrAssign::bitor_assign) updates the current predicate to be the
/// logical OR of this predicate and the rhs predicate. The rhs predicate is
/// dropped.
/// - [-](Sub::sub) returns a new predicate that is the logical difference of
/// this predicate and the rhs predicate. The rhs predicate is not dropped.
/// You should drop it manually afterward.
/// - [-=](SubAssign::sub_assign) updates the current predicate to be the
/// logical difference of this predicate and the rhs predicate. The rhs
/// predicate is dropped.
/// ### Drop
/// [drop](PredicateOp::drop) is a method to consume the predicate. When a valid
/// predicate is no longer needed, you should drop it.
/// - This method is called inside ***op=*** methods to consume the rhs operand.
/// # Examples
/// This example demonstrates how to use the `&` and `&=` like methods.
/// ```no_run
/// use fast_imt::core::r#match::{RuddyPredicateEngine, FieldMatch,
/// MatchEncoder, PredicateOp, Predicate, ipv4_to_match};
/// use fast_imt::core::r#match::family::{MatchFamily};
/// use crate::fast_imt::fm_ipv4_from;
///
/// fn get_predicates<T: Predicate>(engine: &dyn MatchEncoder<P=T>) -> [T; 3] {
///     [
///         engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/24")).0,
///         engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/25")).0,
///         engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/26")).0,
///     ]
/// }
///
/// let family = MatchFamily::Inet4Family;
/// let mut engine = RuddyPredicateEngine::new();
/// engine.init(100, 10, family);
///
/// // --- Example of `op_to` methods
/// // get p1 \and p2 \and p3
/// // p2, p3 are dropped in &= and should no longer be used afterward
/// let [mut p1, p2, p3] = get_predicates(&engine);
/// let p123 = {
///     p1 &= p2;
///     p1 &= p3;
///     p1
/// };
///
/// // --- Example of `op` methods
/// // get the cross product of [p1, p2, p3] and [p1, p2, p3]
/// let pls = Vec::from(get_predicates(&engine));
/// let prs = Vec::from(get_predicates(&engine));
/// let mut res = vec![];
/// for pl in pls.iter() {
///     for pr in prs.iter() {
///         res.push(*pl & *pr);
///    }
/// }
/// // since & method do not consume the operands, we need to drop them manually
/// pls.into_iter().for_each(|p| p.drop());
/// prs.into_iter().for_each(|p| p.drop());
/// ```
pub trait PredicateOp:
  PartialEq<Self> + Not + BitAnd + BitAndAssign + BitOr + BitOrAssign + Sub + SubAssign
where
  Self: Copy,
{
  fn is_empty(&self) -> bool;
  fn drop(self);
}

macro_rules! impl_masked_value_from {
($($t:ty),*) => {
        $(
            impl From<($t, $t)> for MaskedValue {
                fn from(pair: ($t, $t)) -> Self {
                    MaskedValue {
                        value: Integer::from(pair.0),
                        mask: Integer::from(pair.1),
                    }
                }
            }
        )*
    };
}

impl_masked_value_from!(u8, u16, u32, u64, u128);

pub mod macros {
  use crate::core::r#match::Match;

  const INET4_FAMILY_V4_LEN: u128 = 32;
  const INET4_FAMILY_V4_MASK: u128 = (1 << INET4_FAMILY_V4_LEN) - 1;

  pub fn ipv4_to_match(value: String) -> Match {
    let items: Vec<_> = value.split('/').collect();
    let plen: u128 = items[1].parse().expect("Wrong format of IPv4 prefix");
    let ip: u128 = if let Ok(num) = items[0].parse() {
      num
    } else {
      let octets: Vec<u128> = items[0].split('.').map(|s| s.parse().unwrap()).collect();
      (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    };
    let mask = (INET4_FAMILY_V4_MASK >> (INET4_FAMILY_V4_LEN - plen)) << (INET4_FAMILY_V4_LEN - plen);
    Match::TernaryMatch { value: ip, mask }
  }

  /// Create a FieldMatch with an IPv4 value.
  /// ```no_run
  /// use fast_imt::fm_ipv4_from;
  /// use fast_imt::core::r#match::{FieldMatch, Match, ipv4_to_match};
  /// let _ = fm_ipv4_from!("dip", "192.168.1.0/24");
  /// let _ = fm_ipv4_from!("dip", "3232235776/32");
  /// let _ = fm_ipv4_from!("dip", "0/0");
  /// ```
  #[macro_export]
  macro_rules! fm_ipv4_from {
    ($field:expr, $value:expr) => {
      FieldMatch {
        field: $field.to_owned(),
        cond: ipv4_to_match($value.to_owned()),
      }
    };
  }
  #[allow(unused_imports)]
  pub(crate) use fm_ipv4_from;

  /// Create a FieldMatch with an exact value.
  /// ```no_run
  /// use fast_imt::fm_exact_from;
  /// use fast_imt::core::r#match::{FieldMatch, Match, ipv4_to_match};
  /// let _ = fm_exact_from!("dport", 80);
  /// ```
  #[macro_export]
  macro_rules! fm_exact_from {
    ($field:expr, $value:expr) => {
      FieldMatch {
        field: $field.to_owned(),
        cond: Match::ExactMatch { value: $value },
      }
    };
  }
  #[allow(unused_imports)]
  pub(crate) use fm_exact_from;

  /// Create a FieldMatch with a range value, both inclusive.
  /// ```no_run
  /// use fast_imt::fm_range_from;
  /// use fast_imt::core::r#match::{FieldMatch, Match, ipv4_to_match};
  /// let _ = fm_range_from!("sport", 80, 100);
  /// ```
  #[macro_export]
  macro_rules! fm_range_from {
    ($field:expr, $low:expr, $high:expr) => {
      FieldMatch {
        field: $field.to_owned(),
        cond: Match::RangeMatch {
          low: $low,
          high: $high,
        },
      }
    };
  }
  #[allow(unused_imports)]
  pub(crate) use fm_range_from;
}
