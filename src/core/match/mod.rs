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
//! use fast_imt::core::r#match::{Predicate, PredicateEngine, MatchEncoder,
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
//! ```

use std::fmt::{Debug, Display, Formatter};
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not, Sub, SubAssign};

use rug::Integer;

pub use engine::ruddy_engine::RuddyPredicateEngine;
use family::{FamilyDecl, MatchFamily};
pub use macros::ipv4_to_match;

use crate::io::CodedAction;

pub mod engine;
pub mod family;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum Match {
  ExactMatch { value: u128 },
  TernaryMatch { value: u128, mask: u128 },
  RangeMatch { low: u128, high: u128 },
}

#[derive(Debug)]
pub struct FieldMatch {
  pub field: String,
  pub cond: Match,
}

#[derive(Eq, PartialEq, Debug)]
pub struct MaskedValue {
  pub value: Integer,
  pub mask: Integer,
}

impl<'a> BitOr for &'a MaskedValue {
  type Output = MaskedValue;
  fn bitor(self, rhs: Self) -> Self::Output {
    MaskedValue {
      value: Integer::from(&self.value | &rhs.value),
      mask: Integer::from(&self.mask & &rhs.mask),
    }
  }
}

/// PredicateEngine enables serialization and deserialization of a predicate.
/// It is useful when local storing or remote transmitting predicates.
pub trait PredicateEngine<'a, P: PredicateInner>: MatchEncoder<'a, P = P> {
  /// Deserialize a predicate according to the buffer.
  fn read_buffer(&'a self, buffer: &Vec<u8>) -> Option<Predicate<Self::P>>;
  /// Serialize the predicate to the buffer.
  fn write_buffer(&'a self, pred: &Predicate<Self::P>, buffer: &mut Vec<u8>) -> Option<usize>;
}

/// MatchEncoder parses field values and encodes them into predicates.
pub trait MatchEncoder<'a>
where
  Self: 'a,
{
  type P: PredicateInner + 'a;
  fn gc(&self) -> Option<usize>;
  fn one(&'a self) -> Predicate<Self::P>;
  fn zero(&'a self) -> Predicate<Self::P>;
  fn family(&self) -> &MatchFamily;
  fn _encode(&'a self, value: u128, mask: u128, from: u32, to: u32) -> Predicate<Self::P>;

  fn encode_match(&'a self, fm: FieldMatch) -> (Predicate<Self::P>, Vec<MaskedValue>) {
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

  fn encode_matches(&'a self, fms: Vec<FieldMatch>) -> (Predicate<Self::P>, Vec<MaskedValue>) {
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

pub trait PredicateInner: Copy + Eq + PartialEq + Ord + PartialOrd + Display + Debug {
  fn not(&self) -> Self;
  fn and(&self, rhs: &Self) -> Self;
  fn or(&self, rhs: &Self) -> Self;
  fn comp(&self, rhs: &Self) -> Self;
  fn is_empty(&self) -> bool;
  fn _ref(self) -> Self;
  fn _deref(&self);
}

/// # Predicate
/// ## Methods
/// - [!] : logical NOT
/// - [&] : logical AND
/// - [|] : logical OR
/// - [-] : logical DIFF
/// - [==] : equality
/// - [is_empty] : check if the predicate is empty
/// ## Operations explained
/// Predicate hide reference counting inside, it is coherent with the Rust
/// ownership model. When a predicate is moved, it is de-referenced
/// automatically and may be garbage collected afterward. When a new
/// predicate is produced, it is referenced automatically.
///
/// ### Unary operation has two forms
/// - `let b = !a`: `a` is moved
/// - `let b = !&a`: `a` is NOT moved
/// ### Binary operations have three forms
/// `&`, `|`, `-` have the same forms. Take `&` for example:
/// - `let c = a & b`: `a` and `b` are moved
/// - `let c = a & &b`: `a` is moved
/// - `let c = &a & b`: none is moved
/// - `let a &= b`: `a` is mutated and `b` is moved
/// - `let a &= &b`: `a` is mutated
/// # Examples
/// This example demonstrates how to use the `&` and `&=` like methods.
/// ```no_run
/// use fast_imt::core::r#match::{RuddyPredicateEngine, FieldMatch,
/// MatchEncoder, PredicateInner, Predicate, ipv4_to_match};
/// use fast_imt::core::r#match::family::{MatchFamily};
/// use crate::fast_imt::fm_ipv4_from;
///
/// fn get_predicates<T: PredicateInner>(engine: &dyn MatchEncoder<P=T>)-> [Predicate<T>;3] {
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
/// // p2, p3 are dropped and should no longer be used afterward
/// let [mut p1, p2, p3] = get_predicates(&engine);
/// let p123 = {
///     p1 &= p2;
///     p1 &= p3;
///     p1
/// };
///
/// // get the cross product of [p1, p2, p3] and [p1, p2, p3]
/// // since iter() returns reference, the predicates are not moved
/// let pls = Vec::from(get_predicates(&engine));
/// let prs = Vec::from(get_predicates(&engine));
/// let mut res = vec![];
/// for pl in pls.iter() {
///     for pr in prs.iter() {
///         res.push(pl & pr);
///    }
/// }
// ```
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct Predicate<P: PredicateInner>(P);

impl<P: PredicateInner> Predicate<P> {
  fn new(p: P) -> Self {
    Predicate(p._ref())
  }

  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }
}

impl<P: PredicateInner> Clone for Predicate<P> {
  fn clone(&self) -> Self {
    Predicate::new(self.0)
  }
}

impl<P: PredicateInner> Drop for Predicate<P> {
  fn drop(&mut self) {
    self.0._deref();
  }
}

impl<P: PredicateInner> Display for Predicate<P> {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    Display::fmt(&self.0, f)
  }
}

impl<P: PredicateInner> Not for Predicate<P> {
  type Output = Predicate<P>;

  fn not(self) -> Self::Output {
    Predicate::new(self.0.not())
  }
}

impl<P: PredicateInner> Not for &'_ Predicate<P> {
  type Output = Predicate<P>;

  fn not(self) -> Self::Output {
    Predicate::new(self.0.not())
  }
}

impl<P: PredicateInner> BitAnd for Predicate<P> {
  type Output = Predicate<P>;

  fn bitand(self, rhs: Self) -> Self::Output {
    Predicate::new(self.0.and(&rhs.0))
  }
}

impl<P: PredicateInner> BitAnd<&Self> for Predicate<P> {
  type Output = Predicate<P>;

  fn bitand(self, rhs: &Self) -> Self::Output {
    Predicate::new(self.0.and(&rhs.0))
  }
}

impl<P: PredicateInner> BitAnd for &'_ Predicate<P> {
  type Output = Predicate<P>;

  fn bitand(self, rhs: Self) -> Self::Output {
    Predicate::new(self.0.and(&rhs.0))
  }
}

impl<P: PredicateInner> BitAndAssign for Predicate<P> {
  fn bitand_assign(&mut self, rhs: Self) {
    let prev = self.0;
    self.0 = self.0.and(&rhs.0)._ref();
    prev._deref();
  }
}

impl<P: PredicateInner> BitAndAssign<&Self> for Predicate<P> {
  fn bitand_assign(&mut self, rhs: &Self) {
    let prev = self.0;
    self.0 = self.0.and(&rhs.0)._ref();
    prev._deref();
  }
}

impl<P: PredicateInner> BitOr for Predicate<P> {
  type Output = Predicate<P>;

  fn bitor(self, rhs: Self) -> Self::Output {
    Predicate(self.0.or(&rhs.0)._ref())
  }
}

impl<P: PredicateInner> BitOr<&Self> for Predicate<P> {
  type Output = Predicate<P>;

  fn bitor(self, rhs: &Self) -> Self::Output {
    Predicate(self.0.or(&rhs.0)._ref())
  }
}

impl<P: PredicateInner> BitOr for &'_ Predicate<P> {
  type Output = Predicate<P>;

  fn bitor(self, rhs: Self) -> Self::Output {
    Predicate(self.0.or(&rhs.0)._ref())
  }
}

impl<P: PredicateInner> BitOrAssign for Predicate<P> {
  fn bitor_assign(&mut self, rhs: Self) {
    let prev = self.0;
    self.0 = self.0.or(&rhs.0)._ref();
    prev._deref();
  }
}

impl<P: PredicateInner> BitOrAssign<&Self> for Predicate<P> {
  fn bitor_assign(&mut self, rhs: &Self) {
    let prev = self.0;
    self.0 = self.0.or(&rhs.0)._ref();
    prev._deref();
  }
}

impl<P: PredicateInner> Sub for Predicate<P> {
  type Output = Predicate<P>;

  fn sub(self, rhs: Self) -> Self::Output {
    Predicate(self.0.comp(&rhs.0)._ref())
  }
}

impl<P: PredicateInner> Sub<&Self> for Predicate<P> {
  type Output = Predicate<P>;

  fn sub(self, rhs: &Self) -> Self::Output {
    Predicate(self.0.comp(&rhs.0)._ref())
  }
}

impl<P: PredicateInner> Sub for &'_ Predicate<P> {
  type Output = Predicate<P>;

  fn sub(self, rhs: Self) -> Self::Output {
    Predicate(self.0.comp(&rhs.0)._ref())
  }
}

impl<P: PredicateInner> SubAssign for Predicate<P> {
  fn sub_assign(&mut self, rhs: Self) {
    let prev = self.0;
    self.0 = self.0.comp(&rhs.0)._ref();
    prev._deref();
  }
}

impl<P: PredicateInner> SubAssign<&Self> for Predicate<P> {
  fn sub_assign(&mut self, rhs: &Self) {
    let prev = self.0;
    self.0 = self.0.comp(&rhs.0)._ref();
    prev._deref();
  }
}

#[derive(Eq, PartialEq, Debug)]
pub struct Rule<P: PredicateInner, A: CodedAction = u32> {
  pub priority: u32,
  pub action: A,
  pub predicate: Predicate<P>,
  pub origin: Vec<MaskedValue>,
}

impl<P: PredicateInner, A: CodedAction> PartialOrd for Rule<P, A> {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl<P: PredicateInner, A: CodedAction> Ord for Rule<P, A> {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    other
      .priority
      .cmp(&self.priority)
      .then_with(|| other.action.cmp(&self.action))
      .then_with(|| other.predicate.cmp(&self.predicate))
  }
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
