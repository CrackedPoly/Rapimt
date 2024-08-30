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
//! use rapimt_core::{
//!     fm_ipv4_from, ipv4_to_match,
//!     r#match::{
//!         Predicate, PredicateEngine, MatchEncoder,
//!         engine::RuddyPredicateEngine, FieldMatch,
//!         family::{MatchFamily}
//!     }
//! };
//!
//! // Initialize the engine
//! let family = MatchFamily::TcpT4Family;
//! let engine = RuddyPredicateEngine::init(1000, 100, family);
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

pub mod engine;
pub mod family;

use std::{
    fmt::{Debug, Display, Formatter},
    hash::Hash,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not, Sub, SubAssign},
};

use crate::action::{Action, CodedAction, Single};
use bitvec::prelude::*;

use family::{FamilyDecl, HeaderBitOrder, HeaderBitStore, MatchFamily, HEADERSTORENUM};

/// Match is a match condition for a field.
/// No field should exceed 128 bits for now, so u128 should be adequate.
#[derive(Clone, Debug)]
pub enum Match {
    ExactMatch { value: u128 },
    TernaryMatch { value: u128, mask: u128 },
    RangeMatch { low: u128, high: u128 },
}

/// FieldMatch contains the name and the condition of a match in a field.
#[derive(Debug)]
pub struct FieldMatch<'a> {
    pub field: &'a str,
    pub cond: Match,
}

/// MaskedValue is ternary string representing an entire header match.
#[derive(Eq, PartialEq, Hash, Default, Clone, Copy)]
pub struct MaskedValue {
    // #[cfg(target_header="inet4")]
    pub value: BitArray<[HeaderBitStore; HEADERSTORENUM], HeaderBitOrder>,
    // #[cfg(target_header="inet4")]
    pub mask: BitArray<[HeaderBitStore; HEADERSTORENUM], HeaderBitOrder>,
}

impl Debug for MaskedValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:} / {:}", self.value, self.mask)
    }
}

impl BitOr for MaskedValue {
    type Output = MaskedValue;
    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        MaskedValue {
            // #[cfg(target_header="inet4")]
            value: self.value | rhs.value,
            // #[cfg(target_header="inet4")]
            mask: self.mask & rhs.mask,
        }
    }
}

// #[cfg(target_stack="inet4")]
impl From<(u128, u128)> for MaskedValue {
    #[inline]
    fn from(pair: (u128, u128)) -> Self {
        MaskedValue {
            // #[cfg(target_stack="inet4")]
            value: BitArray::new([pair.0 as u32]),
            // #[cfg(target_stack="inet4")]
            mask: BitArray::new([pair.1 as u32]),
        }
    }
}

// #[cfg(target_stack="inet4")]
impl From<(u64, u64)> for MaskedValue {
    #[inline]
    fn from(pair: (u64, u64)) -> Self {
        MaskedValue {
            // #[cfg(target_stack="inet4")]
            value: BitArray::new([pair.0 as u32]),
            // #[cfg(target_stack="inet4")]
            mask: BitArray::new([pair.1 as u32]),
        }
    }
}

/// Inner representation of a predicate should implement Copy (most important) to evade high cost.
pub trait PredicateInner:
    Copy + Clone + Eq + PartialEq + Ord + PartialOrd + Hash + Display + Debug
{
    fn not(&self) -> Self;
    fn and(&self, rhs: &Self) -> Self;
    fn or(&self, rhs: &Self) -> Self;
    fn comp(&self, rhs: &Self) -> Self;
    fn is_empty(&self) -> bool;
    fn _ref(self) -> Self;
    fn _deref(&self);
}

/// Predicate is a logical condition that can be used to represent packer filter.
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
/// use rapimt_core::{
///     fm_ipv4_from, ipv4_to_match,
///     r#match::{
///         Predicate, PredicateEngine, MatchEncoder, PredicateInner,
///         engine::RuddyPredicateEngine, FieldMatch,
///         family::{MatchFamily}
///     }
/// };
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
/// let engine = RuddyPredicateEngine::init(100, 10, family);
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
#[derive(Ord, PartialOrd, Hash, Eq, PartialEq, Debug)]
pub struct Predicate<P: PredicateInner>(P);

impl<P: PredicateInner> Predicate<P> {
    #[inline]
    fn new(p: P) -> Self {
        Predicate(p._ref())
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<P: PredicateInner> Clone for Predicate<P> {
    #[inline]
    fn clone(&self) -> Self {
        Predicate::new(self.0)
    }
}

impl<P: PredicateInner> Drop for Predicate<P> {
    #[inline]
    fn drop(&mut self) {
        self.0._deref();
    }
}

impl<P: PredicateInner> Display for Predicate<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// `!prediate` consumes the predicate.
impl<P: PredicateInner> Not for Predicate<P> {
    type Output = Predicate<P>;

    #[inline]
    fn not(self) -> Self::Output {
        Predicate::new(self.0.not())
    }
}

/// `!(&prediate)` consumes the predicate reference.
impl<P: PredicateInner> Not for &'_ Predicate<P> {
    type Output = Predicate<P>;

    #[inline]
    fn not(self) -> Self::Output {
        Predicate::new(self.0.not())
    }
}

macro_rules! predicate_bitand_impl {
    ($lhs:ty, $rhs:ty) => {
        impl<P: PredicateInner> BitAnd<$rhs> for $lhs {
            type Output = Predicate<P>;

            #[inline]
            fn bitand(self, rhs: $rhs) -> Self::Output {
                Predicate::new(self.0.and(&rhs.0))
            }
        }
    };
}

macro_rules! predicate_bitand_assign_impl {
    ($lhs:ty, $rhs:ty) => {
        impl<P: PredicateInner> BitAndAssign<$rhs> for $lhs {
            #[inline]
            fn bitand_assign(&mut self, rhs: $rhs) {
                let prev = self.0;
                self.0 = self.0.and(&rhs.0)._ref();
                prev._deref();
            }
        }
    };
}

macro_rules! predicate_bitor_impl {
    ($lhs:ty, $rhs:ty) => {
        impl<P: PredicateInner> BitOr<$rhs> for $lhs {
            type Output = Predicate<P>;

            #[inline]
            fn bitor(self, rhs: $rhs) -> Self::Output {
                Predicate(self.0.or(&rhs.0)._ref())
            }
        }
    };
}

macro_rules! predicate_bitor_assign_impl {
    ($lhs:ty, $rhs:ty) => {
        impl<P: PredicateInner> BitOrAssign<$rhs> for $lhs {
            #[inline]
            fn bitor_assign(&mut self, rhs: $rhs) {
                let prev = self.0;
                self.0 = self.0.or(&rhs.0)._ref();
                prev._deref();
            }
        }
    };
}

macro_rules! predicate_sub_impl {
    ($lhs:ty, $rhs:ty) => {
        impl<P: PredicateInner> Sub<$rhs> for $lhs {
            type Output = Predicate<P>;

            #[inline]
            fn sub(self, rhs: $rhs) -> Self::Output {
                Predicate(self.0.comp(&rhs.0)._ref())
            }
        }
    };
}

macro_rules! predicate_sub_assign_impl {
    ($lhs:ty, $rhs:ty) => {
        impl<P: PredicateInner> SubAssign<$rhs> for $lhs {
            #[inline]
            fn sub_assign(&mut self, rhs: $rhs) {
                let prev = self.0;
                self.0 = self.0.comp(&rhs.0)._ref();
                prev._deref();
            }
        }
    };
}

predicate_bitand_impl!(Predicate<P>, Predicate<P>);
predicate_bitand_impl!(Predicate<P>, &Predicate<P>);
predicate_bitand_impl!(Predicate<P>, &mut Predicate<P>);
predicate_bitand_impl!(&Predicate<P>, Predicate<P>);
predicate_bitand_impl!(&Predicate<P>, &Predicate<P>);
predicate_bitand_impl!(&Predicate<P>, &mut Predicate<P>);
predicate_bitand_impl!(&mut Predicate<P>, Predicate<P>);
predicate_bitand_impl!(&mut Predicate<P>, &Predicate<P>);
predicate_bitand_impl!(&mut Predicate<P>, &mut Predicate<P>);

predicate_bitand_assign_impl!(Predicate<P>, Predicate<P>);
predicate_bitand_assign_impl!(Predicate<P>, &Predicate<P>);
predicate_bitand_assign_impl!(Predicate<P>, &mut Predicate<P>);
predicate_bitand_assign_impl!(&mut Predicate<P>, Predicate<P>);
predicate_bitand_assign_impl!(&mut Predicate<P>, &Predicate<P>);
predicate_bitand_assign_impl!(&mut Predicate<P>, &mut Predicate<P>);

predicate_bitor_impl!(Predicate<P>, Predicate<P>);
predicate_bitor_impl!(Predicate<P>, &Predicate<P>);
predicate_bitor_impl!(Predicate<P>, &mut Predicate<P>);
predicate_bitor_impl!(&Predicate<P>, Predicate<P>);
predicate_bitor_impl!(&Predicate<P>, &Predicate<P>);
predicate_bitor_impl!(&Predicate<P>, &mut Predicate<P>);
predicate_bitor_impl!(&mut Predicate<P>, Predicate<P>);
predicate_bitor_impl!(&mut Predicate<P>, &Predicate<P>);
predicate_bitor_impl!(&mut Predicate<P>, &mut Predicate<P>);

predicate_bitor_assign_impl!(Predicate<P>, Predicate<P>);
predicate_bitor_assign_impl!(Predicate<P>, &Predicate<P>);
predicate_bitor_assign_impl!(Predicate<P>, &mut Predicate<P>);
predicate_bitor_assign_impl!(&mut Predicate<P>, Predicate<P>);
predicate_bitor_assign_impl!(&mut Predicate<P>, &Predicate<P>);
predicate_bitor_assign_impl!(&mut Predicate<P>, &mut Predicate<P>);

predicate_sub_impl!(Predicate<P>, Predicate<P>);
predicate_sub_impl!(Predicate<P>, &Predicate<P>);
predicate_sub_impl!(Predicate<P>, &mut Predicate<P>);
predicate_sub_impl!(&Predicate<P>, Predicate<P>);
predicate_sub_impl!(&Predicate<P>, &Predicate<P>);
predicate_sub_impl!(&Predicate<P>, &mut Predicate<P>);
predicate_sub_impl!(&mut Predicate<P>, Predicate<P>);
predicate_sub_impl!(&mut Predicate<P>, &Predicate<P>);
predicate_sub_impl!(&mut Predicate<P>, &mut Predicate<P>);

predicate_sub_assign_impl!(Predicate<P>, Predicate<P>);
predicate_sub_assign_impl!(Predicate<P>, &Predicate<P>);
predicate_sub_assign_impl!(Predicate<P>, &mut Predicate<P>);
predicate_sub_assign_impl!(&mut Predicate<P>, Predicate<P>);
predicate_sub_assign_impl!(&mut Predicate<P>, &Predicate<P>);
predicate_sub_assign_impl!(&mut Predicate<P>, &mut Predicate<P>);

/// MatchEncoder parses field values and encodes them into predicates.
pub trait MatchEncoder<'a>
where
    Self: 'a,
{
    type P: PredicateInner + 'a;
    fn gc(&self) -> usize;
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
                            low += inc;
                            while low - 1 > high {
                                inc >>= 1;
                                low -= inc;
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
            _ => (self.one(), vec![MaskedValue::from((0u128, 0u128))]),
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
                        new_mvs.push(*mv | *sub_mv);
                    }
                }
                mvs = new_mvs;
            }
        }
        (pred, mvs)
    }
}

/// PredicateEngine is a extended trait of MatchEncoder, which additionally enables serialization
/// and deserialization of a predicate. It is useful when local storing or remote transmitting
/// predicates.
pub trait PredicateEngine<'a>: MatchEncoder<'a> {
    /// Deserialize a predicate according to the buffer.
    fn read_buffer(&'a self, buffer: &[u8]) -> Option<Predicate<Self::P>>;
    /// Serialize the predicate to the buffer.
    fn write_buffer(&'a self, pred: &Predicate<Self::P>, buffer: &mut Vec<u8>) -> usize;
}

/// Rule is a local-representation of a flow entry.
#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub struct Rule<P: PredicateInner, A: Action<Single>> {
    pub priority: i32,
    pub action: A,
    pub predicate: Predicate<P>,
    pub origin: Vec<MaskedValue>,
}

/// UncodedRule is equivalent to a OpenFlow Flow Entry.
#[derive(Eq, PartialEq, Hash, Debug)]
pub struct UncodedRule<P: PredicateInner> {
    pub priority: i32,
    pub port: String,
    pub predicate: Predicate<P>,
    pub origin: Vec<MaskedValue>,
}

impl<P: PredicateInner, A: Action<Single>> PartialOrd for Rule<P, A> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<P: PredicateInner, A: Action<Single>> Ord for Rule<P, A> {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| self.predicate.cmp(&other.predicate))
    }
}

impl<P: PredicateInner, A: CodedAction> Display for Rule<P, A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rule {{  priority: {}, action: {}, predicate: {} }}",
            self.priority, self.action, self.predicate
        )
    }
}

pub mod macros {
    use crate::r#match::Match;

    const INET4_FAMILY_V4_LEN: u128 = 32;
    const INET4_FAMILY_V4_MASK: u128 = (1 << INET4_FAMILY_V4_LEN) - 1;

    /// Encode an IPv4 address with prefix into a ternary match.
    pub fn ipv4_to_match(value: String) -> Match {
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

    /// Create a FieldMatch with an IPv4 value.
    /// ```no_run
    /// use rapimt_core::{fm_ipv4_from, ipv4_to_match, r#match::{FieldMatch, Match}};
    /// let _ = fm_ipv4_from!("dip", "192.168.1.0/24");
    /// let _ = fm_ipv4_from!("dip", "3232235776/32");
    /// let _ = fm_ipv4_from!("dip", "0/0");
    /// ```
    #[macro_export]
    macro_rules! fm_ipv4_from {
        ($field:expr, $value:expr) => {
            FieldMatch {
                field: $field,
                cond: ipv4_to_match($value.to_owned()),
            }
        };
    }

    /// Create a FieldMatch with an exact value.
    /// ```no_run
    /// use rapimt_core::{fm_exact_from, r#match::{FieldMatch, Match}};
    /// let _ = fm_exact_from!("dport", 80);
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
    /// use rapimt_core::{fm_range_from, r#match::{FieldMatch, Match}};
    /// let _ = fm_range_from!("sport", 80, 100);
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
