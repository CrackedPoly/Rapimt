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
//! let engine = RuddyPredicateEngine::init(1000, 100);
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
    fmt::{Binary, Debug, Display, Formatter},
    hash::Hash,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not, Sub, SubAssign},
};

use crate::action::{Action, CodedAction, Single};
use bitvec::{field::BitField, prelude::*};
use funty::Unsigned;

use family::{constant, FamilyDecl};

/// Match is a match condition for a field.
/// No field should exceed 128 bits for now, so u128 should be adequate.
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

/// MaskedValue is ternary string representing an entire header match.
#[derive(Eq, PartialEq, Hash, Default, Clone, Copy, Debug)]
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

/// MatchEncoder parses field values and encodes them into predicates.
pub trait MatchEncoder<'a>
where
    Self: 'a,
{
    type P: PredicateInner + 'a;

    fn gc(&self) -> usize;

    fn one(&'a self) -> Predicate<Self::P>;

    fn zero(&'a self) -> Predicate<Self::P>;

    fn _encode<U: Unsigned>(
        &'a self,
        value: U,
        mask: U,
        from: usize,
        to: usize,
    ) -> Predicate<Self::P>;

    fn encode_match<U: Unsigned>(
        &'a self,
        fm: FieldMatch<U>,
    ) -> (Predicate<Self::P>, Vec<MaskedValue>) {
        match constant::GLOBAL_FAMILY.get_field_declaration(fm.field) {
            Some(fdecl) => {
                let from = fdecl.from;
                let to = fdecl.to;
                return match fm.cond {
                    Match::ExactMatch { value } => {
                        let mask = U::MAX;
                        (
                            self._encode(value, mask, from, to),
                            vec![MaskedValue::store(value, mask, from, to)],
                        )
                    }
                    Match::TernaryMatch { value, mask } => (
                        self._encode(value, mask, from, to),
                        vec![MaskedValue::store(value, mask, from, to)],
                    ),
                    Match::RangeMatch { mut low, high } => {
                        // FIX IT: if to - from == U::BITS, it might be wrong
                        let mask = (U::ONE << (to - from)) - U::ONE;
                        let mut vm_pairs = vec![];
                        loop {
                            let t_zeros = low.trailing_zeros();
                            let mut inc = U::ONE << t_zeros;
                            low += inc;
                            while low - U::ONE > high {
                                inc >>= U::ONE;
                                low -= inc;
                            }
                            let t_zeros = inc.trailing_zeros();
                            vm_pairs.push((low - inc, (mask >> t_zeros) << t_zeros));
                            if low - U::ONE == high {
                                break;
                            }
                        }
                        let mut pred = self.zero();
                        let mvs = vm_pairs
                            .iter()
                            .map(|(v, m)| {
                                pred |= self._encode(*v, *m, from, to);
                                MaskedValue::store(*v, *m, from, to)
                            })
                            .collect();
                        (pred, mvs)
                    }
                };
            }
            _ => unimplemented!("{}", fm.field),
        }
    }

    fn encode_match_wo_mv<U: Unsigned>(&'a self, fm: FieldMatch<U>) -> Predicate<Self::P> {
        match constant::GLOBAL_FAMILY.get_field_declaration(fm.field) {
            Some(fdecl) => {
                let from = fdecl.from;
                let to = fdecl.to;
                match fm.cond {
                    Match::ExactMatch { value } => {
                        let mask = (U::ONE << (to - from)) - U::ONE;
                        self._encode(value, mask, from, to)
                    }
                    Match::TernaryMatch { value, mask } => self._encode(value, mask, from, to),
                    Match::RangeMatch { mut low, high } => {
                        let mask = (U::ONE << (to - from)) - U::ONE;
                        let mut pred = self.zero();
                        loop {
                            let t_zeros = low.trailing_zeros();
                            let mut inc = U::ONE << t_zeros;
                            low += inc;
                            while low - U::ONE > high {
                                inc >>= U::ONE;
                                low -= inc;
                            }
                            let t_zeros = inc.trailing_zeros();
                            pred |= self._encode(low - inc, (mask >> t_zeros) << t_zeros, from, to);
                            if low - U::ONE == high {
                                break;
                            }
                        }
                        pred
                    }
                }
            }
            _ => unimplemented!("{}", fm.field),
        }
    }

    fn encode_matches<'b, U: Unsigned, II: IntoIterator<Item = FieldMatch<'b, U>>>(
        &'a self,
        fms: II,
    ) -> (Predicate<Self::P>, Vec<MaskedValue>) {
        let mut pred = self.one();
        let mut mvs = vec![];
        let mut new_mvs = vec![];
        for fm in fms {
            let (p, sub_mvs) = self.encode_match(fm);
            pred &= p;
            if mvs.is_empty() {
                mvs.extend(sub_mvs)
            } else {
                // do a cross product of mvs and sub_mvs
                for mv in mvs.drain(..) {
                    for sub_mv in sub_mvs.iter() {
                        new_mvs.push(mv & *sub_mv);
                    }
                }
                std::mem::swap(&mut mvs, &mut new_mvs);
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

    #[cfg(feature = "dip")]
    fn rewrite_dip(&'a self, before: &Predicate<Self::P>, m: Match<u32>) -> Predicate<Self::P>;
    #[cfg(feature = "dip")]
    fn erase_dip(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P>;
    #[cfg(feature = "dip")]
    fn erase_except_dip(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P>;

    #[cfg(feature = "sip")]
    fn rewrite_sip(&'a self, before: &Predicate<Self::P>, m: Match<u32>) -> Predicate<Self::P>;
    #[cfg(feature = "sip")]
    fn erase_sip(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P>;
    #[cfg(feature = "sip")]
    fn erase_except_sip(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P>;

    #[cfg(feature = "dport")]
    fn rewrite_dport(&'a self, before: &Predicate<Self::P>, m: Match<u16>) -> Predicate<Self::P>;
    #[cfg(feature = "dport")]
    fn erase_dport(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P>;
    #[cfg(feature = "dport")]
    fn erase_except_dport(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P>;

    #[cfg(feature = "sport")]
    fn rewrite_sport(&'a self, before: &Predicate<Self::P>, m: Match<u16>) -> Predicate<Self::P>;
    #[cfg(feature = "sport")]
    fn erase_sport(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P>;
    #[cfg(feature = "sport")]
    fn erase_except_sport(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P>;

    #[cfg(feature = "tag")]
    fn rewrite_tag(&'a self, before: &Predicate<Self::P>, m: Match<u16>) -> Predicate<Self::P>;
    #[cfg(feature = "tag")]
    fn erase_tag(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P>;
    #[cfg(feature = "tag")]
    fn erase_except_tag(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P>;
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
///         Predicate, MatchEncoder,
///         engine::RuddyPredicateEngine, FieldMatch,
///         family::{MatchFamily}
///     }
/// };
///
/// fn get_predicates<ME: for <'a> MatchEncoder<'a>>(engine: &ME)-> [Predicate<<ME as MatchEncoder<'_>>::P>;3] {
///     [
///         engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/24")).0,
///         engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/25")).0,
///         engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/26")).0,
///     ]
/// }
///
/// let engine = RuddyPredicateEngine::init(1000, 100);
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
#[derive(Ord, PartialOrd, Hash, Eq, PartialEq)]
pub struct Predicate<P: PredicateInner>(pub P);

impl<P: PredicateInner> From<P> for Predicate<P> {
    #[inline]
    fn from(value: P) -> Self {
        Predicate(value._ref())
    }
}

impl<P: PredicateInner> Predicate<P> {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<P: PredicateInner> Clone for Predicate<P> {
    #[inline]
    fn clone(&self) -> Self {
        Predicate::from(self.0)
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

impl<P: PredicateInner> Debug for Predicate<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

/// `!prediate` consumes the predicate.
impl<P: PredicateInner> Not for Predicate<P> {
    type Output = Predicate<P>;

    #[inline]
    fn not(self) -> Self::Output {
        Predicate::from(self.0.not())
    }
}

/// `!(&prediate)` consumes the predicate reference.
impl<P: PredicateInner> Not for &'_ Predicate<P> {
    type Output = Predicate<P>;

    #[inline]
    fn not(self) -> Self::Output {
        Predicate::from(self.0.not())
    }
}

macro_rules! predicate_bitand_impl {
    ($lhs:ty, $rhs:ty) => {
        impl<P: PredicateInner> BitAnd<$rhs> for $lhs {
            type Output = Predicate<P>;

            #[inline]
            fn bitand(self, rhs: $rhs) -> Self::Output {
                Predicate::from(self.0.and(&rhs.0))
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
    use std::net::Ipv4Addr;

    use crate::r#match::Match;

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
                cond: ipv4_to_match($value),
            }
        };
    }

    /// Create a FieldMatch with an exact value.
    /// ```no_run
    /// use rapimt_core::{fm_exact_from, r#match::{FieldMatch, Match}};
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
    /// use rapimt_core::{fm_range_from, r#match::{FieldMatch, Match}};
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
