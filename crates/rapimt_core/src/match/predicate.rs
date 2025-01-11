use std::{
    fmt::{Debug, Display, Formatter},
    hash::Hash,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not, Sub, SubAssign},
};

/// Inner representation of a predicate should implement Copy (most important) to avoid high cost.
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
/// Predicate hide reference counting inside, it is coherent with the Rust ownership model. When a
/// predicate is moved, it is de-referenced automatically and the underlying data structure (like
/// bdd nodes) may be garbage collected afterward. When a new predicate is produced, it is
/// referenced automatically.
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
/// use rapimt_core::fm_ipv4_from;
/// use rapimt_core::prelude::{
///     ipv4_to_match,
///     Predicate, MatchEncoder,
///     RuddyPredicateEngine, FieldMatch, MatchFamily
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
