//! # Engine module
//!
//! ## What is a match engine?
//! A match engine parses field values (like "dip=192.168.1.0/24, sport=80")
//! into a predicate that can perform logical operations (like AND, OR, NOT)
//! to express the match condition.
//!

pub mod ruddy_engine;

use crate::core::r#match::family::{FamilyDecl, FieldValue, Match, MatchFamily};
use crate::core::Predicate;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not, Sub, SubAssign};

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
    fn _encode(&'a self, value: u128, mask: u128, lower: u128, higher: u128) -> Self::P;
    /// Encode a field value into a predicate.
    fn encode_value(&'a self, fv: FieldValue) -> Self::P {
        let family = self.family();
        let fm = family.parse(fv);
        match family.get_field_declaration(fm.field) {
            Some(fdecl) => {
                let lower = fdecl.from;
                let upper = fdecl.to;
                match fm.cond {
                    Match::ExactMatch { value } => {
                        self._encode(value, (1 << (upper - lower + 1)) - 1, lower, upper)
                    }
                    Match::TernaryMatch { value, mask } => self._encode(value, mask, lower, upper),
                    _ => panic!("{}", format!("Unsupported match type: {:?}", fm.cond)),
                }
            }
            _ => self.one(),
        }
    }
    /// Encode a list of field values into a predicate.
    fn encode_values(&'a self, fvs: Vec<FieldValue>) -> Self::P {
        fvs.into_iter()
            .map(|fv| self.encode_value(fv))
            .fold(self.one(), |mut acc, pred| {
                acc &= pred;
                acc
            })
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
/// - [empty](PredicateOp::empty) checks if the predicate is empty.
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
/// ```no_run
/// use fast_imt::core::{MatchFamily, RuddyPredicateEngine, FieldValue,
/// MatchEncoder, Predicate, PredicateOp};
/// use crate::fast_imt::fv_from;
///
/// fn get_predicates<T: Predicate>(engine: &dyn MatchEncoder<P=T>) -> [T; 3] {
///     [
///         engine.encode_value(fv_from!("dip", "192.168.1.0/24")),
///         engine.encode_value(fv_from!("dip", "192.168.1.0/25")),
///         engine.encode_value(fv_from!("dip", "192.168.1.0/26")),
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
    fn empty(&self) -> bool;
    fn drop(self);
}
