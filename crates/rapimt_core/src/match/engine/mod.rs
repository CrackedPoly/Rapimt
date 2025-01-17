//! # Engine module
//!
//! ## What is a match engine?
//! A match engine parses field values (like "dip=192.168.1.0/24, sport=80")
//! into a predicate that can perform logical operations (like AND, OR, NOT)
//! to express the match condition.
//!
use std::io::Result;

use crate::r#match::family::{constant, FamilyDecl};
use crate::r#match::predicate::{Predicate, PredicateInner};
use crate::r#match::raw_match::{FieldMatch, MaskedValue, Match};
use funty::Unsigned;

#[cfg(feature = "lid")]
mod no_engine;
mod oxidd_engine;
mod ruddy_engine;
pub use oxidd_engine::{OxiddPredicate, OxiddPredicateEngine};
pub use ruddy_engine::{RuddyPredicate, RuddyPredicateEngine};

/// Parse field values and encodes them into a predicate.
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
                match fm.cond {
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
                }
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
                        let mask = U::MAX;
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

/// An extended trait of MatchEncoder, which additionally enables serialization and deserialization
/// of a predicate.
///
/// It is useful when local storing or remote transmitting predicates.
pub trait PredicateEngine<'a>: MatchEncoder<'a> {
    /// Deserialize a predicate according to the buffer.
    fn read_buffer(&'a self, buffer: &[u8]) -> Result<Predicate<Self::P>>;
    /// Serialize the predicate to the buffer.
    fn write_buffer(&'a self, pred: &Predicate<Self::P>, buffer: &mut Vec<u8>) -> Result<()>;

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
