use crate::RuleLike;
use rapimt_core::prelude::{Action, Predicate, PredicateInner, Single};

/// Local rule of a device.
#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub struct Rule<P: PredicateInner, A: Action<Single>> {
    pub action: A,
    pub predicate: Predicate<P>,
    pub lid: u16,
}

impl<P: PredicateInner, A: Action<Single>> RuleLike for Rule<P, A> {
    type A = A;
    type P = P;

    #[inline(always)]
    fn action(&self) -> &Self::A {
        &self.action
    }

    #[inline(always)]
    fn predicate(&self) -> &Predicate<Self::P> {
        &self.predicate
    }
}

#[allow(clippy::non_canonical_partial_ord_impl)]
impl<P: PredicateInner, A: Action<Single>> PartialOrd for Rule<P, A> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.lid.partial_cmp(&other.lid)
    }
}

impl<P: PredicateInner, A: Action<Single>> Ord for Rule<P, A> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.lid.cmp(&other.lid)
    }
}
