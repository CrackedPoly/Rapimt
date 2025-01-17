use rapimt_core::prelude::{Action, Predicate, PredicateInner, Single};
use crate::RuleLike;

/// Local rule of a device.
#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub struct Rule<P: PredicateInner, A: Action<Single>> {
    pub action: A,
    pub predicate: Predicate<P>,
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
