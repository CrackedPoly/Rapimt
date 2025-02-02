use std::fmt::{Display, Formatter};

use crate::RuleLike;
use rapimt_core::prelude::{Action, CodedAction, MaskedValue, Predicate, PredicateInner, Single};

/// Local rule of a device.
#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub struct Rule<P: PredicateInner, A: Action<Single>> {
    pub priority: i32,
    pub action: A,
    pub predicate: Predicate<P>,
    pub origin: Vec<MaskedValue>,
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

/// Action-unencoded (raw) rule of a device.
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
