//! InverseModel operations and generations.
pub mod default;
pub mod ib;
pub mod im;

#[allow(missing_docs)]
#[doc(hidden)]
pub mod prelude {
    pub use crate::{
        default::monitor::{FastRuleMonitor, RuleStore, SimpleRuleStore, TPTRuleStore},
        default::rule::{RawRule, Rule, UncodedRule},
        im::{InverseModel, InverseModelMonoid, MapInverseModel, VecInverseModel},
        RuleLike, RuleMonitorLike,
    };
}

use im::{InverseModel, InverseModelMonoid};
use rapimt_core::prelude::{Action, Dimension, Predicate, PredicateInner, Single};

pub trait RawRuleLike {}

pub trait RuleLike {
    type A: Action<Single>;
    type P: PredicateInner;

    fn action(&self) -> &Self::A;
    fn predicate(&self) -> &Predicate<Self::P>;
}

/// Rule storage and IM generator.
///
/// [A]: Action type inside the monitor.
/// [OA]: Output action type of the inverse model.
/// [T]: Dimension type of the inverse model.
/// [M]: Inverse model monoid type.
/// [P]: Predicate type inside the monitor.
/// [R]: Rule type stored inside the monitor.
pub trait RuleMonitorLike<A, OA, OT, M, P, R>
where
    A: Action<Single>,
    OA: Action<OT, S = A>,
    OT: Dimension,
    M: InverseModelMonoid<OA, P, OT>,
    P: PredicateInner,
    R: RuleLike<A = A, P = P>,
{
    /// First call of update should return an inverse model of the current state.
    /// Subsequent calls should return an inverse model that represent an incremental update.
    fn update(
        &mut self,
        insertion: impl IntoIterator<Item = R>,
        deletion: impl IntoIterator<Item = R>,
    ) -> InverseModel<OA, P, OT, M>;

    /// Provided methods
    fn insert(&mut self, insertion: impl IntoIterator<Item = R>) -> InverseModel<OA, P, OT, M> {
        self.update(insertion, vec![])
    }

    fn delete(&mut self, deletion: impl IntoIterator<Item = R>) -> InverseModel<OA, P, OT, M> {
        self.update(vec![], deletion)
    }
}
