//! InverseModel operations and generations.
pub mod default;
pub mod ib;
pub mod im;

#[allow(missing_docs)]
#[doc(hidden)]
pub mod prelude {
    pub use crate::{
        default::monitor::{FastRuleMonitor, RuleStore, SimpleRuleStore, TPTRuleStore},
        default::rule::{Rule, UncodedRule},
        im::{InverseModel, InverseModelMonoid},
        RuleLike, RuleMonitorLike,
    };
}

use im::{InverseModel, InverseModelMonoid};
use rapimt_core::prelude::{Action, Dimension, Predicate, PredicateInner, Single};

pub trait RuleLike {
    type A: Action<Single>;
    type P: PredicateInner;

    fn action(&self) -> &Self::A;
    fn predicate(&self) -> &Predicate<Self::P>;
}

/// Rule storage and IM generator.
pub trait RuleMonitorLike<A: Action<Single>, P: PredicateInner, R: RuleLike> {
    /// Required methods
    fn clear(&mut self);

    /// First call of update should return an inverse model of the current state.
    /// Subsequent calls should return an inverse model that represent an incremental update.
    fn update<OA: Action<T, S = A>, T: Dimension, M: InverseModelMonoid<OA, P, T>>(
        &mut self,
        insertion: impl IntoIterator<Item = R>,
        deletion: impl IntoIterator<Item = R>,
    ) -> InverseModel<OA, P, T, M>;

    /// Provided methods
    fn insert<OA: Action<T, S = A>, T: Dimension, M: InverseModelMonoid<OA, P, T>>(
        &mut self,
        insertion: impl IntoIterator<Item = R>,
    ) -> InverseModel<OA, P, T, M> {
        self.update(insertion, vec![])
    }

    fn delete<OA: Action<T, S = A>, T: Dimension, M: InverseModelMonoid<OA, P, T>>(
        &mut self,
        deletion: impl IntoIterator<Item = R>,
    ) -> InverseModel<OA, P, T, M> {
        self.update(vec![], deletion)
    }
}
