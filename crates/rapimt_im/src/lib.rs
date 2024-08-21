//! This module provides FIB monitor and Inverse Model utilities.
//! TODO::This module needs to be documented.
mod im;
mod monitor;

use rapimt_core::{
    action::{Action, ModelType, Single},
    r#match::{PredicateInner, Rule},
};

pub use {im::InverseModel, monitor::DefaultFibMonitor};

pub trait FibMonitor<A: Action<Single> + Clone, P: PredicateInner> {
    // Required methods
    fn clear(&mut self);
    fn update<OA: Action<T, S = A> + From<A>, T: ModelType>(
        &mut self,
        insertion: Vec<Rule<P, A>>,
        deletion: Vec<Rule<P, A>>,
    ) -> InverseModel<OA, P, T>;

    // Provided methods
    fn insert<OA: Action<T, S = A> + From<A>, T: ModelType>(
        &mut self,
        insertion: Vec<Rule<P, A>>,
    ) -> InverseModel<OA, P, T> {
        self.update(insertion, vec![])
    }
    fn delete<OA: Action<T, S = A> + From<A>, T: ModelType>(
        &mut self,
        deletion: Vec<Rule<P, A>>,
    ) -> InverseModel<OA, P, T> {
        self.update(vec![], deletion)
    }
}

#[allow(missing_docs)]
pub mod prelude {
    #[doc(hidden)]
    pub use crate::{DefaultFibMonitor, FibMonitor, InverseModel};
}
