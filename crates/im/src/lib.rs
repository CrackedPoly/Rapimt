mod im;
mod monitor;

use rapimt_core::{
    action::{CodedAction, CodedActions},
    r#match::{PredicateInner, Rule},
};

pub use {im::InverseModel, monitor::DefaultFibMonitor};

pub trait FibMonitor<P: PredicateInner, A: CodedAction> {
    fn clear(&mut self);
    fn update<As: CodedActions<A>>(
        &mut self,
        insertion: Vec<Rule<P, A>>,
        deletion: Vec<Rule<P, A>>,
    ) -> InverseModel<P, A, As>;
    fn insert<As: CodedActions<A>>(
        &mut self,
        insertion: Vec<Rule<P, A>>,
    ) -> InverseModel<P, A, As> {
        self.update(insertion, vec![])
    }
    fn delete<As: CodedActions<A>>(&mut self, deletion: Vec<Rule<P, A>>) -> InverseModel<P, A, As> {
        self.update(vec![], deletion)
    }
}
