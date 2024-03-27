use std::cmp::max;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::ShlAssign;

use crate::core::action::Actions;
use crate::core::r#match::{Predicate, PredicateInner, Rule};
use crate::io::CodedAction;

pub mod monitor;

pub trait FibMonitor<P: PredicateInner, A: CodedAction> {
  fn clear(&mut self);
  fn update<As: Actions<A>>(
    &mut self,
    insertion: Vec<Rule<P, A>>,
    deletion: Vec<Rule<P, A>>,
  ) -> InverseModel<P, A, As>;
  fn insert<As: Actions<A>>(&mut self, insertion: Vec<Rule<P, A>>) -> InverseModel<P, A, As> {
    self.update(insertion, vec![])
  }
  fn delete<As: Actions<A>>(&mut self, deletion: Vec<Rule<P, A>>) -> InverseModel<P, A, As> {
    self.update(vec![], deletion)
  }
}

#[derive(Debug)]
pub struct ModelEntry<P: PredicateInner, A: CodedAction, As: Actions<A>> {
  pub actions: As,
  pub predicate: Predicate<P>,
  _phantom: PhantomData<A>,
}

#[derive(Debug)]
pub struct InverseModel<P: PredicateInner, A: CodedAction, As: Actions<A>> {
  pub n_dim: usize,
  pub size: usize,
  pub data: Vec<ModelEntry<P, A, As>>,
}

impl<P, As, A> From<ModelEntry<P, A, As>> for InverseModel<P, A, As>
where
  P: PredicateInner,
  A: CodedAction,
  As: Actions<A>,
{
  fn from(value: ModelEntry<P, A, As>) -> Self {
    InverseModel {
      n_dim: value.actions.len(),
      size: 1,
      data: vec![value],
    }
  }
}

impl<P, As, A> From<Vec<ModelEntry<P, A, As>>> for InverseModel<P, A, As>
where
  P: PredicateInner,
  A: CodedAction,
  As: Actions<A>,
{
  fn from(value: Vec<ModelEntry<P, A, As>>) -> Self {
    InverseModel {
      n_dim: value.first().unwrap().actions.len(),
      size: value.len(),
      data: value,
    }
  }
}

impl<P, A, As> ShlAssign for InverseModel<P, A, As>
where
  P: PredicateInner,
  A: CodedAction,
  As: Actions<A>,
{
  fn shl_assign(&mut self, rhs: Self) {
    if self.size == 0 {
      *self = rhs;
      return;
    } else if rhs.size == 0 {
      return;
    }
    assert_eq!(self.n_dim, rhs.n_dim);
    let capacity = max(self.size, rhs.size);
    let mut result: HashMap<As, Predicate<P>> = HashMap::with_capacity(capacity);
    self.data.iter().for_each(|ex| {
      let mut px = ex.predicate.clone();
      rhs.data.iter().for_each(|ey| {
        let mut py = ey.predicate.clone();
        let pxy = &px & &py;
        if !pxy.is_empty() {
          let axy = ex.actions.overwritten(&ey.actions);
          result
            .entry(axy)
            .and_modify(|p0| *p0 |= &pxy)
            .or_insert(pxy.clone());
          px -= &pxy;
          py -= &pxy;
        }
      });
    });
    self.data.reserve(result.len());
    self.data.clear();
    result.into_iter().for_each(|(a, p)| {
      self.data.push(ModelEntry {
        actions: a,
        predicate: p,
        _phantom: PhantomData,
      });
    });
    self.size = self.data.len();
  }
}

impl<P, A, As> InverseModel<P, A, As>
where
  P: PredicateInner,
  A: CodedAction,
  As: Actions<A>,
{
  pub fn resize(&mut self, to: usize, offset: usize) {
    assert!(to >= offset + self.n_dim);
    self.n_dim = to;
    for i in 0..self.size {
      self.data[i].actions.resize(to, offset);
    }
  }
}

impl<P, A, As> Default for InverseModel<P, A, As>
where
  P: PredicateInner,
  A: CodedAction,
  As: Actions<A>,
{
  fn default() -> Self {
    InverseModel {
      n_dim: 0,
      size: 0,
      data: vec![],
    }
  }
}
