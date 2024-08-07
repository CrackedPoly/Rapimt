use std::{cmp::max, collections::HashMap, marker::PhantomData, ops::ShlAssign};

use rapimt_core::{
    action::{CodedAction, CodedActions},
    r#match::Predicate,
    r#match::PredicateInner,
};

#[derive(Debug)]
pub struct ModelEntry<P: PredicateInner, A: CodedAction, As: CodedActions<A>> {
    pub actions: As,
    pub predicate: Predicate<P>,
    pub _phantom: PhantomData<A>,
}

impl<P, As, A> From<(As, Predicate<P>)> for ModelEntry<P, A, As>
where
    P: PredicateInner,
    A: CodedAction,
    As: CodedActions<A>,
{
    fn from(tuple: (As, Predicate<P>)) -> Self {
        ModelEntry {
            actions: tuple.0,
            predicate: tuple.1,
            _phantom: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct InverseModel<P: PredicateInner, A: CodedAction, As: CodedActions<A>> {
    pub n_dim: usize,
    pub size: usize,
    pub data: Vec<ModelEntry<P, A, As>>,
}

impl<P, As, A> From<ModelEntry<P, A, As>> for InverseModel<P, A, As>
where
    P: PredicateInner,
    A: CodedAction,
    As: CodedActions<A>,
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
    As: CodedActions<A>,
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
    As: CodedActions<A>,
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
    As: CodedActions<A>,
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
    As: CodedActions<A>,
{
    fn default() -> Self {
        InverseModel {
            n_dim: 0,
            size: 0,
            data: vec![],
        }
    }
}
