use std::{cmp::max, collections::HashMap, marker::PhantomData, ops::ShlAssign};

use fxhash::FxBuildHasher;
use rapimt_core::{
    action::{Action, CodedActions, ModelType, Multiple, Single},
    r#match::{Predicate, PredicateInner},
};

#[derive(Debug)]
pub struct ModelEntry<A: Action<T>, P: PredicateInner, T: ModelType> {
    pub action: A,
    pub predicate: Predicate<P>,
    pub _marker: PhantomData<T>,
}

impl<A, P, T> From<(A, Predicate<P>)> for ModelEntry<A, P, T>
where
    A: Action<T>,
    P: PredicateInner,
    T: ModelType,
{
    fn from(tuple: (A, Predicate<P>)) -> Self {
        ModelEntry {
            action: tuple.0,
            predicate: tuple.1,
            _marker: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct InverseModel<A: Action<T>, P: PredicateInner, T: ModelType> {
    pub size: usize,
    pub data: Vec<ModelEntry<A, P, T>>,
}

impl<A, P, T> From<ModelEntry<A, P, T>> for InverseModel<A, P, T>
where
    A: Action<T>,
    P: PredicateInner,
    T: ModelType,
{
    fn from(value: ModelEntry<A, P, T>) -> Self {
        InverseModel {
            size: 1,
            data: vec![value],
        }
    }
}

impl<A, P, T> From<Vec<ModelEntry<A, P, T>>> for InverseModel<A, P, T>
where
    A: Action<T>,
    P: PredicateInner,
    T: ModelType,
{
    fn from(value: Vec<ModelEntry<A, P, T>>) -> Self {
        InverseModel {
            size: value.len(),
            data: value,
        }
    }
}

impl<A, P> ShlAssign for InverseModel<A, P, Multiple>
where
    A: CodedActions,
    P: PredicateInner,
{
    fn shl_assign(&mut self, rhs: Self) {
        if self.size == 0 {
            *self = rhs;
            return;
        } else if rhs.size == 0 {
            return;
        }
        let capacity = max(self.size, rhs.size);
        let mut result: HashMap<A, Predicate<P>, FxBuildHasher> =
            HashMap::with_capacity_and_hasher(capacity, FxBuildHasher::default());
        self.data.iter().for_each(|ex| {
            let mut px = ex.predicate.clone();
            rhs.data.iter().for_each(|ey| {
                let mut py = ey.predicate.clone();
                let pxy = &px & &py;
                if !pxy.is_empty() {
                    let axy = ex.action.overwritten(&ey.action);
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
                action: a,
                predicate: p,
                _marker: PhantomData,
            });
        });
        self.size = self.data.len();
    }
}

impl<A, P> InverseModel<A, P, Multiple>
where
    A: CodedActions,
    P: PredicateInner,
{
    pub fn resize(&mut self, to: usize, offset: usize) {
        for i in 0..self.size {
            self.data[i].action.resize(to, offset);
        }
    }
}

impl<A, P> From<InverseModel<A::S, P, Single>> for InverseModel<A, P, Multiple>
where
    A: CodedActions,
    P: PredicateInner,
{
    fn from(value: InverseModel<A::S, P, Single>) -> Self {
        let InverseModel { size, data } = value;
        let data = data
            .into_iter()
            .map(|x| ModelEntry {
                action: A::from(x.action),
                predicate: x.predicate,
                _marker: PhantomData,
            })
            .collect();
        Self { size, data }
    }
}

impl<A, P, T> Default for InverseModel<A, P, T>
where
    A: Action<T>,
    P: PredicateInner,
    T: ModelType,
{
    fn default() -> Self {
        Self {
            size: Default::default(),
            data: Default::default(),
        }
    }
}
