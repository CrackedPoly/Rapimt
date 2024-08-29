use std::{
    cmp::max,
    collections::HashMap,
    marker::PhantomData,
    ops::{Deref, DerefMut, ShlAssign},
};

use fxhash::FxBuildHasher;
use rapimt_core::{
    action::{Action, CodedActions, ModelType, Multiple, Single},
    r#match::{Predicate, PredicateInner},
};

#[derive(Debug)]
pub struct InverseModel<A: Action<T>, P: PredicateInner, T: ModelType> {
    pub vec: Vec<(A, Predicate<P>)>,
    _marker: PhantomData<T>,
}

impl<A, P, T, II> From<II> for InverseModel<A, P, T>
where
    A: Action<T>,
    P: PredicateInner,
    T: ModelType,
    II: IntoIterator<Item = (A, Predicate<P>)>,
{
    fn from(value: II) -> Self {
        InverseModel {
            vec: value.into_iter().collect(),
            _marker: PhantomData,
        }
    }
}

impl<A, P, T> Deref for InverseModel<A, P, T>
where
    A: Action<T>,
    P: PredicateInner,
    T: ModelType,
{
    type Target = Vec<(A, Predicate<P>)>;
    fn deref(&self) -> &Self::Target {
        &self.vec
    }
}

impl<A, P, T> DerefMut for InverseModel<A, P, T>
where
    A: Action<T>,
    P: PredicateInner,
    T: ModelType,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vec
    }
}

impl<A, P, T> AsRef<[(A, Predicate<P>)]> for InverseModel<A, P, T>
where
    A: Action<T>,
    P: PredicateInner,
    T: ModelType,
{
    fn as_ref(&self) -> &[(A, Predicate<P>)] {
        &self.vec
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
            vec: vec![],
            _marker: Default::default(),
        }
    }
}

impl<A, P> ShlAssign for InverseModel<A, P, Multiple>
where
    A: CodedActions,
    P: PredicateInner,
{
    fn shl_assign(&mut self, rhs: Self) {
        if self.len() == 0 {
            *self = rhs;
            return;
        } else if rhs.len() == 0 {
            return;
        }
        let capacity = max(self.len(), rhs.len());
        let mut result: HashMap<A, Predicate<P>, FxBuildHasher> =
            HashMap::with_capacity_and_hasher(capacity, FxBuildHasher::default());
        self.iter().for_each(|ex| {
            let mut px = ex.1.clone();
            rhs.iter().for_each(|ey| {
                let mut py = ey.1.clone();
                let pxy = &px & &py;
                if !pxy.is_empty() {
                    let axy = ex.0.overwritten(&ey.0);
                    result
                        .entry(axy)
                        .and_modify(|mut p0| p0 |= &pxy)
                        .or_insert(pxy.clone());
                    px -= &pxy;
                    py -= &pxy;
                }
            });
        });
        self.reserve(result.len());
        self.clear();
        result.into_iter().for_each(|x| {
            self.push(x);
        });
    }
}

impl<A, P> From<InverseModel<A::S, P, Single>> for InverseModel<A, P, Multiple>
where
    A: CodedActions,
    P: PredicateInner,
{
    fn from(value: InverseModel<A::S, P, Single>) -> Self {
        Self::from(value.vec.into_iter().map(|(a, p)| (A::from(a), p)))
    }
}

impl<A, P> InverseModel<A, P, Multiple>
where
    A: CodedActions,
    P: PredicateInner,
{
    pub fn resize(&mut self, to: usize, offset: usize) {
        for i in 0..self.len() {
            self[i].0.resize(to, offset);
        }
    }
}
