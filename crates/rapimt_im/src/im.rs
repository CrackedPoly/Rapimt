use std::{
    cmp::max,
    collections::HashMap,
    hash::BuildHasher,
    marker::PhantomData,
    ops::{Deref, DerefMut, ShlAssign},
};

use rapimt_core::prelude::{
    Action, CodedActions, Dimension, Multiple, Predicate, PredicateInner, Single,
};

pub trait InverseModelMonoid<A: Action<T>, P: PredicateInner, T: Dimension>:
    Default + Clone + IntoIterator<Item = (A, Predicate<P>)> + FromIterator<(A, Predicate<P>)>
{
    fn overwrite(&self, rhs: &Self) -> Self;

    fn overwrite_(&mut self, rhs: Self);

    fn default() -> Self;

    fn is_empty(&self) -> bool;

    fn len(&self) -> usize;

    fn iter<'a>(&'a self) -> impl Iterator<Item = (&'a A, &'a Predicate<P>)>
    where
        A: 'a,
        P: 'a;
}

impl<A, P, T, S> InverseModelMonoid<A, P, T> for HashMap<A, Predicate<P>, S>
where
    A: Action<T>,
    P: PredicateInner,
    T: Dimension,
    S: BuildHasher + Clone + Default,
{
    fn overwrite(&self, rhs: &Self) -> Self {
        if self.is_empty() {
            return rhs.clone();
        } else if rhs.is_empty() {
            return self.clone();
        }
        let capacity = max(self.len(), rhs.len());
        let mut result: HashMap<A, Predicate<P>, S> =
            HashMap::with_capacity_and_hasher(capacity, S::default());
        for ex in self.iter() {
            let mut px = ex.1.clone();
            for ey in rhs.iter() {
                let mut py = ey.1.clone();
                let pxy = &px & &py;
                if !pxy.is_empty() {
                    let axy = ex.0.overwrite(ey.0);
                    result
                        .entry(axy)
                        .and_modify(|mut p0| p0 |= &pxy)
                        .or_insert(pxy.clone());
                    px -= &pxy;
                    py -= &pxy;
                }
            }
        }
        result
    }

    fn overwrite_(&mut self, rhs: Self) {
        if self.is_empty() {
            *self = rhs;
            return;
        } else if rhs.is_empty() {
            return;
        }
        let capacity = max(self.len(), rhs.len());
        let mut result: HashMap<A, Predicate<P>, S> =
            HashMap::with_capacity_and_hasher(capacity, S::default());
        for ex in self.iter() {
            let mut px = ex.1.clone();
            for ey in rhs.iter() {
                let mut py = ey.1.clone();
                let pxy = &px & &py;
                if !pxy.is_empty() {
                    let axy = ex.0.overwrite(ey.0);
                    result
                        .entry(axy)
                        .and_modify(|mut p0| p0 |= &pxy)
                        .or_insert(pxy.clone());
                    px -= &pxy;
                    py -= &pxy;
                }
            }
        }
        self.reserve(result.len());
        self.clear();
        for x in result.into_iter() {
            self.insert(x.0, x.1);
        }
    }

    fn default() -> Self {
        HashMap::with_capacity_and_hasher(0, S::default())
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = (&'a A, &'a Predicate<P>)>
    where
        A: 'a,
        P: 'a,
    {
        self.iter()
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    fn len(&self) -> usize {
        self.len()
    }
}

#[derive(Debug)]
pub struct InverseModel<
    A: Action<T>,
    P: PredicateInner,
    T: Dimension,
    M: InverseModelMonoid<A, P, T>,
>(pub M, PhantomData<(A, P, T)>);

impl<A, P, T, M> Default for InverseModel<A, P, T, M>
where
    A: Action<T>,
    P: PredicateInner,
    T: Dimension,
    M: InverseModelMonoid<A, P, T>,
{
    fn default() -> Self {
        Self(<M as InverseModelMonoid<A, P, T>>::default(), PhantomData)
    }
}

impl<A, P, T, M, II> From<II> for InverseModel<A, P, T, M>
where
    A: Action<T>,
    P: PredicateInner,
    T: Dimension,
    M: InverseModelMonoid<A, P, T>,
    II: IntoIterator<Item = (A, Predicate<P>)>,
{
    fn from(value: II) -> Self {
        InverseModel(value.into_iter().collect(), PhantomData)
    }
}

impl<A, P, T, M> Deref for InverseModel<A, P, T, M>
where
    A: Action<T>,
    P: PredicateInner,
    T: Dimension,
    M: InverseModelMonoid<A, P, T>,
{
    type Target = M;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<A, P, T, M> DerefMut for InverseModel<A, P, T, M>
where
    A: Action<T>,
    P: PredicateInner,
    M: InverseModelMonoid<A, P, T>,
    T: Dimension,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<A, P, T, M> AsRef<M> for InverseModel<A, P, T, M>
where
    A: Action<T>,
    P: PredicateInner,
    T: Dimension,
    M: InverseModelMonoid<A, P, T>,
{
    fn as_ref(&self) -> &M {
        &self.0
    }
}

impl<A, P, T, M> ShlAssign for InverseModel<A, P, T, M>
where
    A: Action<T>,
    P: PredicateInner,
    T: Dimension,
    M: InverseModelMonoid<A, P, T>,
{
    fn shl_assign(&mut self, rhs: Self) {
        self.0.overwrite_(rhs.0);
    }
}

impl<A, P, M, N> From<InverseModel<A::S, P, Single, M>> for InverseModel<A, P, Multiple, N>
where
    A: CodedActions,
    P: PredicateInner,
    M: InverseModelMonoid<A::S, P, Single>,
    N: InverseModelMonoid<A, P, Multiple>,
{
    fn from(value: InverseModel<A::S, P, Single, M>) -> Self {
        Self(
            value.0.into_iter().map(|(a, p)| (A::from(a), p)).collect(),
            PhantomData,
        )
    }
}

impl<A, P, M> InverseModel<A, P, Multiple, M>
where
    A: CodedActions,
    P: PredicateInner,
    M: InverseModelMonoid<A, P, Multiple>,
{
    pub fn resize(origin: Self, to: usize, offset: usize) -> Self {
        Self(
            origin
                .0
                .into_iter()
                .map(|(mut a, p)| {
                    a.resize_(to, offset);
                    (a, p)
                })
                .collect(),
            PhantomData,
        )
    }
}
