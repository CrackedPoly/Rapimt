use std::{
    cmp::max,
    collections::HashMap,
    hash::BuildHasher,
    marker::PhantomData,
    ops::{Deref, DerefMut, ShlAssign},
};

use rapimt_core::prelude::{
    Action, Actions, Dimension, Multiple, Predicate, PredicateInner, Single,
};

/// A monoid defined on the overwrite operator.
pub trait InverseModelMonoid<A: Action<T>, P: PredicateInner, T: Dimension>:
    Default + Clone + IntoIterator<Item = (A, Predicate<P>)> + FromIterator<(A, Predicate<P>)>
{
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
                    let axy = ex.0.overwritten(ey.0);
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

/// This implementation is only used for IB networks, where all IMs are of the same size (#lid).
impl<A, P, T> InverseModelMonoid<A, P, T> for Vec<(A, Predicate<P>)>
where
    A: Action<T>,
    P: PredicateInner,
    T: Dimension,
{
    fn overwrite_(&mut self, rhs: Self) {
        if self.is_empty() {
            *self = rhs;
            return;
        } else if rhs.is_empty() {
            return;
        }
        self.iter_mut().zip(rhs.iter()).for_each(|(ex, ey)| {
            ex.0.overwritten_(ey.0);
        });
    }

    fn default() -> Self {
        vec![]
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = (&'a A, &'a Predicate<P>)>
    where
        A: 'a,
        P: 'a,
    {
        <Vec<(A, Predicate<P>)> as Deref>::deref(self)
            .iter()
            .map(|(a, p)| (a, p))
    }
}

/// Invserse Model maps actions to predicates.
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
    A: Actions,
    P: PredicateInner,
    M: InverseModelMonoid<A::S, P, Single>,
    N: InverseModelMonoid<A, P, Multiple>,
{
    fn from(value: InverseModel<A::S, P, Single, M>) -> Self {
        Self(
            value
                .0
                .into_iter()
                .map(|(a, p)| (A::from_single(a), p))
                .collect(),
            PhantomData,
        )
    }
}

impl<A, P, M> InverseModel<A, P, Multiple, M>
where
    A: Actions,
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

/// Check if the inverse model is both mutually exclusive and complete, return `true` if the check
/// passes.
impl<A, P, T, M> InverseModel<A, P, T, M>
where
    A: Action<T>,
    P: PredicateInner,
    T: Dimension,
    M: InverseModelMonoid<A, P, T>,
{
    pub fn property_check(&self) -> bool {
        for ((_, px), ix) in self.iter().zip(0..) {
            for ((_, py), iy) in self.iter().zip(0..).skip(ix + 1) {
                if ix != iy {
                    let pxy = px & py;
                    if !pxy.is_empty() {
                        return false;
                    }
                }
            }
        }
        if !self.is_empty() {
            let mut sum = self.iter().next().unwrap().1.clone();
            for (_, p) in self.iter() {
                sum |= p;
            }
            // if sum is not ONE
            if !(!sum).is_empty() {
                return false;
            }
        }
        true
    }
}
