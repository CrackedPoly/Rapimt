use std::{
    fmt::{Debug, Display, Result as FmtResult},
    marker::PhantomData,
};

use funty::Unsigned;

use crate::r#match::{
    engine::MatchEncoder,
    predicate::{Predicate, PredicateInner},
};

pub struct NoPredicateEngine<U: Unsigned> {
    _phantom: PhantomData<U>,
}

impl<U: Unsigned> NoPredicateEngine<U> {
    #[allow(unused)]
    pub fn init(_node_num: usize, _cache_size: usize) -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<'a, U: Unsigned> MatchEncoder<'a> for NoPredicateEngine<U>
where
    <U as std::str::FromStr>::Err: std::fmt::Debug,
{
    type P = NoPredicate<U>;

    #[inline]
    fn gc(&self) -> usize {
        0
    }

    #[inline]
    fn one(&'a self) -> Predicate<Self::P> {
        Predicate::from(NoPredicate(U::MAX))
    }

    #[inline]
    fn zero(&'a self) -> Predicate<Self::P> {
        Predicate::from(NoPredicate(U::ZERO))
    }

    fn _encode<T: Unsigned>(
        &'a self,
        value: T,
        _mask: T,
        _from: usize,
        _to: usize,
    ) -> Predicate<Self::P> {
        Predicate::from(NoPredicate(U::from_str(&value.to_string()).unwrap()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NoPredicate<U: Unsigned>(U);

impl<U: Unsigned> Display for NoPredicate<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

impl<U: Unsigned> PredicateInner for NoPredicate<U> {
    #[inline]
    fn not(&self) -> Self {
        unimplemented!()
    }

    #[inline]
    fn and(&self, _rhs: &Self) -> Self {
        unimplemented!()
    }

    #[inline]
    fn or(&self, _rhs: &Self) -> Self {
        unimplemented!()
    }

    #[inline]
    fn comp(&self, _rhs: &Self) -> Self {
        unimplemented!()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        unimplemented!()
    }

    #[inline]
    fn _ref(self) -> Self {
        self
    }

    #[inline]
    fn _deref(&self) {}
}
