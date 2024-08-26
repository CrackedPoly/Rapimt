//! Defines Verification traits and implementations.
use rapimt_core::prelude::{Predicate, PredicateInner};

pub trait Invariant {
    type P: PredicateInner;

    fn name(&self) -> &str;
    fn header_space(&self) -> Predicate<Self::P>;
}

pub enum Requirement<P: PredicateInner> {
    Reachability(Reachability<P>),
    MinHopCount(MinHopCount<P>),
}

impl<P: PredicateInner> Invariant for Requirement<P> {
    type P = P;

    fn name(&self) -> &str {
        match self {
            Requirement::Reachability(r) => r.name.as_str(),
            Requirement::MinHopCount(m) => m.name.as_str(),
        }
    }
    fn header_space(&self) -> Predicate<P> {
        match self {
            Requirement::Reachability(r) => r.header_space.clone(),
            Requirement::MinHopCount(m) => m.header_space.clone(),
        }
    }
}

pub struct Reachability<P: PredicateInner> {
    pub name: String,
    pub header_space: Predicate<P>,
}

pub struct MinHopCount<P: PredicateInner> {
    pub name: String,
    pub header_space: Predicate<P>,
}

#[allow(missing_docs)]
pub mod prelude {
    #[doc(hidden)]
    pub use crate::Invariant;
}
