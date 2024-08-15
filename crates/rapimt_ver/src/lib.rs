//! Defines Verification traits and implementations.
use rapimt_core::prelude::{Predicate, PredicateInner};

pub trait Invariant<P>
where
    P: PredicateInner,
{
    fn name(&self) -> &str;
    fn header_space(&self) -> Predicate<P>;
}


pub enum Requirement<P>
where 
    P: PredicateInner 
{
    Reachability(Reachability<P>),
    MinHopCount(MinHopCount<P>),
}

impl<P> Invariant<P> for Requirement<P>
where 
    P: PredicateInner 
{
    fn name(&self) -> &str {
        match self {
            Requirement::Reachability(r) => r.name.as_str(),
            Requirement::MinHopCount(m) => m.name.as_str()
        }
    }
    fn header_space(&self) -> Predicate<P> {
        match self {
            Requirement::Reachability(r) => r.header_space.clone(),
            Requirement::MinHopCount(m) => m.header_space.clone(),
        }
    }
}

pub struct Reachability<P> 
where 
    P: PredicateInner 
{
    pub name: String,
    pub header_space: Predicate<P>,
}

pub struct MinHopCount<P>
where 
    P: PredicateInner 
{
    pub name: String,
    pub header_space: Predicate<P>,
}

#[allow(missing_docs)]
pub mod prelude {
    #[doc(hidden)]
    pub use crate::Invariant;
}
