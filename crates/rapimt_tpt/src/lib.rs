//! Ternary Patricia Tree (TPT) implementation for FIB monitor to insert, remove, lookup rules.
mod patricia;
mod segment;

#[cfg(feature = "graphviz")]
pub use crate::patricia::GraphvizDebug;

#[allow(missing_docs)]
pub mod prelude {
    #[doc(hidden)]
    pub use crate::{
        patricia::{SetHandle, TernaryPatriciaTree},
        segment::{Segmentized, Segmentizer},
    };
}
