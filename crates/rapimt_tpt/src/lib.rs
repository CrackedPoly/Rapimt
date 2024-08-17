//! This module provides Ternary Patricia Tree (TPT) implementation for FIB monitor to store rules,
//! usually it will only be used internally.
mod patricia;
mod segment;

pub use crate::{
    patricia::TernaryPatriciaTree,
    segment::{Segment, Segmentized, Segmentizer},
};

#[cfg(feature = "graphviz")]
pub use crate::patricia::GraphvizDebug;

#[allow(missing_docs)]
pub mod prelude {
    #[doc(hidden)]
    pub use crate::{patricia::TernaryPatriciaTree, Segmentized, Segmentizer};
}
