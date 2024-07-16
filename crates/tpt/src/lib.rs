mod patricia;
mod segment;

pub use crate::{patricia::TernaryPatriciaTree, segment::{Segment, Segmentized, Segmentizer}};

#[cfg(feature = "graphviz")]
pub use crate::patricia::GraphvizDebug;
