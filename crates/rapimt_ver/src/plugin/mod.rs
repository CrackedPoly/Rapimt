pub mod rsl;
pub mod regexset;

use std::sync::Arc;

use petgraph::graph::{DiGraph, NodeIndex};
use rapimt_core::r#match::predicate::{Predicate, PredicateInner};

use crate::AnyReport;

pub type AnyGraphPlugin<NK, Node, Edge> = Box<dyn GraphPluginLike<NK, Node, Edge>>;
pub type AnyVerifierPlugin<P, NK, Node, Edge> = Box<dyn VerifierPluginLike<P, NK, Node, Edge>>;

/// A graph plugin is verifying properties solely on a graph.
///
/// The main API of plugin is recognize_path(), when verifying a graph, the caller calls this
/// method multiple tiems with simple paths and conclude with a report. The report() method returns
/// the internal state of the plugin.
pub trait GraphPluginLike<NK, Node, Edge>: Send + Sync + std::fmt::Debug {
    /// Get the name of the plugin
    fn get_name(&self) -> Arc<str>;
    /// Check if the plugin is enabled
    fn enabled(&self) -> bool;
    /// Clone the plugin
    fn clone_boxed(&self) -> AnyGraphPlugin<NK, Node, Edge>;
    /// Recognize a path
    fn recognize_path(&mut self, graph: &DiGraph<Node, Edge>, path: &[NodeIndex]);
    /// Generate a report (after recognizing all paths in a graph)
    fn report(&self) -> AnyReport;
}

/// A verifier plugin differs from a graph plugin in that a verifier plugin is needed to be
/// dispatched according to its header space by the verifier.
pub trait VerifierPluginLike<P: PredicateInner, NK, Node, Edge>:
    GraphPluginLike<NK, Node, Edge> + Send + Sync + std::fmt::Debug
{
    fn header_space(&self) -> Predicate<P>;
}
