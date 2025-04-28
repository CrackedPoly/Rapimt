//! Verification traits and implementations.

pub mod error;
pub mod ib;
pub mod plugin;

use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use fxhash::{FxBuildHasher, FxHashMap};
use petgraph::{
    acyclic::Acyclic,
    algo::all_simple_paths,
    graph::{DiGraph, NodeIndex},
};
use plugin::AnyGraphPlugin;
use rapimt_io::ib::loader::Lid;

pub type AnyReport = Box<dyn ReportLike>;

/// A forwarding graph can be registered with multiple plugins to verify different requirements.
///
/// An report is an execution result of a plugin. [CachedFwdGraph] cache reports of first executions
/// of a plugins.
pub struct CachedFwdGraph<NK, Node, Edge> {
    graph: Acyclic<DiGraph<Node, Edge>>,
    #[allow(unused)]
    loop_exists: bool,
    /// map from guid to node index
    node_map: FxHashMap<NK, NodeIndex>,
    /// Cached result of all verification plugins. It is required to NOT have two plugins with the
    /// same name.
    plugin: FxHashMap<Arc<str>, AnyGraphPlugin<NK, Node, Edge>>,
}

#[allow(unused)]
impl<NK, Node, Edge> CachedFwdGraph<NK, Node, Edge> {
    fn add_plugin(&mut self, plugin: AnyGraphPlugin<NK, Node, Edge>) {
        let name = plugin.get_name();
        self.plugin.insert(name.clone(), plugin);
    }

    fn del_plugin(&mut self, name: impl AsRef<str>) {
        self.plugin.remove(name.as_ref());
    }

    fn has_plugin(&self, name: impl AsRef<str>) -> bool {
        self.plugin.contains_key(name.as_ref())
    }

    fn get_report(&mut self, name: &Arc<str>) -> Option<AnyReport> {
        if let Some(plugin) = self.plugin.get(name) {
            Some(plugin.report())
        } else {
            None
        }
    }

    /// Runs all registered plugins on every simple path from each source node to each sink node in the graph.
    ///
    /// For each pair of distinct nodes where the destination has no outgoing edges, finds all simple paths between them and invokes each plugin's `recognize_path` method on these paths. This enables comprehensive verification of the graph structure using the installed plugins.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut graph = CachedFwdGraph::new();
    /// // ... add nodes, edges, and plugins ...
    /// graph.execute(); // Runs verification plugins on all simple paths
    /// ```    fn execute(&mut self) {
        let dsts: Vec<_> = self
            .node_indices()
            .filter(|i| self.neighbors(*i).next().is_none())
            .collect();
        for dst in dsts {
            for src in self.node_indices() {
                if src == dst {
                    continue;
                }
                for path in all_simple_paths::<Vec<_>, _, FxBuildHasher>(
                    self.graph.inner(),
                    src,
                    dst,
                    0,
                    None,
                ) {
                    for plugin in self.plugin.values_mut() {
                        plugin.recognize_path(self.graph.inner(), &path);
                    }
                }
            }
        }
    }
}

impl<NK, Node, Edge> Deref for CachedFwdGraph<NK, Node, Edge> {
    type Target = Acyclic<DiGraph<Node, Edge>>;
    fn deref(&self) -> &Self::Target {
        &self.graph
    }
}

impl<NK, Node, Edge> DerefMut for CachedFwdGraph<NK, Node, Edge> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.graph
    }
}

unsafe impl<NK, Node, Edge> Sync for CachedFwdGraph<NK, Node, Edge> {}

/// A plugin report is an execution result of a plugin.
#[typetag::serde(tag = "type")]
pub trait ReportLike: Send + Sync + std::fmt::Debug {
    fn should_report(&self) -> bool;
}

/// RESTful API for querying a snapshot.
pub trait SnapshotQuery {
    type NK;
    type Edge;

    /// List all alerts
    fn list_alert(&self) -> Vec<AnyReport>;
    /// Get single EC
    fn query_dag(&self, lid: Lid) -> Option<Vec<Self::Edge>>;
    /// Get a DAG from some source of an EC
    fn query_dag_from(&self, lid: Lid, src: Self::NK) -> Option<Vec<Self::Edge>>;
    /// Get the number of ECs
    fn query_num_ec(&self) -> usize;
}

#[allow(missing_docs)]
pub mod prelude {}
