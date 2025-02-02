use std::{
    collections::hash_map::Entry,
    ops::{Deref, DerefMut},
    sync::{Arc, RwLock},
};

use fxhash::FxHashMap;
use petgraph::{
    acyclic::Acyclic,
    graph::{DiGraph, NodeIndex},
};
use rapimt_io::ib::loader::{Guid, Lid};
use serde::Serialize;

use crate::error::Error;

pub mod requirement;
pub mod snapshot;

type AnyPlugin<NK, Node, Edge, R> =
    Arc<RwLock<dyn PluginLike<R, NK = NK, Node = Node, Edge = Edge>>>;

pub struct CachedFwdGraph<NK, Node, Edge, R: PluginReportLike> {
    graph: Acyclic<DiGraph<Node, Edge>>,
    #[allow(unused)]
    loop_exists: bool,
    /// map from guid to node index
    node_map: FxHashMap<NK, NodeIndex>,
    /// Cached result of all verification plugins. It is required to NOT name two plugins with the
    /// same name.
    /// TODO: replace cache assess with trait
    cache: FxHashMap<Arc<str>, R>,
    plugin: FxHashMap<Arc<str>, AnyPlugin<NK, Node, Edge, R>>,
}

#[allow(unused)]
impl<NK, Node, Edge, R: PluginReportLike> CachedFwdGraph<NK, Node, Edge, R> {
    fn add_plugin(&mut self, plugin: AnyPlugin<NK, Node, Edge, R>) {
        self.plugin
            .insert(plugin.read().unwrap().get_name(), plugin.clone());
    }

    fn del_plugin(&mut self, name: &Arc<str>) {
        self.plugin.remove(name);
        self.invalidate_report(name);
    }

    fn has_plugin(&self, name: &Arc<str>) -> bool {
        self.plugin.contains_key(name)
    }

    fn get_report(&mut self, name: &Arc<str>) -> Option<&R> {
        match self.cache.entry(name.clone()) {
            Entry::Occupied(e) => Some(e.into_mut()),
            Entry::Vacant(e) => {
                let executor = self.plugin.get(name)?.read().unwrap();
                let report = executor.execute(self.graph.inner()).ok()?;
                Some(e.insert(report))
            }
        }
    }

    fn invalidate_report(&mut self, name: &Arc<str>) {
        self.cache.remove(name);
    }
}

impl<NK, Node, Edge, R: PluginReportLike> Deref for CachedFwdGraph<NK, Node, Edge, R> {
    type Target = Acyclic<DiGraph<Node, Edge>>;
    fn deref(&self) -> &Self::Target {
        &self.graph
    }
}

impl<NK, Node, Edge, R: PluginReportLike> DerefMut for CachedFwdGraph<NK, Node, Edge, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.graph
    }
}

unsafe impl<NK, Node, Edge, R: PluginReportLike> Sync for CachedFwdGraph<NK, Node, Edge, R> {}

pub trait PluginReportLike: Send + Sync + std::fmt::Debug {}

pub trait PluginLike<R: PluginReportLike>: Send + Sync + std::fmt::Debug {
    /// Unique id of a node
    type NK;
    type Node;
    type Edge;

    /// execute the plugin and put report in the cache
    fn execute(&self, g: &DiGraph<Self::Node, Self::Edge>) -> Result<R, Error>;
    fn enabled(&self) -> bool;
    fn get_name(&self) -> Arc<str>;
}

impl<NK, Node, Edge, R: PluginReportLike> PluginLike<R>
    for Arc<dyn PluginLike<R, NK = NK, Node = Node, Edge = Edge>>
{
    type NK = NK;

    type Node = Node;

    type Edge = Edge;

    fn execute(&self, g: &DiGraph<Self::Node, Self::Edge>) -> Result<R, Error> {
        self.deref().execute(g)
    }

    fn enabled(&self) -> bool {
        self.deref().enabled()
    }

    fn get_name(&self) -> Arc<str> {
        self.deref().get_name()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IbPluginReport {
    to_lid: Option<Lid>,
    to_guid: Option<Guid>,
    should_report: bool,
    report: Result<String, String>,
}

impl PluginReportLike for IbPluginReport {}

pub trait SnapshotQuery<R: PluginReportLike> {
    type NK;
    type Edge;

    /// List all alerts
    fn list_alert(&self) -> Vec<R>;
    /// Get single EC
    fn query_dag(&self, lid: Lid) -> Option<Vec<Self::Edge>>;
    /// Get a DAG from some source of an EC
    fn query_dag_from(&self, lid: Lid, src: Self::NK) -> Option<Vec<Self::Edge>>;
    /// Get the number of ECs
    fn query_num_ec(&self) -> usize;
}
