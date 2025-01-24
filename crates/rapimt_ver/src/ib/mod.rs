use std::{ops::Deref, sync::Arc};

use funty::Unsigned;
use fxhash::FxHashMap;
use petgraph::graph::{DiGraph, NodeIndex};
use rapimt_io::ib::loader::{Guid, Lid, LinkSpec, NodeCommon};
use serde::Serialize;

pub mod requirement;
pub mod snapshot;

pub type LabelFn = fn(&str) -> u8;

#[derive(Debug)]
pub struct CachedFwdGraph<NID: Unsigned, Edge, R: PluginReportLike> {
    /// TODO: replace NodeCommon with a trait
    graph: DiGraph<Arc<NodeCommon>, Edge>,
    /// map from guid to node index
    node_map: FxHashMap<NID, NodeIndex>,
    /// Cached result of all verification plugins. It is required to NOT name two plugins with the
    /// same name.
    /// TODO: replace cache assess with trait
    report_cache: FxHashMap<Arc<str>, R>,
}

unsafe impl<NID: Unsigned, Edge, R: PluginReportLike> Sync for CachedFwdGraph<NID, Edge, R> {}

pub trait PluginReportLike: Send + Sync {}

pub trait PluginExecutorLike<R: PluginReportLike>: Sync {
    /// Unique id of a node
    type NID: Unsigned;
    /// Edge type
    type Edge;

    /// execute the plugin and put report in the cache
    fn _execute(&self, cgraph: &mut CachedFwdGraph<Self::NID, Self::Edge, R>);
    fn get_name(&self) -> Arc<str>;

    fn execute(&self, cgraph: &mut CachedFwdGraph<Self::NID, Self::Edge, R>) {
        if !cgraph.report_cache.contains_key(&self.get_name()) {
            self._execute(cgraph);
        }
    }
}

impl PluginExecutorLike<IbPluginReport>
    for Box<dyn PluginExecutorLike<IbPluginReport, NID = Guid, Edge = Arc<LinkSpec>>>
{
    type NID = Guid;

    type Edge = Arc<LinkSpec>;

    fn _execute(&self, cgraph: &mut CachedFwdGraph<Self::NID, Self::Edge, IbPluginReport>) {
        self.deref()._execute(cgraph)
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
    type ID: Unsigned;
    type Edge;

    /// List all alerts
    fn list_alert(&self) -> Vec<R>;
    /// Get single EC
    fn query_dag(&self, lid: Lid) -> Option<Vec<Self::Edge>>;
    /// Get a DAG from some source of an EC
    fn query_dag_from(&self, lid: Lid, src: Self::ID) -> Option<Vec<Self::Edge>>;
    /// Get the number of ECs
    fn query_num_ec(&self) -> usize;
}
