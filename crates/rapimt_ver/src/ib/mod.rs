use std::{error::Error, rc::Rc};

use fxhash::FxHashMap;
use petgraph::graph::{DiGraph, NodeIndex};
use rapimt_core::{
    action::Actions,
    r#match::predicate::{Predicate, PredicateInner},
};
use rapimt_io::ib::loader::{Guid, Lid, NodeCommon};

pub mod requirement;
pub mod snapshot;

pub type LabelFn = fn(&str) -> u8;

pub type VeriReport = String;

pub struct CachedFwdGraph {
    graph: DiGraph<Rc<NodeCommon>, ()>,
    /// map from guid to node index
    #[allow(unused)]
    node_map: FxHashMap<Guid, NodeIndex>,
    /// Cached result of all verification plugins. It is required to NOT name two plugins with the
    /// same name.
    veri_cache: FxHashMap<String, Result<VeriReport, Box<dyn Error>>>,
}

pub trait VerificationPlugin {
    fn get_name(&self) -> &str;
    fn execute(&self, cgraph: &mut CachedFwdGraph) -> Result<VeriReport, Box<dyn Error>>;
    fn review(&self, report: &VeriReport) -> Result<bool, Box<dyn Error>>;
}

pub trait SnapshotQuery<'a, A: Actions, P: PredicateInner> {
    /// Get single EC
    fn query_ec(&self, lid: Lid) -> Option<(&Predicate<P>, &A)>;
    /// Get the number of ECs
    fn query_num_ec(&self) -> usize;
}
