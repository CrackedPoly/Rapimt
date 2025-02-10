use std::sync::Arc;

use fxhash::FxHashMap;
use petgraph::{acyclic::Acyclic, data::Build, graph::DiGraph, visit::Bfs};
use rapimt_core::{
    action::{seq_action::SeqAction, ActionEncoder, Actions, Multiple, UncodedAction},
    r#match::{engine::MatchEncoder, predicate::Predicate},
};
use rapimt_im::im::InverseModel;
use rapimt_io::ib::{
    db_csv_parser::csv_parser::load_lft,
    loader::{FusedIdx, Guid, IbDataPlane, LftEntry, Lid, LinkSpec, NodeCommon},
    DataPlane, IbDataPlaneConfig,
};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};

use crate::error::*;
use crate::{plugin::GraphPluginLike, AnyReport, CachedFwdGraph, SnapshotQuery};

type ActionsRepr = Arc<SeqAction<FusedIdx>>;
type IM<P> = InverseModel<ActionsRepr, P, Multiple, Vec<(ActionsRepr, Predicate<P>)>>;
type AnyGraphPlugin = Box<dyn GraphPluginLike<Guid, Arc<NodeCommon>, Arc<LinkSpec>>>;

pub struct SnapshotVerifier<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    dp: IbDataPlane<'p, ME>,

    im: IM<ME::P>,
    im_updates: Vec<IM<ME::P>>,

    // fast lookup actions by predicate
    query_cache: FxHashMap<Predicate<ME::P>, ActionsRepr>,
    // forwarding graphs
    graphs: FxHashMap<ActionsRepr, CachedFwdGraph<Guid, Arc<NodeCommon>, Arc<LinkSpec>>>,
    plugins: Vec<AnyGraphPlugin>,
}

impl<'p, ME> SnapshotVerifier<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    pub fn new(config: &IbDataPlaneConfig<'p, ME>) -> Result<Self, Error> {
        let mut verifier = Self {
            dp: IbDataPlane::new(config)?,
            im: InverseModel::default(),
            im_updates: Vec::default(),
            query_cache: FxHashMap::default(),
            graphs: FxHashMap::default(),
            plugins: Vec::default(),
        };
        log::info!("Loading LFTs from {}", config.far_dir.join("lft").display());
        let mut num_dev = 0usize;
        for file in std::fs::read_dir(config.far_dir.join("lft")).unwrap() {
            let (guid, routes) = load_lft(file.unwrap().path())?;
            verifier.diff_raw_rules(&guid, routes, vec![])?;
            num_dev += 1;
        }
        log::info!("Loaded LFTs from {} devices", num_dev);
        Ok(verifier)
    }

    pub fn diff_raw_rules(
        &mut self,
        switch: &Guid,
        insertion: impl IntoIterator<Item = LftEntry>,
        deletion: impl IntoIterator<Item = LftEntry>,
    ) -> Result<(), Error> {
        let update = self.dp.update_rules(switch, insertion, deletion)?;
        self.im_updates.push(update);
        Ok(())
    }

    /// Refresh the inverse model with stashed updates.
    pub fn refresh(&mut self) -> Result<(), Error> {
        log::info!("Refreshing the verifier...");
        // update global model
        for update in self.im_updates.drain(..) {
            self.im <<= update;
        }
        log::info!("#EC: {}", self.im.len());
        // update query cache
        for (action, predicate) in self.im.iter() {
            self.query_cache.insert(predicate.clone(), action.clone());
        }
        // add to forwarding graphs if there are new action patterns
        let mut num_new = 0usize;
        for (action, _) in self.im.iter() {
            self.graphs.entry(action.clone()).or_insert({
                num_new += 1;
                let mut loop_exists = false;
                let mut graph = DiGraph::new();
                graph.reserve_nodes(action.ndim());
                let mut node_map = FxHashMap::default();
                let mut graph = Acyclic::try_from_graph(graph).unwrap();

                // add all switch nodes
                for (src_guid, src) in self.dp.iter_switch_topology() {
                    let node_idx = graph.add_node(src);
                    node_map.insert(src_guid, node_idx);
                }
                // add all edges according to decoded actions
                for (src_guid, src) in self.dp.iter_switch_topology() {
                    let idx = self.dp.get_encoder_index(&src_guid).unwrap();
                    for src_port_idx in self
                        .dp
                        .get_encoder(&src_guid)?
                        .decode(*action.index(idx))?
                        .get_ports()?
                    {
                        let link = &src.ports.get(&src_port_idx).unwrap().link;
                        if let Some(link) = link {
                            let dst_guid = link.dst_node_guid;
                            // may contains CA nodes
                            if self.dp.is_node_host(&dst_guid)? {
                                node_map.entry(dst_guid).or_insert({
                                    let dst = self.dp.get_topology(&dst_guid)?;
                                    graph.add_node(dst.clone())
                                });
                            }
                            if graph
                                .try_add_edge(
                                    *node_map.get(&src_guid).unwrap(),
                                    *node_map.get(&dst_guid).unwrap(),
                                    link.clone(),
                                )
                                .is_err()
                            {
                                loop_exists = true;
                            };
                        }
                    }
                }
                CachedFwdGraph {
                    graph,
                    loop_exists,
                    node_map,
                    plugin: FxHashMap::default(),
                }
            });
        }
        log::info!("#new action patterns: {}", num_new);
        // run verification plugins if result not found in cache
        self.verify()?;
        log::info!("Verifier refreshed");
        Ok(())
    }

    /// Register a verification plugin.
    pub fn register_plugin(&mut self, plugin: AnyGraphPlugin) {
        log::info!("Registering plugin: {}", &plugin.get_name());
        self.plugins.push(plugin.clone_boxed());
        for graph in self.graphs.values_mut() {
            graph.add_plugin(plugin.clone_boxed());
        }
    }

    /// Execute all verification plugins.
    pub fn verify(&mut self) -> Result<(), Error> {
        // ensure plugins are present in new graphs
        for graph in self.graphs.values_mut() {
            for plugin in &self.plugins {
                if !graph.has_plugin(plugin.get_name()) {
                    graph.add_plugin(plugin.clone_boxed());
                }
            }
        }
        self.graphs.par_iter_mut().for_each(|(_, graph)| {
            graph.execute();
        });
        // run verification
        Ok(())
    }
}

impl<'p, ME> SnapshotQuery for SnapshotVerifier<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    type NK = Guid;
    type Edge = Arc<LinkSpec>;

    fn list_alert(&self) -> Vec<AnyReport> {
        let mut alerts = vec![];
        for graph in self.graphs.values() {
            for plugin in graph.plugin.values() {
                let report = plugin.report();
                if report.should_report() {
                    alerts.push(report);
                }
            }
        }
        alerts
    }

    fn query_dag(&self, lid: Lid) -> Option<Vec<Self::Edge>> {
        let p = self.dp.encode_lid(lid);
        let acts = self.query_cache.get(&p)?;
        let g = &self.graphs.get(acts)?.graph;

        let mut links = vec![];
        for e in g.edge_references() {
            links.push(e.weight().clone());
        }
        Some(links)
    }

    fn query_dag_from(&self, lid: Lid, src: Guid) -> Option<Vec<Self::Edge>> {
        // HARDCODE: passed `src` is a CA node, we need to find the access switch.
        let ca = self.dp.get_topology(&src).unwrap();
        let src = ca.ports.get(&1)?.link.as_ref()?.dst_node_guid;

        let p = self.dp.encode_lid(lid);
        let acts = self.query_cache.get(&p)?;
        let cg = &self.graphs.get(acts)?;

        let mut links = vec![];
        let src_idx = cg.node_map.get(&src)?;
        let mut bfs = Bfs::new(&cg.graph, *src_idx);
        while let Some(nx) = bfs.next(&cg.graph) {
            for e in cg.graph.edges(nx) {
                links.push(e.weight().clone());
            }
        }
        Some(links)
    }

    fn query_num_ec(&self) -> usize {
        self.im.len()
    }
}

unsafe impl<'p, ME> Send for SnapshotVerifier<'p, ME> where ME: MatchEncoder<'p> {}
unsafe impl<'p, ME> Sync for SnapshotVerifier<'p, ME> where ME: MatchEncoder<'p> {}

#[cfg(test)]
mod tests {}
