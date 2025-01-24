use std::{error::Error, path::PathBuf, sync::Arc};

use fxhash::{FxBuildHasher, FxHashMap};
use petgraph::{graph::DiGraph, visit::Bfs};
use rapimt_core::{
    action::{ib::IbActionType, ActionEncoder, Actions, Multiple, UncodedAction},
    r#match::{
        engine::MatchEncoder,
        predicate::Predicate,
        raw_match::{FieldMatch, Match},
    },
};
use rapimt_im::{
    ib::{monitor::IbRuleMonitor, rule::Rule},
    im::InverseModel,
    RuleMonitorLike,
};
use rapimt_io::ib::{
    db_csv_parser::csv_parser::{load_groups, load_lft, load_nodes},
    loader::{CaSpec, FusedIdx, Guid, LftEntry, Lid, LinkSpec, NodeType, RawAction, SwitchSpec},
};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};

use super::{CachedFwdGraph, IbPluginReport, LabelFn, PluginExecutorLike, SnapshotQuery};

pub struct IbDataPlaneConfig<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    pub engine: &'p ME,
    pub topology_dir: PathBuf,
    pub far_dir: PathBuf,
    pub label_fn: LabelFn,
}

struct IbDataPlane<'p, ME: MatchEncoder<'p>> {
    engine: &'p ME,
    switch_monitors: FxHashMap<Guid, IbRuleMonitor<'p, FusedIdx, ME>>,
    switch_order: FxHashMap<Guid, usize>,
    switch_specs: FxHashMap<Guid, SwitchSpec>,
    ca_specs: FxHashMap<Guid, CaSpec>,
}

impl<'p, ME> IbDataPlane<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    // Load the snapshot from the given directory.
    // This method implementation is ugly because the input format is not regular.
    fn new(config: &IbDataPlaneConfig<'p, ME>) -> Result<Self, Box<dyn Error>> {
        let mut switch_specs = FxHashMap::with_hasher(FxBuildHasher::default());
        let mut switch_monitors = FxHashMap::with_hasher(FxBuildHasher::default());
        let mut switch_order = FxHashMap::with_hasher(FxBuildHasher::default());
        let mut ca_specs = FxHashMap::with_hasher(FxBuildHasher::default());
        let nodes = load_nodes(&config.topology_dir, config.label_fn)?;
        for (guid, node) in nodes {
            match node.node_type {
                NodeType::Switch => {
                    switch_specs.insert(
                        guid,
                        SwitchSpec {
                            common: node.clone(),
                            ..Default::default()
                        },
                    );
                    switch_monitors.insert(guid, IbRuleMonitor::new(config.engine));
                    switch_order.insert(guid, switch_order.len());
                }
                NodeType::HCA => {
                    ca_specs.insert(
                        guid,
                        CaSpec {
                            common: node.clone(),
                        },
                    );
                }
            }
        }
        // parse all groups
        for file in std::fs::read_dir(config.far_dir.join("group"))? {
            let (guid, groups) = load_groups(file?.path())?;
            let switch_spec = switch_specs
                .get_mut(&guid)
                .ok_or(format!("group error: switch {} not found", guid))?;
            switch_spec.groups = groups;
        }
        let dp = Self {
            engine: config.engine,
            switch_monitors,
            switch_order,
            switch_specs,
            ca_specs,
        };

        Ok(dp)
    }

    #[allow(unused)]
    fn add_switch(&mut self, spec: SwitchSpec) {
        self.switch_monitors
            .insert(spec.common.node_guid, IbRuleMonitor::new(self.engine));
        self.switch_order
            .insert(spec.common.node_guid, self.switch_order.len());
        self.switch_specs.insert(spec.common.node_guid, spec);
    }

    #[allow(unused)]
    fn add_ca(&mut self, spec: CaSpec) {
        self.ca_specs.insert(spec.common.node_guid, spec);
    }

    fn update(
        &mut self,
        switch: Guid,
        insertion: impl IntoIterator<Item = Rule<ME::P, FusedIdx>>,
        deletion: impl IntoIterator<Item = Rule<ME::P, FusedIdx>>,
    ) -> IM<ME::P> {
        let monitor = self.switch_monitors.get_mut(&switch).unwrap();
        InverseModel::resize(
            monitor.update(insertion, deletion),
            self.switch_order.len(),
            *self.switch_order.get(&switch).unwrap(),
        )
    }

    fn encode_lid(&self, lid: Lid) -> Predicate<ME::P> {
        self.engine.encode_match_wo_mv(FieldMatch {
            field: "lid",
            cond: Match::ExactMatch { value: lid },
        })
    }

    fn encode_rules(
        &self,
        switch: Guid,
        rules: impl IntoIterator<Item = LftEntry>,
    ) -> impl IntoIterator<Item = Rule<ME::P, FusedIdx>> {
        let encoder = self.switch_specs.get(&switch).unwrap();
        let mut encoded_rules = vec![];
        for r in rules.into_iter() {
            let raw_action = match r.lid_state {
                IbActionType::Static => RawAction::Static(r.port),
                IbActionType::HashBasedForwarding => RawAction::HBF(r.group),
                IbActionType::AdaptiveRouting => RawAction::AR(r.group),
                _ => panic!("Unsupported action type"),
            };
            encoded_rules.push(Rule {
                predicate: self.encode_lid(r.lid),
                action: encoder.encode_raw(&raw_action).unwrap(),
                lid: r.lid,
            });
        }
        encoded_rules
    }
}

type ActionsRepr = Arc<Vec<FusedIdx>>;
type IM<P> = InverseModel<ActionsRepr, P, Multiple, Vec<(ActionsRepr, Predicate<P>)>>;
type AnyPlugin<R> = Box<dyn PluginExecutorLike<R, NID = Guid, Edge = LinkSpec>>;

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
    graphs: FxHashMap<ActionsRepr, CachedFwdGraph<Guid, LinkSpec, IbPluginReport>>,
    // verification plugins
    plugins: Vec<AnyPlugin<IbPluginReport>>,
}

impl<'p, ME> SnapshotVerifier<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    pub fn new(config: &IbDataPlaneConfig<'p, ME>) -> Result<Self, Box<dyn Error>> {
        let mut verifier = Self {
            dp: IbDataPlane::new(config)?,
            im: InverseModel::default(),
            im_updates: Vec::default(),
            query_cache: FxHashMap::default(),
            graphs: FxHashMap::default(),
            plugins: Vec::default(),
        };
        for file in std::fs::read_dir(config.far_dir.join("lft"))? {
            let (guid, routes) = load_lft(file?.path())?;
            verifier.diff_raw_rules(guid, routes, vec![]);
        }
        Ok(verifier)
    }

    /// Receive a difference of rules for a switch, and stash the update.
    pub fn diff_rules(
        &mut self,
        switch: Guid,
        insertion: impl IntoIterator<Item = Rule<ME::P, FusedIdx>>,
        deletion: impl IntoIterator<Item = Rule<ME::P, FusedIdx>>,
    ) {
        self.im_updates
            .push(self.dp.update(switch, insertion, deletion));
    }

    pub fn diff_raw_rules(
        &mut self,
        switch: Guid,
        insertion: impl IntoIterator<Item = LftEntry>,
        deletion: impl IntoIterator<Item = LftEntry>,
    ) {
        let ins = self.dp.encode_rules(switch, insertion);
        let del = self.dp.encode_rules(switch, deletion);
        self.diff_rules(switch, ins, del);
    }

    /// Refresh the inverse model with stashed updates.
    pub fn refresh(&mut self) -> Result<(), Box<dyn Error>> {
        // update global model
        for update in self.im_updates.drain(..) {
            self.im <<= update;
        }
        // update query cache
        for (action, predicate) in self.im.iter() {
            self.query_cache.insert(predicate.clone(), action.clone());
        }
        // TODO: refactor this bunch of code with traits: DataPlane, Port, Link, Node, Graph
        // add to forwarding graphs if there are new action patterns
        for (action, _) in self.im.iter() {
            self.graphs.entry(action.clone()).or_insert_with(|| {
                let mut graph = DiGraph::default();
                let mut node_map = FxHashMap::default();
                graph.reserve_nodes(action.len());
                // add all switch nodes
                for (src_guid, src) in self.dp.switch_specs.iter() {
                    let node_idx = graph.add_node(src.common.clone());
                    node_map.insert(*src_guid, node_idx);
                }
                // add all edges according to decodec actions
                for (src_guid, src) in self.dp.switch_specs.iter() {
                    let idx = self.dp.switch_order.get(src_guid).unwrap();
                    let decoded_action = src.decode(*action.index(*idx));
                    if let Some(it) = decoded_action.get_ports() {
                        for src_port_idx in it {
                            let (_, link) = src.common.ports.get(&src_port_idx).unwrap();
                            if let Some(link) = link {
                                let dst_guid = link.dst_node_guid;
                                // may contains CA nodes
                                if !self.dp.switch_specs.contains_key(&dst_guid) {
                                    node_map.entry(dst_guid).or_insert_with(|| {
                                        let dst = self.dp.ca_specs.get(&dst_guid).unwrap();
                                        graph.add_node(dst.common.clone())
                                    });
                                }
                                graph.add_edge(
                                    *node_map.get(src_guid).unwrap(),
                                    *node_map.get(&dst_guid).unwrap(),
                                    *link,
                                );
                            }
                        }
                    }
                }
                CachedFwdGraph {
                    graph,
                    node_map,
                    report_cache: FxHashMap::default(),
                }
            });
        }
        // run verification plugins if result not found in cache
        for plugin in &self.plugins {
            let name = plugin.get_name();
            self.graphs.par_iter_mut().for_each(|(_, graph)| {
                if !graph.report_cache.contains_key(name) {
                    plugin.execute(graph);
                }
            });
        }
        Ok(())
    }

    /// Register a verification plugin.
    pub fn register_plugin(&mut self, plugin: AnyPlugin<IbPluginReport>) {
        self.plugins.push(plugin);
    }

    /// Execute all verification plugins.
    pub fn verify(&mut self) -> Result<(), Box<dyn Error>> {
        for plugin in &self.plugins {
            let name = plugin.get_name();
            self.graphs.par_iter_mut().for_each(|(_, graph)| {
                if !graph.report_cache.contains_key(name) {
                    plugin.execute(graph);
                }
            });
        }
        Ok(())
    }
}

impl<'p, ME> SnapshotQuery<IbPluginReport> for SnapshotVerifier<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    type ID = Guid;
    type Edge = LinkSpec;

    fn list_alert(&self) -> Vec<IbPluginReport> {
        let mut alerts = vec![];
        for graph in self.graphs.values() {
            for report in graph.report_cache.values() {
                if report.should_report {
                    alerts.push(report.clone());
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
            links.push(*e.weight());
        }
        Some(links)
    }

    fn query_dag_from(&self, lid: Lid, src: Guid) -> Option<Vec<Self::Edge>> {
        // HARDCODE: passed `src` is a CA node, we need to find the access switch.
        let ca = self.dp.ca_specs.get(&src)?;
        let src = ca.common.ports.get(&1)?.1?.dst_node_guid;

        let p = self.dp.encode_lid(lid);
        let acts = self.query_cache.get(&p)?;
        let cg = &self.graphs.get(acts)?;

        let mut links = vec![];
        let src_idx = cg.node_map.get(&src)?;
        let mut bfs = Bfs::new(&cg.graph, *src_idx);
        while let Some(nx) = bfs.next(&cg.graph) {
            for e in cg.graph.edges(nx) {
                links.push(*e.weight());
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
