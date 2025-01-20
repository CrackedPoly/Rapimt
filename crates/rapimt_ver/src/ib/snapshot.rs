use std::{error::Error, path::PathBuf, rc::Rc};

use fxhash::{FxBuildHasher, FxHashMap};
use petgraph::graph::DiGraph;
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
    loader::{CaSpec, FusedIdx, Guid, LftEntry, Lid, NodeType, RawAction, SwitchSpec},
};

use super::{CachedFwdGraph, LabelFn, SnapshotQuery, VerificationPlugin};

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

type ActionsRepr = Rc<Vec<FusedIdx>>;
type IM<P> = InverseModel<ActionsRepr, P, Multiple, Vec<(ActionsRepr, Predicate<P>)>>;

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
    graphs: FxHashMap<ActionsRepr, CachedFwdGraph>,
    // verification plugins
    plugins: Vec<Box<dyn VerificationPlugin>>,
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
                    if let Some(it) = decoded_action.get_next_hops() {
                        for dst_guid in it {
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
                                (),
                            );
                        }
                    }
                }
                CachedFwdGraph {
                    graph,
                    veri_cache: FxHashMap::default(),
                    node_map,
                }
            });
        }
        // run verification plugins
        for plugin in &self.plugins {
            for (_, graph) in self.graphs.iter_mut() {
                let name = plugin.get_name();
                if !graph.veri_cache.contains_key(name) {
                    let result = plugin.execute(graph);
                    println!("Verification plugin {:?} report: {:?}", name, result);
                    graph.veri_cache.insert(name.to_string(), result);
                }
            }
        }
        Ok(())
    }

    /// Register a verification plugin.
    pub fn register_plugin(&mut self, plugin: Box<dyn VerificationPlugin>) {
        self.plugins.push(plugin);
    }

    /// Execute all verification plugins.
    pub fn verify(&mut self) -> Result<(), Box<dyn Error>> {
        for plugin in &self.plugins {
            let name = plugin.get_name();
            for (_, graph) in self.graphs.iter_mut() {
                if !graph.veri_cache.contains_key(name) {
                    let result = plugin.execute(graph);
                    graph.veri_cache.insert(name.to_string(), result);
                }
            }
        }
        Ok(())
    }
}

impl<'p, ME> SnapshotQuery<'p, ActionsRepr, ME::P> for SnapshotVerifier<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    fn query_ec(&self, lid: Lid) -> Option<(&Predicate<ME::P>, &ActionsRepr)> {
        let p = self.dp.encode_lid(lid);
        self.query_cache.get_key_value(&p)
    }

    fn query_num_ec(&self) -> usize {
        self.im.len()
    }
}

#[cfg(test)]
mod tests {}
