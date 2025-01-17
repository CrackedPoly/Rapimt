use std::{
    collections::hash_map::Entry,
    error::Error,
    ops::Deref,
    path::PathBuf,
    rc::Rc,
    time::{Duration, Instant},
};

use fxhash::{FxBuildHasher, FxHashMap};
use rapimt_core::{
    action::{ActionEncoder, Actions, Multiple},
    r#match::{
        engine::MatchEncoder,
        predicate::{Predicate, PredicateInner},
        raw_match::{FieldMatch, Match},
    },
};
use rapimt_im::{
    ib::{monitor::IbRuleMonitor, rule::Rule},
    im::InverseModel,
    RuleMonitorLike,
};
use rapimt_io::ib::{
    cmd_parser::ibroute_parser::load_routes,
    db_csv_parser::csv_parser::{load_links, load_nodes, load_ports},
    loader::{CaSpec, FusedIdx, Guid, Lid, NodeType, RawAction, RawIbFibRule, SwitchSpec},
};

pub struct SnapshotConfig<'p, ME: MatchEncoder<'p>> {
    pub engine: &'p ME,
    pub topology_dir: PathBuf,
    pub route_dir: PathBuf,
}

pub trait SnapshotQuery<'a, A: Actions, P: PredicateInner> {
    fn query_lid(&self, lid: Lid) -> Option<(&Predicate<P>, &A)>;
    fn query_num_ec(&self) -> usize;
}

struct IbDataPlane<'p, ME: MatchEncoder<'p>> {
    engine: &'p ME,
    switch_monitors: FxHashMap<Guid, IbRuleMonitor<'p, FusedIdx, ME>>,
    switch_order: FxHashMap<Guid, usize>,
    switch_specs: FxHashMap<Guid, Rc<SwitchSpec>>,
    ca_specs: FxHashMap<Guid, CaSpec>,
}

impl<'p, ME> IbDataPlane<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    // Load the snapshot from the given directory.
    // This method implementation is ugly because the input format is not regular.
    fn new(config: &SnapshotConfig<'p, ME>) -> Result<Self, Box<dyn Error>> {
        let mut switch_specs = FxHashMap::with_hasher(FxBuildHasher::default());
        let mut switch_monitors = FxHashMap::with_hasher(FxBuildHasher::default());
        let mut switch_order = FxHashMap::with_hasher(FxBuildHasher::default());
        let mut ca_specs = FxHashMap::with_hasher(FxBuildHasher::default());
        let nodes = load_nodes(config.topology_dir.join("nodes.csv"))?;
        // parse all node information
        for node in nodes {
            match node.node_type {
                NodeType::Switch => {
                    switch_monitors.insert(node.node_guid, IbRuleMonitor::new(config.engine));
                    switch_order.insert(node.node_guid, switch_order.len());
                    let spec = SwitchSpec {
                        common: node,
                        ..Default::default()
                    };
                    switch_specs.insert(spec.common.node_guid, spec);
                }
                NodeType::HCA => {
                    let spec = CaSpec { common: node };
                    ca_specs.insert(spec.common.node_guid, spec);
                }
            }
        }
        // parse all ports
        let ports = load_ports(config.topology_dir.join("ports.csv"))?;
        for (node_guid, ports) in ports {
            if let Entry::Occupied(mut e) = switch_specs.entry(node_guid) {
                let switch_spec = e.get_mut();
                for port in ports {
                    switch_spec.common.ports.insert(port.port_num, (port, None));
                }
                continue;
            }
            if let Entry::Occupied(mut e) = ca_specs.entry(node_guid) {
                let ca_spec = e.get_mut();
                for port in ports {
                    ca_spec.common.ports.insert(port.port_num, (port, None));
                }
            }
        }
        // parse all links
        let links = load_links(config.topology_dir.join("links.csv"))?;
        for link in links {
            // we cannot decide src and dst node type, so we try both
            loop {
                if let Entry::Occupied(mut e) = switch_specs.entry(link.src_node_guid) {
                    let switch_spec = e.get_mut();
                    let (_, mut l) =
                        switch_spec
                            .common
                            .ports
                            .get_mut(&link.src_port_idx)
                            .ok_or(format!(
                                "Link error: Port {} not found in switch {}",
                                link.src_port_idx, link.src_node_guid
                            ))?;
                    l.replace(link);
                    break;
                }
                if let Entry::Occupied(mut e) = ca_specs.entry(link.src_node_guid) {
                    let ca_spec = e.get_mut();
                    let (_, mut l) =
                        ca_spec
                            .common
                            .ports
                            .get_mut(&link.src_port_idx)
                            .ok_or(format!(
                                "Link error: Port {} not found in CA {}",
                                link.src_port_idx, link.src_node_guid
                            ))?;
                    l.replace(link);
                    break;
                }
            }
            loop {
                if let Entry::Occupied(mut e) = switch_specs.entry(link.dst_node_guid) {
                    let switch_spec = e.get_mut();
                    let (_, mut l) =
                        switch_spec
                            .common
                            .ports
                            .get_mut(&link.dst_port_idx)
                            .ok_or(format!(
                                "Link error: Port {} not found in switch {}",
                                link.dst_port_idx, link.dst_node_guid
                            ))?;
                    l.replace(link.swap());
                    break;
                }
                if let Entry::Occupied(mut e) = ca_specs.entry(link.dst_node_guid) {
                    let ca_spec = e.get_mut();
                    let (_, mut l) =
                        ca_spec
                            .common
                            .ports
                            .get_mut(&link.dst_port_idx)
                            .ok_or(format!(
                                "Link error: Port {} not found in CA {}",
                                link.dst_port_idx, link.dst_node_guid
                            ))?;
                    l.replace(link.swap());
                    break;
                }
            }
        }
        let dp = Self {
            engine: config.engine,
            switch_monitors,
            switch_order,
            switch_specs: switch_specs
                .into_iter()
                .map(|(k, v)| (k, Rc::new(v)))
                .collect(),
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
        self.switch_specs
            .insert(spec.common.node_guid, Rc::new(spec));
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
        let im = InverseModel::resize(
            monitor.update(insertion, deletion),
            self.switch_order.len(),
            *self.switch_order.get(&switch).unwrap(),
        );
        im
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
        rules: impl IntoIterator<Item = RawIbFibRule>,
    ) -> impl IntoIterator<Item = Rule<ME::P, FusedIdx>> {
        let encoder = self.switch_specs.get(&switch).unwrap().clone();
        let mut encoded_rules = vec![];
        for r in rules.into_iter() {
            let raw_action = RawAction::Static(r.port);
            encoded_rules.push(Rule {
                predicate: self.encode_lid(r.lid),
                action: encoder.deref().encode_raw(&raw_action).unwrap(),
            });
        }
        encoded_rules
    }
}

type IM<P> = InverseModel<Vec<FusedIdx>, P, Multiple, FxHashMap<Vec<FusedIdx>, Predicate<P>>>;

pub struct SnapshotVerifier<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    dp: IbDataPlane<'p, ME>,

    #[allow(clippy::type_complexity)]
    im: IM<ME::P>,
    #[allow(clippy::type_complexity)]
    im_updates: Vec<IM<ME::P>>,
}

impl<'p, ME> SnapshotVerifier<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    pub fn new(config: &SnapshotConfig<'p, ME>) -> Result<Self, Box<dyn Error>> {
        let mut verifier = Self {
            dp: IbDataPlane::new(config)?,
            im: InverseModel::default(),
            im_updates: Vec::default(),
        };
        for file in std::fs::read_dir(&config.route_dir)? {
            let (guid, routes) = load_routes(file?.path())?;
            verifier.diff_raw_rules(guid, routes, vec![]);
        }
        verifier.refresh();
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
        insertion: impl IntoIterator<Item = RawIbFibRule>,
        deletion: impl IntoIterator<Item = RawIbFibRule>,
    ) {
        let ins = self.dp.encode_rules(switch, insertion);
        let del = self.dp.encode_rules(switch, deletion);
        self.diff_rules(switch, ins, del);
    }

    /// Refresh the inverse model with stashed updates.
    pub fn refresh(&mut self) {
        for update in self.im_updates.drain(..) {
            self.im <<= update;
        }
    }
}

impl<'p, ME> SnapshotQuery<'p, Vec<FusedIdx>, ME::P> for SnapshotVerifier<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    fn query_lid(&self, lid: Lid) -> Option<(&Predicate<ME::P>, &Vec<FusedIdx>)> {
        let p = self.dp.encode_lid(lid);
        for (action, predicate) in self.im.iter() {
            if !(predicate | &p).is_empty() {
                return Some((predicate, action));
            }
        }
        None
    }

    fn query_num_ec(&self) -> usize {
        self.im.len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use rapimt_core::r#match::engine::RuddyPredicateEngine;

    use super::*;

    #[test]
    fn test_snapshot_verifier_query() {
        let engine = RuddyPredicateEngine::init(10000, 5000);
        let config = SnapshotConfig {
            engine: &engine,
            topology_dir: PathBuf::from("examples/ibdiagnet2"),
            route_dir: PathBuf::from("examples/ibroute"),
        };
        let verifier = SnapshotVerifier::new(&config).unwrap();

        let before = Instant::now();
        println!(
            "actions for lid 0x0001: {:?}",
            verifier.query_lid(0x0001).unwrap().1
        );
        println!("query time: {:?}", before.elapsed());
        println!("#EC: {}", verifier.query_num_ec());

        for (_, p) in verifier.im.iter() {
            println!("predicate: {:?}", p);
        }
    }
}
