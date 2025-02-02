use std::{
    borrow::Borrow,
    sync::{Arc, OnceLock},
};

use derivative::Derivative;
use funty::Unsigned;
use fxhash::{FxBuildHasher, FxHashMap};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use rapimt_core::{
    action::{ib::IbActionType, Action, ActionEncoder, Multiple, Single, UncodedAction},
    r#match::{
        engine::MatchEncoder,
        predicate::Predicate,
        raw_match::{FieldMatch, Match},
    },
};
use rapimt_im::{
    ib::{monitor::IbRuleMonitor, rule::Rule},
    im::InverseModel,
    RawRuleLike, RuleMonitorLike,
};
use serde::Serialize;
use snafu::{OptionExt, ResultExt};

use crate::{
    error::*,
    prelude::csv_parser::{load_groups, load_nodes},
};

use super::{DataPlane, IbDataPlaneConfig};

///// Cache for sharing ports vector.
pub static mut CACHE: OnceLock<FxHashMap<String, Arc<[PortIdx]>>> = OnceLock::new();
/// WARN: thread-unsafe.
pub fn get_cache() -> &'static FxHashMap<String, Arc<[PortIdx]>> {
    #[allow(static_mut_refs)]
    unsafe {
        CACHE.get_or_init(FxHashMap::default)
    }
}
/// WARN: thread-unsafe.
pub fn get_mut_cache() -> &'static mut FxHashMap<String, Arc<[PortIdx]>> {
    #[allow(static_mut_refs)]
    unsafe {
        CACHE.get_mut_or_init(FxHashMap::default)
    }
}

pub type Guid = u64;
pub type Lid = u16;

pub type FusedIdx = u16;
const NON_TYPED_WIDTH: u32 = 12;
const TYPE_UNMASK: FusedIdx = FusedIdx::MAX >> (FusedIdx::BITS - NON_TYPED_WIDTH);
pub type GroupIdx = u16;
pub type PortIdx = u8;

#[derive(IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum NodeType {
    HCA = 1,
    #[default]
    Switch = 2,
}

/// Common topology information for all nodes (switch and ca).
#[derive(Derivative, Default, Clone, Serialize)]
#[derivative(Debug, PartialEq, Eq, Hash)]
pub struct NodeCommon {
    pub vendor_id: u16,
    pub device_id: u16,
    pub sysimg_guid: Guid,
    pub node_guid: Guid,
    pub port_guid: Guid,
    pub port_num: PortIdx,
    pub lid: Lid,
    #[serde(skip_serializing)]
    pub node_type: NodeType,
    pub description: String,
    pub label: u8,
    #[derivative(PartialEq = "ignore")]
    #[derivative(Hash = "ignore")]
    #[serde(skip_serializing)]
    pub ports: FxHashMap<PortIdx, PortSpec>,
}

/// IB switch spec.
#[derive(Derivative, Default, Debug)]
#[derivative(PartialEq, Eq, Hash)]
pub struct SwitchSpec {
    pub common: Arc<NodeCommon>,

    #[derivative(PartialEq = "ignore")]
    #[derivative(Hash = "ignore")]
    pub groups: FxHashMap<GroupIdx, GroupSpec>,
}

/// IB channel adapter spec.
#[derive(Derivative, Default, Debug)]
#[derivative(PartialEq, Eq, Hash)]
pub struct CaSpec {
    pub common: Arc<NodeCommon>,
}

/// Speed unit of a port.
#[derive(IntoPrimitive)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum SpeedUnit {
    #[default]
    SRD = 0,
    DDR = 1,
    QDR = 2,
    FDR = 3,
    EDR = 4,
    HDR = 5,
    NDR = 6,
}

impl<T: Borrow<str>> From<T> for SpeedUnit {
    fn from(s: T) -> Self {
        match s.borrow() {
            "SRD" => SpeedUnit::SRD,
            "DDR" => SpeedUnit::DDR,
            "QDR" => SpeedUnit::QDR,
            "FDR" => SpeedUnit::FDR,
            "EDR" => SpeedUnit::EDR,
            "HDR" => SpeedUnit::HDR,
            "NDR" => SpeedUnit::NDR,
            _ => SpeedUnit::SRD,
        }
    }
}

/// Port spec.
#[derive(Default, Debug, Clone)]
pub struct PortSpec {
    // TODO: add more fields
    pub port_guid: Guid,
    pub port_num: PortIdx,
    pub lid: Lid,
    pub link: Option<Arc<LinkSpec>>,
}

/// Link spec between two ports.
#[derive(Default, Debug, Clone, Copy, Serialize)]
pub struct LinkSpec {
    pub src_port_idx: PortIdx,
    pub dst_port_idx: PortIdx,
    pub src_node_guid: Guid,
    pub dst_node_guid: Guid,
}

impl LinkSpec {
    pub fn swap(&self) -> Self {
        Self {
            src_port_idx: self.dst_port_idx,
            dst_port_idx: self.src_port_idx,
            src_node_guid: self.dst_node_guid,
            dst_node_guid: self.src_node_guid,
        }
    }
}

/// Single Linear Forwarding Table entry. (FIB entry)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct LftEntry {
    pub lid: Lid,
    pub port: PortIdx,
    pub group: GroupIdx,
    pub lid_state: IbActionType,
}

impl RawRuleLike for LftEntry {}

/// Group spec in routing table.
#[derive(Default, Debug, Clone)]
pub struct GroupSpec {
    pub group_idx: GroupIdx,
    pub ports: Arc<[PortIdx]>,
}

/// IB fib rule.
#[derive(Default, Debug, Serialize)]
pub struct RawIbFibRule {
    /// match
    pub lid: Lid,
    /// action
    pub port: PortIdx,
    pub description: String,
}

pub enum RawAction {
    NonOverwrite,
    Drop,
    Static(PortIdx),
    AR(GroupIdx),
    HBF(GroupIdx),
}

impl AsRef<RawAction> for &'_ RawAction {
    fn as_ref(&self) -> &RawAction {
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IbActionRef<'a, U: Unsigned> {
    /// may be port or group index
    action: U,
    owner: &'a SwitchSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IbAction<'a> {
    NonOverwrite,
    Drop,
    Static(IbActionRef<'a, PortIdx>),
    AR(IbActionRef<'a, GroupIdx>),
    HBF(IbActionRef<'a, GroupIdx>),
}

impl<'a> Action<Single> for IbAction<'a> {
    type S = IbAction<'a>;

    fn default_action() -> Self {
        Self::Drop
    }

    fn no_overwrite() -> Self {
        Self::NonOverwrite
    }

    fn overwrite(&self, rhs: &Self) -> Self {
        match rhs {
            IbAction::NonOverwrite => *self,
            _ => *rhs,
        }
    }

    fn overwrite_(&mut self, rhs: &Self) {
        match rhs {
            IbAction::NonOverwrite => {}
            _ => *self = *rhs,
        }
    }

    fn from_single(single: Self::S) -> Self {
        single
    }
}

impl<'a> UncodedAction<'a> for IbAction<'a> {
    type N = Guid;
    type P = PortIdx;
    type Err = Error;

    fn get_type(&self) -> impl Into<u8> {
        match self {
            IbAction::NonOverwrite => IbActionType::NonOverwrite,
            IbAction::Drop => IbActionType::Drop,
            IbAction::Static(_) => IbActionType::Static,
            IbAction::AR(_) => IbActionType::AdaptiveRouting,
            IbAction::HBF(_) => IbActionType::HashBasedForwarding,
        }
    }

    fn get_next_hops(&self) -> Result<Box<dyn Iterator<Item = Guid> + 'a>, Self::Err> {
        match self {
            IbAction::Drop => Ok(Box::new(std::iter::empty())),
            IbAction::NonOverwrite => Ok(Box::new(std::iter::empty())),
            IbAction::Static(IbActionRef {
                action: port_idx,
                owner,
            }) => {
                let link = owner
                    .common
                    .ports
                    .get(port_idx as &PortIdx)
                    .context(IbPortNotFoundSnafu {
                        node: owner.common.node_guid,
                        port: *port_idx,
                    })?
                    .link
                    .as_ref()
                    .unwrap();
                Ok(Box::new(std::iter::once(link.dst_node_guid)))
            }
            IbAction::AR(IbActionRef {
                action: group_idx,
                owner,
            })
            | IbAction::HBF(IbActionRef {
                action: group_idx,
                owner,
            }) => {
                let group =
                    owner
                        .groups
                        .get(group_idx as &GroupIdx)
                        .context(IbGroupNotFoundSnafu {
                            node: owner.common.node_guid,
                            group: *group_idx,
                        })?;
                Ok(Box::new(group.ports.iter().filter_map(|port| {
                    owner
                        .common
                        .ports
                        .get(port)?
                        .link
                        .as_ref()
                        .map(|link| link.dst_node_guid)
                })))
            }
        }
    }

    fn get_ports(&self) -> Result<Box<dyn Iterator<Item = Self::P> + 'a>, Self::Err> {
        match self {
            IbAction::Drop => Ok(Box::new(std::iter::empty())),
            IbAction::NonOverwrite => Ok(Box::new(std::iter::empty())),
            IbAction::Static(IbActionRef { action, owner }) => {
                let link = owner
                    .common
                    .ports
                    .get(action as &PortIdx)
                    .context(IbPortNotFoundSnafu {
                        node: owner.common.node_guid,
                        port: *action,
                    })?
                    .link
                    .as_ref();
                // it is possible and normal that a port does not have any link
                if let Some(link) = link {
                    Ok(Box::new(std::iter::once(link.src_port_idx)))
                } else {
                    Ok(Box::new(std::iter::empty()))
                }
            }
            IbAction::AR(IbActionRef { action, owner })
            | IbAction::HBF(IbActionRef { action, owner }) => {
                let group =
                    owner
                        .groups
                        .get(action as &GroupIdx)
                        .context(IbGroupNotFoundSnafu {
                            node: owner.common.node_guid,
                            group: *action,
                        })?;
                Ok(Box::new(group.ports.iter().copied()))
            }
        }
    }
}

impl<'a> ActionEncoder<'a> for &'a SwitchSpec {
    type A = FusedIdx;
    type UA = IbAction<'a>;
    type K = RawAction;
    type Err = Error;

    fn encode(&'a self, action: Self::UA) -> Result<Self::A, Self::Err> {
        match action {
            IbAction::NonOverwrite => Ok(0),
            IbAction::Drop => Ok(1),
            IbAction::Static(IbActionRef { action, owner: _ }) => {
                Ok((action as FusedIdx) | ((IbActionType::Static as FusedIdx) << NON_TYPED_WIDTH))
            }
            IbAction::AR(IbActionRef { action, owner: _ }) => Ok((action as FusedIdx)
                | ((IbActionType::AdaptiveRouting as FusedIdx) << NON_TYPED_WIDTH)),
            IbAction::HBF(IbActionRef { action, owner: _ }) => Ok((action as FusedIdx)
                | ((IbActionType::HashBasedForwarding as FusedIdx) << NON_TYPED_WIDTH)),
        }
    }

    fn decode(&'a self, coded_action: Self::A) -> Result<Self::UA, Self::Err> {
        match coded_action {
            0 => Ok(IbAction::NonOverwrite),
            1 => Ok(IbAction::Drop),
            _ => {
                let owner = self;
                let action_type = (coded_action >> NON_TYPED_WIDTH) as u8;
                match IbActionType::try_from(action_type).map_err(|_| {
                    Error::IbPortTypeNotFound {
                        number: (coded_action >> 12) as u8,
                    }
                })? {
                    IbActionType::NonOverwrite => Ok(IbAction::NonOverwrite),
                    IbActionType::Drop => Ok(IbAction::Drop),
                    IbActionType::Static => {
                        let action = coded_action & TYPE_UNMASK;
                        Ok(IbAction::Static(IbActionRef {
                            action: action as u8,
                            owner,
                        }))
                    }
                    IbActionType::AdaptiveRouting => {
                        let action = coded_action & TYPE_UNMASK;
                        Ok(IbAction::AR(IbActionRef { action, owner }))
                    }
                    IbActionType::HashBasedForwarding => {
                        let action = coded_action & TYPE_UNMASK;
                        Ok(IbAction::HBF(IbActionRef { action, owner }))
                    }
                    _ => {
                        unimplemented!("IB action type not considered")
                    }
                }
            }
        }
    }

    fn lookup(&'a self, port_name: impl AsRef<Self::K>) -> Result<Self::UA, Self::Err> {
        match port_name.as_ref() {
            RawAction::NonOverwrite => Ok(IbAction::NonOverwrite),
            RawAction::Drop => Ok(IbAction::Drop),
            RawAction::Static(port) => Ok(IbAction::Static(IbActionRef {
                action: *port,
                owner: self,
            })),
            RawAction::AR(group) => Ok(IbAction::AR(IbActionRef {
                action: *group,
                owner: self,
            })),
            RawAction::HBF(group) => Ok(IbAction::HBF(IbActionRef {
                action: *group,
                owner: self,
            })),
        }
    }

    fn encode_raw(&self, port_name: impl AsRef<Self::K>) -> Result<Self::A, Self::Err> {
        match port_name.as_ref() {
            RawAction::NonOverwrite => Ok(0),
            RawAction::Drop => Ok(1),
            RawAction::Static(port) => {
                Ok((*port as FusedIdx) | ((IbActionType::Static as FusedIdx) << NON_TYPED_WIDTH))
            }
            RawAction::AR(group) => Ok((*group as FusedIdx)
                | ((IbActionType::AdaptiveRouting as FusedIdx) << NON_TYPED_WIDTH)),
            RawAction::HBF(group) => Ok((*group as FusedIdx)
                | ((IbActionType::HashBasedForwarding as FusedIdx) << NON_TYPED_WIDTH)),
        }
    }
}

pub struct IbDataPlane<'p, ME: MatchEncoder<'p>> {
    engine: &'p ME,
    switch_monitors: FxHashMap<Guid, IbRuleMonitor<'p, FusedIdx, ME>>,
    switch_order: FxHashMap<Guid, usize>,
    switch_specs: FxHashMap<Guid, SwitchSpec>,
    ca_specs: FxHashMap<Guid, CaSpec>,
    nodes: FxHashMap<Guid, Arc<NodeCommon>>,
}

impl<'p, ME> IbDataPlane<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    pub fn encode_lid(&self, lid: Lid) -> Predicate<ME::P> {
        self.engine.encode_match_wo_mv(FieldMatch {
            field: "lid",
            cond: Match::ExactMatch { value: lid },
        })
    }

    fn encode_rules(
        &self,
        switch: &Guid,
        rules: impl IntoIterator<Item = LftEntry>,
    ) -> impl IntoIterator<Item = Rule<ME::P, FusedIdx>> {
        let encoder = self.switch_specs.get(switch).unwrap();
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

impl<'a, 'p, ME> DataPlane<'a, 'p, ME> for IbDataPlane<'p, ME>
where
    ME: MatchEncoder<'p>,
    Self: 'a,
{
    type A = FusedIdx;

    type UA = IbAction<'a>;

    type AE = &'a SwitchSpec;

    type OT = Multiple;

    type OA = Arc<Vec<FusedIdx>>;

    type R = Rule<ME::P, FusedIdx>;

    type RR = LftEntry;

    type M = Vec<(Arc<Vec<FusedIdx>>, Predicate<ME::P>)>;

    type Mon = IbRuleMonitor<'p, FusedIdx, ME>;

    type NK = Guid;

    type Topo = Arc<NodeCommon>;

    // Load the snapshot from the given directory.
    // This method implementation is ugly because the input format is not regular.
    fn new(config: &IbDataPlaneConfig<'p, ME>) -> Result<Self, Error> {
        let mut switch_specs = FxHashMap::with_hasher(FxBuildHasher::default());
        let mut switch_monitors = FxHashMap::with_hasher(FxBuildHasher::default());
        let mut switch_order = FxHashMap::with_hasher(FxBuildHasher::default());
        let mut ca_specs = FxHashMap::with_hasher(FxBuildHasher::default());
        let nodes = load_nodes(&config.topology_dir, config.label_fn)?;
        for (guid, node) in nodes.iter() {
            match node.node_type {
                NodeType::Switch => {
                    switch_specs.insert(
                        *guid,
                        SwitchSpec {
                            common: node.clone(),
                            ..Default::default()
                        },
                    );
                    switch_monitors.insert(*guid, IbRuleMonitor::new(config.engine));
                    switch_order.insert(*guid, switch_order.len());
                }
                NodeType::HCA => {
                    ca_specs.insert(
                        *guid,
                        CaSpec {
                            common: node.clone(),
                        },
                    );
                }
            }
        }
        // parse all groups
        log::info!(
            "Loading groups from {}",
            config.far_dir.join("group").display()
        );
        let mut num_dev = 0usize;
        for file in std::fs::read_dir(config.far_dir.join("group")).context(FileIoSnafu {})? {
            let (guid, groups) = load_groups(file.context(FileIoSnafu {})?.path())?;
            let switch_spec = switch_specs
                .get_mut(&guid)
                .context(IbNodeNotFoundSnafu { node: guid })?;
            switch_spec.groups = groups;
            num_dev += 1;
        }
        log::info!("Loaded groups from {} devices", num_dev);
        let dp = Self {
            engine: config.engine,
            switch_monitors,
            switch_order,
            switch_specs,
            ca_specs,
            nodes,
        };

        Ok(dp)
    }

    fn get_monitor(&self, node: &Self::NK) -> Result<&Self::Mon, Error> {
        self.switch_monitors
            .get(node)
            .context(IbNodeNotFoundSnafu { node: *node })
    }

    fn get_monitor_mut(&mut self, node: &Self::NK) -> Result<&mut Self::Mon, Error> {
        self.switch_monitors
            .get_mut(node)
            .context(IbNodeNotFoundSnafu { node: *node })
    }

    fn get_encoder(&'a self, node: &Self::NK) -> Result<Self::AE, Error> {
        self.switch_specs
            .get(node)
            .context(IbNodeNotFoundSnafu { node: *node })
    }

    fn get_encoder_index(&self, node: &Self::NK) -> Result<usize, Error> {
        self.switch_order
            .get(node)
            .copied()
            .context(IbNodeNotFoundSnafu { node: *node })
    }

    fn iter_encoder(&'a self) -> impl Iterator<Item = (Self::NK, Self::AE)> {
        self.switch_specs.iter().map(|(k, v)| (*k, v))
    }

    fn iter_switch_topology(&self) -> impl Iterator<Item = (Self::NK, Self::Topo)> {
        self.switch_specs
            .iter()
            .map(|(k, v)| (*k, v.common.clone()))
    }

    fn iter_host_topology(&self) -> impl Iterator<Item = (Self::NK, Self::Topo)> {
        self.ca_specs.iter().map(|(k, v)| (*k, v.common.clone()))
    }

    fn get_topology(&self, node: &Self::NK) -> Result<Self::Topo, Error> {
        self.nodes
            .get(node)
            .context(IbNodeNotFoundSnafu { node: *node })
            .cloned()
    }

    fn is_node_host(&self, node: &Self::NK) -> Result<bool, Error> {
        if self.ca_specs.contains_key(node) {
            Ok(true)
        } else if self.switch_specs.contains_key(node) {
            Ok(false)
        } else {
            Err(Error::IbNodeNotFound { node: *node })
        }
    }

    fn update_rules(
        &mut self,
        node: &Self::NK,
        insertion: impl IntoIterator<Item = Self::RR>,
        deletion: impl IntoIterator<Item = Self::RR>,
    ) -> Result<InverseModel<Self::OA, <ME as MatchEncoder<'p>>::P, Self::OT, Self::M>, Error> {
        let ins = self.encode_rules(node, insertion);
        let del = self.encode_rules(node, deletion);
        let monitor = self.switch_monitors.get_mut(node).unwrap();
        Ok(InverseModel::resize(
            monitor.update(ins, del),
            self.switch_order.len(),
            self.get_encoder_index(node).unwrap(),
        ))
    }

    fn get_engine(&self) -> &ME {
        self.engine
    }
}
