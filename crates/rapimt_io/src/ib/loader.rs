use std::{borrow::Borrow, fmt::Debug, sync::Arc};

use derivative::Derivative;
use funty::Unsigned;
use fxhash::FxHashMap;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use rapimt_core::action::{ib::IbActionType, Action, ActionEncoder, Single, UncodedAction};
use serde::Serialize;

///// Cache for sharing ports vector.
//pub static mut CACHE: OnceLock<FxHashMap<String, Vec<PortIdx>>> = OnceLock::new();
///// WARN: thread-unsafe.
//pub fn get_cache() -> &'static FxHashMap<String, Vec<PortIdx>> {
//    #[allow(static_mut_refs)]
//    unsafe {
//        CACHE.get_or_init(FxHashMap::default)
//    }
//}
///// WARN: thread-unsafe.
//pub fn get_mut_cache() -> &'static mut FxHashMap<String, Vec<PortIdx>> {
//    #[allow(static_mut_refs)]
//    unsafe {
//        CACHE.get_mut_or_init(FxHashMap::default)
//    }
//}

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
    pub ports: FxHashMap<PortIdx, (PortSpec, Option<LinkSpec>)>,
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
#[derive(Default, Debug, Clone, Copy)]
pub struct PortSpec {
    // TODO: add more fields
    pub port_guid: Guid,
    pub port_num: PortIdx,
    pub lid: Lid,
}

/// Link spec between two ports.
#[derive(Default, Debug, Clone, Copy, Serialize)]
pub struct LinkSpec {
    pub src_port_idx: PortIdx,
    pub dst_port_idx: PortIdx,
    pub src_node_guid: Guid,
    pub dst_node_guid: Guid,
}

/// Single Linear Forwarding Table entry. (FIB entry)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct LftEntry {
    pub lid: Lid,
    pub port: PortIdx,
    pub group: GroupIdx,
    pub lid_state: IbActionType,
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

/// Group spec in routing table.
#[derive(Default, Debug, Clone)]
pub struct GroupSpec {
    pub group_idx: GroupIdx,
    pub ports: Vec<PortIdx>,
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

    fn get_type(&self) -> impl Into<u8> {
        match self {
            IbAction::NonOverwrite => IbActionType::NonOverwrite,
            IbAction::Drop => IbActionType::Drop,
            IbAction::Static(_) => IbActionType::Static,
            IbAction::AR(_) => IbActionType::AdaptiveRouting,
            IbAction::HBF(_) => IbActionType::HashBasedForwarding,
        }
    }

    fn get_next_hops(&self) -> Option<Box<dyn Iterator<Item = Guid> + 'a>> {
        match self {
            IbAction::Drop => None,
            IbAction::NonOverwrite => None,
            IbAction::Static(IbActionRef {
                action: port_idx,
                owner,
            }) => {
                let link = owner.common.ports.get(port_idx as &PortIdx).unwrap().1?;
                Some(Box::new(std::iter::once(link.dst_node_guid)))
            }
            IbAction::AR(IbActionRef {
                action: group_idx,
                owner,
            })
            | IbAction::HBF(IbActionRef {
                action: group_idx,
                owner,
            }) => {
                let group = owner.groups.get(group_idx as &GroupIdx).unwrap();
                Some(Box::new(group.ports.iter().filter_map(|port| {
                    owner
                        .common
                        .ports
                        .get(port)
                        .unwrap()
                        .1
                        .as_ref()
                        .map(|link| link.dst_node_guid)
                })))
            }
        }
    }

    fn get_ports(&self) -> Option<Box<dyn Iterator<Item = Self::P> + 'a>> {
        match self {
            IbAction::Drop => None,
            IbAction::NonOverwrite => None,
            IbAction::Static(IbActionRef { action, owner }) => {
                let link = owner.common.ports.get(action as &PortIdx).unwrap().1?;
                Some(Box::new(std::iter::once(link.src_port_idx)))
            }
            IbAction::AR(IbActionRef { action, owner })
            | IbAction::HBF(IbActionRef { action, owner }) => {
                let group = owner.groups.get(action as &GroupIdx).unwrap();
                Some(Box::new(group.ports.iter().copied()))
            }
        }
    }
}

impl<'a> ActionEncoder<'a> for &'a SwitchSpec {
    type A = FusedIdx;
    type UA = IbAction<'a>;
    type K = RawAction;

    fn encode(&'a self, action: Self::UA) -> Self::A {
        match action {
            IbAction::NonOverwrite => 0,
            IbAction::Drop => 1,
            IbAction::Static(IbActionRef { action, owner: _ }) => {
                (action as FusedIdx) | ((IbActionType::Static as FusedIdx) << NON_TYPED_WIDTH)
            }
            IbAction::AR(IbActionRef { action, owner: _ }) => {
                (action as FusedIdx)
                    | ((IbActionType::AdaptiveRouting as FusedIdx) << NON_TYPED_WIDTH)
            }
            IbAction::HBF(IbActionRef { action, owner: _ }) => {
                (action as FusedIdx)
                    | ((IbActionType::HashBasedForwarding as FusedIdx) << NON_TYPED_WIDTH)
            }
        }
    }

    fn decode(&'a self, coded_action: Self::A) -> Self::UA {
        match coded_action {
            0 => IbAction::NonOverwrite,
            1 => IbAction::Drop,
            _ => {
                let owner = self;
                match IbActionType::try_from((coded_action >> 12) as u8).unwrap() {
                    IbActionType::NonOverwrite => IbAction::NonOverwrite,
                    IbActionType::Drop => IbAction::Drop,
                    IbActionType::Static => {
                        let action = coded_action & TYPE_UNMASK;
                        IbAction::Static(IbActionRef {
                            action: action as u8,
                            owner,
                        })
                    }
                    IbActionType::AdaptiveRouting => {
                        let action = coded_action & TYPE_UNMASK;
                        IbAction::AR(IbActionRef { action, owner })
                    }
                    IbActionType::HashBasedForwarding => {
                        let action = coded_action & TYPE_UNMASK;
                        IbAction::HBF(IbActionRef { action, owner })
                    }
                    _ => {
                        unimplemented!("IB action type not considered")
                    }
                }
            }
        }
    }

    fn lookup(&'a self, port_name: impl AsRef<Self::K>) -> Option<Self::UA> {
        match port_name.as_ref() {
            RawAction::NonOverwrite => Some(IbAction::NonOverwrite),
            RawAction::Drop => Some(IbAction::Drop),
            RawAction::Static(port) => Some(IbAction::Static(IbActionRef {
                action: *port,
                owner: self,
            })),
            RawAction::AR(group) => Some(IbAction::AR(IbActionRef {
                action: *group,
                owner: self,
            })),
            RawAction::HBF(group) => Some(IbAction::HBF(IbActionRef {
                action: *group,
                owner: self,
            })),
        }
    }

    fn encode_raw(&self, port_name: impl AsRef<Self::K>) -> Option<Self::A> {
        match port_name.as_ref() {
            RawAction::NonOverwrite => Some(0),
            RawAction::Drop => Some(1),
            RawAction::Static(port) => {
                Some((*port as FusedIdx) | ((IbActionType::Static as FusedIdx) << NON_TYPED_WIDTH))
            }
            RawAction::AR(group) => Some(
                (*group as FusedIdx)
                    | ((IbActionType::AdaptiveRouting as FusedIdx) << NON_TYPED_WIDTH),
            ),
            RawAction::HBF(group) => Some(
                (*group as FusedIdx)
                    | ((IbActionType::HashBasedForwarding as FusedIdx) << NON_TYPED_WIDTH),
            ),
        }
    }
}
