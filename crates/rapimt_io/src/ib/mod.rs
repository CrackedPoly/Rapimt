//! IO for InfiniBand networks.

use std::{hash::Hash, path::PathBuf};

use rapimt_core::{
    action::{Action, ActionEncoder, Dimension, Single, UncodedAction},
    r#match::engine::MatchEncoder,
};
use rapimt_im::{
    im::{InverseModel, InverseModelMonoid},
    RawRuleLike, RuleLike, RuleMonitorLike,
};

use crate::error::Error;
pub mod cmd_parser;
pub mod db_csv_parser;
pub mod loader;

pub type LabelFn = fn(&str) -> u8;

pub struct IbDataPlaneConfig<'p, ME>
where
    ME: MatchEncoder<'p>,
{
    pub engine: &'p ME,
    pub topology_dir: PathBuf,
    pub far_dir: PathBuf,
    pub label_fn: LabelFn,
}

// FIXME: move this trait to crate root, it should be general to all data planes.
pub trait DataPlane<'a, 'p, ME>
where
    ME: MatchEncoder<'p>,
{
    /// The type of action that RuleMonitor store.
    type A: Action<Single>;

    type UA: UncodedAction<'a>;

    type AE: ActionEncoder<'a, A = Self::A, UA = Self::UA, Err = Error>;

    /// The dimension of action of output InverseModel of RuleMonitor.
    type OT: Dimension;

    /// The type of action of output InverseModel of RuleMonitor.
    type OA: Action<Self::OT, S = Self::A>;

    /// The type of rule.
    type R: RuleLike<A = Self::A, P = ME::P>;

    type RR: RawRuleLike;

    type M: InverseModelMonoid<Self::OA, ME::P, Self::OT>;

    /// The type of Rule Monitor.
    type Mon: RuleMonitorLike<Self::A, Self::OA, Self::OT, Self::M, ME::P, Self::R>;

    /// The type of node key.
    type NK: Hash + Eq;

    type Topo;

    fn new(config: &IbDataPlaneConfig<'p, ME>) -> Result<Self, Error>
    where
        ME: MatchEncoder<'p>,
        Self: Sized;

    fn get_monitor(&self, node: &Self::NK) -> Result<&Self::Mon, Error>;

    fn get_monitor_mut(&mut self, node: &Self::NK) -> Result<&mut Self::Mon, Error>;

    fn get_encoder(&'a self, node: &Self::NK) -> Result<Self::AE, Error>;

    fn get_encoder_index(&self, node: &Self::NK) -> Result<usize, Error>;

    fn iter_encoder(&'a self) -> impl Iterator<Item = (Self::NK, Self::AE)>;

    fn get_topology(&self, node: &Self::NK) -> Result<Self::Topo, Error>;

    fn iter_switch_topology(&self) -> impl Iterator<Item = (Self::NK, Self::Topo)>;

    fn iter_host_topology(&self) -> impl Iterator<Item = (Self::NK, Self::Topo)>;

    fn is_node_host(&self, node: &Self::NK) -> Result<bool, Error>;

    #[allow(clippy::type_complexity)]
    fn update_rules(
        &mut self,
        node: &Self::NK,
        insertion: impl IntoIterator<Item = Self::RR>,
        deletion: impl IntoIterator<Item = Self::RR>,
    ) -> Result<InverseModel<Self::OA, ME::P, Self::OT, Self::M>, Error>;

    fn get_engine(&self) -> &ME;
}
