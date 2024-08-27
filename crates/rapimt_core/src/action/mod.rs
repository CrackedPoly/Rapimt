//! # Action
//! TODO::This module needs to be documented.
pub mod seq_action;

use std::{
    fmt::{Debug, Display},
    hash::Hash,
    ops::{Index, IndexMut},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ActionType {
    DROP = 0,
    FORWARD = 1,
    FLOOD = 2,
    ECMP = 3,
    FAILOVER = 4,
}

impl From<i32> for ActionType {
    fn from(v: i32) -> Self {
        match v {
            0 => ActionType::DROP,
            1 => ActionType::FORWARD,
            2 => ActionType::FLOOD,
            3 => ActionType::ECMP,
            4 => ActionType::FAILOVER,
            _ => panic!("Invalid ActionType"),
        }
    }
}

/// ModelType is a empty trait that represents the type of action. Now, we have two types of
/// actions: [Single] and [Multiple].
pub trait ModelType {}

/// Single means the action is one-dimensional, it can only contain an action of a single device.
pub struct Single {}

/// Multiple means the action is multi-dimensional, it can contain multiple actions of multiple
/// devices.
pub struct Multiple {}

impl ModelType for Multiple {}

impl ModelType for Single {}

pub trait Action<T: ModelType>: Eq + Hash + Clone + Debug + Default {
    // What single form of action it contains. For structs that implements Action<Single>, it must
    // be itself, while for Action<Multiple> structs, it should define one.
    type S: Action<Single>;
}

/// UncodedAction is an action on a specific device, it should have rich information such as device
/// name, forwrading mode, next hops, and may not be fix-sized. It can be encoded by an action
/// encoder that represents the device.
///
/// ***This trait is manufacture-specific.***
pub trait UncodedAction: Action<Single> + Clone {
    fn get_type(&self) -> ActionType;
    fn get_next_hops(&self) -> impl IntoIterator<Item = impl AsRef<str>>;
}

/// CodedAction should have fixed size and can live in stack to achieve better performance.
/// [Default] trait implementation default() should return a value that represents no action
/// overwrite, refer to Fast-IMT theory for more information.
///
/// ***It seems an integer is sufficient, but we leave this trait for flexibility***
pub trait CodedAction:
    Action<Single>
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + Display
    + Debug
    + Default
    + Hash
    + Sized
    + Copy
    + Clone
{
}

macro_rules! impl_action {
    ($($t:ty),*) => {
        $(
            impl Action<Single> for $t {
                type S = $t;
            }
            impl CodedAction for $t {}
        )*
    };
}

impl_action!(u16, u32, u64, usize, i16, i32, i64, isize);

impl Action<Single> for String {
    type S = Self;
}

/// ActionEncoder is essentially an instance that has all information about this device's topology
/// (name, ports, port mode, neighbors), it can encode/decode raw action into/from CodedAction
/// (which is more compact), and lookup the action by port name.
///
/// ***This trait is manufacture-specific.***
pub trait ActionEncoder<'a>
where
    Self: 'a,
{
    type A: CodedAction;
    type UA: UncodedAction + 'a;
    fn encode(&'a self, action: Self::UA) -> Self::A;
    fn decode(&'a self, coded_action: Self::A) -> Self::UA;
    fn lookup(&'a self, port_name: &str) -> Option<Self::UA>;
}

pub trait CodedActions:
    Action<Multiple>
    + From<<Self as Action<Multiple>>::S>
    + Index<usize, Output = <Self as Action<Multiple>>::S>
    + IndexMut<usize, Output = <Self as Action<Multiple>>::S>
    + Clone
    + Hash
    + Eq
{
    // A is Self::S
    type A: CodedAction;
    const N: usize;

    // Required methods
    fn len(&self) -> usize;
    fn resize(&mut self, to: usize, offset: usize);
    fn overwritten(&self, rhs: &Self) -> Self;
    fn diff(&self, rhs: &Self) -> usize;

    // Provided methods
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
