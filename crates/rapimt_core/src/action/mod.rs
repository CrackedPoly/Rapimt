//! # Action
//! TODO::This module needs to be documented.
pub mod seq_action;

use std::{
    fmt::{Debug, Display},
    hash::Hash,
    ops::{Index, IndexMut},
};

#[derive(Debug, Clone, Copy, PartialEq)]
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

/// UncodedAction is an action on a specific device, it should have rich information such as device
/// name, forwrading mode, next hops, and may not be fix-sized. It can be encoded by an action
/// encoder that represents the device.
///
/// ***This trait is manufacture-specific.***
pub trait UncodedAction {
    fn get_type(&self) -> ActionType;
    fn get_next_hops(&self) -> Vec<&str>;
}

/// CodedAction should have fixed size and can live in stack to achieve better performance.
/// [Default] trait implementation default() should return a value that represents no action
/// overwrite, refer to Fast-IMT theory for more information.
///
/// ***It seems an integer is sufficient, but we leave this trait for flexibility***
pub trait CodedAction:
    Eq + PartialEq + Ord + PartialOrd + Display + Debug + Default + Hash + Sized + Copy
{
}

impl CodedAction for u32 {}

/// ActionEncoder is essentially an instance that has all information about this device's topology
/// (name, ports, port mode, neighbors), it can encode/decode raw action into/from CodedAction
/// (which is more compact), and lookup the action by port name.
///
/// ***This trait is manufacture-specific.***
pub trait ActionEncoder<'a, A: CodedAction = u32>
where
    Self: 'a,
{
    type UA: UncodedAction + 'a;
    fn encode(&'a self, action: Self::UA) -> A;
    fn decode(&'a self, coded_action: A) -> Self::UA;
    fn lookup(&'a self, port_name: &str) -> Self::UA;
}

pub trait CodedActions<A: CodedAction>:
    From<Vec<A>> + Index<usize, Output = A> + IndexMut<usize, Output = A> + Hash + Eq
{
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn resize(&mut self, to: usize, offset: usize);
    fn overwritten(&self, rhs: &Self) -> Self;
    fn diff(&self, rhs: &Self) -> usize;
}
