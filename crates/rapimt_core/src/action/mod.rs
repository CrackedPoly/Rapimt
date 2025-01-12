//! # Action
//!
//! ## Relations of important traits, enums and structs.
//!
//! An action in the system is initially an `UncodedAction` that contains rich information about
//! the action in a specific component. It is then encoded by an `ActionEncoder` into a
//! `CodedAction` with an explanation of the action type.
//!
//!
//! ```text
//!                                 UncodedAction                                   
//!                      +----------------+-----------------+                       
//!                      v                v                 v                       
//! ActionType:    AclActionType    FwdActionType    XXXActionType                  
//! (All enums)          |                |                 |                       
//!                      v                v                 v                       
//!                    +--------------------------------------+                     
//!                    |            ActionEncoder             |                     
//!                    +------------------+-------------------+                     
//!                                       v                                         
//!                                 CodedAction               impls Action<Single>  
//!                              (Primitive types)                                  
//!                              +--------+--------+                                
//!                              v                 v                                
//!                             Vec           TreeActions (todo)    impls Action<Multiple>
//!                                           (MerkleTree)                         
//! ```
pub mod acl;
pub mod fwd;
pub mod seq_action;
pub mod tree_action;

use std::{
    fmt::{Debug, Display},
    hash::Hash,
    ops::{Index, IndexMut},
    rc::Rc,
};

pub trait ActionType:
    Into<u8> +
    Clone +
    Debug +
    Copy +
    PartialEq +
    Eq +
    Hash +
    PartialOrd +
    Ord +
    Default
{
}

/// An empty trait that represents the type of action. 
///
/// Now, we have two types of actions: [Single] and [Multiple].
pub trait Dimension {}

/// [Single] means the action is one-dimensional, e.g., one forwarding action from a port.
pub struct Single {}

/// [Multiple] means the action is multi-dimensional, e.g. a sequence of actions.
pub struct Multiple {}

impl Dimension for Multiple {}

impl Dimension for Single {}

/// [Action] trait represents an action of desired dimension. Use type parameter to distinguish the
/// dimension of action. 
///
/// Required methods are:
///
/// - default_action: return an action that represents the default action.
/// - no_overwrite: return an action that represents no action overwrite in Fast-IMT theory.
/// - overwrite: return an action that represents the overwrite of self by rhs.
/// - overwrite_: in-place version of overwrite.
/// - from_single: new from an action of the single form. 
pub trait Action<T: Dimension>: Eq + Hash + Clone + Debug {
    /// What single form of action it contains. For structs that implements [Action<Single>], `S` must
    /// be itself, while for [Action<Multiple>] structs, it should define one.
    type S: Action<Single>;

    fn default_action() -> Self;
    fn no_overwrite() -> Self;
    fn overwrite(&self, rhs: &Self) -> Self;
    fn overwrite_(&mut self, rhs: &Self);
    fn from_single(single: Self::S) -> Self;
}

/// Unencoded action on a specific device.
///
/// It may have rich information such as device name,
/// forwrading mode, next hops, and may not be fix-sized. It can be encoded by an action encoder
/// that contains all topology information of the device.
pub trait UncodedAction: Action<Single> + Clone {
    fn get_type(&self) -> impl Into<u8>;
    fn get_next_hops(&self) -> Option<impl IntoIterator<Item = &Rc<str>>>;
}

/// Encoded, compact and opaque action.
///
/// [Default] trait implementation default() is expected to return a value that represents no
/// action overwrite. All rust number primitive types are implemented for [CodedAction].
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

macro_rules! impl_coded_action_for_ints {
    ($($t:ty),*) => {
        $(
            impl Action<Single> for $t {
                type S = Self;
                #[inline]
                fn default_action() -> Self {
                    1 as Self
                }
                #[inline]
                fn no_overwrite() -> Self {
                    0 as Self
                }
                #[inline]
                fn overwrite(&self, rhs: &Self) -> Self {
                    if *rhs == 0 {
                        *self
                    } else {
                        *rhs
                    }
                }
                #[inline]
                fn overwrite_(&mut self, rhs: &Self) {
                    if *rhs != 0 {
                        *self = *rhs;
                    }
                }
                #[inline]
                fn from_single(single: Self::S) -> Self {
                    single
                }
            }
            impl CodedAction for $t {}
        )*
    };
}

impl_coded_action_for_ints!(usize, u128, u64, u32, u16, u8, isize, i128, i64, i32, i16, i8);

/// Encoder and decoder between [UncodedAction] and [CodedAction].
///
/// This trait implementors should have all information about this device's topology (name, ports,
/// port mode, neighbors). The interface may be enriched.
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

/// Container of multiple actions.
/// 
/// Represent a sequence of actions that exist in the system.
pub trait Actions: 
    Action<Multiple>
    + Index<usize, Output = <Self as Action<Multiple>>::S>      // read by idx
    + IndexMut<usize, Output = <Self as Action<Multiple>>::S>   // update by idx in-place
    + Clone
    + Hash
    + Eq
{
    // Required methods
    fn len(&self) -> usize;
    fn diff(&self, rhs: &Self) -> usize;
    fn resize_(&mut self, to: usize, offset: usize);

    // Provided methods
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
