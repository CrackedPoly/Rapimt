//! Parse topology and rules from diverse sources.
#![feature(once_cell_get_mut)]

pub mod default;
pub mod error;
pub mod ib;

#[allow(missing_docs)]
#[doc(hidden)]
pub mod prelude {
    pub use crate::{
        default::{
            loader::{DefaultFibLoader, DefaultInstLoader, PortInfoBase, TypedAction},
            FibLoader, InstanceLoader,
        },
        error::*,
        ib,
    };
}
