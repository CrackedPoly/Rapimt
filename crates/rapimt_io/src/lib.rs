//! Parse topology and rules from diverse sources.
#![feature(once_cell_get_mut)]
#![feature(path_file_prefix)]

pub mod default;
pub mod error;
pub mod ib;

#[allow(missing_docs)]
#[doc(hidden)]
pub mod prelude {
    pub use crate::{
        default::{
            loader::{DefaultInstLoader, PortInfoBase, TypedAction},
            FibLoader, InstanceLoader,
        },
        error::*,
        ib::{db_csv_parser::csv_parser, loader::*},
    };
}
