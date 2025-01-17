//! Parse topology and rules from diverse sources.
#![feature(once_cell_get_mut)]

pub mod default;
pub mod ib;

#[allow(missing_docs)]
#[doc(hidden)]
pub mod prelude {
    pub use crate::{
        default::{
            loader::{DefaultInstLoader, PortInfoBase, TypedAction},
            FibLoader, InstanceLoader,
        },
        ib::{
            cmd_parser::{ibfar_parser, ibroute_parser},
            db_csv_parser::csv_parser,
            loader::*,
        },
    };
}
