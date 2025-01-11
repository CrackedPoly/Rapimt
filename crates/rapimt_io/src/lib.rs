//! This module provides basic parsing from the default format. (.fib for FIB rules and .spec for
//! topology instances)
//! TODO::This module needs to be documented.
pub mod default;
pub mod ib;


#[allow(missing_docs)]
pub mod prelude {
    #[doc(hidden)]
    pub use crate::default::{FibLoader, InstanceLoader, loader::{PortInfoBase, DefaultInstLoader, TypedAction}};
}
