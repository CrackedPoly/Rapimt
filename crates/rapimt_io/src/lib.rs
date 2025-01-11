//! Parse topology and rules from diverse sources.
pub mod default;
pub mod ib;


#[allow(missing_docs)]
pub mod prelude {
    #[doc(hidden)]
    pub use crate::default::{FibLoader, InstanceLoader, loader::{PortInfoBase, DefaultInstLoader, TypedAction}};
}
