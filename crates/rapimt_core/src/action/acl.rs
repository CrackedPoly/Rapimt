use super::ActionType;
use num_enum::{FromPrimitive, IntoPrimitive};

#[derive(IntoPrimitive, FromPrimitive)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum AclActionType {
    #[default]
    NonOverwrite = 0,
    Deny = 1,
    Permit = 2,
}

impl ActionType for AclActionType {}
