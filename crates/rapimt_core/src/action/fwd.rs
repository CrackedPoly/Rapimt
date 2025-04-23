use super::ActionType;
use num_enum::{FromPrimitive, IntoPrimitive};

#[derive(IntoPrimitive, FromPrimitive)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum FwdActionType {
    #[default]
    NonOverwrite = 0,
    DROP = 1,
    FORWARD = 2,
    FLOOD = 3,
    ECMP = 4,
    FAILOVER = 5,
}

impl ActionType for FwdActionType {}
