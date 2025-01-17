use num_enum::{IntoPrimitive, TryFromPrimitive};
use super::ActionType;

#[derive(IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum IbActionType {
    #[default]
    NonOverwrite = 0,
    Drop = 1,
    Static = 2,
    AdaptiveRouting = 3,
    HashBasedForwarding = 4,
    Randomization = 5,
    Multicast = 6,
}

impl ActionType for IbActionType {}
