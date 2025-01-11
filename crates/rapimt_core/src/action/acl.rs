use num_enum::IntoPrimitive;
use super::ActionType;

#[derive(IntoPrimitive)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum AclActionType {
    Deny = 0,
    #[default]
    Permit = 1,
}

impl ActionType for AclActionType {}
