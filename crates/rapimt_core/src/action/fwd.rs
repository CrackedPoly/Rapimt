use num_enum::IntoPrimitive;
use super::ActionType;

#[derive(IntoPrimitive)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum FwdActionType {
    #[default]
    DROP = 0,
    FORWARD = 1,
    FLOOD = 2,
    ECMP = 3,
    FAILOVER = 4,
}

impl From<i32> for FwdActionType {
    fn from(v: i32) -> Self {
        match v {
            0 => FwdActionType::DROP,
            1 => FwdActionType::FORWARD,
            2 => FwdActionType::FLOOD,
            3 => FwdActionType::ECMP,
            4 => FwdActionType::FAILOVER,
            _ => panic!("Invalid ActionType"),
        }
    }
}

impl ActionType for FwdActionType {}
