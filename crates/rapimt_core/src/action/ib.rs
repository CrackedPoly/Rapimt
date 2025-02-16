use super::ActionType;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

/// Infiniband action enum. (aka. Lid State)
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

impl Serialize for IbActionType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            IbActionType::NonOverwrite => serializer.serialize_str("NonOverwrite"),
            IbActionType::Drop => serializer.serialize_str("Drop"),
            IbActionType::Static => serializer.serialize_str("Static"),
            IbActionType::AdaptiveRouting => serializer.serialize_str("Free"),
            IbActionType::HashBasedForwarding => serializer.serialize_str("HBF"),
            IbActionType::Randomization => serializer.serialize_str("Randomization"),
            IbActionType::Multicast => serializer.serialize_str("Multicast"),
        }
    }
}

impl<'de> Deserialize<'de> for IbActionType {
    fn deserialize<D>(deserializer: D) -> Result<IbActionType, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "NonOverwrite" => Ok(IbActionType::NonOverwrite),
            "Drop" => Ok(IbActionType::Drop),
            "Static" => Ok(IbActionType::Static),
            "Free" => Ok(IbActionType::AdaptiveRouting),
            "HBF" => Ok(IbActionType::HashBasedForwarding),
            "Randomization" => Ok(IbActionType::Randomization),
            "Multicast" => Ok(IbActionType::Multicast),
            _ => Err(serde::de::Error::custom("Unknown IbActionType")),
        }
    }
}
