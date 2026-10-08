use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Authentication,
    Authorization,
    Identity,
    Storage,
    Compute,
    Network,
    Logging,
    Discovery,
    Configuration,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Read,
    Write,
    Delete,
    PermissionChange,
    Unknown,
}

impl Default for EventCategory {
    fn default() -> Self {
        Self::Other("general".into())
    }
}

impl Default for ActionType {
    fn default() -> Self {
        Self::Unknown
    }
}
