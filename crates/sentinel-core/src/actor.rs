use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    IamUser,
    IamRole,
    AssumedRole,
    FederatedUser,
    Root,
    AwsService,
    Anonymous,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub actor_type: ActorType,
    pub identity: String,
    pub arn: Option<String>,
    pub principal_id: Option<String>,
    pub account_id: Option<String>,
    pub session_name: Option<String>,
}

impl Actor {
    pub fn new(actor_type: ActorType, identity: impl Into<String>) -> Self {
        Self {
            actor_type,
            identity: identity.into(),
            arn: None,
            principal_id: None,
            account_id: None,
            session_name: None,
        }
    }
}
