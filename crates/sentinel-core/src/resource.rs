use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    S3Bucket,
    S3Object,
    IamUser,
    IamRole,
    IamPolicy,
    AccessKey,
    Ec2Instance,
    SecurityGroup,
    CloudTrail,
    Vpc,
    Subnet,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    pub resource_type: ResourceType,
    pub identifier: String,
    pub arn: Option<String>,
    pub account_id: Option<String>,
    pub region: Option<String>,
    pub is_sensitive: bool,
}

impl Resource {
    pub fn new(resource_type: ResourceType, identifier: impl Into<String>) -> Self {
        Self {
            resource_type,
            identifier: identifier.into(),
            arn: None,
            account_id: None,
            region: None,
            is_sensitive: false,
        }
    }
}
