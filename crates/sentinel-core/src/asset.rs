use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetType {
    IamUser,
    IamRole,
    IamPolicy,
    Ec2Instance,
    SecurityGroup,
    Vpc,
    Subnet,
    S3Bucket,
    S3Object,
    AwsAccount,
    IpAddress,
    CloudTrail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetSensitivity {
    Public,
    Internal,
    Sensitive,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAsset {
    pub id: String,
    pub asset_type: AssetType,
    pub account_id: Option<String>,
    pub region: Option<String>,
    pub name: String,
    pub arn: Option<String>,
    pub sensitivity: AssetSensitivity,
    pub criticality_score: u8, // 0 - 100
    pub metadata: serde_json::Value,
}

impl CloudAsset {
    pub fn new(
        id: impl Into<String>,
        asset_type: AssetType,
        name: impl Into<String>,
        sensitivity: AssetSensitivity,
        criticality_score: u8,
    ) -> Self {
        Self {
            id: id.into(),
            asset_type,
            account_id: None,
            region: None,
            name: name.into(),
            arn: None,
            sensitivity,
            criticality_score,
            metadata: serde_json::json!({}),
        }
    }
}
