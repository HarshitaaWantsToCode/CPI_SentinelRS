use dashmap::DashMap;
use sentinel_core::{AssetSensitivity, AssetType, CloudAsset};
use std::sync::Arc;

#[derive(Clone)]
pub struct CloudAssetInventory {
    assets: Arc<DashMap<String, CloudAsset>>,
}

impl CloudAssetInventory {
    pub fn new() -> Self {
        let inv = Self {
            assets: Arc::new(DashMap::new()),
        };
        inv.seed_default_assets();
        inv
    }

    pub fn insert_asset(&self, asset: CloudAsset) {
        self.assets.insert(asset.id.clone(), asset);
    }

    pub fn get_asset(&self, id: &str) -> Option<CloudAsset> {
        self.assets.get(id).map(|e| e.value().clone())
    }

    pub fn list_assets(&self) -> Vec<CloudAsset> {
        self.assets.iter().map(|e| e.value().clone()).collect()
    }

    pub fn count_by_sensitivity(&self, sensitivity: AssetSensitivity) -> usize {
        self.assets
            .iter()
            .filter(|e| e.value().sensitivity == sensitivity)
            .count()
    }

    fn seed_default_assets(&self) {
        let assets = vec![
            CloudAsset {
                id: "user-attacker-demo".into(),
                asset_type: AssetType::IamUser,
                account_id: Some("123456789012".into()),
                region: Some("global".into()),
                name: "attacker-demo".into(),
                arn: Some("arn:aws:iam::123456789012:user/attacker-demo".into()),
                sensitivity: AssetSensitivity::Sensitive,
                criticality_score: 85,
                metadata: serde_json::json!({ "mfa_active": false, "created_at": "2026-09-12" }),
            },
            CloudAsset {
                id: "role-admin-prod".into(),
                asset_type: AssetType::IamRole,
                account_id: Some("123456789012".into()),
                region: Some("global".into()),
                name: "AdministratorRole".into(),
                arn: Some("arn:aws:iam::123456789012:role/AdministratorRole".into()),
                sensitivity: AssetSensitivity::Critical,
                criticality_score: 95,
                metadata: serde_json::json!({ "policies": ["AdministratorAccess"] }),
            },
            CloudAsset {
                id: "policy-admin-access".into(),
                asset_type: AssetType::IamPolicy,
                account_id: Some("aws".into()),
                region: Some("global".into()),
                name: "AdministratorAccess".into(),
                arn: Some("arn:aws:iam::aws:policy/AdministratorAccess".into()),
                sensitivity: AssetSensitivity::Critical,
                criticality_score: 98,
                metadata: serde_json::json!({ "is_aws_managed": true }),
            },
            CloudAsset {
                id: "s3-customer-pii-production".into(),
                asset_type: AssetType::S3Bucket,
                account_id: Some("123456789012".into()),
                region: Some("ap-south-1".into()),
                name: "sentinel-customer-pii-production".into(),
                arn: Some("arn:aws:s3:::sentinel-customer-pii-production".into()),
                sensitivity: AssetSensitivity::Critical,
                criticality_score: 99,
                metadata: serde_json::json!({ "classification": "Customer Financial & PII", "encrypted": true }),
            },
            CloudAsset {
                id: "ec2-app-server-01".into(),
                asset_type: AssetType::Ec2Instance,
                account_id: Some("123456789012".into()),
                region: Some("ap-south-1".into()),
                name: "i-0a8b9c1d2e3f4g5".into(),
                arn: Some("arn:aws:ec2:ap-south-1:123456789012:instance/i-0a8b9c1d2e3f4g5".into()),
                sensitivity: AssetSensitivity::Internal,
                criticality_score: 70,
                metadata: serde_json::json!({ "instance_type": "t3.large", "state": "running" }),
            },
            CloudAsset {
                id: "sg-web-public".into(),
                asset_type: AssetType::SecurityGroup,
                account_id: Some("123456789012".into()),
                region: Some("ap-south-1".into()),
                name: "sg-04a1bc9".into(),
                arn: Some("arn:aws:ec2:ap-south-1:123456789012:security-group/sg-04a1bc9".into()),
                sensitivity: AssetSensitivity::Public,
                criticality_score: 75,
                metadata: serde_json::json!({ "ingress_open_ssh": true }),
            },
            CloudAsset {
                id: "trail-prod-audit".into(),
                asset_type: AssetType::CloudTrail,
                account_id: Some("123456789012".into()),
                region: Some("ap-south-1".into()),
                name: "prod-audit-trail".into(),
                arn: Some("arn:aws:cloudtrail:ap-south-1:123456789012:trail/prod-audit-trail".into()),
                sensitivity: AssetSensitivity::Critical,
                criticality_score: 92,
                metadata: serde_json::json!({ "is_multi_region": true }),
            },
        ];

        for a in assets {
            self.insert_asset(a);
        }
    }
}

impl Default for CloudAssetInventory {
    fn default() -> Self {
        Self::new()
    }
}
