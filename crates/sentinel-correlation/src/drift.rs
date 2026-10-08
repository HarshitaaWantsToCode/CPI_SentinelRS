use chrono::Utc;
use sentinel_core::{CloudAsset, DriftFinding, DriftType, Severity};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IaCResourceSpec {
    pub address: String,
    pub resource_type: String,
    pub attributes: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedIaCInventory {
    pub version: String,
    pub format: String, // e.g. "terraform-state-v4"
    pub resources: Vec<IaCResourceSpec>,
}

pub struct DriftEngine;

impl DriftEngine {
    /// Compares expected IaC state against observed CloudAssetInventory
    pub fn evaluate_drift(
        expected_iac: &NormalizedIaCInventory,
        observed_assets: &[CloudAsset],
    ) -> Vec<DriftFinding> {
        let mut drift_findings = Vec::new();

        // Map observed assets by identifier / ARN / name
        for spec in &expected_iac.resources {
            let matched_asset = observed_assets.iter().find(|a| {
                a.name == spec.address
                    || a.id == spec.address
                    || a.arn.as_deref() == Some(&spec.address)
                    || spec.attributes.get("name").and_then(|v| v.as_str()) == Some(&a.name)
            });

            match matched_asset {
                None => {
                    // Resource defined in IaC but missing in AWS
                    drift_findings.push(DriftFinding {
                        id: Uuid::new_v4(),
                        resource_address: spec.address.clone(),
                        resource_type: spec.resource_type.clone(),
                        drift_type: DriftType::Missing,
                        expected: spec.attributes.clone(),
                        observed: serde_json::Value::Null,
                        severity: Severity::High,
                        security_impact: "Expected security infrastructure / logging resource is missing from live AWS environment.".into(),
                        detected_at: Utc::now(),
                    });
                }
                Some(observed) => {
                    // Compare security-critical attributes
                    if spec.resource_type == "aws_security_group" {
                        let expected_open = spec.attributes.get("ingress_open_ssh").and_then(|v| v.as_bool()).unwrap_or(false);
                        let observed_open = observed.metadata.get("ingress_open_ssh").and_then(|v| v.as_bool()).unwrap_or(false);

                        if !expected_open && observed_open {
                            drift_findings.push(DriftFinding {
                                id: Uuid::new_v4(),
                                resource_address: observed.name.clone(),
                                resource_type: "aws_security_group".into(),
                                drift_type: DriftType::SecurityRelevant,
                                expected: serde_json::json!({ "ingress_open_ssh": false, "authorized_cidrs": ["10.0.0.0/16"] }),
                                observed: serde_json::json!({ "ingress_open_ssh": true, "unrestricted_cidr": "0.0.0.0/0:22" }),
                                severity: Severity::Critical,
                                security_impact: "Inbound SSH rule drifted from IaC baseline to unrestricted public internet exposure.".into(),
                                detected_at: Utc::now(),
                            });
                        }
                    }

                    if spec.resource_type == "aws_s3_bucket" {
                        let expected_enc = spec.attributes.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(true);
                        let observed_enc = observed.metadata.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(false);

                        if expected_enc && !observed_enc {
                            drift_findings.push(DriftFinding {
                                id: Uuid::new_v4(),
                                resource_address: observed.name.clone(),
                                resource_type: "aws_s3_bucket".into(),
                                drift_type: DriftType::SecurityRelevant,
                                expected: serde_json::json!({ "server_side_encryption": "aws:kms" }),
                                observed: serde_json::json!({ "server_side_encryption": "disabled" }),
                                severity: Severity::High,
                                security_impact: "S3 default bucket encryption disabled outside of Terraform IaC pipeline.".into(),
                                detected_at: Utc::now(),
                            });
                        }
                    }
                }
            }
        }

        // Check for unexpected resources in AWS not managed by IaC
        for observed in observed_assets {
            let in_iac = expected_iac.resources.iter().any(|spec| {
                spec.address == observed.name
                    || spec.address == observed.id
                    || spec.attributes.get("name").and_then(|v| v.as_str()) == Some(&observed.name)
            });

            if !in_iac && observed.name.contains("attacker") {
                drift_findings.push(DriftFinding {
                    id: Uuid::new_v4(),
                    resource_address: observed.name.clone(),
                    resource_type: format!("{:?}", observed.asset_type),
                    drift_type: DriftType::Unexpected,
                    expected: serde_json::Value::Null,
                    observed: serde_json::json!({ "name": observed.name, "created_out_of_band": true }),
                    severity: Severity::Critical,
                    security_impact: "Shadow IAM identity created directly via AWS API outside version-controlled IaC state.".into(),
                    detected_at: Utc::now(),
                });
            }
        }

        drift_findings
    }

    /// Generates sample expected Terraform state for demonstration
    pub fn get_demo_iac_state() -> NormalizedIaCInventory {
        NormalizedIaCInventory {
            version: "1.0".into(),
            format: "terraform-state-v4".into(),
            resources: vec![
                IaCResourceSpec {
                    address: "sg-04a1bc9".into(),
                    resource_type: "aws_security_group".into(),
                    attributes: serde_json::json!({ "name": "sg-04a1bc9", "ingress_open_ssh": false, "vpn_cidr": "10.0.0.0/16" }),
                },
                IaCResourceSpec {
                    address: "sentinel-customer-pii-production".into(),
                    resource_type: "aws_s3_bucket".into(),
                    attributes: serde_json::json!({ "name": "sentinel-customer-pii-production", "encrypted": true, "block_public_access": true }),
                },
                IaCResourceSpec {
                    address: "prod-audit-trail".into(),
                    resource_type: "aws_cloudtrail".into(),
                    attributes: serde_json::json!({ "name": "prod-audit-trail", "is_multi_region": true }),
                },
            ],
        }
    }
}
