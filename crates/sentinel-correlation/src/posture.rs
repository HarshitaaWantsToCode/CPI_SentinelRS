use chrono::Utc;
use sentinel_core::{AssetType, CloudAsset, PostureFinding, PostureStatus, Severity};
use std::collections::HashMap;

pub struct PostureScoreBreakdown {
    pub overall_score: u32,
    pub categories: HashMap<String, u32>,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

pub struct PostureEngine;

impl PostureEngine {
    /// Evaluates cloud asset inventory against deterministic CSPM posture rules
    pub fn evaluate_inventory(assets: &[CloudAsset]) -> (Vec<PostureFinding>, PostureScoreBreakdown) {
        let mut findings = Vec::new();

        for asset in assets {
            match asset.asset_type {
                AssetType::IamUser => {
                    // Rule 1: MFA check
                    let mfa_active = asset.metadata.get("mfa_active").and_then(|v| v.as_bool()).unwrap_or(true);
                    if !mfa_active {
                        findings.push(PostureFinding {
                            id: format!("POSTURE-IAM-MFA-{}", asset.id),
                            rule_id: "CSPM-IAM-001".into(),
                            title: format!("Multi-Factor Authentication (MFA) Missing for IAM User '{}'", asset.name),
                            category: "Identity".into(),
                            severity: Severity::High,
                            description: format!("User '{}' has active console/API credentials without enforced hardware/virtual MFA.", asset.name),
                            remediation: "Enforce MFA via AWS IAM policy condition 'aws:MultiFactorAuthPresent'.".into(),
                            resource_id: asset.id.clone(),
                            resource_arn: asset.arn.clone(),
                            evidence: vec!["metadata.mfa_active == false".into()],
                            detected_at: Utc::now(),
                            status: PostureStatus::Open,
                            is_drift: false,
                        });
                    }
                }
                AssetType::IamRole => {
                    // Rule 2: Overly Permissive AdministratorAccess Policy
                    let policies = asset.metadata.get("policies").and_then(|v| v.as_array());
                    let has_admin = policies.map(|arr| arr.iter().any(|p| p.as_str() == Some("AdministratorAccess"))).unwrap_or(false);
                    if has_admin {
                        findings.push(PostureFinding {
                            id: format!("POSTURE-IAM-ADMIN-{}", asset.id),
                            rule_id: "CSPM-IAM-002".into(),
                            title: format!("Overly Permissive AdministratorAccess Policy Attached to Role '{}'", asset.name),
                            category: "Identity".into(),
                            severity: Severity::Critical,
                            description: format!("Role '{}' has full unrestricted administrative wildcard permissions (Action: '*', Resource: '*').", asset.name),
                            remediation: "Scope permissions down using least-privilege IAM policies and service-specific access boundaries.".into(),
                            resource_id: asset.id.clone(),
                            resource_arn: asset.arn.clone(),
                            evidence: vec!["policies contains 'AdministratorAccess'".into()],
                            detected_at: Utc::now(),
                            status: PostureStatus::Open,
                            is_drift: false,
                        });
                    }
                }
                AssetType::S3Bucket => {
                    // Rule 3: S3 Public Access & Encryption
                    let is_encrypted = asset.metadata.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(false);
                    if !is_encrypted {
                        findings.push(PostureFinding {
                            id: format!("POSTURE-S3-ENC-{}", asset.id),
                            rule_id: "CSPM-S3-001".into(),
                            title: format!("Server-Side Encryption (SSE) Disabled on S3 Bucket '{}'", asset.name),
                            category: "Storage".into(),
                            severity: Severity::High,
                            description: format!("Bucket '{}' does not have default AWS KMS or AES-256 SSE encryption enabled.", asset.name),
                            remediation: "Enable default encryption using AWS-KMS managed customer master keys (CMKs).".into(),
                            resource_id: asset.id.clone(),
                            resource_arn: asset.arn.clone(),
                            evidence: vec!["metadata.encrypted == false".into()],
                            detected_at: Utc::now(),
                            status: PostureStatus::Open,
                            is_drift: false,
                        });
                    }
                }
                AssetType::SecurityGroup => {
                    // Rule 4: Open Inbound SSH Port 22 from 0.0.0.0/0
                    let open_ssh = asset.metadata.get("ingress_open_ssh").and_then(|v| v.as_bool()).unwrap_or(false);
                    if open_ssh {
                        findings.push(PostureFinding {
                            id: format!("POSTURE-NET-SSH-{}", asset.id),
                            rule_id: "CSPM-NET-001".into(),
                            title: format!("Security Group '{}' Allows Unrestricted Inbound SSH (Port 22) from 0.0.0.0/0", asset.name),
                            category: "Network".into(),
                            severity: Severity::Critical,
                            description: format!("Security group '{}' exposes management port 22 to the public internet.", asset.name),
                            remediation: "Restrict inbound CIDR blocks to authorized corporate egress / VPN IP gateways only.".into(),
                            resource_id: asset.id.clone(),
                            resource_arn: asset.arn.clone(),
                            evidence: vec!["ingress_open_ssh == true (0.0.0.0/0:22)".into()],
                            detected_at: Utc::now(),
                            status: PostureStatus::Open,
                            is_drift: true,
                        });
                    }
                }
                AssetType::CloudTrail => {
                    // Rule 5: Multi-region Trail
                    let multi_region = asset.metadata.get("is_multi_region").and_then(|v| v.as_bool()).unwrap_or(false);
                    if !multi_region {
                        findings.push(PostureFinding {
                            id: format!("POSTURE-LOG-TRAIL-{}", asset.id),
                            rule_id: "CSPM-LOG-001".into(),
                            title: format!("CloudTrail Trail '{}' Lacks Multi-Region Collection", asset.name),
                            category: "Logging".into(),
                            severity: Severity::Medium,
                            description: format!("Trail '{}' is scoped to a single region, allowing evasion in unmonitored AWS regions.", asset.name),
                            remediation: "Enable multi-region trail logging for complete audit trail coverage.".into(),
                            resource_id: asset.id.clone(),
                            resource_arn: asset.arn.clone(),
                            evidence: vec!["is_multi_region == false".into()],
                            detected_at: Utc::now(),
                            status: PostureStatus::Open,
                            is_drift: false,
                        });
                    }
                }
                _ => {}
            }
        }

        let breakdown = Self::calculate_posture_score(&findings);
        (findings, breakdown)
    }

    /// Calculate explainable 0-100 Posture Score
    pub fn calculate_posture_score(findings: &[PostureFinding]) -> PostureScoreBreakdown {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;

        let mut cat_penalties: HashMap<String, u32> = HashMap::new();
        cat_penalties.insert("Identity".into(), 0);
        cat_penalties.insert("Storage".into(), 0);
        cat_penalties.insert("Network".into(), 0);
        cat_penalties.insert("Logging".into(), 0);
        cat_penalties.insert("Compute".into(), 0);

        for f in findings {
            if f.status != PostureStatus::Open {
                continue;
            }
            let penalty = match f.severity {
                Severity::Critical => {
                    critical_count += 1;
                    18
                }
                Severity::High => {
                    high_count += 1;
                    10
                }
                Severity::Medium => {
                    medium_count += 1;
                    5
                }
                Severity::Low => {
                    low_count += 1;
                    2
                }
                Severity::Informational => 0,
            };

            let entry = cat_penalties.entry(f.category.clone()).or_insert(0);
            *entry += penalty;
        }

        let total_penalty: u32 = cat_penalties.values().sum();
        let overall_score = 100u32.saturating_sub(total_penalty).max(10);

        let mut categories = HashMap::new();
        for (cat, penalty) in &cat_penalties {
            let cat_score = 100u32.saturating_sub(*penalty * 2).max(20);
            categories.insert(cat.to_lowercase(), cat_score);
        }

        PostureScoreBreakdown {
            overall_score,
            categories,
            total_findings: findings.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
        }
    }
}
