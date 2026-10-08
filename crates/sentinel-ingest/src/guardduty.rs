use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sentinel_core::GuardDutyFinding;
use std::sync::Arc;

pub struct GuardDutyCollector {
    dedup_cache: Arc<DashMap<String, DateTime<Utc>>>,
}

impl GuardDutyCollector {
    pub fn new() -> Self {
        Self {
            dedup_cache: Arc::new(DashMap::new()),
        }
    }

    /// Attempts to ingest a GuardDuty finding. Returns true if new, false if duplicate.
    pub fn ingest_finding(&self, finding: &GuardDutyFinding) -> bool {
        let key = finding.deduplication_key();
        if self.dedup_cache.contains_key(&key) {
            tracing::debug!("Discarding duplicate GuardDuty finding: {}", key);
            false
        } else {
            self.dedup_cache.insert(key, Utc::now());
            true
        }
    }

    pub fn count_tracked(&self) -> usize {
        self.dedup_cache.len()
    }

    /// Generates realistic synthetic GuardDuty findings for demo / testing.
    pub fn generate_demo_findings() -> Vec<GuardDutyFinding> {
        vec![
            GuardDutyFinding {
                id: "gd-find-8a9b1c2d3e".into(),
                finding_type: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS".into(),
                severity: 8.0,
                title: "Credentials created for IAM user attacker-demo were used from an external malicious IP".into(),
                description: Some("EC2 temporary credentials or IAM access key AKIAIOSFODNN7EXAMPLE were used from IP 198.51.100.42 located outside AWS network.".into()),
                account_id: Some("123456789012".into()),
                region: Some("ap-south-1".into()),
                resource_id: Some("AKIAIOSFODNN7EXAMPLE".into()),
                resource_type: Some("AccessKey".into()),
                actor_ip: Some("198.51.100.42".into()),
                actor_country: Some("Unknown Proxy / Tor Exit".into()),
                first_seen: Some(Utc::now() - chrono::Duration::minutes(15)),
                last_seen: Some(Utc::now() - chrono::Duration::minutes(2)),
                source: "aws.guardduty".into(),
                raw_json: serde_json::json!({
                    "service": {
                        "serviceName": "guardduty",
                        "detectorId": "d-1234567890abcdef",
                        "action": {
                            "actionType": "AWS_API_CALL",
                            "awsApiCallAction": {
                                "api": "GetCallerIdentity",
                                "serviceName": "sts.amazonaws.com",
                                "callerType": "Remote IP",
                                "remoteIpDetails": {
                                    "ipAddressV4": "198.51.100.42",
                                    "organization": { "asn": "12345", "org": "Anonymous Proxy" }
                                }
                            }
                        }
                    }
                }),
            },
            GuardDutyFinding {
                id: "gd-find-4f5e6d7c8b".into(),
                finding_type: "Stealth:IAMUser/CloudTrailLoggingDisabled".into(),
                severity: 7.5,
                title: "CloudTrail trail prod-audit-trail logging was suspended".into(),
                description: Some("IAM principal attacker-demo disabled CloudTrail trail prod-audit-trail logging, hindering forensic visibility.".into()),
                account_id: Some("123456789012".into()),
                region: Some("ap-south-1".into()),
                resource_id: Some("arn:aws:cloudtrail:ap-south-1:123456789012:trail/prod-audit-trail".into()),
                resource_type: Some("CloudTrail".into()),
                actor_ip: Some("198.51.100.42".into()),
                actor_country: Some("Unknown Proxy / Tor Exit".into()),
                first_seen: Some(Utc::now() - chrono::Duration::minutes(8)),
                last_seen: Some(Utc::now() - chrono::Duration::minutes(8)),
                source: "aws.guardduty".into(),
                raw_json: serde_json::json!({
                    "service": {
                        "serviceName": "guardduty",
                        "detectorId": "d-1234567890abcdef",
                        "action": {
                            "actionType": "AWS_API_CALL",
                            "awsApiCallAction": {
                                "api": "StopLogging",
                                "serviceName": "cloudtrail.amazonaws.com"
                            }
                        }
                    }
                }),
            },
            GuardDutyFinding {
                id: "gd-find-1a2b3c4d5e".into(),
                finding_type: "Exfiltration:S3/AnomalousObjectRetrieval".into(),
                severity: 8.5,
                title: "Anomalous bulk S3 object retrieval from sensitive customer bucket".into(),
                description: Some("Unusual volume of GetObject requests observed on bucket sentinel-customer-pii-production from untrusted IP.".into()),
                account_id: Some("123456789012".into()),
                region: Some("ap-south-1".into()),
                resource_id: Some("s3://sentinel-customer-pii-production".into()),
                resource_type: Some("S3Bucket".into()),
                actor_ip: Some("198.51.100.42".into()),
                actor_country: Some("Unknown Proxy / Tor Exit".into()),
                first_seen: Some(Utc::now() - chrono::Duration::minutes(5)),
                last_seen: Some(Utc::now() - chrono::Duration::minutes(1)),
                source: "aws.guardduty".into(),
                raw_json: serde_json::json!({
                    "service": {
                        "serviceName": "guardduty",
                        "detectorId": "d-1234567890abcdef"
                    }
                }),
            },
        ]
    }
}

impl Default for GuardDutyCollector {
    fn default() -> Self {
        Self::new()
    }
}
