use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sentinel_core::{CloudEvent, DriftFinding, GuardDutyFinding, PostureFinding, Severity, ThreatIntelResult};
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Default, Deserialize)]
pub struct EventFilterQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub action: Option<String>,
    pub actor: Option<String>,
    pub region: Option<String>,
    pub severity: Option<String>,
    pub search: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct EventStore {
    events: Arc<DashMap<Uuid, CloudEvent>>,
    ordered_ids: Arc<parking_lot::RwLock<Vec<Uuid>>>,
    guardduty_findings: Arc<DashMap<String, GuardDutyFinding>>,
    posture_findings: Arc<parking_lot::RwLock<Vec<PostureFinding>>>,
    drift_findings: Arc<parking_lot::RwLock<Vec<DriftFinding>>>,
    threat_intel_cache: Arc<DashMap<IpAddr, ThreatIntelResult>>,
}

impl EventStore {
    pub fn new() -> Self {
        let store = Self {
            events: Arc::new(DashMap::new()),
            ordered_ids: Arc::new(parking_lot::RwLock::new(Vec::new())),
            guardduty_findings: Arc::new(DashMap::new()),
            posture_findings: Arc::new(parking_lot::RwLock::new(Vec::new())),
            drift_findings: Arc::new(parking_lot::RwLock::new(Vec::new())),
            threat_intel_cache: Arc::new(DashMap::new()),
        };
        store.seed_posture_findings();
        store
    }

    pub fn insert_event(&self, event: CloudEvent) {
        let id = event.id;
        self.events.insert(id, event);
        let mut ids = self.ordered_ids.write();
        ids.push(id);
    }

    pub fn insert_guardduty_finding(&self, finding: GuardDutyFinding) {
        self.guardduty_findings.insert(finding.id.clone(), finding);
    }

    pub fn list_guardduty_findings(&self) -> Vec<GuardDutyFinding> {
        self.guardduty_findings.iter().map(|e| e.value().clone()).collect()
    }

    pub fn get_guardduty_finding(&self, id: &str) -> Option<GuardDutyFinding> {
        self.guardduty_findings.get(id).map(|e| e.value().clone())
    }

    pub fn list_events_filtered(&self, filter: &EventFilterQuery) -> Vec<CloudEvent> {
        let limit = filter.limit.unwrap_or(50).min(500);
        let offset = filter.offset.unwrap_or(0);
        let ids = self.ordered_ids.read();

        ids.iter()
            .rev()
            .filter_map(|id| self.events.get(id).map(|e| e.value().clone()))
            .filter(|event| {
                if let Some(ref action) = filter.action {
                    if !event.action.to_lowercase().contains(&action.to_lowercase()) {
                        return false;
                    }
                }
                if let Some(ref actor) = filter.actor {
                    if !event.actor.identity.to_lowercase().contains(&actor.to_lowercase()) {
                        return false;
                    }
                }
                if let Some(ref reg) = filter.region {
                    if event.region.as_deref().unwrap_or("").to_lowercase() != reg.to_lowercase() {
                        return false;
                    }
                }
                if let Some(ref sev) = filter.severity {
                    let ev_sev_str = match event.severity {
                        Some(Severity::Critical) => "critical",
                        Some(Severity::High) => "high",
                        Some(Severity::Medium) => "medium",
                        Some(Severity::Low) => "low",
                        Some(Severity::Informational) => "informational",
                        None => "none",
                    };
                    if ev_sev_str != sev.to_lowercase() {
                        return false;
                    }
                }
                if let Some(ref q) = filter.search {
                    let match_search = event.action.to_lowercase().contains(&q.to_lowercase())
                        || event.actor.identity.to_lowercase().contains(&q.to_lowercase())
                        || event.resource.identifier.to_lowercase().contains(&q.to_lowercase());
                    if !match_search {
                        return false;
                    }
                }
                if let Some(start) = filter.start_time {
                    if event.timestamp < start {
                        return false;
                    }
                }
                if let Some(end) = filter.end_time {
                    if event.timestamp > end {
                        return false;
                    }
                }
                true
            })
            .skip(offset)
            .take(limit)
            .collect()
    }

    pub fn list_events(&self, limit: usize) -> Vec<CloudEvent> {
        let ids = self.ordered_ids.read();
        ids.iter()
            .rev()
            .take(limit)
            .filter_map(|id| self.events.get(id).map(|entry| entry.value().clone()))
            .collect()
    }

    pub fn get_event(&self, id: &Uuid) -> Option<CloudEvent> {
        self.events.get(id).map(|entry| entry.value().clone())
    }

    pub fn count_events(&self) -> usize {
        self.events.len()
    }

    pub fn get_posture_findings(&self) -> Vec<PostureFinding> {
        self.posture_findings.read().clone()
    }

    pub fn set_posture_findings(&self, findings: Vec<PostureFinding>) {
        *self.posture_findings.write() = findings;
    }

    pub fn get_drift_findings(&self) -> Vec<DriftFinding> {
        self.drift_findings.read().clone()
    }

    pub fn set_drift_findings(&self, findings: Vec<DriftFinding>) {
        *self.drift_findings.write() = findings;
    }

    pub fn insert_threat_intel(&self, ip: IpAddr, res: ThreatIntelResult) {
        self.threat_intel_cache.insert(ip, res);
    }

    pub fn get_threat_intel(&self, ip: &IpAddr) -> Option<ThreatIntelResult> {
        self.threat_intel_cache.get(ip).map(|e| e.value().clone())
    }

    fn seed_posture_findings(&self) {
        let mut findings = self.posture_findings.write();
        findings.push(PostureFinding {
            id: "POSTURE-001".into(),
            rule_id: "CSPM-IAM-001".into(),
            title: "MFA Not Enforced on IAM User".into(),
            category: "Identity".into(),
            severity: Severity::High,
            description: "User attacker-demo has console access without mandatory hardware/virtual MFA.".into(),
            remediation: "Attach IAM policy enforcing aws:MultiFactorAuthPresent condition.".into(),
            resource_id: "attacker-demo".into(),
            resource_arn: Some("arn:aws:iam::123456789012:user/attacker-demo".into()),
            evidence: vec!["metadata.mfa_active == false".into()],
            detected_at: Utc::now(),
            status: sentinel_core::PostureStatus::Open,
            is_drift: false,
        });
        findings.push(PostureFinding {
            id: "POSTURE-002".into(),
            rule_id: "CSPM-S3-001".into(),
            title: "S3 Bucket Discovered Without Public Access Block".into(),
            category: "Storage".into(),
            severity: Severity::Critical,
            description: "s3://sentinel-customer-pii-production lacks S3 Block Public Access setting.".into(),
            remediation: "Enable S3 Block Public Access at the account and bucket level.".into(),
            resource_id: "s3://sentinel-customer-pii-production".into(),
            resource_arn: Some("arn:aws:s3:::sentinel-customer-pii-production".into()),
            evidence: vec!["metadata.block_public_access == false".into()],
            detected_at: Utc::now(),
            status: sentinel_core::PostureStatus::Open,
            is_drift: true,
        });
        findings.push(PostureFinding {
            id: "POSTURE-003".into(),
            rule_id: "CSPM-NET-001".into(),
            title: "Security Group Ingress Open to 0.0.0.0/0 on Port 22".into(),
            category: "Network".into(),
            severity: Severity::Critical,
            description: "Security Group sg-04a1bc9 allows unrestricted SSH inbound from any IP.".into(),
            remediation: "Restrict SSH ingress to authorized corporate VPN CIDR ranges.".into(),
            resource_id: "sg-04a1bc9".into(),
            resource_arn: Some("arn:aws:ec2:ap-south-1:123456789012:security-group/sg-04a1bc9".into()),
            evidence: vec!["ingress_open_ssh == true".into()],
            detected_at: Utc::now(),
            status: sentinel_core::PostureStatus::Open,
            is_drift: true,
        });
    }
}

impl Default for EventStore {
    fn default() -> Self {
        Self::new()
    }
}
