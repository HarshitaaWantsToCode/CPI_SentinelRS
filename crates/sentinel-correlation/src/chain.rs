use chrono::{DateTime, Utc};
use sentinel_core::{AttackStep, CloudEvent, DetectionFinding};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackStage {
    Reconnaissance,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    Collection,
    Exfiltration,
    Impact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub id: String,
    pub actor_identity: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub events: Vec<Uuid>,
    pub findings: Vec<DetectionFinding>,
    pub stages: Vec<AttackStep>,
    pub current_stage: AttackStage,
    pub risk_score: u8,
}

impl AttackChain {
    pub fn new(id: impl Into<String>, actor_identity: impl Into<String>, initial_time: DateTime<Utc>) -> Self {
        Self {
            id: id.into(),
            actor_identity: actor_identity.into(),
            first_seen: initial_time,
            last_seen: initial_time,
            events: Vec::new(),
            findings: Vec::new(),
            stages: Vec::new(),
            current_stage: AttackStage::InitialAccess,
            risk_score: 20,
        }
    }

    pub fn add_finding(&mut self, event: &CloudEvent, finding: &DetectionFinding) {
        self.last_seen = event.timestamp;
        if !self.events.contains(&event.id) {
            self.events.push(event.id);
        }
        self.findings.push(finding.clone());

        let step_num = (self.stages.len() + 1) as u32;
        self.stages.push(AttackStep {
            step_number: step_num,
            timestamp: event.timestamp,
            tactic: finding.tactic.clone(),
            technique_id: finding.technique_id.clone(),
            technique_name: finding.technique_name.clone(),
            description: finding.title.clone(),
            event_id: event.id,
            affected_resource: event.resource.identifier.clone(),
        });

        self.current_stage = match finding.tactic.as_str() {
            "Initial Access" => AttackStage::InitialAccess,
            "Privilege Escalation" => AttackStage::PrivilegeEscalation,
            "Persistence" => AttackStage::Persistence,
            "Defense Evasion" => AttackStage::DefenseEvasion,
            "Discovery" => AttackStage::Discovery,
            "Exfiltration" => AttackStage::Exfiltration,
            "Impact" => AttackStage::Impact,
            _ => self.current_stage.clone(),
        };
    }
}
