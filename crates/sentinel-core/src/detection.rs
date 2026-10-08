use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::event::Severity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionCategory {
    PrivilegeEscalation,
    DefenseEvasion,
    Persistence,
    CredentialAccess,
    Discovery,
    Exfiltration,
    InitialAccess,
    Impact,
    BehavioralAnomaly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub key: String,
    pub value: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFinding {
    pub id: Uuid,
    pub detector_id: String,
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: u8, // 0 - 100%
    pub category: DetectionCategory,
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
    pub why_suspicious: String,
    pub recommended_response: String,
    pub evidence: Vec<EvidenceItem>,
    pub risk_contribution: u8,
}
