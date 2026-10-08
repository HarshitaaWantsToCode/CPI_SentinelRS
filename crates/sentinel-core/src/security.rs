use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

use crate::event::Severity;

// ==========================================
// Phase 5A: GuardDuty Finding Domain Model
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardDutyFinding {
    pub id: String,
    pub finding_type: String,
    pub severity: f32, // GuardDuty severity 0.1 - 8.9+
    pub title: String,
    pub description: Option<String>,
    pub account_id: Option<String>,
    pub region: Option<String>,
    pub resource_id: Option<String>,
    pub resource_type: Option<String>,
    pub actor_ip: Option<String>,
    pub actor_country: Option<String>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub source: String,
    pub raw_json: serde_json::Value,
}

impl GuardDutyFinding {
    /// Deterministic deduplication key: account_id + region + finding_id
    pub fn deduplication_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.account_id.as_deref().unwrap_or("unknown-account"),
            self.region.as_deref().unwrap_or("unknown-region"),
            self.id
        )
    }

    /// Map GuardDuty numeric severity to canonical SentinelRS Severity
    pub fn canonical_severity(&self) -> Severity {
        if self.severity >= 7.0 {
            Severity::Critical
        } else if self.severity >= 4.0 {
            Severity::High
        } else if self.severity >= 1.5 {
            Severity::Medium
        } else if self.severity > 0.0 {
            Severity::Low
        } else {
            Severity::Informational
        }
    }
}

// ==========================================
// Phase 5B: Threat Intelligence Models
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreatIntelStatus {
    Live,
    Cached,
    Simulated,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelResult {
    pub ip: IpAddr,
    pub malicious: bool,
    pub confidence: Option<f32>, // 0.0 - 1.0
    pub reputation_score: Option<f32>, // 0.0 - 100.0 (higher = more malicious)
    pub categories: Vec<String>,
    pub source: String,
    pub status: ThreatIntelStatus,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub raw_reference: Option<String>,
    pub queried_at: DateTime<Utc>,
}

// ==========================================
// Phase 5C & 5D: Posture & Drift Domain Models
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureStatus {
    Open,
    Acknowledged,
    Resolved,
    Suppressed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureFinding {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub category: String, // Identity, Logging, Network, Storage, Compute
    pub severity: Severity,
    pub description: String,
    pub remediation: String,
    pub resource_id: String,
    pub resource_arn: Option<String>,
    pub evidence: Vec<String>,
    pub detected_at: DateTime<Utc>,
    pub status: PostureStatus,
    pub is_drift: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DriftType {
    Missing,
    Unexpected,
    Modified,
    SecurityRelevant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftFinding {
    pub id: Uuid,
    pub resource_address: String,
    pub resource_type: String,
    pub drift_type: DriftType,
    pub expected: serde_json::Value,
    pub observed: serde_json::Value,
    pub severity: Severity,
    pub security_impact: String,
    pub detected_at: DateTime<Utc>,
}

// ==========================================
// Phase 5E - 5H: Response Orchestration & Safe Gating
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    Simulation,
    ApprovalRequired,
    Live,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Recommended,
    PendingApproval,
    Approved,
    Simulated,
    Executing,
    Executed,
    Failed,
    Rejected,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseApproval {
    pub approver_id: String,
    pub decision: ApprovalDecision,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
    pub policy_version: String,
    pub action_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub id: Uuid,
    pub incident_id: String,
    pub title: String,
    pub description: String,
    pub target_resource: String,
    pub action_type: String, // e.g., "RevokeAccessKey", "DetachPolicy", "IsolateInstance", "RevokeSecurityGroupIngress", "StartLogging"
    pub status: ResponseStatus,
    pub mode: ResponseMode,
    pub approvals: Vec<ResponseApproval>,
    pub required_approvals_count: usize,
    pub approval_expires_at: Option<DateTime<Utc>>,
    pub simulation_result: Option<SimulationDetails>,
    pub created_at: DateTime<Utc>,
    pub executed_at: Option<DateTime<Utc>>,
    pub result_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationDetails {
    pub validation_passed: bool,
    pub permissions_verified: Vec<String>,
    pub hypothetical_aws_call: String,
    pub expected_impact: String,
    pub executed_at: DateTime<Utc>,
    pub execution_mode: String,
}

// ==========================================
// Phase 5I: Immutable Cryptographic Audit Log
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub record_id: Uuid,
    pub sequence_number: u64,
    pub timestamp: DateTime<Utc>,
    pub incident_id: String,
    pub response_id: Uuid,
    pub actor: String,
    pub action_type: String,
    pub target_resource: String,
    pub execution_mode: ResponseMode,
    pub previous_state: ResponseStatus,
    pub new_state: ResponseStatus,
    pub request_hash: String,
    pub result: String,
    pub aws_metadata: Option<serde_json::Value>,
    pub previous_hash: String,
    pub current_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditVerificationResult {
    pub valid: bool,
    pub records_checked: usize,
    pub first_invalid_record: Option<u64>,
    pub genesis_hash: String,
    pub tip_hash: String,
    pub verified_at: DateTime<Utc>,
}
