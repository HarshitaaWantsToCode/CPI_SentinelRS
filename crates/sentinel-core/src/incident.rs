use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::event::Severity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Active,
    Investigating,
    Contained,
    Remediated,
    Closed,
    Dismissed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub step_number: u32,
    pub timestamp: DateTime<Utc>,
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
    pub description: String,
    pub event_id: Uuid,
    pub affected_resource: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String, // e.g. "SR-1042"
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub status: IncidentStatus,
    pub risk_score: u8,
    pub confidence_score: u8,
    pub affected_assets_count: usize,
    pub initial_access_time: DateTime<Utc>,
    pub last_activity_time: DateTime<Utc>,
    pub stages: Vec<AttackStep>,
    pub involved_actors: Vec<String>,
    pub involved_resources: Vec<String>,
    pub recommended_actions: Vec<String>,
}
