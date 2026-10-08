use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

use crate::actor::Actor;
use crate::classification::{ActionType, EventCategory};
use crate::resource::Resource;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    Kubernetes,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    CloudTrail,
    GuardDuty,
    VpcFlowLogs,
    Iam,
    S3,
    Ec2,
    DatasetReplay,
    SyntheticScenario,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    Success,
    Failure,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub cloud_provider: CloudProvider,
    pub account_id: Option<String>,
    pub actor: Actor,
    pub source: EventSource,
    pub action: String,
    pub action_type: ActionType,
    pub category: EventCategory,
    pub resource: Resource,
    pub source_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub region: Option<String>,
    pub outcome: EventOutcome,
    pub severity: Option<Severity>,
    pub metadata: serde_json::Value,
}

impl CloudEvent {
    pub fn new(
        cloud_provider: CloudProvider,
        actor: Actor,
        source: EventSource,
        action: impl Into<String>,
        resource: Resource,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            cloud_provider,
            account_id: None,
            actor,
            source,
            action: action.into(),
            action_type: ActionType::Unknown,
            category: EventCategory::Other("general".into()),
            resource,
            source_ip: None,
            user_agent: None,
            region: None,
            outcome: EventOutcome::Success,
            severity: Some(Severity::Low),
            metadata: serde_json::json!({}),
        }
    }
}
