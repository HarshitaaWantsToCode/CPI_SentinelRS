use chrono::{DateTime, Utc};
use sentinel_core::{
    ActionType, Actor, ActorType, CloudEvent, CloudProvider, EventCategory, EventOutcome, EventSource,
    GuardDutyFinding, Resource, ResourceType, Severity,
};
use serde_json::Value;
use std::net::IpAddr;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum NormalizationError {
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
    #[error("Invalid timestamp format: {0}")]
    InvalidTimestamp(String),
    #[error("JSON deserialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Empty record list")]
    EmptyRecords,
}

pub struct CloudTrailParser;

impl CloudTrailParser {
    /// Parses either a single CloudTrail event or a {"Records": [...]} array.
    pub fn parse_str(json_str: &str) -> Result<Vec<CloudEvent>, NormalizationError> {
        let value: Value = serde_json::from_str(json_str)?;
        Self::parse_value(&value)
    }

    /// Parses a serde_json::Value representing either a single event or a Records batch.
    pub fn parse_value(value: &Value) -> Result<Vec<CloudEvent>, NormalizationError> {
        if let Some(records) = value.get("Records").and_then(|r| r.as_array()) {
            let mut events = Vec::with_capacity(records.len());
            for record in records {
                match Self::normalize_single_event(record) {
                    Ok(ev) => events.push(ev),
                    Err(e) => tracing::warn!("Skipping malformed CloudTrail record in batch: {}", e),
                }
            }
            if events.is_empty() && !records.is_empty() {
                return Err(NormalizationError::MissingField("Valid records in batch"));
            }
            Ok(events)
        } else {
            let event = Self::normalize_single_event(value)?;
            Ok(vec![event])
        }
    }

    pub fn normalize_single_event(raw: &Value) -> Result<CloudEvent, NormalizationError> {
        let event_name = raw["eventName"]
            .as_str()
            .ok_or(NormalizationError::MissingField("eventName"))?;

        let timestamp_str = raw["eventTime"]
            .as_str()
            .ok_or(NormalizationError::MissingField("eventTime"))?;

        let timestamp = DateTime::parse_from_rfc3339(timestamp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|_| NormalizationError::InvalidTimestamp(timestamp_str.to_string()))?;

        let user_identity = &raw["userIdentity"];
        let actor_type = match user_identity["type"].as_str().unwrap_or("Unknown") {
            "IAMUser" => ActorType::IamUser,
            "AssumedRole" => ActorType::AssumedRole,
            "Role" => ActorType::IamRole,
            "FederatedUser" => ActorType::FederatedUser,
            "Root" => ActorType::Root,
            "AWSService" => ActorType::AwsService,
            "Anonymous" => ActorType::Anonymous,
            _ => ActorType::Unknown,
        };

        let identity = user_identity["userName"]
            .as_str()
            .or_else(|| user_identity["principalId"].as_str())
            .or_else(|| user_identity["sessionContext"]["sessionIssuer"]["userName"].as_str())
            .unwrap_or("anonymous")
            .to_string();

        let account_id = user_identity["accountId"]
            .as_str()
            .or_else(|| raw["recipientAccountId"].as_str())
            .map(String::from);

        let actor = Actor {
            actor_type,
            identity,
            arn: user_identity["arn"].as_str().map(String::from),
            principal_id: user_identity["principalId"].as_str().map(String::from),
            account_id: account_id.clone(),
            session_name: user_identity["sessionContext"]["sessionIssuer"]["userName"]
                .as_str()
                .map(String::from),
        };

        let source_ip: Option<IpAddr> = raw["sourceIPAddress"]
            .as_str()
            .and_then(|ip| ip.parse().ok());

        let region = raw["awsRegion"].as_str().map(String::from);
        let user_agent = raw["userAgent"].as_str().map(String::from);

        let error_code = raw["errorCode"].as_str();
        let outcome = match error_code {
            None => EventOutcome::Success,
            Some("AccessDenied") | Some("UnauthorizedOperation") => EventOutcome::Denied,
            _ => EventOutcome::Failure,
        };

        let event_source = raw["eventSource"].as_str().unwrap_or("");
        let (source, default_resource_type, category) = Self::classify_source(event_source, event_name);
        let action_type = Self::classify_action(event_name);

        let resource_name = raw["requestParameters"]["userName"]
            .as_str()
            .or_else(|| raw["requestParameters"]["bucketName"].as_str())
            .or_else(|| raw["requestParameters"]["key"].as_str())
            .or_else(|| raw["requestParameters"]["name"].as_str())
            .or_else(|| raw["requestParameters"]["trailName"].as_str())
            .or_else(|| raw["requestParameters"]["roleName"].as_str())
            .or_else(|| raw["resources"][0]["ARN"].as_str())
            .unwrap_or("*");

        let is_sensitive = resource_name.contains("pii")
            || resource_name.contains("secret")
            || resource_name.contains("production")
            || resource_name.contains("financial")
            || event_name.contains("AdministratorAccess");

        let resource = Resource {
            resource_type: default_resource_type,
            identifier: resource_name.to_string(),
            arn: raw["resources"][0]["ARN"].as_str().map(String::from),
            account_id: account_id.clone(),
            region: region.clone(),
            is_sensitive,
        };

        let severity = Self::determine_baseline_severity(event_name, &action_type, is_sensitive);

        Ok(CloudEvent {
            id: Uuid::new_v4(),
            timestamp,
            cloud_provider: CloudProvider::Aws,
            account_id,
            actor,
            source,
            action: event_name.to_string(),
            action_type,
            category,
            resource,
            source_ip,
            user_agent,
            region,
            outcome,
            severity: Some(severity),
            metadata: raw.clone(),
        })
    }

    fn classify_source(event_source: &str, event_name: &str) -> (EventSource, ResourceType, EventCategory) {
        if event_source.contains("iam") || event_name.contains("User") || event_name.contains("Policy") || event_name.contains("Role") {
            if event_name.contains("Policy") {
                (EventSource::Iam, ResourceType::IamPolicy, EventCategory::Authorization)
            } else if event_name.contains("Key") {
                (EventSource::Iam, ResourceType::AccessKey, EventCategory::Identity)
            } else if event_name.contains("Role") {
                (EventSource::Iam, ResourceType::IamRole, EventCategory::Identity)
            } else {
                (EventSource::Iam, ResourceType::IamUser, EventCategory::Identity)
            }
        } else if event_source.contains("s3") || event_name.contains("Bucket") || event_name.contains("Object") {
            if event_name.contains("Object") {
                (EventSource::S3, ResourceType::S3Object, EventCategory::Storage)
            } else {
                (EventSource::S3, ResourceType::S3Bucket, EventCategory::Storage)
            }
        } else if event_source.contains("cloudtrail") || event_name.contains("Trail") || event_name.contains("Logging") {
            (EventSource::CloudTrail, ResourceType::CloudTrail, EventCategory::Logging)
        } else if event_source.contains("ec2") || event_name.contains("Instance") || event_name.contains("SecurityGroup") {
            if event_name.contains("SecurityGroup") {
                (EventSource::Ec2, ResourceType::SecurityGroup, EventCategory::Network)
            } else {
                (EventSource::Ec2, ResourceType::Ec2Instance, EventCategory::Compute)
            }
        } else if event_name.contains("Login") || event_name.contains("Authenticate") {
            (EventSource::CloudTrail, ResourceType::IamUser, EventCategory::Authentication)
        } else {
            (EventSource::CloudTrail, ResourceType::Unknown(event_source.to_string()), EventCategory::Other("general".into()))
        }
    }

    fn classify_action(event_name: &str) -> ActionType {
        if event_name.starts_with("Get") || event_name.starts_with("List") || event_name.starts_with("Describe") {
            ActionType::Read
        } else if event_name.starts_with("Delete") || event_name.starts_with("Terminate") || event_name.starts_with("Stop") {
            ActionType::Delete
        } else if event_name.contains("Policy") || event_name.contains("Permission") || event_name.contains("Acl") {
            ActionType::PermissionChange
        } else if event_name.starts_with("Create") || event_name.starts_with("Put") || event_name.starts_with("Attach") || event_name.starts_with("Run") {
            ActionType::Write
        } else {
            ActionType::Unknown
        }
    }

    fn determine_baseline_severity(event_name: &str, action_type: &ActionType, is_sensitive: bool) -> Severity {
        if event_name == "AttachUserPolicy" && is_sensitive || event_name == "StopLogging" || event_name == "DeleteTrail" {
            Severity::Critical
        } else if event_name == "CreateAccessKey" || (event_name == "GetObject" && is_sensitive) {
            Severity::High
        } else if event_name == "ConsoleLogin" || *action_type == ActionType::Write {
            Severity::Medium
        } else if *action_type == ActionType::Read {
            Severity::Low
        } else {
            Severity::Informational
        }
    }
}

/// Normalizer for AWS GuardDuty findings into canonical SentinelRS CloudEvents
pub struct GuardDutyNormalizer;

impl GuardDutyNormalizer {
    pub fn normalize_finding(finding: &GuardDutyFinding) -> CloudEvent {
        let timestamp = finding.last_seen.unwrap_or_else(Utc::now);
        let severity = finding.canonical_severity();

        let actor = Actor {
            actor_type: ActorType::Unknown,
            identity: finding.actor_ip.clone().unwrap_or_else(|| "untrusted-external".into()),
            arn: None,
            principal_id: None,
            account_id: finding.account_id.clone(),
            session_name: None,
        };

        let source_ip: Option<IpAddr> = finding.actor_ip.as_deref().and_then(|ip| ip.parse().ok());

        let resource_type = match finding.resource_type.as_deref() {
            Some("AccessKey") => ResourceType::AccessKey,
            Some("S3Bucket") => ResourceType::S3Bucket,
            Some("CloudTrail") => ResourceType::CloudTrail,
            Some("Instance") | Some("Ec2Instance") => ResourceType::Ec2Instance,
            _ => ResourceType::Unknown("GuardDutyTarget".into()),
        };

        let resource = Resource {
            resource_type,
            identifier: finding.resource_id.clone().unwrap_or_else(|| "*".into()),
            arn: None,
            account_id: finding.account_id.clone(),
            region: finding.region.clone(),
            is_sensitive: true,
        };

        CloudEvent {
            id: Uuid::new_v4(),
            timestamp,
            cloud_provider: CloudProvider::Aws,
            account_id: finding.account_id.clone(),
            actor,
            source: EventSource::CloudTrail, // Ingested as cloud security telemetry
            action: finding.finding_type.clone(),
            action_type: ActionType::Unknown,
            category: EventCategory::Other("GuardDutyFinding".into()),
            resource,
            source_ip,
            user_agent: Some("AWS GuardDuty Findings Ingestor".into()),
            region: finding.region.clone(),
            outcome: EventOutcome::Failure,
            severity: Some(severity),
            metadata: serde_json::json!({
                "guardduty_finding_id": finding.id,
                "title": finding.title,
                "raw_severity": finding.severity,
                "finding_type": finding.finding_type,
                "source": finding.source,
                "raw_finding": finding.raw_json,
            }),
        }
    }
}
