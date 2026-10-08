use crate::source::{EventSource, IngestError};
use sentinel_core::CloudEvent;
use sentinel_normalizer::CloudTrailParser;

pub enum ScenarioType {
    NormalActivity,
    CredentialCompromise,
    IamPrivilegeEscalation,
    S3Exfiltration,
    CloudTrailTampering,
    FullMultiStageAttack,
}

pub struct SyntheticSource {
    events: Vec<CloudEvent>,
    index: usize,
}

impl SyntheticSource {
    pub fn from_scenario(scenario: ScenarioType) -> Result<Self, IngestError> {
        let json_data = match scenario {
            ScenarioType::NormalActivity => include_str!("../../../data/demo/normal.json"),
            ScenarioType::CredentialCompromise => include_str!("../../../data/demo/credential_compromise.json"),
            ScenarioType::IamPrivilegeEscalation => include_str!("../../../data/demo/iam_privilege_escalation.json"),
            ScenarioType::S3Exfiltration => include_str!("../../../data/demo/s3_exfiltration.json"),
            ScenarioType::CloudTrailTampering => include_str!("../../../data/demo/cloudtrail_tampering.json"),
            ScenarioType::FullMultiStageAttack => include_str!("../../../data/demo/full_attack_chain.json"),
        };

        let events = CloudTrailParser::parse_str(json_data)
            .map_err(|e| IngestError::Normalization(e.to_string()))?;

        Ok(Self { events, index: 0 })
    }
}

pub struct ScenarioGenerator;

impl ScenarioGenerator {
    pub fn generate_scenario_events(scenario: ScenarioType) -> Vec<CloudEvent> {
        let source = SyntheticSource::from_scenario(scenario).unwrap_or_else(|_| SyntheticSource {
            events: Vec::new(),
            index: 0,
        });
        source.events
    }
}

#[async_trait::async_trait]
impl EventSource for SyntheticSource {
    async fn next_event(&mut self) -> Result<Option<CloudEvent>, IngestError> {
        if self.index < self.events.len() {
            let ev = self.events[self.index].clone();
            self.index += 1;
            Ok(Some(ev))
        } else {
            Ok(None)
        }
    }
}
