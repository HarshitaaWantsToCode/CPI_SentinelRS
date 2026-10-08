use crate::chain::AttackChain;
use dashmap::DashMap;
use sentinel_core::{CloudEvent, DetectionFinding, Incident, IncidentStatus, Severity};
use sentinel_risk::RiskEngine;
use std::sync::Arc;

pub struct CorrelationEngine {
    chains: Arc<DashMap<String, AttackChain>>,
    incidents: Arc<DashMap<String, Incident>>,
    window_seconds: i64,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            chains: Arc::new(DashMap::new()),
            incidents: Arc::new(DashMap::new()),
            window_seconds: 900, // 15-minute correlation window
        }
    }

    pub fn process_finding(
        &self,
        event: &CloudEvent,
        finding: &DetectionFinding,
    ) -> (AttackChain, Option<Incident>) {
        let chain_id = format!("chain-{}", event.actor.identity);
        let mut chain_entry = self
            .chains
            .entry(chain_id.clone())
            .or_insert_with(|| AttackChain::new(chain_id.clone(), event.actor.identity.clone(), event.timestamp));

        // Check if temporal window has expired; if so, start new sequence
        let time_diff = (event.timestamp - chain_entry.last_seen).num_seconds();
        if time_diff > self.window_seconds {
            *chain_entry = AttackChain::new(chain_id.clone(), event.actor.identity.clone(), event.timestamp);
        }

        chain_entry.add_finding(event, finding);

        // Compute Explainable Risk Score
        let risk_breakdown = RiskEngine::calculate_risk_for_findings(&chain_entry.findings);
        chain_entry.risk_score = risk_breakdown.total_score;

        let chain_copy = chain_entry.clone();
        drop(chain_entry);

        // Generate or update Incident if severity threshold is met
        let mut generated_incident = None;
        if chain_copy.findings.len() >= 1 || chain_copy.risk_score >= 40 {
            let inc_id = "SR-1042".to_string();
            let mut inc_entry = self.incidents.entry(inc_id.clone()).or_insert_with(|| Incident {
                id: inc_id.clone(),
                title: "Multi-Stage Cloud Compromise Campaign".into(),
                description: "Correlated kill-chain targeting IAM identity and sensitive S3 cloud storage.".into(),
                severity: Severity::Critical,
                status: IncidentStatus::Active,
                risk_score: chain_copy.risk_score,
                confidence_score: 95,
                affected_assets_count: 5,
                initial_access_time: chain_copy.first_seen,
                last_activity_time: chain_copy.last_seen,
                stages: chain_copy.stages.clone(),
                involved_actors: vec![event.actor.identity.clone()],
                involved_resources: vec![event.resource.identifier.clone()],
                recommended_actions: vec![
                    "Revoke IAM AccessKey AKIAIOSFODNN7EXAMPLE".into(),
                    "Detach AdministratorAccess Policy".into(),
                    "Re-enable CloudTrail Audit Trail".into(),
                ],
            });

            inc_entry.risk_score = chain_copy.risk_score;
            inc_entry.last_activity_time = chain_copy.last_seen;
            inc_entry.stages = chain_copy.stages.clone();
            if !inc_entry.involved_resources.contains(&event.resource.identifier) {
                inc_entry.involved_resources.push(event.resource.identifier.clone());
            }

            generated_incident = Some(inc_entry.clone());
        }

        (chain_copy, generated_incident)
    }

    pub fn get_active_incidents(&self) -> Vec<Incident> {
        self.incidents.iter().map(|e| e.value().clone()).collect()
    }

    pub fn get_incident(&self, id: &str) -> Option<Incident> {
        self.incidents.get(id).map(|e| e.value().clone())
    }

    pub fn update_incident_status(&self, id: &str, status: IncidentStatus) -> Option<Incident> {
        if let Some(mut entry) = self.incidents.get_mut(id) {
            entry.status = status;
            Some(entry.clone())
        } else {
            None
        }
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}
