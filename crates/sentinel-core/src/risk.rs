use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub name: String,
    pub description: String,
    pub score_delta: i16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoreBreakdown {
    pub total_score: u8,
    pub base_severity: u8,
    pub behavioral_anomaly: u8,
    pub asset_criticality: u8,
    pub attack_chain_progression: u8,
    pub mitre_impact: u8,
    pub threat_context: u8,
    pub factors: Vec<RiskFactor>,
}

impl RiskScoreBreakdown {
    pub fn new(total_score: u8) -> Self {
        Self {
            total_score,
            base_severity: 0,
            behavioral_anomaly: 0,
            asset_criticality: 0,
            attack_chain_progression: 0,
            mitre_impact: 0,
            threat_context: 0,
            factors: Vec::new(),
        }
    }
}
