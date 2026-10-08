use sentinel_core::{DetectionFinding, RiskFactor, RiskScoreBreakdown, Severity, ThreatIntelResult};

pub struct RiskEngine;

impl RiskEngine {
    pub fn calculate_risk_for_findings(findings: &[DetectionFinding]) -> RiskScoreBreakdown {
        Self::calculate_risk_with_context(findings, None, None)
    }

    pub fn calculate_risk_with_context(
        findings: &[DetectionFinding],
        threat_intel: Option<&ThreatIntelResult>,
        posture_findings_count: Option<usize>,
    ) -> RiskScoreBreakdown {
        let mut breakdown = RiskScoreBreakdown::new(0);

        if findings.is_empty() && threat_intel.is_none() {
            return breakdown;
        }

        // 1. Base Severity from Highest Finding
        let max_sev_score = findings
            .iter()
            .map(|f| match f.severity {
                Severity::Critical => 35,
                Severity::High => 25,
                Severity::Medium => 15,
                Severity::Low => 5,
                Severity::Informational => 0,
            })
            .max()
            .unwrap_or(0);

        breakdown.base_severity = max_sev_score;
        if max_sev_score > 0 {
            breakdown.factors.push(RiskFactor {
                name: "Highest Finding Severity".into(),
                description: format!("Baseline contribution from highest severity finding (+{})", max_sev_score),
                score_delta: max_sev_score as i16,
            });
        }

        // 2. Behavioral Anomaly
        let has_behavioral = findings.iter().any(|f| f.detector_id.starts_with("BEHAVIOR") || f.technique_id == "T1078.004");
        if has_behavioral {
            breakdown.behavioral_anomaly = 18;
            breakdown.factors.push(RiskFactor {
                name: "Identity / Behavioral Anomaly".into(),
                description: "Anomalous origin IP or non-standard authentication parameters (+18)".into(),
                score_delta: 18,
            });
        }

        // 3. Asset Criticality (S3 PII or Admin IAM)
        let has_sensitive_asset = findings.iter().any(|f| f.detector_id.starts_with("S3") || f.detector_id == "IAM-001");
        if has_sensitive_asset {
            breakdown.asset_criticality = 20;
            breakdown.factors.push(RiskFactor {
                name: "Sensitive Cloud Asset Targeted".into(),
                description: "Critical infrastructure, IAM admin policy, or confidential S3 storage accessed (+20)".into(),
                score_delta: 20,
            });
        }

        // 4. Attack Chain Progression
        let chain_len = findings.len() as u8;
        let chain_points = (chain_len * 4).min(18);
        breakdown.attack_chain_progression = chain_points;
        if chain_points > 0 {
            breakdown.factors.push(RiskFactor {
                name: "Attack Chain Progression".into(),
                description: format!("{} correlated multi-stage detection findings (+{})", chain_len, chain_points),
                score_delta: chain_points as i16,
            });
        }

        // 5. Defense Evasion / Tampering
        let has_evasion = findings.iter().any(|f| f.detector_id.starts_with("CT") || f.tactic == "Defense Evasion");
        if has_evasion {
            breakdown.threat_context = 15;
            breakdown.factors.push(RiskFactor {
                name: "Defense Evasion / CloudTrail Tampering".into(),
                description: "Adversary attempted to silence or delete logging infrastructure (+15)".into(),
                score_delta: 15,
            });
        }

        // 6. Threat Intelligence Reputation (Phase 5B)
        let mut threat_intel_delta: u8 = 0;
        if let Some(ti) = threat_intel {
            if ti.malicious {
                let score = ti.reputation_score.unwrap_or(80.0);
                threat_intel_delta = if score >= 80.0 {
                    20
                } else if score >= 50.0 {
                    15
                } else {
                    10
                };

                breakdown.factors.push(RiskFactor {
                    name: "Threat Intelligence IP Reputation".into(),
                    description: format!(
                        "Origin IP {} identified as malicious by {} (Reputation: {:.0}, Categories: {}) (+{})",
                        ti.ip,
                        ti.source,
                        score,
                        ti.categories.join(", "),
                        threat_intel_delta
                    ),
                    score_delta: threat_intel_delta as i16,
                });
            }
        }

        // 7. Posture Misconfiguration Context (Phase 5C)
        let mut posture_delta: u8 = 0;
        if let Some(count) = posture_findings_count {
            if count > 0 {
                posture_delta = (count * 5).min(15) as u8;
                breakdown.factors.push(RiskFactor {
                    name: "Cloud Security Posture Deficiencies".into(),
                    description: format!(
                        "Targeted asset has {} active CSPM posture misconfigurations (+{})",
                        count, posture_delta
                    ),
                    score_delta: posture_delta as i16,
                });
            }
        }

        let total = (breakdown.base_severity as u16
            + breakdown.behavioral_anomaly as u16
            + breakdown.asset_criticality as u16
            + breakdown.attack_chain_progression as u16
            + breakdown.threat_context as u16
            + threat_intel_delta as u16
            + posture_delta as u16)
            .min(100) as u8;

        breakdown.total_score = total;
        breakdown
    }
}
