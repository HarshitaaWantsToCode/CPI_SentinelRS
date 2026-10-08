use sentinel_correlation::CorrelationEngine;
use sentinel_detection::DetectorRegistry;
use sentinel_ingest::{ScenarioGenerator, ScenarioType};
use sentinel_risk::RiskEngine;

#[tokio::test]
async fn test_full_kill_chain_detection_and_correlation() {
    let detector = DetectorRegistry::new();
    let correlation = CorrelationEngine::new();

    let events = ScenarioGenerator::generate_scenario_events(ScenarioType::FullMultiStageAttack);
    assert!(events.len() >= 6, "Full attack scenario must contain at least 6 events");

    let mut total_findings = Vec::new();

    for ev in &events {
        let findings = detector.evaluate_event(ev);
        for finding in findings {
            total_findings.push(finding.clone());
            correlation.process_finding(ev, &finding);
        }
    }

    assert!(total_findings.len() >= 4, "Should trigger multiple high-fidelity detection rules");

    let incidents = correlation.get_active_incidents();
    assert_eq!(incidents.len(), 1, "Should correlate multiple steps into one unified incident");

    let inc = &incidents[0];
    assert_eq!(inc.id, "SR-1042");
    assert!(inc.risk_score >= 80, "Incident risk score must be critical (>80)");
    assert_eq!(inc.stages.len(), total_findings.len());

    let risk_breakdown = RiskEngine::calculate_risk_for_findings(&total_findings);
    assert_eq!(risk_breakdown.total_score, inc.risk_score);
    assert!(!risk_breakdown.factors.is_empty(), "Risk breakdown must contain explainable factors");
}
