use sentinel_core::{
    ApprovalDecision, CloudAsset, DriftType, GuardDutyFinding, ResponseMode, ResponseStatus,
    Severity, ThreatIntelResult, ThreatIntelStatus,
};
use sentinel_correlation::{CloudAssetInventory, DriftEngine, PostureEngine};
use sentinel_detection::DetectorRegistry;
use sentinel_ingest::{
    GuardDutyCollector, SimulatedThreatIntelProvider, ThreatIntelProvider, ThreatIntelService,
};
use sentinel_normalizer::GuardDutyNormalizer;
use sentinel_response::ResponseOrchestrator;
use sentinel_risk::RiskEngine;
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

#[test]
fn test_scenario_1_guardduty_normalization_and_deduplication() {
    let collector = GuardDutyCollector::new();
    let demos = GuardDutyCollector::generate_demo_findings();
    assert!(!demos.is_empty());

    let finding = &demos[0];
    assert!(collector.ingest_finding(finding), "First ingest should succeed");
    assert!(!collector.ingest_finding(finding), "Duplicate finding should be discarded");

    let event = GuardDutyNormalizer::normalize_finding(finding);
    assert_eq!(event.severity, Some(Severity::Critical));
    assert_eq!(event.actor.identity, "198.51.100.42");
    assert_eq!(event.resource.identifier, "AKIAIOSFODNN7EXAMPLE");
}

#[tokio::test]
async fn test_scenario_2_threat_intelligence_enrichment_and_risk_adjustment() {
    let service = ThreatIntelService::new(Arc::new(SimulatedThreatIntelProvider), 3600);
    let ip: IpAddr = "198.51.100.42".parse().unwrap();

    let res = service.enrich_ip(ip).await.expect("Lookup should succeed");
    assert!(res.is_some());
    let ti = res.unwrap();
    assert!(ti.malicious);
    assert_eq!(ti.reputation_score, Some(88.0));

    // Cached check
    let cached_res = service.enrich_ip(ip).await.expect("Second lookup should hit cache");
    assert_eq!(cached_res.unwrap().status, ThreatIntelStatus::Cached);

    // Calculate risk with threat intelligence context
    let detector = DetectorRegistry::new();
    let demo_gd = &GuardDutyCollector::generate_demo_findings()[0];
    let ev = GuardDutyNormalizer::normalize_finding(demo_gd);
    let findings = detector.evaluate_event(&ev);

    let risk_with_ti = RiskEngine::calculate_risk_with_context(&findings, Some(&ti), Some(2));
    assert!(risk_with_ti.total_score >= 20);
    assert!(risk_with_ti.factors.iter().any(|f| f.name.contains("Threat Intelligence")));
}

#[test]
fn test_scenario_3_cloud_posture_scoring_and_findings() {
    let inventory = CloudAssetInventory::new();
    let assets = inventory.list_assets();
    assert!(!assets.is_empty());

    let (findings, breakdown) = PostureEngine::evaluate_inventory(&assets);
    assert!(!findings.is_empty(), "Should identify MFA, SSH open, or admin findings");
    assert!(breakdown.overall_score > 0 && breakdown.overall_score <= 100);
    assert!(breakdown.critical_count > 0);
    assert!(breakdown.categories.contains_key("network"));
}

#[test]
fn test_scenario_4_terraform_iac_drift_detection() {
    let iac = DriftEngine::get_demo_iac_state();
    let inventory = CloudAssetInventory::new();
    let assets = inventory.list_assets();

    let drifts = DriftEngine::evaluate_drift(&iac, &assets);
    assert!(!drifts.is_empty(), "Should detect drifted security group or unexpected attacker user");
    assert!(drifts.iter().any(|d| d.drift_type == DriftType::SecurityRelevant));
}

#[test]
fn test_scenario_5_response_orchestration_simulation_dual_approval_and_audit_chain() {
    let orchestrator = ResponseOrchestrator::new(false); // Live mode disabled
    let actions = orchestrator.list_actions();
    assert!(!actions.is_empty());

    let action_id = actions[0].id;

    // 1. Run Dry-Run Simulation
    let sim_res = orchestrator.simulate_action(action_id, "soc-analyst-1").expect("Simulation should succeed");
    assert_eq!(sim_res.status, ResponseStatus::Simulated);
    assert!(sim_res.simulation_result.is_some());

    // 2. First Approval
    let app1 = orchestrator
        .add_approval(action_id, "sec-lead-alice", ApprovalDecision::Approved, "Approved containment")
        .expect("Approval 1 should succeed");
    assert_eq!(app1.status, ResponseStatus::PendingApproval, "Should still be pending 2nd approval");

    // Prevent duplicate approval by same identity
    let dup_res = orchestrator.add_approval(action_id, "sec-lead-alice", ApprovalDecision::Approved, "Dup");
    assert!(dup_res.is_err(), "Duplicate approval by same identity must be rejected");

    // 3. Second Independent Approval
    let app2 = orchestrator
        .add_approval(action_id, "ciso-bob", ApprovalDecision::Approved, "Dual approval confirmed")
        .expect("Approval 2 should succeed");
    assert_eq!(app2.status, ResponseStatus::Approved);

    // 4. Safe Simulation Execution
    let exec_res = orchestrator
        .execute_action(action_id, "sec-lead-alice", ResponseMode::Simulation)
        .expect("Simulation execution should succeed");
    assert_eq!(exec_res.status, ResponseStatus::Executed);

    // 5. Verify Cryptographic SHA-256 Audit Chain
    let audit_store = orchestrator.get_audit_store();
    let verify_res = audit_store.verify_integrity();
    assert!(verify_res.valid, "Immutable audit log chain must be valid and intact");
    assert!(verify_res.records_checked >= 4, "Should verify genesis + sim + approvals + execution records");
}
