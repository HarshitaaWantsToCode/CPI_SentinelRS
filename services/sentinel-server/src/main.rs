use dashmap::DashMap;
use sentinel_api::{create_router, AppState};
use sentinel_correlation::{CloudAssetInventory, CorrelationEngine, DeepAttackGraph};
use sentinel_detection::DetectorRegistry;
use sentinel_ingest::{
    AwsCloudTrailCollector, EventBus, GuardDutyCollector, ScenarioGenerator, ScenarioType,
    SimulatedThreatIntelProvider, ThreatIntelService,
};
use sentinel_normalizer::GuardDutyNormalizer;
use sentinel_response::ResponseOrchestrator;
use sentinel_storage::EventStore;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!("🛡️ Starting SentinelRS Threat Intelligence, Cloud Posture & Safe Response Platform (Phase 5)...");

    let live_response_enabled = std::env::var("SENTINEL_LIVE_RESPONSE_ENABLED")
        .map(|v| v == "true")
        .unwrap_or(false);

    let store = EventStore::new();
    let detector = Arc::new(DetectorRegistry::new());
    let correlation = Arc::new(CorrelationEngine::new());
    let orchestrator = Arc::new(ResponseOrchestrator::new(live_response_enabled));
    let inventory = Arc::new(CloudAssetInventory::new());
    let attack_graph = Arc::new(parking_lot::RwLock::new(DeepAttackGraph::new()));
    let aws_collector = Arc::new(AwsCloudTrailCollector::new(10));
    let guardduty_collector = Arc::new(GuardDutyCollector::new());
    let threat_intel = Arc::new(ThreatIntelService::new(Arc::new(SimulatedThreatIntelProvider), 3600));
    let findings_store = Arc::new(DashMap::new());
    let event_bus = EventBus::new(4096);

    // 1. Bootstrap with GuardDuty findings
    let gd_demos = GuardDutyCollector::generate_demo_findings();
    for gd in &gd_demos {
        store.insert_guardduty_finding(gd.clone());
        let gd_event = GuardDutyNormalizer::normalize_finding(gd);
        store.insert_event(gd_event.clone());
        let _ = event_bus.publish(gd_event);
    }

    // 2. Bootstrap with Full Attack Chain demo telemetry
    let initial_events = ScenarioGenerator::generate_scenario_events(ScenarioType::FullMultiStageAttack);
    for event in &initial_events {
        store.insert_event(event.clone());
        let _ = event_bus.publish(event.clone());
        let findings = detector.evaluate_event(event);
        for finding in findings {
            findings_store.insert(finding.id, finding.clone());
            correlation.process_finding(event, &finding);
        }
    }

    let state = AppState {
        store,
        detector,
        correlation,
        orchestrator,
        inventory,
        attack_graph,
        aws_collector,
        guardduty_collector,
        threat_intel,
        findings_store,
        event_bus,
    };

    let app = create_router(state);
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into()).parse::<u16>()?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!("🚀 SentinelRS API & WebSocket Server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
