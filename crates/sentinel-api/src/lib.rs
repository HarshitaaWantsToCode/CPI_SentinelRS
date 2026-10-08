use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use sentinel_core::{
    ApprovalDecision, DetectionFinding, DriftFinding,
    GuardDutyFinding, Incident, IncidentStatus, PostureFinding, ResponseAction, ResponseMode,
    ThreatIntelResult,
};
use sentinel_correlation::{
    AttackGraphBuilder, CloudAssetInventory, CorrelationEngine, DeepAttackGraph, DriftEngine,
    PathQueryRequest, PostureEngine,
};
use sentinel_detection::DetectorRegistry;
use sentinel_ingest::{
    AwsCloudTrailCollector, EventBus, GuardDutyCollector, ScenarioGenerator, ScenarioType,
    ThreatIntelService,
};
use sentinel_mitre::MitreMapper;
use sentinel_normalizer::GuardDutyNormalizer;
use sentinel_response::ResponseOrchestrator;
use sentinel_risk::RiskEngine;
use sentinel_storage::{EventFilterQuery, EventStore};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub store: EventStore,
    pub detector: Arc<DetectorRegistry>,
    pub correlation: Arc<CorrelationEngine>,
    pub orchestrator: Arc<ResponseOrchestrator>,
    pub inventory: Arc<CloudAssetInventory>,
    pub attack_graph: Arc<parking_lot::RwLock<DeepAttackGraph>>,
    pub aws_collector: Arc<AwsCloudTrailCollector>,
    pub guardduty_collector: Arc<GuardDutyCollector>,
    pub threat_intel: Arc<ThreatIntelService>,
    pub findings_store: Arc<DashMap<Uuid, DetectionFinding>>,
    pub event_bus: EventBus,
}

#[derive(Serialize)]
#[serde(tag = "type", content = "payload")]
pub enum WebSocketBroadcastMessage {
    #[serde(rename = "EVENT_RECEIVED")]
    EventReceived(sentinel_core::CloudEvent),
    #[serde(rename = "DETECTION_TRIGGERED")]
    DetectionTriggered(DetectionFinding),
    #[serde(rename = "INCIDENT_UPDATED")]
    IncidentUpdated(Incident),
    #[serde(rename = "GUARDDUTY_FINDING")]
    GuardDutyFinding(GuardDutyFinding),
    #[serde(rename = "THREAT_INTEL_ENRICHED")]
    ThreatIntelEnriched(ThreatIntelResult),
    #[serde(rename = "POSTURE_FINDING")]
    PostureFinding(PostureFinding),
    #[serde(rename = "DRIFT_DETECTED")]
    DriftDetected(DriftFinding),
    #[serde(rename = "RESPONSE_ACTION_UPDATED")]
    ResponseActionUpdated(ResponseAction),
}

#[derive(Serialize)]
pub struct AwsStatusResponse {
    pub connected: bool,
    pub mode: &'static str,
    pub account_id: &'static str,
    pub region: &'static str,
    pub identity: &'static str,
    pub cloudtrail_collector: &'static str,
    pub guardduty_collector: &'static str,
    pub threat_intel_provider: &'static str,
    pub live_response_enabled: bool,
}

#[derive(Deserialize)]
pub struct SimulateRequest {
    pub scenario: String,
}

#[derive(Deserialize)]
pub struct StatusUpdateRequest {
    pub status: IncidentStatus,
}

#[derive(Deserialize, Serialize)]
pub struct FalsePositiveFeedbackRequest {
    pub analyst: String,
    pub reason: String,
}

#[derive(Deserialize)]
pub struct ApprovalRequest {
    pub approver_id: String,
    pub decision: ApprovalDecision,
    pub reason: String,
}

#[derive(Deserialize)]
pub struct ExecuteActionRequest {
    pub executor: String,
    pub mode: ResponseMode,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/aws/status", get(aws_status_handler))
        .route("/api/assets", get(list_assets_handler))
        .route("/api/graph/path", post(query_attack_path_handler))
        .route("/api/events", get(list_events_handler))
        .route("/api/events/:id", get(get_event_handler))
        .route("/api/detections", get(list_detections_handler))
        .route("/api/incidents", get(list_incidents_handler))
        .route("/api/incidents/:id", get(get_incident_handler))
        .route("/api/incidents/:id/evidence", get(get_incident_evidence_handler))
        .route("/api/incidents/:id/status", post(update_incident_status_handler))
        .route("/api/incidents/:id/false-positive", post(false_positive_feedback_handler))
        .route("/api/incidents/:id/graph", get(incident_graph_handler))
        .route("/api/graph", get(attack_graph_handler))
        .route("/api/mitre", get(mitre_handler))
        
        // Phase 5A: GuardDuty Endpoints
        .route("/api/aws/guardduty/findings", get(list_guardduty_findings_handler))
        .route("/api/aws/guardduty/findings/:id", get(get_guardduty_finding_handler))
        .route("/api/aws/guardduty/ingest-demo", post(ingest_demo_guardduty_handler))

        // Phase 5B: Threat Intelligence Endpoints
        .route("/api/threat-intel/lookup/:ip", get(lookup_threat_intel_handler))
        .route("/api/threat-intel/cache", get(list_threat_intel_cache_handler))

        // Phase 5C & 5D: Posture & Drift Endpoints
        .route("/api/posture", get(posture_handler))
        .route("/api/posture/scan", post(scan_posture_handler))
        .route("/api/drift/findings", get(list_drift_findings_handler))
        .route("/api/drift/evaluate", post(evaluate_drift_handler))

        // Phase 5E - 5H: Response Lifecycle Endpoints
        .route("/api/responses", get(list_responses_handler))
        .route("/api/responses/:id/simulate", post(simulate_response_handler))
        .route("/api/responses/:id/approve", post(approve_response_handler))
        .route("/api/responses/:id/execute", post(execute_response_handler))

        // Phase 5I: Immutable Audit Log Endpoints
        .route("/api/audit/response", get(list_audit_records_handler))
        .route("/api/audit/response/verify", get(verify_audit_chain_handler))

        .route("/api/simulate", post(simulate_scenario_handler))
        .route("/ws/events", get(ws_events_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let total_events = state.store.count_events();
    let active_incidents = state.correlation.get_active_incidents().len();
    let total_detections = state.findings_store.len();
    let total_gd = state.store.list_guardduty_findings().len();

    Json(serde_json::json!({
        "status": "healthy",
        "version": "0.5.0",
        "engine": "SentinelRS-Rust-Unified-Detection-Response-Engine",
        "timestamp": chrono::Utc::now(),
        "total_events": total_events,
        "active_incidents": active_incidents,
        "total_detections": total_detections,
        "guardduty_findings": total_gd,
        "threat_intel_cache": state.threat_intel.cache_size(),
        "cloud_mode": "Phase 5 Autonomous Response & Threat Intel Ready"
    }))
}

async fn aws_status_handler() -> impl IntoResponse {
    let has_aws_env = std::env::var("AWS_ACCESS_KEY_ID").is_ok() || std::env::var("AWS_PROFILE").is_ok();
    let live_resp = std::env::var("SENTINEL_LIVE_RESPONSE_ENABLED").map(|v| v == "true").unwrap_or(false);

    if has_aws_env {
        Json(AwsStatusResponse {
            connected: true,
            mode: "AWS_LIVE_READONLY",
            account_id: "123456789012",
            region: "ap-south-1",
            identity: "sentinelrs-readonly",
            cloudtrail_collector: "ACTIVE_POLLING",
            guardduty_collector: "ACTIVE_POLLING",
            threat_intel_provider: "Live HTTP Provider Ready",
            live_response_enabled: live_resp,
        })
    } else {
        Json(AwsStatusResponse {
            connected: false,
            mode: "DEMO_SYNTHETIC_MODE",
            account_id: "123456789012",
            region: "ap-south-1",
            identity: "demo-simulator",
            cloudtrail_collector: "DEMO_REPLAY",
            guardduty_collector: "DEMO_SYNTHETIC",
            threat_intel_provider: "Simulated Threat Intel Feed",
            live_response_enabled: false,
        })
    }
}

async fn list_assets_handler(State(state): State<AppState>) -> impl IntoResponse {
    let assets = state.inventory.list_assets();
    Json(assets)
}

async fn query_attack_path_handler(
    State(state): State<AppState>,
    Json(payload): Json<PathQueryRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let graph = state.attack_graph.read();
    if let Some(path_result) = graph.find_shortest_attack_path(&payload.source, &payload.target, payload.max_depth) {
        Ok(Json(path_result))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn list_events_handler(
    State(state): State<AppState>,
    Query(filter): Query<EventFilterQuery>,
) -> impl IntoResponse {
    let events = state.store.list_events_filtered(&filter);
    Json(events)
}

async fn get_event_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Some(event) = state.store.get_event(&id) {
        Ok(Json(event))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn list_detections_handler(State(state): State<AppState>) -> impl IntoResponse {
    let findings: Vec<DetectionFinding> = state.findings_store.iter().map(|e| e.value().clone()).collect();
    Json(findings)
}

async fn list_incidents_handler(State(state): State<AppState>) -> impl IntoResponse {
    let incidents = state.correlation.get_active_incidents();
    Json(incidents)
}

async fn get_incident_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Some(inc) = state.correlation.get_incident(&id) {
        Ok(Json(inc))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn get_incident_evidence_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Some(inc) = state.correlation.get_incident(&id) {
        let findings: Vec<DetectionFinding> = state.findings_store.iter().map(|e| e.value().clone()).collect();
        let attacker_ip: Option<IpAddr> = "198.51.100.42".parse().ok();
        let threat_intel_res = match attacker_ip {
            Some(ip) => state.threat_intel.enrich_ip(ip).await.ok().flatten(),
            None => None,
        };

        let posture_count = state.store.get_posture_findings().len();
        let risk_breakdown = RiskEngine::calculate_risk_with_context(
            &findings,
            threat_intel_res.as_ref(),
            Some(posture_count),
        );

        Ok(Json(serde_json::json!({
            "incident_id": inc.id,
            "title": inc.title,
            "risk_score": inc.risk_score,
            "risk_decomposition": risk_breakdown,
            "threat_intelligence": threat_intel_res,
            "stages": inc.stages,
            "findings": findings
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn update_incident_status_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<StatusUpdateRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Some(inc) = state.correlation.update_incident_status(&id, payload.status) {
        Ok(Json(inc))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn false_positive_feedback_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<FalsePositiveFeedbackRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Some(inc) = state.correlation.update_incident_status(&id, IncidentStatus::Dismissed) {
        Ok(Json(serde_json::json!({
            "status": "marked_false_positive",
            "incident": inc,
            "feedback": payload
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn ws_events_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_event_socket(socket, state))
}

async fn handle_event_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.event_bus.subscribe();

    tokio::spawn(async move {
        while let Some(Ok(_)) = receiver.next().await {}
    });

    while let Ok(event) = rx.recv().await {
        let msg = WebSocketBroadcastMessage::EventReceived(event);
        if let Ok(json_str) = serde_json::to_string(&msg) {
            if sender.send(Message::Text(json_str)).await.is_err() {
                break;
            }
        }
    }
}

async fn attack_graph_handler() -> impl IntoResponse {
    let graph = AttackGraphBuilder::get_demo_attack_graph();
    Json(graph)
}

async fn incident_graph_handler(Path(_id): Path<String>) -> impl IntoResponse {
    let graph = AttackGraphBuilder::get_demo_attack_graph();
    Json(graph)
}

async fn mitre_handler() -> impl IntoResponse {
    let matrix = MitreMapper::get_matrix_data();
    Json(matrix)
}

// -------------------------------------------------------------------
// Phase 5A Handlers: GuardDuty
// -------------------------------------------------------------------
async fn list_guardduty_findings_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut findings = state.store.list_guardduty_findings();
    if findings.is_empty() {
        // Seed demo findings if empty
        let demos = GuardDutyCollector::generate_demo_findings();
        for d in demos {
            state.store.insert_guardduty_finding(d);
        }
        findings = state.store.list_guardduty_findings();
    }
    Json(findings)
}

async fn get_guardduty_finding_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Some(f) = state.store.get_guardduty_finding(&id) {
        Ok(Json(f))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn ingest_demo_guardduty_handler(State(state): State<AppState>) -> impl IntoResponse {
    let demos = GuardDutyCollector::generate_demo_findings();
    let mut ingested = 0;
    for finding in demos {
        if state.guardduty_collector.ingest_finding(&finding) {
            state.store.insert_guardduty_finding(finding.clone());
            // Normalize finding into canonical CloudEvent
            let event = GuardDutyNormalizer::normalize_finding(&finding);
            state.store.insert_event(event.clone());
            let _ = state.event_bus.publish(event);
            ingested += 1;
        }
    }
    Json(serde_json::json!({
        "status": "success",
        "findings_ingested": ingested,
        "message": "GuardDuty findings ingested, normalized, and dispatched to detection pipeline."
    }))
}

// -------------------------------------------------------------------
// Phase 5B Handlers: Threat Intelligence
// -------------------------------------------------------------------
async fn lookup_threat_intel_handler(
    State(state): State<AppState>,
    Path(ip_str): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        match state.threat_intel.enrich_ip(ip).await {
            Ok(Some(res)) => Ok(Json(res)),
            Ok(None) => Err(StatusCode::NOT_FOUND),
            Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

async fn list_threat_intel_cache_handler(State(state): State<AppState>) -> impl IntoResponse {
    let indicators = state.threat_intel.list_cached_indicators();
    Json(indicators)
}

// -------------------------------------------------------------------
// Phase 5C & 5D Handlers: Posture & Drift
// -------------------------------------------------------------------
async fn posture_handler(State(state): State<AppState>) -> impl IntoResponse {
    let assets = state.inventory.list_assets();
    let (findings, score_breakdown) = PostureEngine::evaluate_inventory(&assets);

    Json(serde_json::json!({
        "overall_score": score_breakdown.overall_score,
        "categories": score_breakdown.categories,
        "total_findings": score_breakdown.total_findings,
        "critical_count": score_breakdown.critical_count,
        "high_count": score_breakdown.high_count,
        "medium_count": score_breakdown.medium_count,
        "low_count": score_breakdown.low_count,
        "findings": findings
    }))
}

async fn scan_posture_handler(State(state): State<AppState>) -> impl IntoResponse {
    let assets = state.inventory.list_assets();
    let (findings, score) = PostureEngine::evaluate_inventory(&assets);
    state.store.set_posture_findings(findings.clone());

    Json(serde_json::json!({
        "status": "scan_completed",
        "assets_scanned": assets.len(),
        "findings_detected": findings.len(),
        "overall_posture_score": score.overall_score
    }))
}

async fn list_drift_findings_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut drifts = state.store.get_drift_findings();
    if drifts.is_empty() {
        let iac = DriftEngine::get_demo_iac_state();
        let assets = state.inventory.list_assets();
        drifts = DriftEngine::evaluate_drift(&iac, &assets);
        state.store.set_drift_findings(drifts.clone());
    }
    Json(drifts)
}

async fn evaluate_drift_handler(State(state): State<AppState>) -> impl IntoResponse {
    let iac = DriftEngine::get_demo_iac_state();
    let assets = state.inventory.list_assets();
    let drifts = DriftEngine::evaluate_drift(&iac, &assets);
    state.store.set_drift_findings(drifts.clone());

    Json(serde_json::json!({
        "status": "drift_evaluation_completed",
        "resources_compared": iac.resources.len(),
        "drift_findings_count": drifts.len(),
        "drift_findings": drifts
    }))
}

// -------------------------------------------------------------------
// Phase 5E - 5H Handlers: Response Lifecycle
// -------------------------------------------------------------------
async fn list_responses_handler(State(state): State<AppState>) -> impl IntoResponse {
    let actions = state.orchestrator.list_actions();
    Json(actions)
}

async fn simulate_response_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    match state.orchestrator.simulate_action(id, "soc-analyst-simulation") {
        Ok(action) => Ok(Json(action)),
        Err(err) => Err((StatusCode::BAD_REQUEST, err)),
    }
}

async fn approve_response_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<ApprovalRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    match state.orchestrator.add_approval(id, &payload.approver_id, payload.decision, &payload.reason) {
        Ok(action) => Ok(Json(action)),
        Err(err) => Err((StatusCode::BAD_REQUEST, err)),
    }
}

async fn execute_response_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<ExecuteActionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    match state.orchestrator.execute_action(id, &payload.executor, payload.mode) {
        Ok(action) => Ok(Json(action)),
        Err(err) => Err((StatusCode::FORBIDDEN, err)),
    }
}

// -------------------------------------------------------------------
// Phase 5I Handlers: Immutable Audit Log
// -------------------------------------------------------------------
async fn list_audit_records_handler(State(state): State<AppState>) -> impl IntoResponse {
    let records = state.orchestrator.get_audit_store().list_records();
    Json(records)
}

async fn verify_audit_chain_handler(State(state): State<AppState>) -> impl IntoResponse {
    let result = state.orchestrator.get_audit_store().verify_integrity();
    Json(result)
}

async fn simulate_scenario_handler(
    State(state): State<AppState>,
    Json(payload): Json<SimulateRequest>,
) -> impl IntoResponse {
    let scenario_type = match payload.scenario.as_str() {
        "full_attack" | "Full Multi-Stage Attack" => ScenarioType::FullMultiStageAttack,
        "credential_compromise" => ScenarioType::CredentialCompromise,
        "privilege_escalation" => ScenarioType::IamPrivilegeEscalation,
        "s3_exfiltration" => ScenarioType::S3Exfiltration,
        "cloudtrail_tampering" => ScenarioType::CloudTrailTampering,
        _ => ScenarioType::NormalActivity,
    };

    let events = ScenarioGenerator::generate_scenario_events(scenario_type);
    let mut detections_triggered = 0;
    let mut last_incident = None;

    for event in &events {
        state.store.insert_event(event.clone());
        let _ = state.event_bus.publish(event.clone());

        let findings = state.detector.evaluate_event(event);
        for finding in findings {
            detections_triggered += 1;
            state.findings_store.insert(finding.id, finding.clone());
            let (_chain, inc_opt) = state.correlation.process_finding(event, &finding);
            if inc_opt.is_some() {
                last_incident = inc_opt;
            }
        }
    }

    Json(serde_json::json!({
        "status": "success",
        "scenario": payload.scenario,
        "events_injected": events.len(),
        "detections_triggered": detections_triggered,
        "incident_created": last_incident.is_some(),
        "incident": last_incident,
        "message": "Scenario evaluated through detection rules and correlated into attack sequence."
    }))
}
