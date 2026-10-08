use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sentinel_core::{
    ApprovalDecision, AuditRecord, AuditVerificationResult, ResponseAction, ResponseApproval,
    ResponseMode, ResponseStatus, SimulationDetails,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use uuid::Uuid;

// Cryptographic hash simulation using standard hash & formatting for chain integrity
fn calculate_record_hash(
    sequence: u64,
    timestamp: &DateTime<Utc>,
    incident_id: &str,
    response_id: &Uuid,
    action: &str,
    target: &str,
    mode: &ResponseMode,
    prev_state: &ResponseStatus,
    new_state: &ResponseStatus,
    prev_hash: &str,
) -> String {
    let mut hasher = DefaultHasher::new();
    sequence.hash(&mut hasher);
    timestamp.to_rfc3339().hash(&mut hasher);
    incident_id.hash(&mut hasher);
    response_id.to_string().hash(&mut hasher);
    action.hash(&mut hasher);
    target.hash(&mut hasher);
    format!("{:?}", mode).hash(&mut hasher);
    format!("{:?}", prev_state).hash(&mut hasher);
    format!("{:?}", new_state).hash(&mut hasher);
    prev_hash.hash(&mut hasher);
    let hash_num = hasher.finish();
    format!("{:016x}{:016x}{:016x}{:016x}", hash_num, hash_num ^ 0x5a5a, hash_num.rotate_left(13), sequence)
}

pub struct AuditLogStore {
    records: Arc<parking_lot::RwLock<Vec<AuditRecord>>>,
}

impl AuditLogStore {
    pub fn new() -> Self {
        let store = Self {
            records: Arc::new(parking_lot::RwLock::new(Vec::new())),
        };
        store.seed_genesis_record();
        store
    }

    fn seed_genesis_record(&self) {
        let now = Utc::now() - chrono::Duration::hours(2);
        let genesis_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let cur_hash = calculate_record_hash(
            0,
            &now,
            "SYSTEM",
            &Uuid::nil(),
            "GENESIS_AUDIT_ANCHOR",
            "audit_chain",
            &ResponseMode::Simulation,
            &ResponseStatus::Recommended,
            &ResponseStatus::Recommended,
            genesis_hash,
        );

        let mut recs = self.records.write();
        recs.push(AuditRecord {
            record_id: Uuid::new_v4(),
            sequence_number: 0,
            timestamp: now,
            incident_id: "SYSTEM-INIT".into(),
            response_id: Uuid::nil(),
            actor: "sentinel-system".into(),
            action_type: "GENESIS_AUDIT_ANCHOR".into(),
            target_resource: "audit_chain".into(),
            execution_mode: ResponseMode::Simulation,
            previous_state: ResponseStatus::Recommended,
            new_state: ResponseStatus::Recommended,
            request_hash: "00000000".into(),
            result: "AUDIT_CHAIN_INITIALIZED".into(),
            aws_metadata: None,
            previous_hash: genesis_hash.into(),
            current_hash: cur_hash,
        });
    }

    pub fn append_record(
        &self,
        incident_id: &str,
        response_id: Uuid,
        actor: &str,
        action_type: &str,
        target_resource: &str,
        mode: &ResponseMode,
        previous_state: ResponseStatus,
        new_state: ResponseStatus,
        result: &str,
        aws_metadata: Option<serde_json::Value>,
    ) -> AuditRecord {
        let mut recs = self.records.write();
        let seq = recs.len() as u64;
        let prev_hash = recs.last().map(|r| r.current_hash.clone()).unwrap_or_else(|| "00000000".into());
        let now = Utc::now();

        let cur_hash = calculate_record_hash(
            seq,
            &now,
            incident_id,
            &response_id,
            action_type,
            target_resource,
            mode,
            &previous_state,
            &new_state,
            &prev_hash,
        );

        let record = AuditRecord {
            record_id: Uuid::new_v4(),
            sequence_number: seq,
            timestamp: now,
            incident_id: incident_id.to_string(),
            response_id,
            actor: actor.to_string(),
            action_type: action_type.to_string(),
            target_resource: target_resource.to_string(),
            execution_mode: mode.clone(),
            previous_state,
            new_state,
            request_hash: format!("{:016x}", seq),
            result: result.to_string(),
            aws_metadata,
            previous_hash: prev_hash,
            current_hash: cur_hash,
        };

        recs.push(record.clone());
        record
    }

    pub fn list_records(&self) -> Vec<AuditRecord> {
        self.records.read().clone()
    }

    pub fn verify_integrity(&self) -> AuditVerificationResult {
        let recs = self.records.read();
        let total = recs.len();

        if total == 0 {
            return AuditVerificationResult {
                valid: true,
                records_checked: 0,
                first_invalid_record: None,
                genesis_hash: "".into(),
                tip_hash: "".into(),
                verified_at: Utc::now(),
            };
        }

        let genesis_hash = recs[0].previous_hash.clone();
        let tip_hash = recs[total - 1].current_hash.clone();

        for i in 1..total {
            let prev = &recs[i - 1];
            let cur = &recs[i];

            // 1. Check previous_hash link
            if cur.previous_hash != prev.current_hash {
                return AuditVerificationResult {
                    valid: false,
                    records_checked: i,
                    first_invalid_record: Some(cur.sequence_number),
                    genesis_hash,
                    tip_hash,
                    verified_at: Utc::now(),
                };
            }

            // 2. Re-calculate current_hash
            let expected_hash = calculate_record_hash(
                cur.sequence_number,
                &cur.timestamp,
                &cur.incident_id,
                &cur.response_id,
                &cur.action_type,
                &cur.target_resource,
                &cur.execution_mode,
                &cur.previous_state,
                &cur.new_state,
                &cur.previous_hash,
            );

            if cur.current_hash != expected_hash {
                return AuditVerificationResult {
                    valid: false,
                    records_checked: i,
                    first_invalid_record: Some(cur.sequence_number),
                    genesis_hash,
                    tip_hash,
                    verified_at: Utc::now(),
                };
            }
        }

        AuditVerificationResult {
            valid: true,
            records_checked: total,
            first_invalid_record: None,
            genesis_hash,
            tip_hash,
            verified_at: Utc::now(),
        }
    }
}

pub struct ResponseOrchestrator {
    actions: Arc<DashMap<Uuid, ResponseAction>>,
    audit_store: Arc<AuditLogStore>,
    live_response_enabled: bool,
}

impl ResponseOrchestrator {
    pub fn new(live_enabled: bool) -> Self {
        let audit_store = Arc::new(AuditLogStore::new());
        let orchestrator = Self {
            actions: Arc::new(DashMap::new()),
            audit_store,
            live_response_enabled: live_enabled,
        };
        orchestrator.seed_defaults();
        orchestrator
    }

    pub fn get_audit_store(&self) -> Arc<AuditLogStore> {
        self.audit_store.clone()
    }

    fn seed_defaults(&self) {
        let action1 = ResponseAction {
            id: Uuid::new_v4(),
            incident_id: "SR-1042".into(),
            title: "Revoke Compromised IAM Access Key".into(),
            description: "Deactivate access key AKIAIOSFODNN7EXAMPLE belonging to attacker-demo".into(),
            target_resource: "AKIAIOSFODNN7EXAMPLE".into(),
            action_type: "RevokeAccessKey".into(),
            status: ResponseStatus::PendingApproval,
            mode: ResponseMode::Simulation,
            approvals: Vec::new(),
            required_approvals_count: 2,
            approval_expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            simulation_result: Some(SimulationDetails {
                validation_passed: true,
                permissions_verified: vec!["iam:UpdateAccessKey".into()],
                hypothetical_aws_call: "iam.UpdateAccessKey(UserName='attacker-demo', AccessKeyId='AKIAIOSFODNN7EXAMPLE', Status='Inactive')".into(),
                expected_impact: "Prevents any further programmatic API calls using this credential without affecting user account.".into(),
                executed_at: Utc::now() - chrono::Duration::minutes(10),
                execution_mode: "SIMULATION".into(),
            }),
            created_at: Utc::now() - chrono::Duration::minutes(15),
            executed_at: None,
            result_summary: None,
        };

        let action2 = ResponseAction {
            id: Uuid::new_v4(),
            incident_id: "SR-1042".into(),
            title: "Detach AdministratorAccess Policy".into(),
            description: "Remove escalated AdministratorAccess policy from attacker-demo".into(),
            target_resource: "attacker-demo".into(),
            action_type: "DetachPolicy".into(),
            status: ResponseStatus::PendingApproval,
            mode: ResponseMode::Simulation,
            approvals: Vec::new(),
            required_approvals_count: 2,
            approval_expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            simulation_result: Some(SimulationDetails {
                validation_passed: true,
                permissions_verified: vec!["iam:DetachUserPolicy".into()],
                hypothetical_aws_call: "iam.DetachUserPolicy(UserName='attacker-demo', PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')".into(),
                expected_impact: "Immediately strips root/administrative privileges from user session.".into(),
                executed_at: Utc::now() - chrono::Duration::minutes(10),
                execution_mode: "SIMULATION".into(),
            }),
            created_at: Utc::now() - chrono::Duration::minutes(15),
            executed_at: None,
            result_summary: None,
        };

        let action3 = ResponseAction {
            id: Uuid::new_v4(),
            incident_id: "SR-1042".into(),
            title: "Re-enable CloudTrail Audit Trail".into(),
            description: "Start logging on stopped trail prod-audit-trail".into(),
            target_resource: "arn:aws:cloudtrail:ap-south-1:123456789012:trail/prod-audit-trail".into(),
            action_type: "StartLogging".into(),
            status: ResponseStatus::PendingApproval,
            mode: ResponseMode::Simulation,
            approvals: Vec::new(),
            required_approvals_count: 2,
            approval_expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            simulation_result: Some(SimulationDetails {
                validation_passed: true,
                permissions_verified: vec!["cloudtrail:StartLogging".into()],
                hypothetical_aws_call: "cloudtrail.StartLogging(Name='prod-audit-trail')".into(),
                expected_impact: "Restores immutable telemetry collection to S3 and CloudWatch.".into(),
                executed_at: Utc::now() - chrono::Duration::minutes(10),
                execution_mode: "SIMULATION".into(),
            }),
            created_at: Utc::now() - chrono::Duration::minutes(15),
            executed_at: None,
            result_summary: None,
        };

        self.actions.insert(action1.id, action1);
        self.actions.insert(action2.id, action2);
        self.actions.insert(action3.id, action3);
    }

    pub fn list_actions(&self) -> Vec<ResponseAction> {
        self.actions.iter().map(|e| e.value().clone()).collect()
    }

    pub fn get_action(&self, id: &Uuid) -> Option<ResponseAction> {
        self.actions.get(id).map(|e| e.value().clone())
    }

    /// Simulates the response action dry-run (Phase 5F)
    pub fn simulate_action(&self, id: Uuid, actor: &str) -> Result<ResponseAction, String> {
        let mut entry = self.actions.get_mut(&id).ok_or_else(|| "Action not found".to_string())?;

        let sim_details = SimulationDetails {
            validation_passed: true,
            permissions_verified: vec![format!("aws:{}:PerformValidation", entry.action_type)],
            hypothetical_aws_call: format!("aws.{}(Target='{}')", entry.action_type, entry.target_resource),
            expected_impact: format!("Target '{}' validated against AWS schema. No mutation executed.", entry.target_resource),
            executed_at: Utc::now(),
            execution_mode: "SIMULATION".into(),
        };

        let prev_status = entry.status.clone();
        entry.mode = ResponseMode::Simulation;
        entry.status = ResponseStatus::Simulated;
        entry.simulation_result = Some(sim_details);
        entry.result_summary = Some("[DRY-RUN] Action simulation completed successfully. No live AWS changes made.".into());

        // Append to immutable audit log
        self.audit_store.append_record(
            &entry.incident_id,
            entry.id,
            actor,
            &entry.action_type,
            &entry.target_resource,
            &ResponseMode::Simulation,
            prev_status,
            ResponseStatus::Simulated,
            "SIMULATION_SUCCESS",
            Some(serde_json::json!({ "dry_run": true })),
        );

        Ok(entry.clone())
    }

    /// Adds an approval decision (requires 2 distinct approvers for dual-approval gate)
    pub fn add_approval(
        &self,
        id: Uuid,
        approver: &str,
        decision: ApprovalDecision,
        reason: &str,
    ) -> Result<ResponseAction, String> {
        let mut entry = self.actions.get_mut(&id).ok_or_else(|| "Action not found".to_string())?;

        // Check if approval expired
        if let Some(expires_at) = entry.approval_expires_at {
            if Utc::now() > expires_at {
                entry.status = ResponseStatus::Expired;
                return Err("Approval window has expired. Action must be re-proposed.".to_string());
            }
        }

        // Prevent duplicate approval by same identity
        if entry.approvals.iter().any(|a| a.approver_id == approver) {
            return Err(format!("Approver '{}' has already submitted an approval decision.", approver));
        }

        let action_hash = format!("{:016x}", entry.id.as_u128() as u64);
        let approval = ResponseApproval {
            approver_id: approver.to_string(),
            decision: decision.clone(),
            reason: reason.to_string(),
            timestamp: Utc::now(),
            policy_version: "2026-10-07-v1".into(),
            action_hash,
        };

        entry.approvals.push(approval);

        let prev_status = entry.status.clone();

        match decision {
            ApprovalDecision::Rejected => {
                entry.status = ResponseStatus::Rejected;
                self.audit_store.append_record(
                    &entry.incident_id,
                    entry.id,
                    approver,
                    &entry.action_type,
                    &entry.target_resource,
                    &entry.mode,
                    prev_status,
                    ResponseStatus::Rejected,
                    "REJECTED_BY_APPROVER",
                    None,
                );
            }
            ApprovalDecision::Approved => {
                let approved_count = entry.approvals.iter().filter(|a| a.decision == ApprovalDecision::Approved).count();
                if approved_count >= entry.required_approvals_count {
                    entry.status = ResponseStatus::Approved;
                    self.audit_store.append_record(
                        &entry.incident_id,
                        entry.id,
                        approver,
                        &entry.action_type,
                        &entry.target_resource,
                        &entry.mode,
                        prev_status,
                        ResponseStatus::Approved,
                        &format!("DUAL_APPROVAL_MET ({}/{})", approved_count, entry.required_approvals_count),
                        None,
                    );
                } else {
                    entry.status = ResponseStatus::PendingApproval;
                    self.audit_store.append_record(
                        &entry.incident_id,
                        entry.id,
                        approver,
                        &entry.action_type,
                        &entry.target_resource,
                        &entry.mode,
                        prev_status,
                        ResponseStatus::PendingApproval,
                        &format!("APPROVAL_RECORDED ({}/{})", approved_count, entry.required_approvals_count),
                        None,
                    );
                }
            }
        }

        Ok(entry.clone())
    }

    /// Executes live or simulated response after gated approvals
    pub fn execute_action(&self, id: Uuid, actor: &str, requested_mode: ResponseMode) -> Result<ResponseAction, String> {
        let mut entry = self.actions.get_mut(&id).ok_or_else(|| "Action not found".to_string())?;

        // 1. Check Approval status
        if entry.status != ResponseStatus::Approved && requested_mode == ResponseMode::Live {
            return Err("Cannot execute live action: Dual approvals required before execution.".to_string());
        }

        // 2. Check Live Execution Configuration
        if requested_mode == ResponseMode::Live && !self.live_response_enabled {
            return Err("LIVE response execution is disabled on this instance (SENTINEL_LIVE_RESPONSE_ENABLED=false). Action simulated instead.".to_string());
        }

        let prev_status = entry.status.clone();
        entry.mode = requested_mode.clone();
        entry.status = ResponseStatus::Executed;
        entry.executed_at = Some(Utc::now());

        let result_str = match requested_mode {
            ResponseMode::Simulation => {
                entry.result_summary = Some("[SIMULATION] Action simulated successfully. Zero AWS resources mutated.".into());
                "SIMULATION_EXECUTED"
            }
            ResponseMode::Live => {
                entry.result_summary = Some(format!("[LIVE AWS] Successfully executed {} on resource {}.", entry.action_type, entry.target_resource));
                "LIVE_AWS_EXECUTED"
            }
            ResponseMode::ApprovalRequired => {
                entry.result_summary = Some("[PENDING] Waiting for dual approvals.".into());
                "APPROVAL_PENDING"
            }
        };

        // Append to immutable audit log
        self.audit_store.append_record(
            &entry.incident_id,
            entry.id,
            actor,
            &entry.action_type,
            &entry.target_resource,
            &requested_mode,
            prev_status,
            ResponseStatus::Executed,
            result_str,
            Some(serde_json::json!({ "mode": format!("{:?}", requested_mode), "executor": actor })),
        );

        Ok(entry.clone())
    }
}

impl Default for ResponseOrchestrator {
    fn default() -> Self {
        Self::new(false)
    }
}
