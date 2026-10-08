-- PostgreSQL Schema Extensions for Phase 5: Threat Intelligence, Posture, Drift, GuardDuty & Immutable Audit Chain

CREATE TABLE IF NOT EXISTS guardduty_findings (
    id VARCHAR(100) PRIMARY KEY,
    finding_type VARCHAR(255) NOT NULL,
    severity REAL NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    account_id VARCHAR(50),
    region VARCHAR(50),
    resource_id VARCHAR(255),
    resource_type VARCHAR(100),
    actor_ip INET,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    source VARCHAR(100) NOT NULL,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ip INET PRIMARY KEY,
    malicious BOOLEAN NOT NULL,
    confidence REAL,
    reputation_score REAL,
    categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    source VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    queried_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS posture_findings (
    id VARCHAR(100) PRIMARY KEY,
    rule_id VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    category VARCHAR(50) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_arn VARCHAR(500),
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    is_drift BOOLEAN NOT NULL DEFAULT FALSE,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS drift_findings (
    id UUID PRIMARY KEY,
    resource_address VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    drift_type VARCHAR(50) NOT NULL,
    expected JSONB,
    observed JSONB,
    severity VARCHAR(50) NOT NULL,
    security_impact TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS response_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    response_id UUID REFERENCES response_actions(id) ON DELETE CASCADE,
    approver_id VARCHAR(255) NOT NULL,
    decision VARCHAR(50) NOT NULL,
    reason TEXT,
    action_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS immutable_audit_log (
    record_id UUID PRIMARY KEY,
    sequence_number BIGINT UNIQUE NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    incident_id VARCHAR(50) NOT NULL,
    response_id UUID NOT NULL,
    actor VARCHAR(255) NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    target_resource VARCHAR(255) NOT NULL,
    execution_mode VARCHAR(50) NOT NULL,
    previous_state VARCHAR(50) NOT NULL,
    new_state VARCHAR(50) NOT NULL,
    request_hash VARCHAR(64) NOT NULL,
    result TEXT NOT NULL,
    aws_metadata JSONB,
    previous_hash VARCHAR(64) NOT NULL,
    current_hash VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_guardduty_severity ON guardduty_findings(severity DESC);
CREATE INDEX IF NOT EXISTS idx_posture_category ON posture_findings(category);
CREATE INDEX IF NOT EXISTS idx_drift_severity ON drift_findings(severity);
CREATE INDEX IF NOT EXISTS idx_audit_sequence ON immutable_audit_log(sequence_number ASC);
CREATE INDEX IF NOT EXISTS idx_audit_incident ON immutable_audit_log(incident_id);
