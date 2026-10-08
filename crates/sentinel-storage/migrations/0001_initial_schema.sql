-- PostgreSQL Initial Schema for SentinelRS

CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    cloud_provider VARCHAR(50) NOT NULL,
    account_id VARCHAR(50),
    actor_identity VARCHAR(255) NOT NULL,
    actor_type VARCHAR(50) NOT NULL,
    source VARCHAR(50) NOT NULL,
    action VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    source_ip INET,
    region VARCHAR(50),
    outcome VARCHAR(50) NOT NULL,
    severity VARCHAR(50),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS detections (
    id UUID PRIMARY KEY,
    event_id UUID REFERENCES events(id) ON DELETE CASCADE,
    rule_id VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    tactic VARCHAR(100) NOT NULL,
    technique_id VARCHAR(50) NOT NULL,
    risk_delta INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR(50) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    risk_score INT NOT NULL,
    confidence_score INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS response_actions (
    id UUID PRIMARY KEY,
    incident_id VARCHAR(50) REFERENCES incidents(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    target_resource VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    mode VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_at TIMESTAMPTZ,
    result_summary TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_identity);
CREATE INDEX IF NOT EXISTS idx_detections_event_id ON detections(event_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
