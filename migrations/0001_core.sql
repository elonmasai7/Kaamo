CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    target TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_occurred_at ON audit_logs (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);

CREATE TABLE IF NOT EXISTS api_tokens (
    token_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_active ON api_tokens (token_hash) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS security_events (
    event_id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    host TEXT NOT NULL,
    user_name TEXT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    raw_payload JSONB NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_host ON security_events (host);
CREATE INDEX IF NOT EXISTS idx_security_events_user_name ON security_events (user_name);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events (event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_raw_payload ON security_events USING GIN (raw_payload);

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    condition TEXT NOT NULL,
    severity TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS detection_alerts (
    alert_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL REFERENCES detection_rules(rule_id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    event_ids JSONB NOT NULL,
    host TEXT NULL,
    user_name TEXT NULL,
    reason TEXT NOT NULL,
    mitre_technique_id TEXT NULL,
    mitre_tactic TEXT NULL,
    mitre_confidence DOUBLE PRECISION NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detection_alerts_created_at ON detection_alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_detection_alerts_severity ON detection_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_detection_alerts_host ON detection_alerts (host);
CREATE INDEX IF NOT EXISTS idx_detection_alerts_status ON detection_alerts (status);

CREATE TABLE IF NOT EXISTS triage_results (
    alert_id TEXT PRIMARY KEY REFERENCES detection_alerts(alert_id) ON DELETE CASCADE,
    priority_score DOUBLE PRECISION NOT NULL,
    likely_attack_stage TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    recommended_actions JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS forensic_artifacts (
    artifact_id TEXT PRIMARY KEY,
    source_host TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    evidence_path TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_forensic_artifacts_source_host ON forensic_artifacts (source_host);
CREATE INDEX IF NOT EXISTS idx_forensic_artifacts_collected_at ON forensic_artifacts (collected_at DESC);

CREATE TABLE IF NOT EXISTS detection_coverage (
    attack_path_id TEXT PRIMARY KEY,
    covered_steps INTEGER NOT NULL,
    uncovered_steps INTEGER NOT NULL,
    coverage_score DOUBLE PRECISION NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detection_coverage_created_at ON detection_coverage (created_at DESC);
