-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Users & Authentication
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50),  -- admin, analyst, contributor, viewer
    github_username VARCHAR(100),
    jira_username VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 2. Business Units / Teams
CREATE TABLE IF NOT EXISTS business_units (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    lead_user_id UUID REFERENCES users(id),
    jira_project_key VARCHAR(20),
    slack_channel VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

-- 3. Repositories
CREATE TABLE IF NOT EXISTS repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    name VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(500),  -- org/repo
    url TEXT,
    description TEXT,
    default_branch VARCHAR(100),
    language VARCHAR(100),
    owner_type VARCHAR(50),  -- user, org, business_unit
    owner_id VARCHAR(255),
    business_criticality VARCHAR(20),  -- critical, high, medium, low
    last_scanned_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Join table for repository owners (Business Units)
CREATE TABLE IF NOT EXISTS repository_owners (
    repository_id UUID REFERENCES repositories(id),
    business_unit_id UUID REFERENCES business_units(id),
    PRIMARY KEY (repository_id, business_unit_id)
);

-- 4. Scan Runs
CREATE TABLE IF NOT EXISTS scan_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    repository_id UUID REFERENCES repositories(id),
    scan_type VARCHAR(50),  -- full, incremental, validation
    status VARCHAR(50),  -- queued, running, completed, failed, cancelled
    triggered_by VARCHAR(100),  -- user, schedule, api, jira
    trigger_reference VARCHAR(255),  -- Jira ticket number, user ID, etc
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    findings_count INTEGER,
    new_findings_count INTEGER,
    resolved_findings_count INTEGER,
    architecture_overview TEXT,
    scan_config JSONB,  -- scanners used, thresholds, etc
    error_message TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 5. Findings (Core Table)
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    finding_uuid UUID UNIQUE DEFAULT gen_random_uuid(), -- Legacy/External reference
    repository_id UUID REFERENCES repositories(id),
    scan_run_id UUID REFERENCES scan_runs(id),
    
    -- Finding details
    scanner_name VARCHAR(100),  -- trivy, semgrep, codeql, etc
    finding_type VARCHAR(100),  -- vulnerability, secret, code_quality, etc
    severity VARCHAR(20),  -- critical, high, medium, low, info
    title TEXT NOT NULL,
    description TEXT,
    
    -- Location
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    code_snippet TEXT,
    
    -- Vulnerability info
    cve_id VARCHAR(50),
    cwe_id VARCHAR(50),
    package_name VARCHAR(255),
    package_version VARCHAR(100),
    fixed_version VARCHAR(100),
    
    -- Lifecycle
    status VARCHAR(50) DEFAULT 'open',  -- open, assigned, in_progress, resolved, false_positive, accepted_risk, reopened
    resolution VARCHAR(50),  -- fixed, wont_fix, duplicate, not_applicable
    resolution_notes TEXT,
    
    -- Assignment
    assigned_to UUID REFERENCES users(id),
    assigned_at TIMESTAMP,
    jira_ticket_key VARCHAR(50),
    jira_ticket_url TEXT,
    
    -- AI Remediation
    ai_remediation_text TEXT,
    ai_remediation_diff TEXT,
    ai_confidence_score DECIMAL(3,2),
    
    -- Tracking
    first_seen_at TIMESTAMP DEFAULT NOW(),
    last_seen_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repository_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_jira ON findings(jira_ticket_key);

-- 6. Finding History
CREATE TABLE IF NOT EXISTS finding_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    finding_id UUID REFERENCES findings(id),
    changed_by UUID REFERENCES users(id),
    change_type VARCHAR(50),  -- status_change, assignment, comment, jira_sync
    old_value TEXT,
    new_value TEXT,
    comment TEXT,
    metadata JSONB,  -- flexible field for additional context
    created_at TIMESTAMP DEFAULT NOW()
);

-- 7. Comments
CREATE TABLE IF NOT EXISTS finding_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    finding_id UUID REFERENCES findings(id),
    author_id UUID REFERENCES users(id),
    comment_text TEXT NOT NULL,
    is_internal BOOLEAN DEFAULT true,  -- vs public/visible to contributors
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 8. Remediation Knowledge Base (Updated to match existing + new standards)
CREATE TABLE IF NOT EXISTS remediations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    vuln_id VARCHAR(255),
    vuln_type VARCHAR(255),
    context_hash VARCHAR(64),
    remediation_text TEXT,
    code_diff TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(vuln_id, context_hash)
);
CREATE INDEX IF NOT EXISTS idx_remediations_lookup ON remediations(vuln_id, context_hash);
