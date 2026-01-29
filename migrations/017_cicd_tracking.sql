-- Migration 017: CI/CD Tracking and Deployment History
-- This migration adds support for tracking CI/CD pipelines, deployments, and environments

-- Deployment Targets (Environments)
CREATE TABLE IF NOT EXISTS deployment_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL, -- prod, staging, dev, qa, etc.
    type VARCHAR(50) NOT NULL, -- production, staging, development, test
    url VARCHAR(512), -- deployment URL if applicable
    cloud_provider VARCHAR(50), -- aws, gcp, azure, on-premise
    region VARCHAR(100), -- cloud region
    extra_data JSONB, -- additional environment extra_data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(organization_id, name)
);

CREATE INDEX idx_deployment_targets_org ON deployment_targets(organization_id);
CREATE INDEX idx_deployment_targets_type ON deployment_targets(type);

-- CI/CD Pipelines
CREATE TABLE IF NOT EXISTS cicd_pipelines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    platform VARCHAR(50) NOT NULL, -- github_actions, gitlab_ci, jenkins, circleci, etc.
    name VARCHAR(255) NOT NULL, -- workflow name
    file_path VARCHAR(512), -- path to workflow file (e.g., .github/workflows/deploy.yml)
    branch VARCHAR(255), -- primary branch for this pipeline
    is_active BOOLEAN DEFAULT true,
    config JSONB, -- pipeline configuration details
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_run_at TIMESTAMP,
    UNIQUE(repository_id, platform, name)
);

CREATE INDEX idx_cicd_pipelines_repo ON cicd_pipelines(repository_id);
CREATE INDEX idx_cicd_pipelines_platform ON cicd_pipelines(platform);
CREATE INDEX idx_cicd_pipelines_active ON cicd_pipelines(is_active);

-- Workflow Runs (GitHub Actions specific, but adaptable)
CREATE TABLE IF NOT EXISTS workflow_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipeline_id UUID REFERENCES cicd_pipelines(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    run_id BIGINT, -- External platform run ID
    run_number INTEGER,
    workflow_name VARCHAR(255),
    event VARCHAR(50), -- push, pull_request, workflow_dispatch, etc.
    status VARCHAR(50), -- queued, in_progress, completed, cancelled, failed
    conclusion VARCHAR(50), -- success, failure, cancelled, skipped, timed_out
    branch VARCHAR(255),
    commit_sha VARCHAR(40),
    commit_message TEXT,
    actor VARCHAR(255), -- user who triggered the run
    html_url VARCHAR(512), -- link to workflow run
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    extra_data JSONB, -- additional workflow run data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_workflow_runs_pipeline ON workflow_runs(pipeline_id);
CREATE INDEX idx_workflow_runs_repo ON workflow_runs(repository_id);
CREATE INDEX idx_workflow_runs_status ON workflow_runs(status);
CREATE INDEX idx_workflow_runs_conclusion ON workflow_runs(conclusion);
CREATE INDEX idx_workflow_runs_commit ON workflow_runs(commit_sha);
CREATE INDEX idx_workflow_runs_started ON workflow_runs(started_at DESC);

-- Deployments
CREATE TABLE IF NOT EXISTS deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    target_id UUID REFERENCES deployment_targets(id) ON DELETE SET NULL,
    workflow_run_id UUID REFERENCES workflow_runs(id) ON DELETE SET NULL,
    deployment_id BIGINT, -- External platform deployment ID (GitHub Deployments API)
    environment VARCHAR(255) NOT NULL, -- environment name
    status VARCHAR(50) NOT NULL, -- queued, in_progress, success, failure, error, cancelled
    commit_sha VARCHAR(40) NOT NULL,
    commit_message TEXT,
    ref VARCHAR(255), -- branch or tag
    deployer VARCHAR(255), -- user or service that triggered deployment
    deployment_url VARCHAR(512), -- URL where deployment is accessible
    log_url VARCHAR(512), -- URL to deployment logs
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    error_message TEXT,
    extra_data JSONB, -- additional deployment extra_data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_deployments_repo ON deployments(repository_id);
CREATE INDEX idx_deployments_target ON deployments(target_id);
CREATE INDEX idx_deployments_workflow_run ON deployments(workflow_run_id);
CREATE INDEX idx_deployments_environment ON deployments(environment);
CREATE INDEX idx_deployments_status ON deployments(status);
CREATE INDEX idx_deployments_commit ON deployments(commit_sha);
CREATE INDEX idx_deployments_started ON deployments(started_at DESC);

-- Deployment Artifacts (optional - tracks what was deployed)
CREATE TABLE IF NOT EXISTS deployment_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id UUID REFERENCES deployments(id) ON DELETE CASCADE,
    artifact_type VARCHAR(50), -- docker_image, zip, tar, binary, etc.
    artifact_name VARCHAR(255),
    artifact_version VARCHAR(100),
    artifact_url VARCHAR(512),
    artifact_hash VARCHAR(128), -- SHA256 or similar
    size_bytes BIGINT,
    extra_data JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_deployment_artifacts_deployment ON deployment_artifacts(deployment_id);
CREATE INDEX idx_deployment_artifacts_type ON deployment_artifacts(artifact_type);

-- Update trigger for updated_at columns
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply triggers
CREATE TRIGGER update_deployment_targets_updated_at BEFORE UPDATE ON deployment_targets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_cicd_pipelines_updated_at BEFORE UPDATE ON cicd_pipelines
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_workflow_runs_updated_at BEFORE UPDATE ON workflow_runs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_deployments_updated_at BEFORE UPDATE ON deployments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Comments for documentation
COMMENT ON TABLE deployment_targets IS 'Deployment environments and targets';
COMMENT ON TABLE cicd_pipelines IS 'CI/CD pipeline configurations from various platforms';
COMMENT ON TABLE workflow_runs IS 'Individual workflow/pipeline execution runs';
COMMENT ON TABLE deployments IS 'Deployment events to specific environments';
COMMENT ON TABLE deployment_artifacts IS 'Artifacts produced by deployments';
