-- Migration 020: Deployment Topology (Phase P1 - reusable workflow contracts)
--
-- Adds the two tables that back the repo -> environment -> cloud-resource map.
--
-- P1 populates these from centrally-shared reusable workflows plus per-repo
-- GitHub Environments and Actions variables. Later phases (GitHub Deployments,
-- per-repo static parse, IaC join, run logs, cloud reconcile) write into the
-- same repo_deployment_map with a different `method` value, so provenance
-- survives and no phase overwrites another.
--
-- DATA CLASSIFICATION: repo_deployment_map.evidence and
-- reusable_workflow_targets.referenced_secrets hold secret and variable NAMES
-- plus cloud resource identifiers (subscription ids, resource groups, service
-- principal client ids). They never hold secret VALUES. Treat these tables at
-- the same classification as findings exports.

-- ---------------------------------------------------------------------------
-- Parsed deployment contract of a centrally-shared reusable workflow.
-- One row per (source_repo, workflow_path, ref).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reusable_workflow_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,

    -- Identity of the shared workflow
    source_repo VARCHAR(512) NOT NULL,        -- e.g. SleepNumberInc/node-function-app-cd-gha-workflow
    workflow_path VARCHAR(512) NOT NULL,      -- e.g. .github/workflows/node-function-app-cd.yaml
    ref VARCHAR(255) NOT NULL,                -- tag/branch the consumers pin, e.g. v3, main
    resolved_sha VARCHAR(40),                 -- commit the ref pointed at when parsed
    workflow_name VARCHAR(512),               -- `name:` in the workflow
    kind VARCHAR(50),                         -- cd | ci | infra | release | utility | unknown

    -- Reach
    consumer_count INTEGER DEFAULT 0,         -- distinct repos referencing this (source: dependencies)

    -- What it deploys
    cloud_providers JSONB,                    -- ["azure"]
    resource_types JSONB,                     -- ["function_app","terraform_infra"]
    is_deploying BOOLEAN DEFAULT false,        -- true when it mutates cloud state

    -- How the environment is chosen
    environment_source VARCHAR(50),           -- deployment_event|input|literal|matrix|unknown
    environment_gate_vars JSONB,              -- ["CD_PLAN_ENVIRONMENTS","CD_APPLY_ENVIRONMENTS"]
    literal_environments JSONB,               -- envs hardcoded in the workflow, if any

    -- Credential + execution surface
    runner_labels JSONB,                      -- ["onprem-runner","azure-runner","self-hosted",...]
    inputs JSONB,                             -- workflow_call inputs schema (name/type/default/required)
    declared_secrets JSONB,                   -- workflow_call secrets schema
    referenced_vars JSONB,                    -- vars.* names read by the workflow
    referenced_secrets JSONB,                 -- secrets.* NAMES read by the workflow (never values)
    nested_workflows JSONB,                   -- job-level `uses:` reusable workflow refs
    actions_used JSONB,                       -- [{uses, pinned_sha, is_third_party}]
    permissions JSONB,                        -- job-level permissions blocks
    oidc_used BOOLEAN DEFAULT false,          -- id-token: write present
    secrets_bulk_exposure JSONB,              -- sinks receiving toJSON(secrets) or `secrets: inherit`

    -- Provenance
    parse_confidence NUMERIC(3,2),
    parser_version VARCHAR(20),
    evidence JSONB,                           -- {markers: [{line, text, kind}], ...}
    fetch_status VARCHAR(50),                 -- ok | not_found | forbidden | parse_error
    fetch_error TEXT,
    fetched_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(organization_id, source_repo, workflow_path, ref)
);

CREATE INDEX IF NOT EXISTS idx_rwt_org ON reusable_workflow_targets(organization_id);
CREATE INDEX IF NOT EXISTS idx_rwt_source_repo ON reusable_workflow_targets(source_repo);
CREATE INDEX IF NOT EXISTS idx_rwt_consumer_count ON reusable_workflow_targets(consumer_count DESC);
CREATE INDEX IF NOT EXISTS idx_rwt_deploying ON reusable_workflow_targets(is_deploying);

-- ---------------------------------------------------------------------------
-- The map itself: one row per (repo, environment, method, resource).
-- A row with is_resolved = false is an explicit "we looked and could not
-- determine" marker - an unbounded unknown, NOT an assertion of "deploys
-- nowhere". Coverage stats must count these separately.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS repo_deployment_map (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,

    environment VARCHAR(255) NOT NULL,        -- dev, tst, stg, prd, prd-ncus, or '__unresolved__'
    environment_kind VARCHAR(50),             -- production|staging|test|development|ephemeral|unknown

    cloud_provider VARCHAR(50),               -- azure | aws | gcp | kubernetes | unknown
    resource_type VARCHAR(100),               -- function_app | app_service | managed_api | aks |
                                              -- container_image | terraform_infra | npm_package | ...
    resource_identifier VARCHAR(512),         -- function app name, image ref, tf state key, ...
    subscription_or_account VARCHAR(255),     -- Azure subscription id / AWS account id
    region VARCHAR(100),

    -- Who/what executes the deploy and with which identity
    runner_labels JSONB,
    deploy_identity VARCHAR(255),             -- e.g. Azure SP client id used for this environment
    tf_backend JSONB,                         -- {subscription_id, resource_group, storage_account, container, key}

    -- Provenance
    method VARCHAR(50) NOT NULL,              -- reusable_workflow | gh_deployments | gh_environments |
                                              -- workflow_static | run_log | iac | cloud_reconcile
    confidence NUMERIC(3,2) NOT NULL,
    source_workflow_id UUID REFERENCES reusable_workflow_targets(id) ON DELETE SET NULL,
    is_resolved BOOLEAN DEFAULT false,
    unresolved_reason VARCHAR(255),           -- e.g. org_variables_forbidden, no_env_vars, expr_unresolvable
    evidence JSONB NOT NULL,                  -- file+line, API endpoint, var names consulted

    first_observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_current BOOLEAN DEFAULT true,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- COALESCE so NULL resource_identifier still de-duplicates (plain UNIQUE would not).
CREATE UNIQUE INDEX IF NOT EXISTS uq_rdm_repo_env_method_resource
    ON repo_deployment_map(
        repository_id,
        environment,
        method,
        COALESCE(resource_identifier, ''),
        COALESCE(resource_type, '')
    );

CREATE INDEX IF NOT EXISTS idx_rdm_org ON repo_deployment_map(organization_id);
CREATE INDEX IF NOT EXISTS idx_rdm_repo ON repo_deployment_map(repository_id);
CREATE INDEX IF NOT EXISTS idx_rdm_env ON repo_deployment_map(environment);
CREATE INDEX IF NOT EXISTS idx_rdm_env_kind ON repo_deployment_map(environment_kind);
CREATE INDEX IF NOT EXISTS idx_rdm_method ON repo_deployment_map(method);
CREATE INDEX IF NOT EXISTS idx_rdm_provider ON repo_deployment_map(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_rdm_resolved ON repo_deployment_map(is_resolved);
CREATE INDEX IF NOT EXISTS idx_rdm_subscription ON repo_deployment_map(subscription_or_account);

-- ---------------------------------------------------------------------------
-- Coverage as data: every repository gets a row, including the ones we know
-- nothing about. Absence of a map row is reported as unknown, not as zero.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW repo_deployment_coverage AS
SELECT
    r.id                AS repository_id,
    r.organization_id,
    r.name              AS repository_name,
    r.is_archived,
    COUNT(m.id)                                                   AS map_rows,
    COUNT(DISTINCT CASE WHEN m.is_resolved THEN m.environment END) AS resolved_environments,
    COUNT(DISTINCT m.method)                                       AS methods,
    MAX(m.confidence)                                              AS best_confidence,
    BOOL_OR(m.environment_kind = 'production' AND m.is_resolved)    AS reaches_production,
    CASE
        WHEN COUNT(m.id) = 0 THEN 'unknown'
        WHEN BOOL_OR(m.is_resolved) THEN 'resolved'
        ELSE 'unresolved'
    END                                                            AS coverage_state
FROM repositories r
LEFT JOIN repo_deployment_map m
       ON m.repository_id = r.id AND m.is_current
GROUP BY r.id, r.organization_id, r.name, r.is_archived;
