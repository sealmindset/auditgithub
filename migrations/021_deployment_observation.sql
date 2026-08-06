-- Migration 021: Deployment observation (Phase P2 - GitHub Deployments API)
--
-- P1 recorded deployment *capability* from centrally-shared reusable workflows.
-- P2 records observed deployments, writing repo_deployment_map rows with
-- method = 'github_deployment' alongside (never over) the P1 rows, plus raw
-- records into the pre-existing deployments / deployment_targets tables from
-- migration 017, which had no writer until now.
--
-- No new tables. This migration only adds what an idempotent, resumable sync
-- needs: a conflict target for the deployment upsert and indexes for the
-- "which repositories still need probing" and "what deployed recently" queries.
--
-- DATA CLASSIFICATION: deployments.extra_data and repo_deployment_map.evidence
-- hold deployment payload KEY NAMES only - a deployment payload is supplied by
-- whoever created the deployment and can contain credential material, so values
-- are dropped at ingest and never written here.

-- One row per (repository, external GitHub deployment id). NULL deployment_id
-- rows (from any other writer) remain unconstrained because NULLs are distinct.
CREATE UNIQUE INDEX IF NOT EXISTS uq_deployments_repo_external_id
    ON deployments(repository_id, deployment_id);

-- Resume cursor: the P2 sync orders candidates by their oldest observation.
CREATE INDEX IF NOT EXISTS idx_rdm_method_last_observed
    ON repo_deployment_map(method, last_observed_at);

-- "Which environments actually received a deploy, and how recently" per repo.
CREATE INDEX IF NOT EXISTS idx_deployments_repo_env_started
    ON deployments(repository_id, environment, started_at DESC);

COMMENT ON COLUMN deployments.status IS
    'Latest GitHub deployment status state (success, failure, error, in_progress, '
    'queued, pending, inactive), or ''unknown'' when the statuses call was not '
    'spent on this record. ''unknown'' is a budget decision, not a GitHub answer.';

COMMENT ON COLUMN deployments.extra_data IS
    'Observation metadata: task, production/transient flags, creator type, '
    'payload KEY NAMES only (never payload values), status source, observer version.';
