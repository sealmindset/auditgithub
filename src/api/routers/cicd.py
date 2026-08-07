"""
CI/CD Tracking API Endpoints

Provides endpoints for managing and querying CI/CD deployments, workflow runs, and pipeline data.
"""
import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from datetime import datetime

from src.rbac.dependencies import require_permissions

from ..dependencies import get_tenant_db
from .. import models
from ..utils.github_actions_service import GitHubActionsService, sync_all_repositories_cicd
from ..config import settings
from ..schemas.common import LIST_ERRORS, CRUD_ERRORS, CREATE_ERRORS

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/cicd",
    tags=["cicd"]
)


# =============================================================================
# Request/Response Models
# =============================================================================

class DeploymentResponse(BaseModel):
    id: str = Field(..., description="Deployment UUID")
    repository_name: str = Field(..., description="Name of the repository")
    environment: str = Field(..., description="Deployment environment (e.g. production, staging)")
    status: str = Field(..., description="Deployment status (success, failure, in_progress)")
    commit_sha: str = Field(..., description="Git commit SHA deployed")
    commit_message: Optional[str] = Field(None, description="Commit message for the deployment")
    deployer: Optional[str] = Field(None, description="Username who triggered the deployment")
    deployment_url: Optional[str] = Field(None, description="URL of the deployment")
    started_at: Optional[str] = Field(None, description="ISO 8601 timestamp when deployment started")
    completed_at: Optional[str] = Field(None, description="ISO 8601 timestamp when deployment completed")
    duration_seconds: Optional[int] = Field(None, description="Duration of the deployment in seconds")


class WorkflowRunResponse(BaseModel):
    id: str = Field(..., description="Workflow run UUID")
    repository_name: str = Field(..., description="Name of the repository")
    workflow_name: str = Field(..., description="Name of the CI/CD workflow")
    status: str = Field(..., description="Run status (queued, in_progress, completed)")
    conclusion: Optional[str] = Field(None, description="Run conclusion (success, failure, cancelled)")
    branch: Optional[str] = Field(None, description="Git branch the workflow ran on")
    commit_sha: str = Field(..., description="Git commit SHA that triggered the run")
    actor: Optional[str] = Field(None, description="GitHub username who triggered the run")
    html_url: Optional[str] = Field(None, description="URL to view the run on GitHub")
    started_at: Optional[str] = Field(None, description="ISO 8601 timestamp when run started")
    completed_at: Optional[str] = Field(None, description="ISO 8601 timestamp when run completed")
    duration_seconds: Optional[int] = Field(None, description="Duration of the run in seconds")


class DeploymentStatusResponse(BaseModel):
    repository_id: str = Field(..., description="Repository UUID")
    repository_name: str = Field(..., description="Name of the repository")
    environments: List[Dict[str, Any]] = Field(..., description="List of environment deployment statuses")
    total_environments: int = Field(..., description="Total number of deployment environments")


class SyncRequest(BaseModel):
    organization_id: Optional[str] = Field(None, description="Organization UUID to sync. Defaults to current org")
    repository_id: Optional[str] = Field(None, description="Specific repository UUID to sync. If omitted, syncs all")
    days_back: int = Field(30, description="Number of days of CI/CD history to fetch")


class SyncResponse(BaseModel):
    status: str = Field(..., description="Sync status (success, started, error)")
    message: str = Field(..., description="Human-readable status message")
    stats: Dict[str, Any] = Field(..., description="Sync statistics (repositories processed, records created)")


# =============================================================================
# Deployment Endpoints
# =============================================================================

@router.get(
    "/deployments",
    summary="List deployment history",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={**LIST_ERRORS},
)
async def list_deployments(
    repository_name: Optional[str] = None,
    environment: Optional[str] = None,
    status: Optional[str] = None,
    days_back: int = 90,
    limit: int = 100,
    db: Session = Depends(get_tenant_db)
):
    """
    List deployment history with optional filters.

    Returns a paginated list of deployments across all repositories in
    the current organization. Results can be narrowed by repository name,
    target environment, deployment status, and time window.

    **Required permissions:** `findings:read`

    Args:
        repository_name: Filter by repository name.
        environment: Filter by environment (e.g. production, staging).
        status: Filter by deployment status (success, failure, in_progress).
        days_back: Number of days of history to return (default 90).
        limit: Maximum number of results to return (default 100).

    Returns:
        List of deployments with applied filter metadata.
    """
    from ...ai_agent.tools.db_tools import search_deployments
    from ..database import get_request_org_id

    organization_id = get_request_org_id()

    try:
        deployments = search_deployments(
            db=db,
            repository_name=repository_name,
            environment=environment,
            status=status,
            days_back=days_back,
            organization_id=organization_id
        )

        return {
            "deployments": deployments[:limit],
            "total": len(deployments),
            "filters_applied": {
                "repository_name": repository_name,
                "environment": environment,
                "status": status,
                "days_back": days_back
            }
        }

    except Exception as e:
        logger.error(f"Error listing deployments: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/deployments/repository/{repository_id}",
    summary="Get repository deployment status",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={**CRUD_ERRORS, 404: {"description": "Repository not found"}},
)
async def get_repository_deployments(
    repository_id: str,
    environment: Optional[str] = None,
    db: Session = Depends(get_tenant_db)
):
    """
    Get deployment status for a specific repository.

    Retrieves current deployment information for each environment
    associated with the given repository, optionally filtered to a
    single environment.

    **Required permissions:** `findings:read`

    Args:
        repository_id: Repository UUID.
        environment: Optional environment filter (e.g. production, staging).

    Returns:
        Deployment status information including per-environment details.
    """
    from ...ai_agent.tools.db_tools import get_repository_deployment_status

    try:
        # Verify repository exists
        repository = db.query(models.Repository).filter(
            models.Repository.id == repository_id
        ).first()

        if not repository:
            raise HTTPException(status_code=404, detail="Repository not found")

        status = get_repository_deployment_status(
            db=db,
            repository_id=repository_id,
            environment=environment
        )

        return {
            **status,
            "repository_name": repository.name
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting repository deployments: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Workflow Run Endpoints
# =============================================================================

@router.get(
    "/workflow-runs",
    summary="List CI/CD workflow runs",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={**LIST_ERRORS},
)
async def list_workflow_runs(
    repository_name: Optional[str] = None,
    workflow_name: Optional[str] = None,
    branch: Optional[str] = None,
    status: Optional[str] = None,
    conclusion: Optional[str] = None,
    days_back: int = 30,
    limit: int = 100,
    db: Session = Depends(get_tenant_db)
):
    """
    List CI/CD workflow runs with optional filters.

    Returns a paginated list of GitHub Actions workflow runs across all
    repositories in the current organization. Results can be narrowed by
    repository, workflow name, branch, run status, and conclusion.

    **Required permissions:** `findings:read`

    Args:
        repository_name: Filter by repository name.
        workflow_name: Filter by workflow/pipeline name.
        branch: Filter by Git branch.
        status: Filter by status (queued, in_progress, completed).
        conclusion: Filter by conclusion (success, failure, cancelled).
        days_back: Number of days of history to return (default 30).
        limit: Maximum number of results to return (default 100).

    Returns:
        List of workflow runs with applied filter metadata.
    """
    from ...ai_agent.tools.db_tools import search_workflow_runs
    from ..database import get_request_org_id

    organization_id = get_request_org_id()

    try:
        workflow_runs = search_workflow_runs(
            db=db,
            repository_name=repository_name,
            workflow_name=workflow_name,
            branch=branch,
            status=status,
            conclusion=conclusion,
            days_back=days_back,
            organization_id=organization_id
        )

        return {
            "workflow_runs": workflow_runs[:limit],
            "total": len(workflow_runs),
            "filters_applied": {
                "repository_name": repository_name,
                "workflow_name": workflow_name,
                "branch": branch,
                "status": status,
                "conclusion": conclusion,
                "days_back": days_back
            }
        }

    except Exception as e:
        logger.error(f"Error listing workflow runs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Sync Endpoints
# =============================================================================

@router.post(
    "/sync",
    response_model=SyncResponse,
    summary="Sync CI/CD data from GitHub Actions",
    dependencies=[Depends(require_permissions("findings:write"))],
    responses={
        **CREATE_ERRORS,
        400: {"description": "Organization ID required"},
        404: {"description": "Organization or repository not found"},
        500: {"description": "GitHub token not configured or sync error"},
    },
)
async def sync_cicd_data(
    request: SyncRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_tenant_db)
):
    """
    Sync CI/CD data from GitHub Actions.

    Fetches workflow runs and deployments from the GitHub API and stores
    them in the database for analysis. When a specific repository is
    provided, the sync runs synchronously and returns statistics. When no
    repository is specified, the sync runs in the background for all
    repositories in the organization.

    **Required permissions:** `findings:write`

    Args:
        request: Sync request with organization/repository filters and days_back window.
        background_tasks: FastAPI background tasks runner.

    Returns:
        Sync status and statistics.
    """
    from ..database import get_request_org_id

    # Get organization ID
    org_id = request.organization_id or get_request_org_id()

    if not org_id:
        raise HTTPException(status_code=400, detail="Organization ID required")

    # Get organization to find GitHub token
    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Get GitHub token (from settings or org-specific)
    github_token = settings.GITHUB_TOKEN

    # Try to get org-specific token
    try:
        import sys
        sys.path.insert(0, '/app/execution')
        from secrets_manager import get_org_credentials
        import asyncio

        creds = asyncio.run(get_org_credentials(org.name))
        if creds and creds.get('github_token'):
            github_token = creds['github_token']
            logger.info(f"Using org-specific token for {org.name}")
    except Exception as e:
        logger.warning(f"Could not get org credentials: {e}")

    if not github_token:
        raise HTTPException(
            status_code=500,
            detail="GitHub token not configured"
        )

    try:
        if request.repository_id:
            # Sync single repository
            repository = db.query(models.Repository).filter(
                models.Repository.id == request.repository_id,
                models.Repository.organization_id == org_id
            ).first()

            if not repository:
                raise HTTPException(status_code=404, detail="Repository not found")

            service = GitHubActionsService(github_token)

            # Parse owner/repo from URL
            url_parts = repository.url.rstrip('.git').split('/')
            owner = url_parts[-2]
            repo_name = url_parts[-1]

            stats = service.sync_repository_workflows(
                db, repository, owner, repo_name, days_back=request.days_back
            )

            return SyncResponse(
                status="success",
                message=f"Synced CI/CD data for {repository.name}",
                stats=stats
            )

        else:
            # Sync all repositories in organization (background task)
            background_tasks.add_task(
                sync_all_repositories_cicd,
                db=db,
                organization_id=org_id,
                github_token=github_token,
                days_back=request.days_back
            )

            return SyncResponse(
                status="started",
                message=f"CI/CD sync started for organization {org.name}",
                stats={"status": "in_progress"}
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error syncing CI/CD data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Statistics Endpoints
# =============================================================================

@router.get(
    "/stats",
    summary="Get CI/CD statistics",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={**LIST_ERRORS},
)
async def get_cicd_stats(
    days_back: int = 30,
    db: Session = Depends(get_tenant_db)
):
    """
    Get CI/CD statistics for the organization.

    Returns aggregate statistics about deployments and workflow runs,
    including breakdowns by status, conclusion, and environment for the
    specified time window.

    **Required permissions:** `findings:read`

    Args:
        days_back: Number of days of history to analyze (default 30).

    Returns:
        Statistics about deployments and workflow runs.
    """
    from ..database import get_request_org_id
    from datetime import datetime, timedelta
    from sqlalchemy import func, and_

    organization_id = get_request_org_id()
    cutoff = datetime.utcnow() - timedelta(days=days_back)

    try:
        # Deployment stats
        deployment_query = db.query(models.Deployment).join(models.Repository)

        if organization_id:
            deployment_query = deployment_query.filter(
                models.Repository.organization_id == organization_id
            )

        deployment_query = deployment_query.filter(
            models.Deployment.started_at >= cutoff
        )

        total_deployments = deployment_query.count()

        deployment_by_status = dict(
            db.query(models.Deployment.status, func.count(models.Deployment.id))
            .join(models.Repository)
            .filter(
                and_(
                    models.Repository.organization_id == organization_id,
                    models.Deployment.started_at >= cutoff
                )
            )
            .group_by(models.Deployment.status)
            .all()
        )

        deployment_by_env = dict(
            db.query(models.Deployment.environment, func.count(models.Deployment.id))
            .join(models.Repository)
            .filter(
                and_(
                    models.Repository.organization_id == organization_id,
                    models.Deployment.started_at >= cutoff
                )
            )
            .group_by(models.Deployment.environment)
            .all()
        )

        # Workflow run stats
        workflow_query = db.query(models.WorkflowRun).join(models.Repository)

        if organization_id:
            workflow_query = workflow_query.filter(
                models.Repository.organization_id == organization_id
            )

        workflow_query = workflow_query.filter(
            models.WorkflowRun.started_at >= cutoff
        )

        total_workflow_runs = workflow_query.count()

        workflow_by_conclusion = dict(
            db.query(models.WorkflowRun.conclusion, func.count(models.WorkflowRun.id))
            .join(models.Repository)
            .filter(
                and_(
                    models.Repository.organization_id == organization_id,
                    models.WorkflowRun.started_at >= cutoff
                )
            )
            .group_by(models.WorkflowRun.conclusion)
            .all()
        )

        return {
            "days_analyzed": days_back,
            "deployments": {
                "total": total_deployments,
                "by_status": deployment_by_status,
                "by_environment": deployment_by_env
            },
            "workflow_runs": {
                "total": total_workflow_runs,
                "by_conclusion": workflow_by_conclusion
            }
        }

    except Exception as e:
        logger.error(f"Error getting CI/CD stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Deployment Topology Endpoints (phase P1: reusable-workflow propagation)
# =============================================================================

class TopologySyncRequest(BaseModel):
    organization_id: Optional[str] = Field(None, description="Organization UUID. Defaults to current org")
    org_login: Optional[str] = Field(None, description="GitHub org login. Defaults to the organization name")
    min_consumers: int = Field(5, description="Skip shared workflows with fewer consumer repositories")
    repo_limit: Optional[int] = Field(None, description="Cap (repo, contract) resolutions for an incremental run")
    include_non_deploying: bool = Field(False, description="Also resolve consumers of workflows that do not mutate cloud state")
    wait_for_rate_limit: int = Field(0, description="Max seconds to wait for a GitHub rate-limit reset (0 aborts)")


@router.get(
    "/topology/workflows",
    summary="List parsed reusable workflow deployment contracts",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={**LIST_ERRORS},
)
async def list_reusable_workflow_targets(
    deploying_only: bool = False,
    min_consumers: int = 0,
    limit: int = 100,
    db: Session = Depends(get_tenant_db)
):
    """
    List the parsed deployment contracts of centrally-shared reusable workflows.

    Each row is one shared workflow: which cloud it targets, what it deploys,
    how the environment name is chosen, which runner labels execute it, and how
    many repositories call it.

    **Required permissions:** `findings:read`

    Args:
        deploying_only: Return only workflows that mutate cloud state.
        min_consumers: Minimum consumer repository count.
        limit: Maximum rows to return.

    Returns:
        Reusable workflow contracts ordered by reach.
    """
    query = db.query(models.ReusableWorkflowTarget)
    if deploying_only:
        query = query.filter(models.ReusableWorkflowTarget.is_deploying.is_(True))
    if min_consumers:
        query = query.filter(models.ReusableWorkflowTarget.consumer_count >= min_consumers)

    rows = query.order_by(models.ReusableWorkflowTarget.consumer_count.desc()).limit(limit).all()

    return {
        "total": len(rows),
        "workflows": [
            {
                "id": str(row.id),
                "source_repo": row.source_repo,
                "workflow_path": row.workflow_path,
                "ref": row.ref,
                "resolved_sha": row.resolved_sha,
                "workflow_name": row.workflow_name,
                "kind": row.kind,
                "consumer_count": row.consumer_count,
                "cloud_providers": row.cloud_providers,
                "resource_types": row.resource_types,
                "is_deploying": row.is_deploying,
                "environment_source": row.environment_source,
                "environment_gate_vars": row.environment_gate_vars,
                "runner_labels": row.runner_labels,
                "oidc_used": row.oidc_used,
                "secrets_bulk_exposure": row.secrets_bulk_exposure,
                "parse_confidence": float(row.parse_confidence) if row.parse_confidence is not None else None,
                "fetch_status": row.fetch_status,
                "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
            }
            for row in rows
        ],
    }


@router.get(
    "/topology/repositories/{repository_id}",
    summary="Get a repository's deployment topology",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={**CRUD_ERRORS, 404: {"description": "Repository not found"}},
)
async def get_repository_topology(
    repository_id: str,
    db: Session = Depends(get_tenant_db)
):
    """
    Get where one repository's code runs, with provenance per row.

    Every row carries its collection `method`, a `confidence` score, and the
    `evidence` that produced it. Rows with `is_resolved` false are explicit
    unknowns - they mean "looked and could not determine", never "deploys
    nowhere".

    **Required permissions:** `findings:read`

    Args:
        repository_id: Repository UUID.

    Returns:
        Deployment map rows grouped by environment, plus a coverage summary.
    """
    repository = db.query(models.Repository).filter(
        models.Repository.id == repository_id
    ).first()
    if not repository:
        raise HTTPException(status_code=404, detail="Repository not found")

    rows = db.query(models.RepoDeploymentMap).filter(
        models.RepoDeploymentMap.repository_id == repository_id,
        models.RepoDeploymentMap.is_current.is_(True),
    ).order_by(
        models.RepoDeploymentMap.confidence.desc()
    ).all()

    resolved = [r for r in rows if r.is_resolved]
    return {
        "repository_id": str(repository.id),
        "repository_name": repository.name,
        "is_archived": repository.is_archived,
        "coverage_state": (
            "unknown" if not rows else ("resolved" if resolved else "unresolved")
        ),
        "methods_applied": sorted({r.method for r in rows}),
        "reaches_production": any(r.environment_kind == "production" for r in resolved),
        "environments": [
            {
                "environment": row.environment,
                "environment_kind": row.environment_kind,
                "cloud_provider": row.cloud_provider,
                "resource_type": row.resource_type,
                "resource_identifier": row.resource_identifier,
                "subscription_or_account": row.subscription_or_account,
                "region": row.region,
                "runner_labels": row.runner_labels,
                "deploy_identity": row.deploy_identity,
                "tf_backend": row.tf_backend,
                "method": row.method,
                "confidence": float(row.confidence),
                "is_resolved": row.is_resolved,
                "unresolved_reason": row.unresolved_reason,
                "evidence": row.evidence,
                "last_observed_at": row.last_observed_at.isoformat() if row.last_observed_at else None,
            }
            for row in rows
        ],
    }


@router.get(
    "/topology/coverage",
    summary="Get deployment topology coverage statistics",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={**LIST_ERRORS},
)
async def get_topology_coverage(
    db: Session = Depends(get_tenant_db)
):
    """
    Get coverage-as-data for the deployment topology map.

    Reports resolved, unresolved, and never-examined repositories separately.
    A repository with no map rows is `unknown`, which is an unbounded gap - it
    is never reported as "deploys nowhere".

    **Required permissions:** `findings:read`

    Returns:
        Coverage counts by state and method, plus environment and unresolved-reason breakdowns.
    """
    from sqlalchemy import text as sa_text
    from ..database import get_request_org_id

    org_id = get_request_org_id()

    def rows_to_dict(sql: str):
        return {
            (key if key is not None else "unknown"): count
            for key, count in db.execute(sa_text(sql), {"org_id": org_id}).fetchall()
        }

    coverage = rows_to_dict(
        """
        SELECT coverage_state, COUNT(*)
        FROM repo_deployment_coverage
        WHERE (:org_id IS NULL OR organization_id = CAST(:org_id AS uuid))
        GROUP BY coverage_state
        """
    )
    by_method = rows_to_dict(
        """
        SELECT m.method, COUNT(DISTINCT m.repository_id)
        FROM repo_deployment_map m
        JOIN repositories r ON r.id = m.repository_id
        WHERE m.is_current AND (:org_id IS NULL OR r.organization_id = CAST(:org_id AS uuid))
        GROUP BY m.method
        """
    )
    by_env_kind = rows_to_dict(
        """
        SELECT m.environment_kind, COUNT(DISTINCT m.repository_id)
        FROM repo_deployment_map m
        JOIN repositories r ON r.id = m.repository_id
        WHERE m.is_current AND m.is_resolved
          AND (:org_id IS NULL OR r.organization_id = CAST(:org_id AS uuid))
        GROUP BY m.environment_kind
        """
    )
    unresolved_reasons = rows_to_dict(
        """
        SELECT m.unresolved_reason, COUNT(*)
        FROM repo_deployment_map m
        JOIN repositories r ON r.id = m.repository_id
        WHERE m.is_current AND m.unresolved_reason IS NOT NULL
          AND (:org_id IS NULL OR r.organization_id = CAST(:org_id AS uuid))
        GROUP BY m.unresolved_reason
        """
    )
    production_repos = db.execute(
        sa_text(
            """
            SELECT COUNT(*)
            FROM repo_deployment_coverage
            WHERE reaches_production
              AND (:org_id IS NULL OR organization_id = CAST(:org_id AS uuid))
            """
        ),
        {"org_id": org_id},
    ).scalar()

    return {
        "coverage_by_state": coverage,
        "repositories_by_method": by_method,
        "repositories_by_environment_kind": by_env_kind,
        "unresolved_reasons": unresolved_reasons,
        "repositories_reaching_production": production_repos,
        "note": (
            "coverage_state='unknown' means no collection method has produced a row "
            "for that repository yet. It is an unbounded gap, not evidence that the "
            "repository deploys nowhere."
        ),
    }


@router.post(
    "/topology/sync",
    response_model=SyncResponse,
    summary="Sync deployment topology from reusable workflows",
    dependencies=[Depends(require_permissions("findings:write"))],
    responses={
        **CREATE_ERRORS,
        400: {"description": "Organization ID required"},
        404: {"description": "Organization not found"},
        500: {"description": "GitHub token not configured or sync error"},
    },
)
async def sync_deployment_topology(
    request: TopologySyncRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_tenant_db)
):
    """
    Run phase P1 of deployment topology collection.

    Parses each centrally-shared reusable workflow once, then propagates its
    deployment contract to every repository that calls it, resolving concrete
    environments and cloud identifiers from per-repository GitHub Environments
    and Actions variables.

    Requires only `repo`-scope GitHub read access. Any permission denial is
    returned in `stats.rights_gaps` with the exact endpoint and impact, so an
    access request can be raised with evidence. GitHub throttling is reported
    separately as `stats.rate_limited` and never as a rights gap.

    **Required permissions:** `findings:write`

    Args:
        request: Sync scope, consumer threshold, and rate-limit behavior.
        background_tasks: FastAPI background tasks runner.

    Returns:
        Sync status and statistics, including rights gaps and coverage counts.
    """
    from ..database import get_request_org_id
    from ..utils.deployment_topology_service import DeploymentTopologyService

    org_id = request.organization_id or get_request_org_id()
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization ID required")

    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    github_token = settings.GITHUB_TOKEN
    try:
        import sys
        sys.path.insert(0, '/app/execution')
        from secrets_manager import get_org_credentials
        import asyncio

        creds = asyncio.run(get_org_credentials(org.name))
        if creds and creds.get('github_token'):
            github_token = creds['github_token']
            logger.info(f"Using org-specific token for {org.name}")
    except Exception as e:
        logger.warning(f"Could not get org credentials: {e}")

    if not github_token:
        raise HTTPException(status_code=500, detail="GitHub token not configured")

    service = DeploymentTopologyService(
        github_token, max_rate_limit_wait=request.wait_for_rate_limit
    )
    org_login = request.org_login or org.name

    try:
        stats = service.sync(
            db,
            organization_id=str(org_id),
            org_login=org_login,
            min_consumers=request.min_consumers,
            deploying_only=not request.include_non_deploying,
            repo_limit=request.repo_limit,
        )
    except Exception as e:
        logger.error(f"Error syncing deployment topology: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    if stats.get("rate_limited"):
        message = stats.get("aborted", "GitHub rate limit reached; run is incomplete")
        return SyncResponse(status="incomplete", message=message, stats=stats)

    return SyncResponse(
        status="success",
        message=(
            f"Parsed {stats['central_workflows_parsed']} shared workflows "
            f"({stats['deploying_workflows']} deploying) and wrote "
            f"{stats['map_rows_written']} topology rows"
        ),
        stats=stats,
    )


# =============================================================================
# Deployment Observation Endpoints (phase P2: GitHub Deployments API)
# =============================================================================

class ObservationSyncRequest(BaseModel):
    organization_id: Optional[str] = Field(None, description="Organization UUID. Defaults to current org")
    org_login: Optional[str] = Field(None, description="GitHub org login. Defaults to the organization name")
    all_repos: bool = Field(False, description="Probe every repository, not only those with an existing map row")
    include_archived: bool = Field(False, description="Also probe archived repositories")
    refresh_days: int = Field(7, description="Skip repositories observed more recently than this")
    repo_limit: Optional[int] = Field(None, description="Cap the number of repositories probed in this run")
    max_pages: int = Field(1, description="Deployment history pages per repository (100 records each)")
    statuses_per_repo: int = Field(4, description="Status calls per repository, newest deploy of each environment first")
    active_days: int = Field(365, description="Deploys older than this are marked stale")
    ignore_budget: bool = Field(False, description="Do not stop at the shared on-demand budget floor")
    wait_for_rate_limit: int = Field(0, description="Max seconds to wait for a GitHub rate-limit reset (0 aborts)")


@router.get(
    "/topology/activity",
    summary="Compare deployment capability against observed deployments",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={**LIST_ERRORS},
)
async def get_topology_activity(
    limit: int = 50,
    db: Session = Depends(get_tenant_db)
):
    """
    Compare what repositories are *wired* to deploy (P1) with what has actually
    deployed (P2).

    Three populations, reported separately because they carry different risk:
    `capability_only` is a wired path with no observed use (still full blast
    radius if the repository is compromised), `observed_only` is a deploy that no
    parsed contract explains (an unmapped delivery path), `both` is a confirmed
    live path.

    Absence of an observation is **not** evidence a path is unused: a workflow
    that deploys without creating a GitHub Deployment object is invisible to P2
    by construction.

    **Required permissions:** `findings:read`

    Args:
        limit: Maximum repository names listed per bucket.

    Returns:
        Per-environment-kind bucket counts, wired-but-unobserved production
        repositories, and recency of observed production deployments.
    """
    from sqlalchemy import text as sa_text
    from ..database import get_request_org_id

    org_id = get_request_org_id()
    params = {"org_id": org_id, "method": "github_deployment", "limit": limit}

    buckets = db.execute(
        sa_text(
            """
            WITH scoped AS (
                SELECT m.repository_id, m.environment_kind, m.method
                FROM repo_deployment_map m
                JOIN repositories r ON r.id = m.repository_id
                WHERE m.is_current AND m.is_resolved
                  AND (:org_id IS NULL OR r.organization_id = CAST(:org_id AS uuid))
            ),
            cap AS (SELECT DISTINCT repository_id, environment_kind FROM scoped WHERE method <> :method),
            obs AS (SELECT DISTINCT repository_id, environment_kind FROM scoped WHERE method = :method)
            SELECT COALESCE(cap.environment_kind, obs.environment_kind) AS environment_kind,
                   COUNT(*) FILTER (WHERE obs.repository_id IS NULL) AS capability_only,
                   COUNT(*) FILTER (WHERE cap.repository_id IS NULL) AS observed_only,
                   COUNT(*) FILTER (WHERE cap.repository_id IS NOT NULL
                                      AND obs.repository_id IS NOT NULL) AS both
            FROM cap
            FULL OUTER JOIN obs
                 ON obs.repository_id = cap.repository_id
                AND obs.environment_kind = cap.environment_kind
            GROUP BY 1
            """
        ),
        params,
    ).fetchall()

    wired_unobserved = db.execute(
        sa_text(
            """
            SELECT r.name
            FROM repositories r
            WHERE (:org_id IS NULL OR r.organization_id = CAST(:org_id AS uuid))
              AND EXISTS (
                  SELECT 1 FROM repo_deployment_map c
                  WHERE c.repository_id = r.id AND c.is_current AND c.is_resolved
                    AND c.environment_kind = 'production' AND c.method <> :method)
              AND NOT EXISTS (
                  SELECT 1 FROM repo_deployment_map o
                  WHERE o.repository_id = r.id AND o.is_current AND o.is_resolved
                    AND o.environment_kind = 'production' AND o.method = :method)
            ORDER BY r.name
            LIMIT :limit
            """
        ),
        params,
    ).fetchall()

    recency = db.execute(
        sa_text(
            """
            SELECT CASE
                       WHEN d IS NULL THEN 'unknown'
                       WHEN d <= 7 THEN 'last_7_days'
                       WHEN d <= 30 THEN 'last_30_days'
                       WHEN d <= 90 THEN 'last_90_days'
                       WHEN d <= 365 THEN 'last_year'
                       ELSE 'over_a_year'
                   END AS bucket,
                   COUNT(DISTINCT repository_id)
            FROM (
                SELECT m.repository_id,
                       (m.evidence->>'days_since_last_deployment')::int AS d
                FROM repo_deployment_map m
                JOIN repositories r ON r.id = m.repository_id
                WHERE m.is_current AND m.is_resolved AND m.method = :method
                  AND m.environment_kind = 'production'
                  AND (:org_id IS NULL OR r.organization_id = CAST(:org_id AS uuid))
            ) x
            GROUP BY 1
            """
        ),
        params,
    ).fetchall()

    probed_no_deployments = db.execute(
        sa_text(
            """
            SELECT COUNT(DISTINCT m.repository_id)
            FROM repo_deployment_map m
            JOIN repositories r ON r.id = m.repository_id
            WHERE m.is_current AND m.method = :method
              AND m.unresolved_reason = 'no_deployments_observed'
              AND (:org_id IS NULL OR r.organization_id = CAST(:org_id AS uuid))
            """
        ),
        params,
    ).scalar()

    return {
        "by_environment_kind": [
            {
                "environment_kind": kind or "unknown",
                "capability_only": cap_only,
                "observed_only": obs_only,
                "both": both,
            }
            for kind, cap_only, obs_only, both in buckets
        ],
        "production_wired_but_never_observed": [row[0] for row in wired_unobserved],
        "production_wired_but_never_observed_shown": len(wired_unobserved),
        "observed_production_recency": {bucket: count for bucket, count in recency},
        "repositories_probed_with_no_deployment_records": probed_no_deployments,
        "note": (
            "A repository in capability_only is not proven unused. Deployments that "
            "do not create a GitHub Deployment object (most Azure Function App and "
            "Terraform pushes in this estate) are invisible to method "
            "'github_deployment'. Treat observation as confirmation, never as the "
            "denominator."
        ),
    }


@router.post(
    "/topology/observe",
    response_model=SyncResponse,
    summary="Sync observed deployments from the GitHub Deployments API",
    dependencies=[Depends(require_permissions("findings:write"))],
    responses={
        **CREATE_ERRORS,
        400: {"description": "Organization ID required"},
        404: {"description": "Organization not found"},
        500: {"description": "GitHub token not configured or sync error"},
    },
)
async def sync_deployment_observations(
    request: ObservationSyncRequest,
    db: Session = Depends(get_tenant_db)
):
    """
    Run phase P2 of deployment topology collection.

    Reads each repository's GitHub Deployment records (and the latest status of
    the newest deploy per environment) and writes `repo_deployment_map` rows with
    `method='github_deployment'`, alongside - never over - P1's capability rows.

    The run holds an `on_demand` budget lease so scheduled scans stand down, and
    stops cleanly at the shared budget floor rather than running into 403s;
    `stats.stopped_early` and `stats.candidates_remaining` say how much is left.
    Repositories are probed oldest-observation-first and committed as they
    complete, so re-running continues rather than restarting.

    **Required permissions:** `findings:write`

    Args:
        request: Sync scope, history depth, and budget behavior.

    Returns:
        Sync status and statistics, including rights gaps and coverage counts.
    """
    from ..database import get_request_org_id
    from ..utils.deployment_observation_service import DeploymentObservationService

    org_id = request.organization_id or get_request_org_id()
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization ID required")

    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    github_token = settings.GITHUB_TOKEN
    try:
        import sys
        sys.path.insert(0, '/app/execution')
        from secrets_manager import get_org_credentials
        import asyncio

        creds = asyncio.run(get_org_credentials(org.name))
        if creds and creds.get('github_token'):
            github_token = creds['github_token']
            logger.info(f"Using org-specific token for {org.name}")
    except Exception as e:
        logger.warning(f"Could not get org credentials: {e}")

    if not github_token:
        raise HTTPException(status_code=500, detail="GitHub token not configured")

    service = DeploymentObservationService(
        github_token, max_rate_limit_wait=request.wait_for_rate_limit
    )
    org_login = request.org_login or org.name

    try:
        stats = service.sync(
            db,
            organization_id=str(org_id),
            org_login=org_login,
            only_mapped=not request.all_repos,
            include_archived=request.include_archived,
            refresh_days=request.refresh_days,
            repo_limit=request.repo_limit,
            max_pages=request.max_pages,
            statuses_per_repo=request.statuses_per_repo,
            active_days=request.active_days,
            respect_budget=not request.ignore_budget,
        )
    except Exception as e:
        logger.error(f"Error syncing deployment observations: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    if stats.get("rate_limited") or stats.get("stopped_early"):
        message = stats.get("aborted") or stats.get("stopped_early")
        return SyncResponse(status="incomplete", message=message, stats=stats)

    return SyncResponse(
        status="success",
        message=(
            f"Probed {stats['repositories_probed']} repositories: "
            f"{stats['repositories_with_deployments']} had deployment records, "
            f"{stats['map_rows_written']} observation rows written"
        ),
        stats=stats,
    )
