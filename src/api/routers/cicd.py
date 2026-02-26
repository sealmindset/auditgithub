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

from ..dependencies import get_tenant_db, require_permissions
from .. import models
from ..utils.github_actions_service import GitHubActionsService, sync_all_repositories_cicd
from ..config import settings

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

@router.get("/deployments", summary="List deployment history", dependencies=[Depends(require_permissions("findings:read"))], responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions"}, 500: {"description": "Internal server error"}})
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

    Args:
        repository_name: Filter by repository name
        environment: Filter by environment (prod, staging, etc.)
        status: Filter by deployment status
        days_back: How many days of history to return
        limit: Maximum number of results

    Returns:
        List of deployments
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


@router.get("/deployments/repository/{repository_id}", summary="Get repository deployment status", dependencies=[Depends(require_permissions("findings:read"))], responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions"}, 404: {"description": "Repository not found"}, 500: {"description": "Internal server error"}})
async def get_repository_deployments(
    repository_id: str,
    environment: Optional[str] = None,
    db: Session = Depends(get_tenant_db)
):
    """
    Get deployment status for a specific repository.

    Args:
        repository_id: Repository UUID
        environment: Optional environment filter

    Returns:
        Deployment status information
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

@router.get("/workflow-runs", summary="List CI/CD workflow runs", dependencies=[Depends(require_permissions("findings:read"))], responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions"}, 500: {"description": "Internal server error"}})
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

    Args:
        repository_name: Filter by repository name
        workflow_name: Filter by workflow/pipeline name
        branch: Filter by branch
        status: Filter by status (queued, in_progress, completed)
        conclusion: Filter by conclusion (success, failure, cancelled)
        days_back: How many days of history to return
        limit: Maximum number of results

    Returns:
        List of workflow runs
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

@router.post("/sync", response_model=SyncResponse, summary="Sync CI/CD data from GitHub Actions", dependencies=[Depends(require_permissions("findings:write"))], responses={400: {"description": "Organization ID required"}, 401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions"}, 404: {"description": "Organization or repository not found"}, 500: {"description": "GitHub token not configured or sync error"}})
async def sync_cicd_data(
    request: SyncRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_tenant_db)
):
    """
    Sync CI/CD data from GitHub Actions.

    This endpoint fetches workflow runs and deployments from GitHub API
    and stores them in the database for analysis.

    Args:
        request: Sync request with organization/repository filters
        background_tasks: FastAPI background tasks

    Returns:
        Sync status and statistics
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

@router.get("/stats", summary="Get CI/CD statistics", dependencies=[Depends(require_permissions("findings:read"))], responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions"}, 500: {"description": "Internal server error"}})
async def get_cicd_stats(
    days_back: int = 30,
    db: Session = Depends(get_tenant_db)
):
    """
    Get CI/CD statistics for the organization.

    Args:
        days_back: How many days of history to analyze

    Returns:
        Statistics about deployments and workflow runs
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
