"""
CI/CD Tracking API Endpoints

Provides endpoints for managing and querying CI/CD deployments, workflow runs, and pipeline data.
"""
import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
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
    id: str
    repository_name: str
    environment: str
    status: str
    commit_sha: str
    commit_message: Optional[str]
    deployer: Optional[str]
    deployment_url: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]
    duration_seconds: Optional[int]


class WorkflowRunResponse(BaseModel):
    id: str
    repository_name: str
    workflow_name: str
    status: str
    conclusion: Optional[str]
    branch: Optional[str]
    commit_sha: str
    actor: Optional[str]
    html_url: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]
    duration_seconds: Optional[int]


class DeploymentStatusResponse(BaseModel):
    repository_id: str
    repository_name: str
    environments: List[Dict[str, Any]]
    total_environments: int


class SyncRequest(BaseModel):
    organization_id: Optional[str] = None
    repository_id: Optional[str] = None
    days_back: int = 30


class SyncResponse(BaseModel):
    status: str
    message: str
    stats: Dict[str, Any]


# =============================================================================
# Deployment Endpoints
# =============================================================================

@router.get("/deployments", dependencies=[Depends(require_permissions("findings:read"))])
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


@router.get("/deployments/repository/{repository_id}", dependencies=[Depends(require_permissions("findings:read"))])
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

@router.get("/workflow-runs", dependencies=[Depends(require_permissions("findings:read"))])
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

@router.post("/sync", response_model=SyncResponse, dependencies=[Depends(require_permissions("findings:write"))])
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

@router.get("/stats", dependencies=[Depends(require_permissions("findings:read"))])
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
