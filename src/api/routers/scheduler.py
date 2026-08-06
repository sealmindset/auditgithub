"""
Scheduler API Endpoints

Provides REST API for:
- Viewing scheduler status
- Manually triggering jobs
- Viewing job history
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
from datetime import datetime

from ..scheduler import get_scheduler
from src.rbac.dependencies import require_permissions
from src.auth.models import User
from src.auth.dependencies import get_current_user
from src.api.schemas.common import CRUD_ERRORS, LIST_ERRORS

router = APIRouter(prefix="/scheduler", tags=["scheduler"])


class JobTriggerRequest(BaseModel):
    """Request to trigger a job."""
    job_name: str = Field(..., description="Name of the scheduled job to trigger (e.g. annealing, scan, backup)")


class JobStatusResponse(BaseModel):
    """Response for job status."""
    description: str = Field(..., description="Human-readable description of the job")
    cron: str = Field(..., description="Cron expression defining the schedule")
    enabled: bool = Field(..., description="Whether the job is enabled")
    last_run: Optional[str] = Field(None, description="ISO-8601 timestamp of the last execution")
    last_status: str = Field(..., description="Status of the last run (success, error, pending)")
    last_error: Optional[str] = Field(None, description="Error message from the last failed run")
    run_count: int = Field(..., description="Total number of successful runs")
    error_count: int = Field(..., description="Total number of failed runs")


class SchedulerStatusResponse(BaseModel):
    """Response for scheduler status."""
    enabled: bool = Field(..., description="Whether the scheduler is enabled in configuration")
    running: bool = Field(..., description="Whether the scheduler is currently running")
    jobs: Dict[str, JobStatusResponse] = Field(..., description="Map of job names to their current status")


class TriggerResponse(BaseModel):
    """Response for job trigger."""
    status: str = Field(..., description="Outcome of the trigger (success, error)")
    job_name: str = Field(..., description="Name of the triggered job")
    result: Optional[Dict[str, Any]] = Field(None, description="Result payload returned by the job")
    error: Optional[str] = Field(None, description="Error message if the job failed")


@router.get(
    "/status",
    response_model=SchedulerStatusResponse,
    dependencies=[Depends(require_permissions("admin:manage"))],
    summary="Get scheduler status",
    responses={**CRUD_ERRORS, 403: {"description": "Missing admin:manage permission"}},
)
async def get_scheduler_status():
    """
    Get the current scheduler status and all job information.

    Requires the **admin:manage** permission. Returns whether the scheduler
    is enabled and running, along with status details for every configured job.
    """
    scheduler = get_scheduler()
    return scheduler.get_status()


@router.get(
    "/jobs",
    dependencies=[Depends(require_permissions("admin:manage"))],
    summary="List all scheduled jobs",
    responses={**LIST_ERRORS, 403: {"description": "Missing admin:manage permission"}},
)
async def list_jobs():
    """
    List all configured scheduled jobs with their current configurations.

    Requires the **admin:manage** permission. Returns each job's name,
    schedule, and run history in a flat list format.
    """
    scheduler = get_scheduler()
    status = scheduler.get_status()
    
    return {
        "scheduler_enabled": status["enabled"],
        "scheduler_running": status["running"],
        "jobs": [
            {
                "name": name,
                **job_info
            }
            for name, job_info in status["jobs"].items()
        ]
    }


@router.get(
    "/jobs/{job_name}",
    dependencies=[Depends(require_permissions("admin:manage"))],
    summary="Get status for a specific job",
    responses={**CRUD_ERRORS, 403: {"description": "Missing admin:manage permission"}, 404: {"description": "Job not found"}},
)
async def get_job_status(job_name: str):
    """
    Get detailed status for a specific scheduled job.

    Requires the **admin:manage** permission. Returns the job's schedule,
    run counts, last execution status, and any error messages.
    """
    scheduler = get_scheduler()
    status = scheduler.get_status()
    
    if job_name not in status["jobs"]:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_name}")
    
    return {
        "name": job_name,
        **status["jobs"][job_name]
    }


@router.post(
    "/jobs/{job_name}/trigger",
    response_model=TriggerResponse,
    dependencies=[Depends(require_permissions("admin:manage"))],
    summary="Manually trigger a job",
    responses={**CRUD_ERRORS, 403: {"description": "Missing admin:manage permission"}, 404: {"description": "Job not found"}, 500: {"description": "Internal error during job execution"}},
)
async def trigger_job(job_name: str):
    """
    Manually trigger a scheduled job outside of its normal cron schedule.

    Requires the **admin:manage** permission. Executes the job immediately
    and returns its result or error status.
    """
    scheduler = get_scheduler()
    
    if job_name not in scheduler.jobs:
        raise HTTPException(
            status_code=404, 
            detail=f"Job not found: {job_name}. Available jobs: {list(scheduler.jobs.keys())}"
        )
    
    try:
        result = await scheduler.trigger_job(job_name)
        return TriggerResponse(
            status=result["status"],
            job_name=job_name,
            result=result.get("result"),
            error=result.get("error")
        )
    except Exception as e:
        return TriggerResponse(
            status="error",
            job_name=job_name,
            error=str(e)
        )


@router.post(
    "/start",
    dependencies=[Depends(require_permissions("admin:manage"))],
    summary="Start the scheduler",
    responses={**CRUD_ERRORS, 400: {"description": "Scheduler is disabled in configuration"}, 403: {"description": "Missing admin:manage permission"}},
)
async def start_scheduler():
    """
    Start the scheduler if it is not already running.

    Requires the **admin:manage** permission. Returns an error if the
    scheduler is disabled via SCHEDULER_ENABLED in the environment.
    """
    scheduler = get_scheduler()
    
    if not scheduler.enabled:
        raise HTTPException(
            status_code=400,
            detail="Scheduler is disabled. Set SCHEDULER_ENABLED=true in .env"
        )
    
    await scheduler.start()
    return {"status": "started", "scheduler": scheduler.get_status()}


@router.post(
    "/stop",
    dependencies=[Depends(require_permissions("admin:manage"))],
    summary="Stop the scheduler",
    responses={**CRUD_ERRORS, 403: {"description": "Missing admin:manage permission"}},
)
async def stop_scheduler():
    """
    Stop the running scheduler and all scheduled jobs.

    Requires the **admin:manage** permission. Returns the updated scheduler
    status after shutdown.
    """
    scheduler = get_scheduler()
    await scheduler.stop()
    return {"status": "stopped", "scheduler": scheduler.get_status()}


@router.get(
    "/next-runs",
    dependencies=[Depends(require_permissions("admin:manage"))],
    summary="Get next scheduled run times",
    responses={**LIST_ERRORS, 403: {"description": "Missing admin:manage permission"}},
)
async def get_next_runs():
    """
    Get the next scheduled run time for each enabled job.

    Requires the **admin:manage** permission. Returns an empty list if the
    scheduler is not currently running.
    """
    scheduler = get_scheduler()
    
    if not scheduler.scheduler or not scheduler._running:
        return {"message": "Scheduler not running", "jobs": []}
    
    next_runs = []
    for job in scheduler.scheduler.get_jobs():
        next_run = job.next_run_time
        next_runs.append({
            "job_name": job.id,
            "description": job.name,
            "next_run": next_run.isoformat() if next_run else None
        })
    
    return {"jobs": next_runs}


@router.get(
    "/github-budget",
    dependencies=[Depends(require_permissions("admin:manage"))],
    summary="Shared GitHub API rate-limit budget and admission decisions",
    responses={**CRUD_ERRORS, 403: {"description": "Missing admin:manage permission"}},
)
async def get_github_budget():
    """
    Show the shared GitHub PAT budget every scanner competes for, and whether
    each priority tier would be admitted right now.

    `remaining` comes from the headers of the last *real* GitHub response, not
    from `GET /rate_limit`, which has been observed reporting a full budget
    while real requests were already returning 403.
    """
    from ..utils import github_budget

    snap = github_budget.snapshot()
    tiers = {}
    for tier in (
        github_budget.TIER_INTERACTIVE,
        github_budget.TIER_ON_DEMAND,
        github_budget.TIER_BACKGROUND,
    ):
        allowed, reason, _ = github_budget.can_run(
            tier, need=github_budget.DEFAULT_SCAN_COST
        )
        tiers[tier] = {
            "would_admit": allowed,
            "reason": reason,
            "floor": snap["floors"][tier],
            "active_leases": github_budget.active_leases(tier),
            "seconds_since_activity": github_budget.seconds_since_activity(tier),
        }

    return {
        "budget": snap,
        "tiers": tiers,
        "idle_threshold_seconds": github_budget.IDLE_SECONDS,
        "scan_cost_estimate": github_budget.DEFAULT_SCAN_COST,
        "note": (
            "background tier = cron scans; on_demand = operator-triggered runs; "
            "interactive is never gated. A refusal here is throttling/priority, "
            "not a permissions problem."
        ),
    }
