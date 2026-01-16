"""
Scheduler API Endpoints

Provides REST API for:
- Viewing scheduler status
- Manually triggering jobs
- Viewing job history
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from datetime import datetime

from ..scheduler import get_scheduler
from src.rbac.dependencies import require_permissions
from src.auth.models import User
from src.auth.dependencies import get_current_user

router = APIRouter(prefix="/scheduler", tags=["scheduler"])


class JobTriggerRequest(BaseModel):
    """Request to trigger a job."""
    job_name: str


class JobStatusResponse(BaseModel):
    """Response for job status."""
    description: str
    cron: str
    enabled: bool
    last_run: Optional[str]
    last_status: str
    last_error: Optional[str]
    run_count: int
    error_count: int


class SchedulerStatusResponse(BaseModel):
    """Response for scheduler status."""
    enabled: bool
    running: bool
    jobs: Dict[str, JobStatusResponse]


class TriggerResponse(BaseModel):
    """Response for job trigger."""
    status: str
    job_name: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@router.get("/status", response_model=SchedulerStatusResponse, dependencies=[Depends(require_permissions("admin:manage"))])
async def get_scheduler_status():
    """
    Get the current scheduler status and all job information.
    
    Returns:
        Scheduler status including all configured jobs
    """
    scheduler = get_scheduler()
    return scheduler.get_status()


@router.get("/jobs", dependencies=[Depends(require_permissions("admin:manage"))])
async def list_jobs():
    """
    List all configured scheduled jobs.
    
    Returns:
        List of job names and their configurations
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


@router.get("/jobs/{job_name}", dependencies=[Depends(require_permissions("admin:manage"))])
async def get_job_status(job_name: str):
    """
    Get status for a specific job.
    
    Args:
        job_name: Name of the job (annealing, scan, backup)
    
    Returns:
        Job status and configuration
    """
    scheduler = get_scheduler()
    status = scheduler.get_status()
    
    if job_name not in status["jobs"]:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_name}")
    
    return {
        "name": job_name,
        **status["jobs"][job_name]
    }


@router.post("/jobs/{job_name}/trigger", response_model=TriggerResponse, dependencies=[Depends(require_permissions("admin:manage"))])
async def trigger_job(job_name: str):
    """
    Manually trigger a scheduled job.
    
    Args:
        job_name: Name of the job to trigger (annealing, scan, backup)
    
    Returns:
        Result of the job execution
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


@router.post("/start", dependencies=[Depends(require_permissions("admin:manage"))])
async def start_scheduler():
    """
    Start the scheduler if it's not running.
    
    Returns:
        Scheduler status after starting
    """
    scheduler = get_scheduler()
    
    if not scheduler.enabled:
        raise HTTPException(
            status_code=400,
            detail="Scheduler is disabled. Set SCHEDULER_ENABLED=true in .env"
        )
    
    await scheduler.start()
    return {"status": "started", "scheduler": scheduler.get_status()}


@router.post("/stop", dependencies=[Depends(require_permissions("admin:manage"))])
async def stop_scheduler():
    """
    Stop the scheduler.
    
    Returns:
        Scheduler status after stopping
    """
    scheduler = get_scheduler()
    await scheduler.stop()
    return {"status": "stopped", "scheduler": scheduler.get_status()}


@router.get("/next-runs", dependencies=[Depends(require_permissions("admin:manage"))])
async def get_next_runs():
    """
    Get the next scheduled run time for each enabled job.
    
    Returns:
        List of jobs with their next run times
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
