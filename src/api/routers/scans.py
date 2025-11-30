from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import uuid
from ..database import get_db
from .. import models
import logging

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/scans",
    tags=["scans"]
)

class ScanRequest(BaseModel):
    repo_name: str
    scan_type: str = "full"  # full, incremental, validation
    finding_ids: Optional[List[str]] = None  # For validation scans

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

def run_scan_background(scan_id: str, repo_name: str, scan_type: str, finding_ids: List[str] = None):
    """
    Background task to execute the scan.
    In a real production environment, this would push a job to a queue (Celery/Redis).
    For now, we'll simulate the execution or call the CLI tools directly if possible.
    """
    logger.info(f"Starting scan {scan_id} for {repo_name} (Type: {scan_type})")
    
    # TODO: Integrate with actual execution scripts in `execution/`
    # This requires bridging the API context with the CLI scripts
    pass

@router.post("/", response_model=ScanResponse)
async def trigger_scan(
    request: ScanRequest, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Trigger a new security scan."""
    # Verify repo exists
    repo = db.query(models.Repository).filter(models.Repository.name == request.repo_name).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Create Scan Run record
    scan_id = uuid.uuid4()
    scan_run = models.ScanRun(
        id=scan_id,
        repository_id=repo.id,
        scan_type=request.scan_type,
        status="queued",
        triggered_by="api",
        started_at=datetime.utcnow()
    )
    db.add(scan_run)
    db.commit()

    # Queue the scan
    background_tasks.add_task(
        run_scan_background, 
        str(scan_id), 
        request.repo_name, 
        request.scan_type, 
        request.finding_ids
    )

    return ScanResponse(
        scan_id=str(scan_id),
        status="queued",
        message=f"{request.scan_type.capitalize()} scan initiated for {request.repo_name}"
    )

@router.get("/{scan_id}")
async def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    """Get the status of a scan."""
    scan = db.query(models.ScanRun).filter(models.ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": str(scan.id),
        "status": scan.status,
        "findings_count": scan.findings_count,
        "created_at": scan.created_at,
        "completed_at": scan.completed_at
    }
