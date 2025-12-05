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
    scanners: Optional[List[str]] = None # List of scanners to run (e.g. ['syft', 'trivy'])
    finding_ids: Optional[List[str]] = None  # For validation scans

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

def run_scan_background(scan_id: str, repo_name: str, scan_type: str, scanners: List[str] = None, finding_ids: List[str] = None):
    """
    Background task to execute the scan.
    """
    logger.info(f"Starting scan {scan_id} for {repo_name} (Type: {scan_type}, Scanners: {scanners})")
    
    db = next(get_db())
    scan_run = db.query(models.ScanRun).filter(models.ScanRun.id == scan_id).first()
    
    try:
        if scan_run:
            scan_run.status = "running"
            db.commit()

        # Build command
        cmd = ["python3", "scan_repos.py", "--repo", repo_name, "--no-ai-agent"]
        
        if scanners:
            cmd.extend(["--scanners", ",".join(scanners)])
            
        # Execute scan
        import subprocess
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd="/app" # Assuming running in container
        )
        
        if process.returncode != 0:
            logger.error(f"Scan failed: {process.stderr}")
            if scan_run:
                scan_run.status = "failed"
                scan_run.error_message = process.stderr
                db.commit()
            return

        # Ingest results
        try:
            # Import here to avoid circular imports
            import sys
            import os
            sys.path.append(os.path.join(os.path.dirname(__file__), '../../..'))
            from ingest_scans import ingest_single_repo
            
            # We need the report directory. Assuming default structure.
            # scan_repos.py writes to /app/vulnerability_reports/{safe_repo_name}
            # ingest_single_repo expects repo_name and repo_dir
            
            # Sanitize repo name as done in scan_repos.py
            safe_repo_name = "".join(c if c.isalnum() or c in '._-' else '_' for c in repo_name)
            report_dir = f"/app/vulnerability_reports/{safe_repo_name}"
            
            ingest_single_repo(repo_name, report_dir)
            
            if scan_run:
                scan_run.status = "completed"
                scan_run.completed_at = datetime.utcnow()
                db.commit()
                
        except Exception as e:
            logger.error(f"Ingestion failed: {e}")
            if scan_run:
                scan_run.status = "failed"
                scan_run.error_message = f"Scan succeeded but ingestion failed: {e}"
                db.commit()

    except Exception as e:
        logger.error(f"Scan execution failed: {e}")
        if scan_run:
            scan_run.status = "failed"
            scan_run.error_message = str(e)
            db.commit()
    finally:
        db.close()

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
        request.scanners,
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
