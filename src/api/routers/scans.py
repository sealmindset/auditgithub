from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
import os
import uuid
import docker
from loguru import logger
from ..dependencies import get_tenant_db
from .. import models
from src.auth.dependencies import get_current_user
from src.rbac.dependencies import require_permissions
from src.auth.models import User

SCANNER_IMAGE = os.getenv("SCANNER_IMAGE", "auditgithub-scanner:latest")
DOCKER_NETWORK = os.getenv("DOCKER_NETWORK", "auditgithub_default")

router = APIRouter(
    prefix="/scans",
    tags=["scans"]
)

class ScanRequest(BaseModel):
    repo_name: str = Field(..., description="Repository name to scan", examples=["my-service"])
    scan_type: str = Field("full", description="Scan type: full, incremental, or validation", examples=["full"])
    scanners: Optional[List[str]] = Field(None, description="Specific scanners to run (e.g., ['syft', 'trivy'])")
    finding_ids: Optional[List[str]] = Field(None, description="Finding IDs to re-validate (for validation scans)")

class ScanResponse(BaseModel):
    scan_id: str = Field(..., description="UUID of the created scan run")
    status: str = Field(..., description="Initial scan status (queued)")
    message: str = Field(..., description="Human-readable status message")

class ScanStatusResponse(BaseModel):
    scan_id: str = Field(..., description="Scan run UUID")
    status: str = Field(..., description="Current status: queued, running, completed, failed")
    scan_type: Optional[str] = Field(None, description="Scan type: full, incremental, or validation")
    findings_count: Optional[int] = Field(None, description="Number of findings discovered")
    created_at: Optional[datetime] = Field(None, description="Scan creation timestamp")
    started_at: Optional[datetime] = Field(None, description="Scan start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Scan completion timestamp")
    elapsed_seconds: Optional[int] = Field(None, description="Elapsed time in seconds")
    error_message: Optional[str] = Field(None, description="Error details if scan failed")


def _get_scanner_env(github_token: str = None, github_org: str = None) -> dict:
    """Build environment dict for scanner container from current env."""
    keys = [
        "GITHUB_TOKEN", "GITHUB_ORG", "GITHUB_API",
        "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
        "SECRETS_MASTER_KEY",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION", "AWS_SESSION_TOKEN",
    ]
    env = {k: os.getenv(k, "") for k in keys if os.getenv(k)}
    env["POSTGRES_HOST"] = "db"
    env["POSTGRES_PORT"] = "5432"
    if github_token:
        env["GITHUB_TOKEN"] = github_token
    if github_org:
        env["GITHUB_ORG"] = github_org
    return env


def _resolve_org_credentials(db, repo) -> tuple:
    """Resolve GitHub token and org name for a repository's organization."""
    if not repo.organization_id:
        return os.getenv("GITHUB_TOKEN", ""), os.getenv("GITHUB_ORG", "")

    org = db.query(models.Organization).filter(
        models.Organization.id == repo.organization_id
    ).first()
    if not org:
        return os.getenv("GITHUB_TOKEN", ""), os.getenv("GITHUB_ORG", "")

    org_name = org.name.lower()
    token_key = f"ORG_{org_name.upper()}_TOKEN"
    token = os.getenv(token_key, "")
    if not token:
        token = os.getenv("GITHUB_TOKEN", "")

    return token, org.github_org or os.getenv("GITHUB_ORG", "")


def run_scan_background(scan_id: str, repo_name: str, scan_type: str, scanners: List[str] = None, finding_ids: List[str] = None):
    """Run scan in the dedicated scanner container via Docker SDK."""
    logger.info(f"Starting scan {scan_id} for {repo_name} (Type: {scan_type}, Scanners: {scanners})")

    from ..database import get_db
    db = next(get_db())
    scan_run = db.query(models.ScanRun).filter(models.ScanRun.id == scan_id).first()

    container = None
    try:
        if scan_run:
            scan_run.status = "running"
            db.commit()

        client = docker.from_env()

        # Resolve org-specific credentials for this repo
        repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
        org_token, org_github = _resolve_org_credentials(db, repo) if repo else ("", "")
        if not org_token:
            org_token = os.getenv("GITHUB_TOKEN", "")
        if not org_github:
            org_github = os.getenv("GITHUB_ORG", "")

        # Build scanner command args
        cmd_parts = ["--repo", repo_name, "--no-ai-agent",
                      "--report-dir", "/app/vulnerability_reports",
                      "--loglevel", "INFO"]
        if org_github:
            cmd_parts.extend(["--org", org_github])
        if scanners:
            cmd_parts.extend(["--scanners", ",".join(scanners)])

        # Resolve host path for volume mounts (map from container /app to host)
        host_project_dir = os.getenv("HOST_PROJECT_DIR", "/app")

        volumes = {
            f"{host_project_dir}/vulnerability_reports": {"bind": "/app/vulnerability_reports", "mode": "rw"},
        }

        logger.info(f"Launching scanner container: {SCANNER_IMAGE} for {org_github}/{repo_name}")

        container = client.containers.run(
            SCANNER_IMAGE,
            command=cmd_parts,
            environment=_get_scanner_env(github_token=org_token, github_org=org_github),
            volumes=volumes,
            network=DOCKER_NETWORK,
            name=f"auditgh_scan_{scan_id[:8]}",
            detach=True,
            mem_limit="8g",
            cpu_count=4,
        )

        # Wait for container to finish (timeout 1 hour)
        result = container.wait(timeout=3600)
        exit_code = result.get("StatusCode", -1)
        logs = container.logs(tail=200).decode("utf-8", errors="replace")

        logger.info(f"Scanner container exited with code {exit_code} for {repo_name}")
        if logs:
            logger.info(f"Scanner output (last 500 chars): {logs[-500:]}")

        if exit_code != 0:
            if scan_run:
                scan_run.status = "failed"
                scan_run.error_message = logs[-1000:]
                db.commit()
            return

        # Scan succeeded — mark completed
        if scan_run:
            scan_run.status = "completed"
            scan_run.completed_at = datetime.utcnow()
            db.commit()

        logger.info(f"Scan {scan_id} completed for {repo_name}")

    except docker.errors.ImageNotFound:
        msg = f"Scanner image '{SCANNER_IMAGE}' not found. Build with: docker compose build scanner"
        logger.error(msg)
        if scan_run:
            scan_run.status = "failed"
            scan_run.error_message = msg
            db.commit()
    except Exception as e:
        logger.error(f"Scan execution failed: {e}")
        if scan_run:
            scan_run.status = "failed"
            scan_run.error_message = str(e)[:1000]
            db.commit()
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass
        db.close()

@router.post("/", dependencies=[Depends(require_permissions("scans:execute"))], response_model=ScanResponse, summary="Trigger a security scan", responses={404: {"description": "Repository not found"}, 401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions"}})
async def trigger_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_tenant_db)
):
    """Trigger a new security scan for a repository.

    Queues a background scan job that runs the configured security scanners
    (Gitleaks, Semgrep, Grype, Trivy, etc.) and ingests results into the findings database.

    **Required permissions:** `scans:execute`
    """
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

@router.get("/{scan_id}", dependencies=[Depends(require_permissions("scans:read"))], response_model=ScanStatusResponse, summary="Get scan status", responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions"}, 404: {"description": "Scan not found"}})
async def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """Get the current status of a scan run.

    Returns the scan's progress status, findings count (when complete),
    and timestamps. Use this to poll for scan completion after triggering a scan.

    **Required permissions:** `scans:read`
    """
    # TODO Phase 4: Filter by user's tenant_id
    scan = db.query(models.ScanRun).filter(models.ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    now = datetime.utcnow()
    started = scan.started_at
    elapsed = None
    if started:
        end = scan.completed_at or now
        elapsed = int((end - started).total_seconds())

    return {
        "scan_id": str(scan.id),
        "status": scan.status,
        "scan_type": scan.scan_type,
        "findings_count": scan.findings_count,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "elapsed_seconds": elapsed,
        "error_message": scan.error_message,
    }
