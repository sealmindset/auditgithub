from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any
from ..database import get_db
from .. import models
import uuid

router = APIRouter(
    prefix="/projects",
    tags=["projects"]
)

@router.get("/")
async def get_projects(db: Session = Depends(get_db)):
    """Get a list of all projects with summary stats."""
    projects = db.query(models.Repository).all()
    
    results = []
    for p in projects:
        open_findings = db.query(models.Finding).filter(
            models.Finding.repository_id == p.id,
            models.Finding.status == 'open'
        ).count()
        
        results.append({
            "id": str(p.id),
            "name": p.name,
            "description": p.description,
            "language": p.language or "Unknown",
            "last_scanned_at": p.last_scanned_at,
            "stats": {
                "open_findings": open_findings
            }
        })
    
    return results

@router.get("/{project_id}")
async def get_project_details(project_id: str, db: Session = Depends(get_db)):
    """Get basic details for a specific project."""
    try:
        # Try to parse UUID
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        # Fallback to name search if not a UUID (for convenience)
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Calculate aggregate stats
    open_findings_count = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.status == 'open'
    ).count()
    
    return {
        "id": str(project.id),
        "name": project.name,
        "description": project.description,
        "language": project.language or "Unknown",
        "default_branch": project.default_branch or "main",
        "last_scanned_at": project.last_scanned_at,
        "stats": {
            "open_findings": open_findings_count,
            # Placeholders for fields not yet in DB but in UI plan
            "stars": 0,
            "forks": 0,
            "loc": 0
        }
    }

@router.get("/{project_id}/secrets")
async def get_project_secrets(project_id: str, db: Session = Depends(get_db)):
    """Get secrets findings for a project."""
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()
        
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.finding_type == 'secret',
        models.Finding.status == 'open'
    ).all()

    return [{
        "id": str(f.finding_uuid),
        "title": f.title,
        "severity": f.severity,
        "file_path": f.file_path,
        "line": f.line_start,
        "description": f.description,
        "created_at": f.created_at
    } for f in findings]

@router.get("/{project_id}/sast")
async def get_project_sast(project_id: str, db: Session = Depends(get_db)):
    """Get SAST (Semgrep/CodeQL) findings for a project."""
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.finding_type == 'sast',
        models.Finding.status == 'open'
    ).all()

    return [{
        "id": str(f.finding_uuid),
        "title": f.title,
        "severity": f.severity,
        "file_path": f.file_path,
        "line": f.line_start,
        "description": f.description,
        "created_at": f.created_at
    } for f in findings]

@router.get("/{project_id}/terraform")
async def get_project_terraform(project_id: str, db: Session = Depends(get_db)):
    """Get Terraform/IaC findings for a project."""
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.finding_type == 'iac',
        models.Finding.status == 'open'
    ).all()

    return [{
        "id": str(f.finding_uuid),
        "title": f.title,
        "severity": f.severity,
        "file_path": f.file_path,
        "line": f.line_start,
        "description": f.description,
        "created_at": f.created_at
    } for f in findings]

@router.get("/{project_id}/oss")
async def get_project_oss(project_id: str, db: Session = Depends(get_db)):
    """Get OSS/Dependency findings for a project."""
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.finding_type == 'oss',
        models.Finding.status == 'open'
    ).all()

    return [{
        "id": str(f.finding_uuid),
        "title": f.title,
        "severity": f.severity,
        "file_path": f.file_path,
        "line": f.line_start,
        "description": f.description,
        "created_at": f.created_at
    } for f in findings]

@router.get("/{project_id}/runs")
async def get_project_runs(project_id: str, db: Session = Depends(get_db)):
    """Get scan runs for a project."""
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    runs = db.query(models.ScanRun).filter(
        models.ScanRun.repository_id == project.id
    ).order_by(models.ScanRun.created_at.desc()).limit(50).all()

    return [{
        "id": str(r.id),
        "scan_type": r.scan_type,
        "status": r.status,
        "findings_count": r.findings_count,
        "created_at": r.created_at,
        "completed_at": r.completed_at,
        "duration_seconds": r.duration_seconds
    } for r in runs]
