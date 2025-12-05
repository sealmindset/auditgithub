from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any, Optional
from ..database import get_db
from .. import models
from .. import models
import uuid
from pydantic import BaseModel
from datetime import datetime
import os

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

class ContributorResponse(BaseModel):
    id: str
    name: str
    email: Optional[str]
    commits: int
    last_commit_at: Optional[datetime]
    languages: List[str]
    risk_score: int

    class Config:
        orm_mode = True

@router.get("/{project_id}/contributors", response_model=List[ContributorResponse])
def get_project_contributors(project_id: str, db: Session = Depends(get_db)):
    """Get contributors for a project."""
    # Try to parse UUID
    try:
        uuid_obj = uuid.UUID(project_id)
    except ValueError:
        # If not UUID, try to find by name (assuming project_id might be name in some contexts, 
        # but for now let's stick to UUID or handle 404)
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    repo = db.query(models.Repository).filter(models.Repository.id == uuid_obj).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Project not found")

    return [ContributorResponse(
        id=str(c.id),
        name=c.name,
        email=c.email,
        commits=c.commits,
        last_commit_at=c.last_commit_at,
        languages=c.languages if c.languages else [],
        risk_score=c.risk_score
    ) for c in repo.contributors]

class LanguageStatResponse(BaseModel):
    name: str
    files: int
    lines: int
    blanks: int
    comments: int
    findings: Dict[str, int] # severity -> count

    class Config:
        orm_mode = True

@router.get("/{project_id}/languages", response_model=List[LanguageStatResponse])
def get_project_languages(project_id: str, db: Session = Depends(get_db)):
    """Get language stats and findings for a project."""
    try:
        uuid_obj = uuid.UUID(project_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    repo = db.query(models.Repository).filter(models.Repository.id == uuid_obj).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get all findings for this repo
    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == repo.id,
        models.Finding.status == 'open'
    ).all()

    # Map extensions to languages (simplified map for now)
    # In a real app, we might use a library or DB table for this
    ext_map = {
        '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript',
        '.jsx': 'JavaScript', '.go': 'Go', '.java': 'Java', '.c': 'C', '.cpp': 'C++',
        '.rb': 'Ruby', '.php': 'PHP', '.rs': 'Rust', '.html': 'HTML', '.css': 'CSS',
        '.sh': 'Shell', '.yml': 'YAML', '.yaml': 'YAML', '.json': 'JSON', '.md': 'Markdown',
        '.sql': 'SQL', '.dockerfile': 'Docker', '.tf': 'HCL'
    }

    # Aggregate findings by language
    findings_by_lang = {} # lang -> {severity -> count}
    
    for f in findings:
        ext = os.path.splitext(f.file_path)[1].lower() if f.file_path else ""
        lang = ext_map.get(ext, "Other")
        
        if lang not in findings_by_lang:
            findings_by_lang[lang] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            
        severity = f.severity.lower()
        if severity in findings_by_lang[lang]:
            findings_by_lang[lang][severity] += 1

    # Combine with stored language stats
    results = []
    for stat in repo.languages:
        f_stats = findings_by_lang.get(stat.name, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        results.append(LanguageStatResponse(
            name=stat.name,
            files=stat.files,
            lines=stat.lines,
            blanks=stat.blanks,
            comments=stat.comments,
            findings=f_stats
        ))
        
    # Sort by lines of code desc
    results.sort(key=lambda x: x.lines, reverse=True)
    
    return results

class DependencyResponse(BaseModel):
    id: str
    name: str
    version: str
    type: str
    package_manager: str
    license: str
    locations: List[str]
    source: Optional[str]
    
    # Enriched fields
    vulnerability_count: int = 0
    max_severity: str = "Safe"
    ai_analysis: Optional[Dict[str, Any]] = None
    
    class Config:
        orm_mode = True

@router.get("/{project_id}/dependencies", response_model=List[DependencyResponse])
def get_project_dependencies(project_id: str, db: Session = Depends(get_db)):
    """Get dependencies (SBOM) for a project, enriched with vulnerability data."""
    try:
        uuid_obj = uuid.UUID(project_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    repo = db.query(models.Repository).filter(models.Repository.id == uuid_obj).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Project not found")

    # 1. Fetch all dependencies
    dependencies = repo.dependencies
    
    # 2. Fetch all findings for this repo that are related to dependencies
    # We assume findings with package_name are dependency findings
    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == repo.id,
        models.Finding.package_name.isnot(None)
    ).all()
    
    # Map findings to dependencies (name + version)
    findings_map = {} # (name, version) -> [findings]
    for f in findings:
        key = (f.package_name, f.package_version)
        if key not in findings_map:
            findings_map[key] = []
        findings_map[key].append(f)
        
    # 3. Fetch all component analyses
    # We can't easily filter by list of tuples in SQL without complex query, 
    # so we might fetch all relevant ones or just fetch individually if list is small.
    # For now, let's fetch all analyses that match any dependency name in this repo
    dep_names = [d.name for d in dependencies]
    analyses = db.query(models.ComponentAnalysis).filter(
        models.ComponentAnalysis.package_name.in_(dep_names)
    ).all()
    
    analysis_map = {} # (name, version, manager) -> analysis
    for a in analyses:
        # Normalize manager if needed, but for now assume exact match
        key = (a.package_name, a.version, a.package_manager)
        analysis_map[key] = a

    results = []
    for d in dependencies:
        # Find matching findings
        # Try exact match first
        related_findings = findings_map.get((d.name, d.version), [])
        
        # Calculate max severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "safe": -1}
        max_sev = "Safe"
        max_score = -1
        
        for f in related_findings:
            s = f.severity.lower() if f.severity else "low"
            score = severity_order.get(s, 0)
            if score > max_score:
                max_score = score
                max_sev = f.severity
        
        if not related_findings and max_score == -1:
             max_sev = "Safe"

        # Find matching analysis
        # We need to be careful with package_manager names matching
        # Syft might say 'npm', we store 'npm'.
        analysis = analysis_map.get((d.name, d.version, d.package_manager))
        analysis_data = None
        if analysis:
            analysis_data = {
                "vulnerability_summary": analysis.vulnerability_summary,
                "analysis_text": analysis.analysis_text,
                "severity": analysis.severity,
                "exploitability": analysis.exploitability,
                "fixed_version": analysis.fixed_version,
                "source": "cache"
            }

        results.append(DependencyResponse(
            id=str(d.id),
            name=d.name,
            version=d.version or "Unknown",
            type=d.type or "Unknown",
            package_manager=d.package_manager or "Unknown",
            license=d.license or "Unknown",
            locations=d.locations if d.locations else [],
            source=d.source,
            vulnerability_count=len(related_findings),
            max_severity=max_sev,
            ai_analysis=analysis_data
        ))
        
    return results

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
