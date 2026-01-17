from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from typing import List, Dict, Any, Optional
from loguru import logger
from ..dependencies import get_tenant_db
from ..database import  get_current_org_id
from .. import models
import uuid
from pydantic import BaseModel
from datetime import datetime
from src.rbac.dependencies import require_permissions
import os

router = APIRouter(
    prefix="/projects",
    tags=["projects"]
)


def _get_current_organization_id(db: Session) -> Optional[str]:
    """
    Get the current organization ID from context.
    Uses the global org context set by /organizations/{name}/select.
    """
    # Use the global org context from database.py
    org_id = get_current_org_id()
    if org_id:
        return org_id
    
    # Fall back to default organization if no context is set
    try:
        result = db.execute(text("SELECT id FROM organizations WHERE is_default = true LIMIT 1"))
        row = result.fetchone()
        if row:
            return str(row[0])
    except Exception:
        pass
    
    return None


@router.get("/")
async def get_projects(
    db: Session = Depends(get_tenant_db),
    organization_id: Optional[str] = Query(None, description="Filter by organization ID")
):
    """
    Get a list of all projects with summary stats.
    
    Multi-tenant: Results are scoped to the current organization.
    """
    # Get organization ID for multi-tenant scoping
    org_id = organization_id or _get_current_organization_id(db)
    
    # Build query with optional organization filter
    query = db.query(models.Repository)
    if org_id:
        query = query.filter(models.Repository.organization_id == org_id)
    
    projects = query.all()

    results = []
    for p in projects:
        open_findings = db.query(models.Finding).filter(
            models.Finding.repository_id == p.id,
            models.Finding.status == 'open'
        ).count()

        # Get the most recent commit date from contributors (fallback)
        last_commit = db.query(func.max(models.Contributor.last_commit_at)).filter(
            models.Contributor.repository_id == p.id
        ).scalar()

        # Get highest severity from SAST findings
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        sast_findings = db.query(models.Finding).filter(
            models.Finding.repository_id == p.id,
            models.Finding.finding_type == 'sast',
            models.Finding.status == 'open'
        ).all()

        max_severity = None
        max_severity_value = 0
        for finding in sast_findings:
            severity = finding.severity.lower() if finding.severity else 'low'
            severity_value = severity_order.get(severity, 0)
            if severity_value > max_severity_value:
                max_severity_value = severity_value
                max_severity = finding.severity

        results.append({
            "id": str(p.id),
            "name": p.name,
            "description": p.description,
            "language": p.language or "Unknown",
            "default_branch": p.default_branch or "main",
            "last_scanned_at": p.last_scanned_at,
            # Use pushed_at from GitHub API, fallback to contributor data
            "last_commit_at": p.pushed_at or last_commit,
            "pushed_at": p.pushed_at,
            "visibility": p.visibility,
            "is_archived": p.is_archived,
            "is_private": p.is_private,
            "max_severity": max_severity,
            "stats": {
                "open_findings": open_findings,
                "stars": p.stargazers_count or 0,
                "forks": p.forks_count or 0,
            }
        })

    return results

@router.get("/{project_id}")
async def get_project_details(project_id: str, db: Session = Depends(get_tenant_db)):
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
        "full_name": project.full_name,
        "description": project.description,
        "url": project.url,
        "language": project.language or "Unknown",
        "default_branch": project.default_branch or "main",
        "last_scanned_at": project.last_scanned_at,
        # GitHub API metadata
        "pushed_at": project.pushed_at,
        "github_created_at": project.github_created_at,
        "github_updated_at": project.github_updated_at,
        "visibility": project.visibility,
        "is_archived": project.is_archived,
        "is_private": project.is_private,
        "is_fork": project.is_fork,
        "topics": project.topics or [],
        "license_name": project.license_name,
        "has_wiki": project.has_wiki,
        "has_pages": project.has_pages,
        "has_discussions": project.has_discussions,
        "stats": {
            "open_findings": open_findings_count,
            "stars": project.stargazers_count or 0,
            "forks": project.forks_count or 0,
            "watchers": project.watchers_count or 0,
            "open_issues": project.open_issues_count or 0,
            "size_kb": project.size_kb or 0,
        }
    }

@router.get("/{project_id}/secrets")
async def get_project_secrets(project_id: str, db: Session = Depends(get_tenant_db)):
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
async def get_project_sast(project_id: str, db: Session = Depends(get_tenant_db)):
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

class FileWithSeverity(BaseModel):
    """File entry with security severity data."""
    path: str
    severity: Optional[str]
    findings_count: int = 0


class ContributorSummary(BaseModel):
    """Summary for table display."""
    id: str
    name: str
    email: Optional[str]
    github_username: Optional[str]
    commits: int
    commit_percentage: Optional[float]
    last_commit_at: Optional[datetime]
    languages: List[str]
    files_count: int
    folders_count: int
    risk_score: int
    highest_severity: Optional[str]

    model_config = {"from_attributes": True}


class ContributorDetail(BaseModel):
    """Full contributor details for modal display."""
    id: str
    name: str
    email: Optional[str]
    github_username: Optional[str]
    commits: int
    commit_percentage: Optional[float]
    last_commit_at: Optional[datetime]
    languages: List[str]
    files_contributed: List[FileWithSeverity]
    folders_contributed: List[str]
    risk_score: int
    ai_summary: Optional[str]
    # Computed stats for modal
    critical_files_count: int = 0
    high_files_count: int = 0
    medium_files_count: int = 0
    low_files_count: int = 0

    model_config = {"from_attributes": True}


class ContributorsResponse(BaseModel):
    """Response for contributors list endpoint."""
    total_contributors: int
    total_commits: int
    bus_factor: int
    team_ai_summary: Optional[str]
    contributors: List[ContributorSummary]


# Keep old response model for backward compatibility
class ContributorResponse(BaseModel):
    id: str
    name: str
    email: Optional[str]
    commits: int
    last_commit_at: Optional[datetime]
    languages: List[str]
    risk_score: int

    model_config = {"from_attributes": True}


@router.get("/{project_id}/contributors", response_model=ContributorsResponse)
def get_project_contributors(
    project_id: str,
    db: Session = Depends(get_tenant_db),
    limit: int = 100
):
    """Get all contributors with summary data for table display."""
    try:
        repo_uuid = uuid.UUID(project_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    repo = db.query(models.Repository).filter(models.Repository.id == repo_uuid).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    contributors = db.query(models.Contributor).filter(
        models.Contributor.repository_id == repo_uuid
    ).order_by(models.Contributor.commits.desc()).limit(limit).all()

    total_commits = sum(c.commits for c in contributors)

    # Calculate bus factor (minimum contributors needed for 50% of commits)
    bus_factor = 0
    cumulative = 0
    threshold = total_commits * 0.5
    for i, c in enumerate(contributors, 1):
        cumulative += c.commits
        if cumulative >= threshold:
            bus_factor = i
            break

    # Build summary responses
    summaries = []
    for c in contributors:
        files = c.files_contributed or []

        # Get highest severity
        severities = [f.get('severity') for f in files if f.get('severity')]
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        highest = None
        if severities:
            highest = min(severities, key=lambda s: severity_order.get(s, 99))

        summaries.append(ContributorSummary(
            id=str(c.id),
            name=c.name,
            email=c.email,
            github_username=c.github_username,
            commits=c.commits,
            commit_percentage=float(c.commit_percentage) if c.commit_percentage else None,
            last_commit_at=c.last_commit_at,
            languages=c.languages or [],
            files_count=len(files),
            folders_count=len(c.folders_contributed or []),
            risk_score=c.risk_score or 0,
            highest_severity=highest
        ))

    return ContributorsResponse(
        total_contributors=len(contributors),
        total_commits=total_commits,
        bus_factor=bus_factor,
        team_ai_summary=None,  # Can be populated from repo-level AI analysis
        contributors=summaries
    )


@router.get("/{project_id}/contributors/{contributor_id}", response_model=ContributorDetail)
def get_contributor_detail(
    project_id: str,
    contributor_id: str,
    db: Session = Depends(get_tenant_db)
):
    """Get full contributor details for modal display."""
    try:
        repo_uuid = uuid.UUID(project_id)
        contrib_uuid = uuid.UUID(contributor_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid ID format")

    contributor = db.query(models.Contributor).filter(
        models.Contributor.id == contrib_uuid,
        models.Contributor.repository_id == repo_uuid
    ).first()

    if not contributor:
        raise HTTPException(status_code=404, detail="Contributor not found")

    files = contributor.files_contributed or []

    # Count files by severity
    critical_count = len([f for f in files if f.get('severity') == 'critical'])
    high_count = len([f for f in files if f.get('severity') == 'high'])
    medium_count = len([f for f in files if f.get('severity') == 'medium'])
    low_count = len([f for f in files if f.get('severity') == 'low'])

    return ContributorDetail(
        id=str(contributor.id),
        name=contributor.name,
        email=contributor.email,
        github_username=contributor.github_username,
        commits=contributor.commits,
        commit_percentage=float(contributor.commit_percentage) if contributor.commit_percentage else None,
        last_commit_at=contributor.last_commit_at,
        languages=contributor.languages or [],
        files_contributed=[FileWithSeverity(**f) for f in files],
        folders_contributed=contributor.folders_contributed or [],
        risk_score=contributor.risk_score or 0,
        ai_summary=contributor.ai_summary,
        critical_files_count=critical_count,
        high_files_count=high_count,
        medium_files_count=medium_count,
        low_files_count=low_count
    )

class LanguageStatResponse(BaseModel):
    name: str
    files: int
    lines: int
    blanks: int
    comments: int
    findings: Dict[str, int] # severity -> count

    model_config = {"from_attributes": True}

@router.get("/{project_id}/languages", response_model=List[LanguageStatResponse])
def get_project_languages(project_id: str, db: Session = Depends(get_tenant_db)):
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

    model_config = {"from_attributes": True}

@router.get("/{project_id}/dependencies", response_model=List[DependencyResponse])
def get_project_dependencies(project_id: str, db: Session = Depends(get_tenant_db)):
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
async def get_project_terraform(project_id: str, db: Session = Depends(get_tenant_db)):
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
async def get_project_oss(project_id: str, db: Session = Depends(get_tenant_db)):
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
async def get_project_runs(project_id: str, db: Session = Depends(get_tenant_db)):
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


# =============================================================================
# Security Assessment Report
# =============================================================================

class SecurityReportRequest(BaseModel):
    """Request model for generating security assessment report."""
    include_architecture: bool = True
    include_diagram: bool = True
    highlight_count: int = 10


@router.post("/{project_id}/security-report")
async def generate_security_report(
    project_id: str,
    request: SecurityReportRequest,
    db: Session = Depends(get_tenant_db)
):
    """
    Generate an AI-powered security assessment report for a project.
    
    This endpoint aggregates all security findings, architecture analysis,
    and project insights into a comprehensive report with AI-curated highlights.
    """
    import sys
    sys.path.insert(0, '/app/execution')
    
    # Get project
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    logger.info(f"Generating security report for project: {project.name}")

    # Gather all findings (using finding_type column)
    secrets = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.finding_type == "secret"
    ).all()

    sast = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.finding_type == "sast"
    ).all()

    infrastructure = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.finding_type == "iac"
    ).all()

    dependencies = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.finding_type == "oss"
    ).all()

    # Get CI/CD scan runs
    cicd = db.query(models.ScanRun).filter(
        models.ScanRun.repository_id == project.id
    ).all()

    # Get contributors
    contributors = db.query(models.Contributor).filter(
        models.Contributor.repository_id == project.id
    ).all()

    # Get languages (using LanguageStat model)
    languages = db.query(models.LanguageStat).filter(
        models.LanguageStat.repository_id == project.id
    ).all()

    # SBOM is not yet implemented as a model - return empty list
    sbom = []

    # Get API audit results - only successful authentications (2xx status codes)
    # Filter out 404s, connection failures, and other unsuccessful attempts
    try:
        api_audit_all = db.query(models.CredentialUrlTestResult).filter(
            models.CredentialUrlTestResult.repository_id == project.id
        ).all()
        # Only include successful exploits/compromises (2xx status codes)
        api_audit = [
            a for a in api_audit_all 
            if a.auth_status_code and 200 <= a.auth_status_code < 300
        ]
    except Exception:
        api_audit = []

    # Get architecture report if available
    architecture_report = project.architecture_report or ""
    # Note: architecture_diagram contains Python code, not the image
    # We need to execute the code to generate the image
    architecture_diagram = None
    if request.include_diagram and project.architecture_diagram:
        try:
            from .ai import execute_diagram_code
            architecture_diagram = execute_diagram_code(
                project.architecture_diagram,
                report_context=architecture_report
            )
            logger.info(f"Generated architecture diagram for project {project_id}")
        except Exception as e:
            logger.warning(f"Failed to generate architecture diagram: {e}")
    
    # Calculate risk scores
    risk_scores = _calculate_risk_scores(secrets, sast, infrastructure, dependencies)

    # Generate AI-powered executive summary and highlights
    executive_summary, highlight_reel, architecture_insights = await _generate_ai_analysis(
        project=project,
        secrets=secrets,
        sast=sast,
        infrastructure=infrastructure,
        dependencies=dependencies,
        api_audit=api_audit,
        architecture_report=architecture_report,
        highlight_count=request.highlight_count
    )

    # Build language breakdown (using lines of code)
    total_lines = sum(l.lines or 0 for l in languages)
    language_breakdown = {}
    if total_lines > 0:
        for lang in languages:
            pct = round((lang.lines or 0) / total_lines * 100, 1)
            if pct > 0:
                language_breakdown[lang.name] = pct

    # Generate critical insights - RCE and other critical vulnerabilities that MUST be highlighted
    critical_insights = _generate_critical_insights(secrets, sast, infrastructure, dependencies)

    # Build response
    report_data = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.utcnow().isoformat(),
        "project": {
            "id": str(project.id),
            "name": project.name,
            "full_name": project.full_name,
            "description": project.description,
            "url": project.url,
            "default_branch": project.default_branch,
            "created_at": project.created_at.isoformat() if project.created_at else None,
            "updated_at": project.updated_at.isoformat() if project.updated_at else None
        },
        "executive_summary": executive_summary,
        "critical_insights": critical_insights,  # RCE and other critical vulnerabilities
        "architecture": {
            "report": architecture_report,
            "diagram_base64": architecture_diagram if request.include_diagram else None,
            "insights": architecture_insights
        },
        "project_insights": {
            "development_evaluation": _evaluate_development(project, contributors, languages),
            "contributor_count": len(contributors),
            "contributor_analysis": _analyze_contributors(contributors),
            "language_breakdown": language_breakdown,
            "additional_context": {
                "total_findings": len(secrets) + len(sast) + len(infrastructure) + len(dependencies),
                "sbom_components": len(sbom),
                "api_endpoints_compromised": len(api_audit),  # Only successful authentications (2xx)
                "scan_runs": len(cicd)
            }
        },
        "highlight_reel": highlight_reel,
        "findings": {
            # Sort all findings by severity: critical, high, medium, low, informational
            "secrets": [_serialize_finding(f) for f in _sort_by_severity(secrets)],
            "sast": [_serialize_finding(f) for f in _sort_by_severity(sast)],
            "infrastructure": [_serialize_finding(f) for f in _sort_by_severity(infrastructure)],
            "dependencies": [_serialize_finding(f) for f in _sort_by_severity(dependencies)],
            "cicd": [_serialize_scan_run(r) for r in cicd],
            "contributors": [_serialize_contributor(c) for c in contributors],
            "languages": language_breakdown,
            "sbom": [_serialize_sbom(s) for s in sbom],
            "api_audit": [_serialize_api_audit(a) for a in api_audit]  # Already sorted by threat_level in frontend
        },
        "risk_score": risk_scores
    }

    logger.info(f"Security report generated for {project.name}")
    return report_data


def _sort_by_severity(findings: List) -> List:
    """Sort findings by severity: critical, high, medium, low, informational."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    return sorted(findings, key=lambda f: severity_order.get((f.severity or "informational").lower(), 5))


def _calculate_risk_scores(secrets, sast, infrastructure, dependencies) -> Dict[str, int]:
    """Calculate risk scores based on findings severity distribution."""
    def score_findings(findings) -> int:
        if not findings:
            return 0
        
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        
        # Weighted score (max 100)
        raw_score = (critical * 25) + (high * 15) + (medium * 5) + (low * 1)
        return min(100, raw_score)
    
    secrets_score = score_findings(secrets)
    sast_score = score_findings(sast)
    infra_score = score_findings(infrastructure)
    deps_score = score_findings(dependencies)
    
    # Overall is weighted average
    overall = int((secrets_score * 0.3) + (sast_score * 0.25) + (infra_score * 0.25) + (deps_score * 0.2))
    
    return {
        "overall": overall,
        "secrets": secrets_score,
        "sast": sast_score,
        "infrastructure": infra_score,
        "dependencies": deps_score
    }


def _evaluate_development(project, contributors, languages) -> str:
    """Generate development evaluation text."""
    parts = []
    
    if len(contributors) > 10:
        parts.append(f"Active project with {len(contributors)} contributors indicating mature development.")
    elif len(contributors) > 3:
        parts.append(f"Moderate team size with {len(contributors)} contributors.")
    else:
        parts.append(f"Small team with {len(contributors)} contributor(s).")
    
    if languages:
        primary = max(languages, key=lambda l: l.lines or 0)
        parts.append(f"Primary language: {primary.name}.")
    
    return " ".join(parts)


def _analyze_contributors(contributors) -> str:
    """Generate contributor analysis text."""
    if not contributors:
        return "No contributor data available."
    
    total_commits = sum(c.commits or 0 for c in contributors)
    top_contributor = max(contributors, key=lambda c: c.commits or 0) if contributors else None
    
    if top_contributor:
        return f"Total {total_commits} commits. Top contributor: {top_contributor.github_username or top_contributor.name or 'Unknown'} with {top_contributor.commits or 0} commits."
    return f"Total {total_commits} commits across {len(contributors)} contributors."


async def _generate_ai_analysis(
    project,
    secrets,
    sast,
    infrastructure,
    dependencies,
    api_audit,
    architecture_report,
    highlight_count
) -> tuple:
    """Generate AI-powered analysis including executive summary and highlight reel."""
    
    # Try to use AI agent for analysis
    try:
        from ai_credential_url_agent import get_ai_provider
        provider = get_ai_provider()
        
        if provider:
            # Build context for AI
            findings_summary = f"""
Project: {project.name}
Description: {project.description or 'N/A'}

Findings Summary:
- Secrets: {len(secrets)} ({sum(1 for f in secrets if f.severity == 'critical')} critical, {sum(1 for f in secrets if f.severity == 'high')} high)
- SAST: {len(sast)} ({sum(1 for f in sast if f.severity == 'critical')} critical, {sum(1 for f in sast if f.severity == 'high')} high)
- Infrastructure: {len(infrastructure)} ({sum(1 for f in infrastructure if f.severity == 'critical')} critical)
- Dependencies: {len(dependencies)} ({sum(1 for f in dependencies if f.severity == 'critical')} critical)
- API Audit: {len(api_audit)} endpoints successfully compromised (2xx responses)

Architecture Overview:
{architecture_report[:2000] if architecture_report else 'No architecture analysis available.'}
"""

            # Generate executive summary
            exec_prompt = f"""You are a senior security analyst. Based on the following security scan results, write a concise executive summary (2-3 paragraphs) highlighting the overall security posture, key risks, and recommended priorities.

{findings_summary}

Write the executive summary in a professional tone suitable for leadership. Focus on business impact and actionable insights."""

            exec_response = await provider.generate(exec_prompt, max_tokens=500)
            executive_summary = exec_response if exec_response else _generate_fallback_summary(project, secrets, sast, infrastructure, dependencies)

            # Generate highlight reel - identify most impactful findings
            highlight_reel = await _generate_highlight_reel(
                provider, secrets, sast, infrastructure, dependencies, api_audit, highlight_count
            )

            # Generate architecture insights
            arch_insights = ""
            if architecture_report:
                arch_prompt = f"""Based on this architecture analysis, provide 2-3 key security insights about the system design:

{architecture_report[:3000]}

Focus on potential attack surfaces, security boundaries, and architectural risks."""
                arch_insights = await provider.generate(arch_prompt, max_tokens=300)

            return executive_summary, highlight_reel, arch_insights

    except Exception as e:
        logger.warning(f"AI analysis failed, using fallback: {e}")

    # Fallback to non-AI analysis
    return (
        _generate_fallback_summary(project, secrets, sast, infrastructure, dependencies),
        _generate_fallback_highlights(secrets, sast, infrastructure, dependencies, api_audit, highlight_count),
        ""
    )


def _generate_fallback_summary(project, secrets, sast, infrastructure, dependencies) -> str:
    """Generate a fallback executive summary without AI."""
    total = len(secrets) + len(sast) + len(infrastructure) + len(dependencies)
    critical = sum(1 for f in secrets + sast + infrastructure + dependencies if f.severity == "critical")
    high = sum(1 for f in secrets + sast + infrastructure + dependencies if f.severity == "high")
    
    summary = f"Security assessment of **{project.name}** identified **{total} findings** across all scan categories. "
    
    if critical > 0:
        summary += f"**{critical} critical** issues require immediate attention. "
    if high > 0:
        summary += f"**{high} high severity** issues should be prioritized for remediation. "
    
    if len(secrets) > 0:
        summary += f"\n\n**Secrets Detection:** {len(secrets)} potential credential exposures were identified. "
    if len(sast) > 0:
        summary += f"**Code Analysis:** {len(sast)} code quality and security issues found. "
    if len(infrastructure) > 0:
        summary += f"**Infrastructure:** {len(infrastructure)} configuration issues detected. "
    if len(dependencies) > 0:
        summary += f"**Dependencies:** {len(dependencies)} vulnerable components identified."
    
    return summary


async def _generate_highlight_reel(provider, secrets, sast, infrastructure, dependencies, api_audit, count) -> List[Dict]:
    """Generate AI-curated highlight reel of most impactful findings."""
    highlights = []
    
    # Prioritize findings by impact potential
    all_findings = []
    
    for f in secrets:
        all_findings.append(("secrets", f, _assess_secret_impact(f)))
    for f in sast:
        all_findings.append(("sast", f, _assess_sast_impact(f)))
    for f in infrastructure:
        all_findings.append(("infrastructure", f, _assess_infra_impact(f)))
    for f in dependencies:
        all_findings.append(("dependencies", f, _assess_dep_impact(f)))
    
    # Sort by impact score
    all_findings.sort(key=lambda x: x[2], reverse=True)
    
    # Take top N
    for category, finding, impact_score in all_findings[:count]:
        # Generate AI analysis for each highlight
        try:
            analysis_prompt = f"""Analyze this security finding and explain its potential impact in 2-3 sentences:

Category: {category}
Title: {finding.title}
Severity: {finding.severity}
File: {finding.file_path or 'N/A'}
Description: {finding.description or finding.message or 'N/A'}

Focus on real-world attack scenarios and business impact."""

            ai_analysis = await provider.generate(analysis_prompt, max_tokens=150)
        except Exception as e:
            logger.warning(f"Failed to generate AI analysis for finding {finding.id}: {str(e)}")
            ai_analysis = f"This {finding.severity} severity {category} finding requires attention due to potential security implications."

        highlights.append({
            "category": category,
            "title": finding.title or "Untitled Finding",
            "severity": finding.severity or "unknown",
            "impact": _get_impact_description(category, finding),
            "finding_id": str(finding.id),
            "analysis": ai_analysis,
            "file_path": finding.file_path,
            "line": finding.line_start,
            "code_snippet": finding.code_snippet  # Full unredacted code for security analyst validation
        })
    
    return highlights


def _generate_fallback_highlights(secrets, sast, infrastructure, dependencies, api_audit, count) -> List[Dict]:
    """Generate highlight reel without AI."""
    highlights = []
    all_findings = []
    
    for f in secrets:
        all_findings.append(("secrets", f, _assess_secret_impact(f)))
    for f in sast:
        all_findings.append(("sast", f, _assess_sast_impact(f)))
    for f in infrastructure:
        all_findings.append(("infrastructure", f, _assess_infra_impact(f)))
    for f in dependencies:
        all_findings.append(("dependencies", f, _assess_dep_impact(f)))
    
    all_findings.sort(key=lambda x: x[2], reverse=True)
    
    for category, finding, _ in all_findings[:count]:
        highlights.append({
            "category": category,
            "title": finding.title or "Untitled Finding",
            "severity": finding.severity or "unknown",
            "impact": _get_impact_description(category, finding),
            "finding_id": str(finding.id),
            "analysis": f"This {finding.severity} severity finding in {category} should be reviewed for potential security impact.",
            "file_path": finding.file_path,
            "line": finding.line_start,
            "code_snippet": finding.code_snippet  # Full unredacted code for security analyst validation
        })
    
    return highlights


def _assess_secret_impact(finding) -> int:
    """Assess impact score for a secret finding."""
    score = {"critical": 100, "high": 75, "medium": 50, "low": 25}.get(finding.severity, 10)
    
    # Boost score for high-value credential types
    title_lower = (finding.title or "").lower()
    if any(k in title_lower for k in ["aws", "azure", "gcp", "api_key", "private_key", "password"]):
        score += 20
    if "token" in title_lower:
        score += 15
    
    return min(100, score)


def _assess_sast_impact(finding) -> int:
    """Assess impact score for a SAST finding."""
    score = {"critical": 100, "high": 75, "medium": 50, "low": 25}.get(finding.severity, 10)
    
    title_lower = (finding.title or "").lower()
    desc_lower = (finding.description or "").lower()
    combined = title_lower + " " + desc_lower
    
    # RCE findings are ALWAYS critical - maximum score
    # These are the most dangerous vulnerabilities
    rce_keywords = ["remote code execution", "rce", "code execution", "command injection", 
                    "os command", "shell injection", "eval injection", "deserialization"]
    if any(k in combined for k in rce_keywords):
        return 100  # Always max score for RCE
    
    # Other high-impact vulnerabilities
    if any(k in combined for k in ["injection", "xss", "sqli", "command"]):
        score += 25
    if "auth" in combined or "bypass" in combined:
        score += 20
    
    return min(100, score)


def _assess_infra_impact(finding) -> int:
    """Assess impact score for an infrastructure finding."""
    score = {"critical": 100, "high": 75, "medium": 50, "low": 25}.get(finding.severity, 10)
    
    title_lower = (finding.title or "").lower()
    if any(k in title_lower for k in ["public", "exposed", "open", "unencrypted"]):
        score += 20
    
    return min(100, score)


def _assess_dep_impact(finding) -> int:
    """Assess impact score for a dependency finding."""
    score = {"critical": 100, "high": 75, "medium": 50, "low": 25}.get(finding.severity, 10)
    
    # Check for known exploited vulnerabilities
    desc_lower = (finding.description or "").lower()
    if "exploit" in desc_lower or "actively" in desc_lower:
        score += 25
    
    return min(100, score)


def _is_rce_finding(finding) -> bool:
    """Check if a finding is a Remote Code Execution vulnerability."""
    title_lower = (finding.title or "").lower()
    desc_lower = (finding.description or "").lower()
    combined = title_lower + " " + desc_lower
    
    rce_keywords = ["remote code execution", "rce", "code execution", "command injection", 
                    "os command", "shell injection", "eval injection", "deserialization"]
    return any(k in combined for k in rce_keywords)


def _generate_critical_insights(secrets, sast, infrastructure, dependencies) -> List[Dict]:
    """
    Generate critical insights for the report.
    
    Includes:
    - RCE and other critical vulnerabilities (auto-detected)
    - Findings manually marked with include_in_report=True by Security Analyst
    
    Exclusions:
    - Findings marked as 'false_positive' status
    - Findings with severity 'info' or 'informational' (analyst has downgraded)
    
    Severity is determined by vulnerability type, not original finding severity.
    """
    critical_insights = []
    seen_finding_ids = set()  # Track to avoid duplicates
    
    # Collect all findings
    all_findings = []
    for f in sast:
        all_findings.append(("sast", f))
    for f in infrastructure:
        all_findings.append(("infrastructure", f))
    for f in dependencies:
        all_findings.append(("dependencies", f))
    for f in secrets:
        all_findings.append(("secrets", f))
    
    for category, finding in all_findings:
        # Skip false positives
        if getattr(finding, 'status', None) == 'false_positive':
            continue
        
        # Skip findings marked as 'info' or 'informational' by Security Analyst
        finding_severity = (getattr(finding, 'severity', '') or '').lower()
        if finding_severity in ['info', 'informational']:
            continue
        
        title_lower = (finding.title or "").lower()
        desc_lower = (finding.description or "").lower()
        combined = title_lower + " " + desc_lower
        
        insight_type = None
        insight_message = None
        insight_severity = None  # Severity based on vulnerability type
        is_manually_included = getattr(finding, 'include_in_report', False) or False
        
        # RCE - Remote Code Execution (ALWAYS critical)
        if _is_rce_finding(finding):
            insight_type = "Remote Code Execution"
            insight_severity = "critical"
            insight_message = "This vulnerability allows attackers to execute arbitrary code on the server. Immediate remediation required."
        
        # SQL Injection (critical)
        elif any(k in combined for k in ["sql injection", "sqli", "sql query"]):
            insight_type = "SQL Injection"
            insight_severity = "critical"
            insight_message = "This vulnerability allows attackers to manipulate database queries, potentially leading to data theft or modification."
        
        # Authentication Bypass (critical)
        elif any(k in combined for k in ["auth bypass", "authentication bypass", "broken authentication"]):
            insight_type = "Authentication Bypass"
            insight_severity = "critical"
            insight_message = "This vulnerability allows attackers to bypass authentication controls and gain unauthorized access."
        
        # Path Traversal (high)
        elif any(k in combined for k in ["path traversal", "directory traversal", "lfi", "local file inclusion"]):
            insight_type = "Path Traversal"
            insight_severity = "high"
            insight_message = "This vulnerability allows attackers to access files outside the intended directory."
        
        # SSRF (high)
        elif any(k in combined for k in ["ssrf", "server-side request forgery"]):
            insight_type = "Server-Side Request Forgery"
            insight_severity = "high"
            insight_message = "This vulnerability allows attackers to make requests from the server to internal resources."
        
        # XXE (high)
        elif any(k in combined for k in ["xxe", "xml external entity"]):
            insight_type = "XML External Entity"
            insight_severity = "high"
            insight_message = "This vulnerability allows attackers to read files, perform SSRF, or cause denial of service."
        
        # Manually included by Security Analyst (use finding's own severity)
        elif is_manually_included:
            insight_type = "Analyst Highlighted"
            insight_severity = finding_severity if finding_severity in ["critical", "high", "medium", "low"] else "high"
            insight_message = "This finding was manually included in the report by a Security Analyst for executive attention."
        
        if insight_type and str(finding.id) not in seen_finding_ids:
            seen_finding_ids.add(str(finding.id))
            critical_insights.append({
                "type": insight_type,
                "category": category,
                "title": finding.title,
                "severity": insight_severity,  # Severity based on vulnerability type
                "message": insight_message,
                "file_path": finding.file_path,
                "line": finding.line_start,
                "finding_id": str(finding.id),
                "code_snippet": finding.code_snippet,  # Full unredacted for security analyst validation
                "manually_included": is_manually_included
            })
    
    # Sort by severity: critical first, then high
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    critical_insights.sort(key=lambda x: severity_order.get(x["severity"], 4))
    
    return critical_insights


def _get_impact_description(category: str, finding) -> str:
    """Generate impact description for a finding."""
    severity = finding.severity or "unknown"
    
    # Special handling for RCE - always critical impact description
    if _is_rce_finding(finding):
        return "⚠️ CRITICAL: Remote Code Execution vulnerability allows attackers to execute arbitrary code on the server, potentially leading to complete system compromise, data theft, and lateral movement within the network."
    
    if category == "secrets":
        return f"Potential credential exposure could lead to unauthorized access to systems or data."
    elif category == "sast":
        return f"Code vulnerability could be exploited to compromise application security."
    elif category == "infrastructure":
        return f"Infrastructure misconfiguration could expose systems to unauthorized access."
    elif category == "dependencies":
        return f"Vulnerable dependency could be exploited through known attack vectors."
    
    return f"Security issue requiring review and remediation."


def _serialize_finding(f) -> Dict:
    """Serialize a finding to dict with full code snippet (unredacted)."""
    return {
        "id": str(f.id),
        "title": f.title,
        "severity": f.severity,
        "file_path": f.file_path,
        "line": f.line_start,
        "description": f.description,
        "message": getattr(f, 'message', None) or f.description,
        "finding_type": f.finding_type,
        "code_snippet": f.code_snippet,  # Full unredacted code snippet for security analyst validation
        "scanner_name": f.scanner_name,
        "is_verified_by_scanner": f.is_verified_by_scanner,
        "is_validated_active": f.is_validated_active
    }


def _serialize_scan_run(r) -> Dict:
    """Serialize a scan run to dict."""
    return {
        "id": str(r.id),
        "scan_type": r.scan_type,
        "status": r.status,
        "findings_count": r.findings_count,
        "created_at": r.created_at.isoformat() if r.created_at else None
    }


def _serialize_contributor(c) -> Dict:
    """Serialize a contributor to dict."""
    return {
        "login": c.github_username,
        "name": c.name,
        "commits": c.commits,
        "email": c.email,
        "risk_score": c.risk_score
    }


def _serialize_sbom(s) -> Dict:
    """Serialize an SBOM component to dict."""
    return {
        "name": s.name,
        "version": s.version,
        "type": s.type,
        "purl": s.purl,
        "license": s.license
    }


def _serialize_api_audit(a) -> Dict:
    """Serialize an API audit result to dict with full details including credential values."""
    return {
        "id": str(a.id),
        "target_url": a.target_url,
        "credential_type": a.credential_type,
        "credential_value": a.credential_value,  # Full unredacted credential for security analyst validation
        "credential_environment": a.credential_environment,
        "confidence_score": a.confidence_score,
        # Authentication Results
        "auth_status": a.auth_status,
        "auth_status_code": a.auth_status_code,
        "auth_response_time_ms": a.auth_response_time_ms,
        "auth_error_message": a.auth_error_message,
        "auth_request_method": a.auth_request_method,
        # Service Detection
        "detected_service": a.detected_service,
        "service_detection_score": a.service_detection_score,
        # Path Discovery
        "discovered_paths": a.discovered_paths or [],
        "discovered_paths_count": a.discovered_paths_count or 0,
        "hidden_paths_found": a.hidden_paths_found or 0,
        # Data Sampling
        "sample_data_retrieved": a.sample_data_retrieved or [],
        "data_sensitivity_indicators": a.data_sensitivity_indicators or [],
        # OSINT Results
        "osint_findings": a.osint_findings or [],
        "github_repos_found": a.github_repos_found or 0,
        "documentation_links_found": a.documentation_links_found or 0,
        # Analysis
        "overview": a.ai_overview,
        "risk_assessment": a.ai_risk_assessment,
        "recommendations": a.ai_recommendations or [],
        "threat_level": a.threat_level,
        # Metadata
        "test_mode": a.test_mode,
        "tested_at": a.tested_at.isoformat() if a.tested_at else None,
        "test_duration_seconds": a.test_duration_seconds
    }
