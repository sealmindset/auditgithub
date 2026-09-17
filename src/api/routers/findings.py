from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import and_, case, func, or_
from typing import List, Optional, Dict
from loguru import logger
from ..dependencies import get_tenant_db
from ..database import get_current_org_id
from ..config import settings
from .. import models
from pydantic import BaseModel, Field
from datetime import datetime
import uuid
from ..utils.risk_scoring import calculate_risk_score, get_risk_level
from src.auth.dependencies import get_current_user
from src.auth.models import User
from src.rbac.dependencies import require_permissions
from src.api.schemas.common import LIST_ERRORS, CRUD_ERRORS, CREATE_ERRORS, DELETE_ERRORS

router = APIRouter(
    prefix="/findings",
    tags=["findings"]
)

# Severity priority for sorting (lower = higher priority)
SEVERITY_PRIORITY = {
    'critical': 1,
    'high': 2,
    'medium': 3,
    'low': 4,
    'info': 5,
    'warning': 6
}

class RemediationModel(BaseModel):
    """A remediation suggestion generated for a security finding."""
    id: str = Field(description="Unique identifier for the remediation entry")
    remediation_text: str = Field(description="Human-readable remediation guidance text")
    diff: Optional[str] = Field(default=None, description="Suggested code diff to apply the remediation")
    confidence: Optional[float] = Field(default=None, description="AI confidence score for this remediation (0.0-1.0)")
    created_at: datetime = Field(description="Timestamp when the remediation was generated")

    model_config = {"from_attributes": True}

class FindingResponse(BaseModel):
    """Full representation of a security finding with enrichment data."""
    id: str = Field(description="Unique UUID identifier for the finding")
    title: str = Field(description="Short title summarizing the finding")
    description: Optional[str] = Field(default=None, description="Detailed description of the security finding")
    severity: str = Field(description="Severity level: critical, high, medium, low, info, or warning")
    status: str = Field(description="Current status of the finding (e.g. open, resolved)")
    scanner_name: Optional[str] = Field(default=None, description="Name of the scanner that detected this finding")
    rule_id: Optional[str] = Field(
        default=None,
        description=(
            "Scanner's own rule identifier. With scanner_name it identifies the "
            "defect, which is what AuditBoard filings are grouped and matched on."
        ),
    )
    file_path: Optional[str] = Field(default=None, description="Path to the file where the finding was detected")
    line_start: Optional[int] = Field(default=None, description="Starting line number within the file")
    code_snippet: Optional[str] = Field(default=None, description="Relevant code snippet around the finding")
    created_at: datetime = Field(description="Timestamp when the finding was first detected")
    repo_pushed_at: Optional[datetime] = Field(default=None, description="Last push to the repository (from GitHub API)")
    file_last_commit_at: Optional[datetime] = Field(default=None, description="Last commit date for the specific file")
    file_last_commit_author: Optional[str] = Field(default=None, description="Author of the last commit to the specific file")
    repo_name: str = Field(description="Name of the repository where the finding was detected")
    repository_id: Optional[str] = Field(default=None, description="Unique identifier of the repository")
    is_archived: Optional[bool] = Field(default=None, description="Whether the repository is archived on GitHub")
    investigation_status: Optional[str] = Field(default=None, description="Investigation workflow status: triage, incident_response, or resolved")
    investigation_started_at: Optional[datetime] = Field(default=None, description="Timestamp when investigation was started")
    # Risk scoring (Phase 1.1)
    risk_score: Optional[int] = Field(default=None, description="Computed risk score (0-100) combining severity, exposure, and activity")
    risk_level: Optional[str] = Field(default=None, description="Risk level derived from risk score: critical, high, medium, or low")
    risk_factors: Optional[Dict] = Field(default=None, description="Breakdown of individual risk factor contributions")
    # Snooze (Phase 1.2)
    snoozed_until: Optional[datetime] = Field(default=None, description="If snoozed, the datetime when the finding becomes active again")
    snooze_reason: Optional[str] = Field(default=None, description="Reason provided for snoozing this finding")
    # AI Triage (Phase 3.2)
    ai_triage_recommendation: Optional[str] = Field(default=None, description="AI-generated triage recommendation text")
    ai_triage_confidence: Optional[float] = Field(default=None, description="AI confidence in the triage recommendation (0.0-1.0)")
    # Report inclusion
    include_in_report: Optional[bool] = Field(default=False, description="Whether to include this finding in the Critical Insights report section")
    remediations: List[RemediationModel] = Field(default=[], description="List of remediation suggestions for this finding")

    model_config = {"from_attributes": True}


class PaginatedFindingsResponse(BaseModel):
    """Paginated response for findings with metadata for UI pagination."""
    items: List[FindingResponse] = Field(description="List of finding objects for the current page")
    total: int = Field(description="Total number of findings matching the query filters")
    page: int = Field(description="Current page number (1-indexed)")
    page_size: int = Field(description="Number of items per page")
    total_pages: int = Field(description="Total number of pages available")
    has_next: bool = Field(description="Whether a next page exists")
    has_prev: bool = Field(description="Whether a previous page exists")


# Redis cache helper
def get_redis_client():
    """Get Redis client for caching."""
    from src.auth.tokens import redis_client
    return redis_client


def get_findings_cache_key(org_id: Optional[str], page: int, page_size: int,
                           severity: Optional[str], status: Optional[str],
                           repo_name: Optional[str], order_by: str) -> str:
    """Generate cache key for findings query."""
    return f"findings:v1:{org_id or 'all'}:{page}:{page_size}:{severity or ''}:{status or ''}:{repo_name or ''}:{order_by}"


def get_count_cache_key(org_id: Optional[str], severity: Optional[str],
                        status: Optional[str], repo_name: Optional[str]) -> str:
    """Generate cache key for findings count."""
    return f"findings_count:v1:{org_id or 'all'}:{severity or ''}:{status or ''}:{repo_name or ''}"


@router.get(
    "/paginated",
    dependencies=[Depends(require_permissions("findings:read"))],
    response_model=PaginatedFindingsResponse,
    summary="List findings with pagination",
    responses={**LIST_ERRORS, 403: {"description": "Insufficient permissions - requires findings:read"}},
)
def get_findings_paginated(
    page: int = 1,
    page_size: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    repo_name: Optional[str] = None,
    order_by: Optional[str] = "severity",
    include_snoozed: Optional[bool] = False,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """Get paginated findings with caching for better performance.

    Returns findings with pagination metadata for efficient UI rendering.
    Results are cached in Redis for 60 seconds to reduce database load.
    Requires the ``findings:read`` permission.
    """
    import json

    org_id = get_current_org_id()
    redis = get_redis_client()

    # Validate pagination params
    if page < 1:
        page = 1
    if page_size < 1 or page_size > 100:
        page_size = 50

    skip = (page - 1) * page_size

    # Try to get count from cache
    count_cache_key = get_count_cache_key(org_id, severity, status, repo_name)
    cached_count = None
    try:
        cached_count = redis.get(count_cache_key)
        if cached_count:
            cached_count = int(cached_count)
    except Exception as e:
        logger.warning(f"Redis cache read error: {e}")

    # Build base query for counting
    count_query = db.query(func.count(models.Finding.id)).join(models.Repository)

    if org_id:
        count_query = count_query.filter(models.Finding.organization_id == org_id)
    if severity:
        count_query = count_query.filter(models.Finding.severity == severity)
    if status:
        count_query = count_query.filter(models.Finding.status == status)
    if repo_name:
        count_query = count_query.filter(models.Repository.name == repo_name)
    if not include_snoozed:
        from sqlalchemy import or_
        count_query = count_query.filter(
            or_(
                models.Finding.snoozed_until.is_(None),
                models.Finding.snoozed_until < datetime.utcnow()
            )
        )

    # Get total count (from cache or query)
    if cached_count is not None:
        total = cached_count
    else:
        total = count_query.scalar() or 0
        # Cache count for 60 seconds
        try:
            redis.setex(count_cache_key, 60, str(total))
        except Exception as e:
            logger.warning(f"Redis cache write error: {e}")

    # Calculate pagination metadata
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    has_next = page < total_pages
    has_prev = page > 1

    # Build data query
    query = db.query(models.Finding).join(models.Repository)

    if org_id:
        query = query.filter(models.Finding.organization_id == org_id)
    if severity:
        query = query.filter(models.Finding.severity == severity)
    if status:
        query = query.filter(models.Finding.status == status)
    if repo_name:
        query = query.filter(models.Repository.name == repo_name)
    if not include_snoozed:
        from sqlalchemy import or_
        query = query.filter(
            or_(
                models.Finding.snoozed_until.is_(None),
                models.Finding.snoozed_until < datetime.utcnow()
            )
        )

    # Order by
    if order_by == "risk_score":
        query = query.order_by(
            models.Finding.risk_score.desc().nullslast(),
            models.Finding.created_at.desc()
        )
    elif order_by == "severity":
        severity_order = case(
            (models.Finding.severity == 'critical', 1),
            (models.Finding.severity == 'high', 2),
            (models.Finding.severity == 'medium', 3),
            (models.Finding.severity == 'low', 4),
            (models.Finding.severity == 'info', 5),
            (models.Finding.severity == 'warning', 6),
            else_=7
        )
        query = query.order_by(severity_order, models.Finding.created_at.desc())
    elif order_by == "repo_name":
        query = query.order_by(models.Repository.name, models.Finding.created_at.desc())
    else:
        query = query.order_by(models.Finding.created_at.desc())

    # Apply pagination
    query = query.offset(skip).limit(page_size)
    findings = query.all()

    # Get file commit data for findings (batch query)
    file_commits_map: Dict[str, models.FileCommit] = {}
    finding_file_keys = [
        (f.repository_id, f.file_path)
        for f in findings
        if f.repository_id and f.file_path
    ]
    if finding_file_keys:
        file_commits = db.query(models.FileCommit).filter(
            models.FileCommit.repository_id.in_([k[0] for k in finding_file_keys])
        ).all()
        for fc in file_commits:
            key = f"{fc.repository_id}:{fc.file_path}"
            file_commits_map[key] = fc

    # Build response items
    items = []
    for f in findings:
        stored_score = f.risk_score
        stored_factors = f.risk_factors
        if stored_score is None:
            computed_score, computed_factors = calculate_risk_score(f, f.repository)
            stored_score = computed_score
            stored_factors = computed_factors

        fc_key = f"{f.repository_id}:{f.file_path}"
        items.append(FindingResponse(
            id=str(f.finding_uuid),
            title=f.title,
            description=f.description,
            severity=f.severity,
            status=f.status,
            scanner_name=f.scanner_name,
            rule_id=f.rule_id,
            file_path=f.file_path,
            line_start=f.line_start,
            code_snippet=f.code_snippet,
            created_at=f.created_at,
            repo_pushed_at=f.repository.pushed_at if f.repository else None,
            file_last_commit_at=file_commits_map.get(fc_key).last_commit_date if fc_key in file_commits_map else None,
            file_last_commit_author=file_commits_map.get(fc_key).last_commit_author if fc_key in file_commits_map else None,
            repo_name=f.repository.name if f.repository else "Unknown",
            repository_id=str(f.repository.id) if f.repository else None,
            is_archived=f.repository.is_archived if f.repository else None,
            investigation_status=f.investigation_status,
            investigation_started_at=f.investigation_started_at,
            risk_score=stored_score,
            risk_level=get_risk_level(stored_score) if stored_score else None,
            risk_factors=stored_factors,
            snoozed_until=f.snoozed_until,
            snooze_reason=f.snooze_reason,
            ai_triage_recommendation=f.ai_triage_recommendation,
            ai_triage_confidence=float(f.ai_triage_confidence) if f.ai_triage_confidence else None,
            remediations=[RemediationModel(
                id=str(r.id),
                remediation_text=r.remediation_text,
                diff=r.diff,
                confidence=float(r.confidence) if r.confidence else None,
                created_at=r.created_at
            ) for r in f.remediations]
        ))

    return PaginatedFindingsResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        has_next=has_next,
        has_prev=has_prev
    )


@router.get(
    "/",
    dependencies=[Depends(require_permissions("findings:read"))],
    response_model=List[FindingResponse],
    summary="List all findings",
    responses={**LIST_ERRORS, 403: {"description": "Insufficient permissions - requires findings:read"}},
)
def get_findings(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    repo_name: Optional[str] = None,
    order_by: Optional[str] = "severity",  # "severity", "created_at", "repo_name", "risk_score"
    include_snoozed: Optional[bool] = False,  # Filter out snoozed findings by default
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """Get all findings with optional filtering, sorting, and offset-based pagination.

    Supports filtering by severity, status, and repository name. Snoozed findings
    are excluded by default. Requires the ``findings:read`` permission.

    Args:
        skip: Number of records to skip (pagination)
        limit: Maximum number of records to return
        severity: Filter by severity (critical, high, medium, low, info)
        status: Filter by status (open, resolved, etc.)
        repo_name: Filter by repository name
        order_by: Sort order - "severity" (default), "created_at", "repo_name", or "risk_score"
        include_snoozed: If False (default), exclude findings snoozed until future date
        current_user: Authenticated user (injected by dependency)
    """
    # TODO(Phase 5): Add additional tenant filtering at query level for defense-in-depth
    # Currently relying on SET search_path, Phase 5 should add explicit WHERE tenant_id= filters
    query = db.query(models.Finding).join(models.Repository)

    # Filter by current organization if one is selected
    org_id = get_current_org_id()
    if org_id:
        query = query.filter(models.Finding.organization_id == org_id)
    
    if severity:
        query = query.filter(models.Finding.severity == severity)
    
    if status:
        query = query.filter(models.Finding.status == status)
    
    if repo_name:
        query = query.filter(models.Repository.name == repo_name)
    
    # Filter out snoozed findings by default
    if not include_snoozed:
        from sqlalchemy import or_
        query = query.filter(
            or_(
                models.Finding.snoozed_until.is_(None),
                models.Finding.snoozed_until < datetime.utcnow()
            )
        )
    
    # Order by severity priority, then by created_at
    if order_by == "risk_score":
        # Sort by risk score descending (nulls last)
        query = query.order_by(
            models.Finding.risk_score.desc().nullslast(),
            models.Finding.created_at.desc()
        )
    elif order_by == "severity":
        severity_order = case(
            (models.Finding.severity == 'critical', 1),
            (models.Finding.severity == 'high', 2),
            (models.Finding.severity == 'medium', 3),
            (models.Finding.severity == 'low', 4),
            (models.Finding.severity == 'info', 5),
            (models.Finding.severity == 'warning', 6),
            else_=7
        )
        query = query.order_by(severity_order, models.Finding.created_at.desc())
    elif order_by == "repo_name":
        query = query.order_by(models.Repository.name, models.Finding.created_at.desc())
    else:  # created_at
        query = query.order_by(models.Finding.created_at.desc())
    
    # Apply pagination - limit=0 means no limit (fetch all)
    if skip > 0:
        query = query.offset(skip)
    if limit > 0:
        query = query.limit(limit)
        
    findings = query.all()
    
    # Get file commit data for findings with file_paths (batch query)
    file_commits_map: Dict[str, models.FileCommit] = {}
    finding_file_keys = [
        (f.repository_id, f.file_path) 
        for f in findings 
        if f.repository_id and f.file_path
    ]
    if finding_file_keys:
        # Query all file commits in one go
        file_commits = db.query(models.FileCommit).filter(
            models.FileCommit.repository_id.in_([k[0] for k in finding_file_keys])
        ).all()
        for fc in file_commits:
            key = f"{fc.repository_id}:{fc.file_path}"
            file_commits_map[key] = fc
    
    # Build response with computed risk scores
    response = []
    for f in findings:
        # Compute risk score if not already stored
        stored_score = f.risk_score
        stored_factors = f.risk_factors
        if stored_score is None:
            computed_score, computed_factors = calculate_risk_score(f, f.repository)
            stored_score = computed_score
            stored_factors = computed_factors
        
        response.append(FindingResponse(
            id=str(f.finding_uuid),
            title=f.title,
            description=f.description,
            severity=f.severity,
            status=f.status,
            scanner_name=f.scanner_name,
            rule_id=f.rule_id,
            file_path=f.file_path,
            line_start=f.line_start,
            code_snippet=f.code_snippet,
            created_at=f.created_at,
            repo_pushed_at=f.repository.pushed_at if f.repository else None,
            file_last_commit_at=file_commits_map.get(f"{f.repository_id}:{f.file_path}").last_commit_date if f.repository_id and f.file_path and f"{f.repository_id}:{f.file_path}" in file_commits_map else None,
            file_last_commit_author=file_commits_map.get(f"{f.repository_id}:{f.file_path}").last_commit_author if f.repository_id and f.file_path and f"{f.repository_id}:{f.file_path}" in file_commits_map else None,
            repo_name=f.repository.name if f.repository else "Unknown",
            repository_id=str(f.repository.id) if f.repository else None,
            is_archived=f.repository.is_archived if f.repository else None,
            investigation_status=f.investigation_status,
            investigation_started_at=f.investigation_started_at,
            # Risk scoring (Phase 1.1)
            risk_score=stored_score,
            risk_level=get_risk_level(stored_score) if stored_score else None,
            risk_factors=stored_factors,
            # Snooze (Phase 1.2)
            snoozed_until=f.snoozed_until,
            snooze_reason=f.snooze_reason,
            # AI Triage (Phase 3.2)
            ai_triage_recommendation=f.ai_triage_recommendation,
            ai_triage_confidence=float(f.ai_triage_confidence) if f.ai_triage_confidence else None,
            remediations=[RemediationModel(
                id=str(r.id),
                remediation_text=r.remediation_text,
                diff=r.diff,
                confidence=float(r.confidence) if r.confidence else None,
                created_at=r.created_at
            ) for r in f.remediations]
        ))
    
    return response

@router.get(
    "/{finding_id}",
    dependencies=[Depends(require_permissions("findings:read"))],
    response_model=FindingResponse,
    summary="Get a finding by ID",
    responses={**CRUD_ERRORS, 403: {"description": "Insufficient permissions - requires findings:read"}},
)
def get_finding(finding_id: str, db: Session = Depends(get_tenant_db)):
    """Retrieve a single security finding by its UUID, including file commit metadata.

    Returns the full finding object with risk scores, remediation suggestions,
    and repository context. Requires the ``findings:read`` permission.
    """
    # Try to parse UUID
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        # Fallback to check primary key id if finding_uuid fails (though model uses finding_uuid for public access usually)
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get file commit data if available
    file_commit = None
    if finding.repository_id and finding.file_path:
        file_commit = db.query(models.FileCommit).filter(
            models.FileCommit.repository_id == finding.repository_id,
            models.FileCommit.file_path == finding.file_path
        ).first()

    return FindingResponse(
        id=str(finding.finding_uuid),
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        status=finding.status,
        scanner_name=finding.scanner_name,
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        line_start=finding.line_start,
        code_snippet=finding.code_snippet,
        created_at=finding.created_at,
        repo_pushed_at=finding.repository.pushed_at if finding.repository else None,
        file_last_commit_at=file_commit.last_commit_date if file_commit else None,
        file_last_commit_author=file_commit.last_commit_author if file_commit else None,
        repo_name=finding.repository.name if finding.repository else "Unknown",
        repository_id=str(finding.repository.id) if finding.repository else None,
        is_archived=finding.repository.is_archived if finding.repository else None,
        investigation_status=finding.investigation_status,
        investigation_started_at=finding.investigation_started_at,
        remediations=[RemediationModel(
            id=str(r.id),
            remediation_text=r.remediation_text,
            diff=r.diff,
            confidence=float(r.confidence) if r.confidence else None,
            created_at=r.created_at
        ) for r in finding.remediations]
    )


# =============================================================================
# Occurrence Grouping (read-only)
# =============================================================================

class FindingOccurrencesResponse(BaseModel):
    """How many findings share this finding's scanner and file path."""
    scope: str = Field(description="Scope the count was taken at: 'specific' or 'global'")
    count: int = Field(description="Number of findings in scope")
    scanner_name: str = Field(description="Scanner the group is keyed on")
    file_path: Optional[str] = Field(default=None, description="File path the group is keyed on")
    repo_names: List[str] = Field(description="Distinct repositories the group spans, sorted")
    sample_findings: List[dict] = Field(description="Up to 5 findings in scope (id, title, file_path, scanner_name, repo_name)")
    org_scoped: bool = Field(description="True when the count was restricted to the caller's current organization")


@router.get(
    "/{finding_id}/occurrences",
    dependencies=[Depends(require_permissions("findings:read"))],
    response_model=FindingOccurrencesResponse,
    summary="Count findings sharing this finding's scanner and file path",
    responses={**CRUD_ERRORS, 403: {"description": "Insufficient permissions - requires findings:read"}},
)
def get_finding_occurrences(
    finding_id: str,
    scope: str = "global",
    db: Session = Depends(get_tenant_db)
):
    """Count the findings that a 'global' action would cover, without changing anything.

    Keyed on scanner name and file path, matching the grouping the exception
    endpoints use, so a caller filing one ticket for a repeated finding reports
    the same population those endpoints would act on.

    Read-only by design. The equivalent count was previously only reachable
    through ``/exception/delete/dry-run``, which requires ``findings:delete``;
    this endpoint requires only ``findings:read``.

    Unlike the exception endpoints, the global count is restricted to the
    caller's current organization when one is set, so the figure does not
    include findings the caller is not currently scoped to.
    """
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if scope not in ["specific", "global"]:
        raise HTTPException(status_code=400, detail="Scope must be 'specific' or 'global'")

    org_id = get_current_org_id()

    def describe(f) -> dict:
        return {
            "id": str(f.finding_uuid),
            "title": f.title,
            "file_path": f.file_path,
            "scanner_name": f.scanner_name,
            "repo_name": f.repository.name if f.repository else None,
        }

    if scope == "specific":
        matches = [finding]
        count = 1
        repo_names = [finding.repository.name] if finding.repository else []
    else:
        query = db.query(models.Finding).filter(
            and_(
                models.Finding.scanner_name == finding.scanner_name,
                models.Finding.file_path == finding.file_path
            )
        )
        if org_id:
            query = query.filter(models.Finding.organization_id == org_id)

        count = query.count()
        matches = query.limit(5).all()

        repo_rows = (
            query.join(models.Repository)
            .with_entities(models.Repository.name)
            .distinct()
            .all()
        )
        repo_names = sorted({row[0] for row in repo_rows if row[0]})

    return FindingOccurrencesResponse(
        scope=scope,
        count=count,
        scanner_name=finding.scanner_name or "Unknown",
        file_path=finding.file_path,
        repo_names=repo_names,
        sample_findings=[describe(f) for f in matches],
        org_scoped=bool(org_id),
    )


# =============================================================================
# Defect Grouping (read-only)
#
# The filing principle lives in services/finding_groups.py. These endpoints
# only report what it measures, so a dialog previews exactly the population the
# filing endpoint will act on.
# =============================================================================

class GroupLocationModel(BaseModel):
    """One place a defect was found, with the scan scaffolding stripped."""
    path: str = Field(description="Repo-relative path, free of the per-scan temp prefix")
    count: int = Field(description="Findings at this path")
    line: Optional[int] = Field(default=None, description="Lowest reported line, omitted when the scanner reports file-level")


class GroupProjectModel(BaseModel):
    """Every location of one defect inside one project."""
    repo_name: str
    finding_count: int = Field(description="Findings in this project")
    location_count: int = Field(description="Distinct locations in this project")
    locations: List[GroupLocationModel]


class FindingGroupResponse(BaseModel):
    """What an issue filed at a given tier would speak for."""
    tier: str = Field(description="Tier measured: 'specific', 'project' or 'org'")
    recommended_tier: str = Field(description="Tier the volume rule points to for this defect")
    fileable_tiers: List[str] = Field(description="Tiers a caller may file at")
    identity_key: str = Field(description="Defect identity the group is keyed on: scanner::rule_id")
    scanner_name: str
    rule_id: Optional[str] = Field(default=None, description="Null when the scanner emitted no rule, which leaves 'specific' the only option")
    members: List[str] = Field(description="Every identity filing under this one. Longer than one only where a reviewer approved a cross-scanner merge.")
    finding_count: int = Field(description="Findings in scope at this tier, measured server-side")
    project_count: int = Field(description="Projects this defect touches, measured across the organization regardless of tier")
    location_count: int = Field(description="Distinct locations in scope")
    locations_omitted: int = Field(default=0, description="Locations the body cap would leave out")
    severity: Optional[str] = Field(default=None, description="Highest severity among the findings in scope")
    severity_breakdown: List[dict] = Field(description="(scanner, severity, count), so scanner disagreement stays visible")
    projects: List[GroupProjectModel]
    location_text: str = Field(description="The location section as it will appear in the issue body")
    org_scoped: bool = Field(description="True when the measurement was restricted to the caller's organization")
    exceeds_threshold: bool = Field(description="True when the defect spans more projects than the escalation threshold")
    escalation_threshold: int = Field(description="Projects a defect may touch before 'org' is recommended")
    fileable: bool = Field(description="False when policy blocks filing this finding at all")
    blocked_reason: Optional[str] = Field(default=None, description="Why filing is blocked, in words a dialog can show")


@router.get(
    "/{finding_id}/group",
    dependencies=[Depends(require_permissions("findings:read"))],
    response_model=FindingGroupResponse,
    summary="Measure the defect group a filing would cover",
    responses={**CRUD_ERRORS, 403: {"description": "Insufficient permissions - requires findings:read"}},
)
def get_finding_group(
    finding_id: str,
    tier: str = "project",
    db: Session = Depends(get_tenant_db),
):
    """Report the population an AuditBoard issue would speak for, without filing.

    Keyed on the defect's identity — ``(scanner_name, rule_id)`` — and the
    project it lives in, which is what the filing endpoint uses. The two read
    the same service, so a dialog cannot preview one population and create an
    issue describing another.

    ``project_count`` is always measured across the organization, even at
    project tier, because it is what decides whether the defect is too
    widespread for one team to own.

    Read-only, and requires only ``findings:read``.
    """
    from ..services import finding_groups as groups

    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        requested = groups.GroupTier(tier)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Tier must be one of: {', '.join(t.value for t in groups.FILEABLE_TIERS)}",
        )
    if requested not in groups.FILEABLE_TIERS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Tier '{tier}' is readable but no longer fileable. It was the "
                "pre-2026-09-16 grouping and is kept only so issues filed then "
                "keep matching their findings."
            ),
        )

    org_id = get_current_org_id()
    equivalence = groups.load_equivalence_map(db, org_id)
    population = groups.measure_group(db, finding, requested, equivalence, org_id)

    fileable, blocked = groups.is_filing_eligible(finding)

    if population is None:
        # No rule_id, so no defect identity. Reported rather than guessed: a
        # fallback to grouping by title would merge unrelated defects.
        return FindingGroupResponse(
            tier=groups.GroupTier.SPECIFIC.value,
            recommended_tier=groups.GroupTier.SPECIFIC.value,
            fileable_tiers=[groups.GroupTier.SPECIFIC.value],
            identity_key="",
            scanner_name=finding.scanner_name or "unknown",
            rule_id=None,
            members=[],
            finding_count=1,
            project_count=1 if finding.repository_id else 0,
            location_count=1 if finding.file_path else 0,
            severity=finding.severity,
            severity_breakdown=[],
            projects=[],
            location_text="Locations\nNone recorded.",
            org_scoped=bool(org_id),
            exceeds_threshold=False,
            escalation_threshold=settings.FILING_PROJECT_ESCALATION_THRESHOLD,
            fileable=fileable,
            blocked_reason=blocked or (
                "This scanner reported no rule identifier, so findings from it "
                "cannot be grouped. Only a single-finding filing is available."
            ),
        )

    max_locations = settings.FILING_MAX_LOCATIONS
    omitted = max(0, population.location_count - max_locations)

    return FindingGroupResponse(
        tier=requested.value,
        recommended_tier=groups.recommended_tier(
            population.project_count, settings.FILING_PROJECT_ESCALATION_THRESHOLD
        ).value,
        fileable_tiers=[t.value for t in groups.FILEABLE_TIERS],
        identity_key=population.identity.key,
        scanner_name=population.identity.scanner_name,
        rule_id=population.identity.rule_id,
        members=[m.key for m in population.members],
        finding_count=population.finding_count,
        project_count=population.project_count,
        location_count=population.location_count,
        locations_omitted=omitted,
        severity=population.severity,
        severity_breakdown=[
            {"scanner": scanner, "severity": severity, "count": count}
            for scanner, severity, count in population.severity_breakdown
        ],
        projects=[
            GroupProjectModel(
                repo_name=project.repo_name,
                finding_count=project.finding_count,
                location_count=project.location_count,
                locations=[
                    GroupLocationModel(path=loc.path, count=loc.count, line=loc.line)
                    for loc in project.locations
                ],
            )
            for project in population.projects
        ],
        location_text=groups.render_locations(population.projects, requested, max_locations),
        org_scoped=population.org_scoped,
        exceeds_threshold=population.exceeds_threshold,
        escalation_threshold=settings.FILING_PROJECT_ESCALATION_THRESHOLD,
        fileable=fileable,
        blocked_reason=blocked,
    )


# =============================================================================
# AuditBoard GRC Issue Filing
# =============================================================================

class AuditBoardConfigResponse(BaseModel):
    """Whether AuditBoard filing is available, and the vocabulary to file with."""
    enabled: bool = Field(description="True when the integration is fully configured")
    problem: Optional[str] = Field(default=None, description="Why it is unavailable, if it is")
    base_url: Optional[str] = Field(default=None, description="AuditBoard site root, for display only")
    issue_category_id: Optional[int] = Field(default=None, description="Category new issues are filed under")
    issue_category_name: Optional[str] = Field(default=None, description="Human name of that category")
    source_type: Optional[str] = Field(default=None, description="Record type issues attach to, when the category is source-backed (e.g. 'Risk')")
    source_id: Optional[int] = Field(default=None, description="ID of the record issues attach to")
    create_status: str = Field(description="Status new issues are created in")
    default_deficiency_levels: Dict[str, int] = Field(description="Severity to deficiency_level_id mapping applied by default")
    deficiency_levels: List[dict] = Field(description="Selectable deficiency levels (id, name)")
    standalone_categories: List[dict] = Field(description="Categories that accept a standalone source (id, name)")
    executive_summary_target_chars: int = Field(
        default=0,
        description="Length the category's form asks the Executive Summary to stay under. Guidance, not a server limit.",
    )
    executive_summary_required: bool = Field(
        default=False,
        description="True when the category requires an Executive Summary to sit at the create status",
    )
    unstamped_required_fields: List[str] = Field(
        default_factory=list,
        description=(
            "Fields the category requires that this app has no configured value for. "
            "Filing still succeeds — the API enforces none of them — but the record "
            "lands incomplete and needs finishing in AuditBoard."
        ),
    )


class AuditBoardIssueRequest(BaseModel):
    """Request to file a finding into AuditBoard as a GRC issue."""
    scope: str = Field(
        default="specific",
        description=(
            "Tier the issue speaks at: 'specific' (this finding instance), "
            "'project' (this defect everywhere in this project) or 'org' (this "
            "defect across every project). 'global' — the pre-2026-09-16 key of "
            "scanner plus file path — is readable but no longer fileable."
        ),
    )
    title: str = Field(description="Normalized issue title, as previewed by the filer")
    description: str = Field(description="Normalized issue body, as previewed by the filer")
    deficiency_level_id: Optional[int] = Field(default=None, description="Override the default severity mapping. Omit to accept the default.")
    executive_summary: Optional[str] = Field(
        default=None,
        description=(
            "Executive Summary — one plain-language line naming the problem and "
            "its impact, for a reader who does not work in security. Written to "
            "custom_text4, which category 10 requires at status Open. Omit to "
            "leave it blank, which files an incomplete register entry."
        ),
    )


class AuditBoardIssueResponse(BaseModel):
    """Result of filing an issue."""
    issue_id: Optional[str] = Field(default=None, description="AuditBoard issue ID as returned by the API")
    issue_url: Optional[str] = Field(default=None, description="Link to the created issue")
    deficiency_level_id: int = Field(description="Deficiency level the issue was filed at")
    deficiency_level_name: str = Field(description="Human name of that deficiency level")
    scope: str = Field(description="Tier the issue was filed at: 'specific', 'project' or 'org'")
    occurrence_count: int = Field(description="Findings the issue speaks for, counted server-side")
    project_count: int = Field(default=1, description="Projects the defect affects organization-wide")
    location_count: int = Field(default=0, description="Distinct locations listed in the issue body")
    locations_omitted: int = Field(default=0, description="Locations left out of the body for length")
    identity_key: Optional[str] = Field(default=None, description="Defect identity filed on: scanner::rule_id")


@router.get(
    "/auditboard/config",
    dependencies=[Depends(require_permissions("findings:read"))],
    response_model=AuditBoardConfigResponse,
    summary="AuditBoard filing availability and vocabulary",
    responses={**LIST_ERRORS, 403: {"description": "Insufficient permissions - requires findings:read"}},
)
def get_auditboard_config():
    """Report whether a finding can be filed to AuditBoard, and with what values.

    Never returns the API token. Creating an AuditBoard issue is an
    authenticated write, so the credential stays server-side; the browser only
    learns whether the integration works and which values it may choose from.
    """
    from ..integrations.auditboard import (
        CATEGORY_10_REQUIRED_AT_OPEN,
        DEFICIENCY_LEVEL_BY_SEVERITY,
        EXECUTIVE_SUMMARY_TARGET,
        auditboard_client,
    )

    reference = auditboard_client.reference_data()
    summary_required = (
        auditboard_client.category_id == 10
        and "customText4" in CATEGORY_10_REQUIRED_AT_OPEN
    )
    return AuditBoardConfigResponse(
        enabled=auditboard_client.enabled and not auditboard_client.config_problem(),
        problem=auditboard_client.config_problem(),
        base_url=auditboard_client.url or None,
        issue_category_id=auditboard_client.category_id or None,
        issue_category_name=auditboard_client.category_name,
        source_type=auditboard_client.source_type,
        source_id=auditboard_client.source_id or None,
        create_status=auditboard_client.create_status,
        default_deficiency_levels=DEFICIENCY_LEVEL_BY_SEVERITY,
        deficiency_levels=reference["deficiency_levels"],
        standalone_categories=reference["standalone_categories"],
        executive_summary_target_chars=EXECUTIVE_SUMMARY_TARGET,
        executive_summary_required=summary_required,
        unstamped_required_fields=auditboard_client.unstamped_required_fields(),
    )


@router.post(
    "/{finding_id}/auditboard-issue",
    dependencies=[Depends(require_permissions("findings:write"))],
    response_model=AuditBoardIssueResponse,
    summary="File a finding into AuditBoard as a GRC issue",
    responses={**CREATE_ERRORS, 403: {"description": "Insufficient permissions - requires findings:write"}},
)
def create_auditboard_issue(
    finding_id: str,
    request: AuditBoardIssueRequest,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user),
):
    """Create an AuditBoard issue from a finding.

    Unlike the Jira path, this writes to an external system of record
    immediately — there is no confirmation screen on the far side. The caller
    is expected to have shown the user the exact title and body first, and
    those are what get sent.

    The occurrence count and the provenance footer are derived here rather
    than taken from the request, so a figure that leaves this system is one
    this system measured. Requires ``findings:write``.
    """
    from ..integrations.auditboard import (
        DEFICIENCY_LEVELS,
        AuditBoardError,
        auditboard_client,
    )

    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    from ..services import finding_groups as groups

    try:
        tier = groups.GroupTier(request.scope)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Scope must be one of: {', '.join(t.value for t in groups.FILEABLE_TIERS)}",
        )
    if tier not in groups.FILEABLE_TIERS:
        raise HTTPException(
            status_code=400,
            detail=(
                "Scope 'global' — scanner plus file path — is no longer fileable. "
                "Use 'project' to file this defect for one project, or 'org' to "
                "file it once across every project."
            ),
        )

    problem = auditboard_client.config_problem()
    if problem:
        raise HTTPException(status_code=503, detail=problem)

    org_id = get_current_org_id()

    # Measure here. A number this system did not measure does not leave it,
    # and the same service answers the preview endpoint, so what the user was
    # shown and what the issue claims cannot diverge.
    equivalence = groups.load_equivalence_map(db, org_id)
    population = groups.measure_group(db, finding, tier, equivalence, org_id)

    if population is None and tier is not groups.GroupTier.SPECIFIC:
        # No rule identifier means no defect identity, so there is nothing to
        # group on. Refused rather than guessed: grouping on title instead
        # would file one issue claiming to cover unrelated defects.
        raise HTTPException(
            status_code=400,
            detail=(
                f"{finding.scanner_name or 'This scanner'} reported no rule "
                "identifier for this finding, so it cannot be grouped. File it "
                "with scope 'specific'."
            ),
        )

    # The severity floor is policy for grouped filings, where one press speaks
    # for findings the filer never saw. A deliberate single-finding filing is
    # left to the person pressing the button.
    if tier is not groups.GroupTier.SPECIFIC:
        eligible, blocked = groups.is_filing_eligible(finding)
        if not eligible:
            raise HTTPException(status_code=400, detail=blocked)

    occurrence_count = population.finding_count if population else 1
    project_count = population.project_count if population else (1 if finding.repository_id else 0)

    # The body arrives as text from the caller, so the browser withholding a
    # secret snippet is a suggestion until it is enforced here.
    from ..services.issue_redaction import redact_snippet

    description, redacted = redact_snippet(request.description, finding)
    if redacted:
        logger.warning(
            "Redacted a secret-scanner snippet from an AuditBoard body for "
            "finding %s (scanner=%s) before sending it",
            finding.finding_uuid, finding.scanner_name,
        )

    body_parts = [description]
    locations_omitted = 0
    if population and tier in (groups.GroupTier.PROJECT, groups.GroupTier.ORG):
        max_locations = settings.FILING_MAX_LOCATIONS
        locations_omitted = max(0, population.location_count - max_locations)
        body_parts.append(
            "\n\n" + groups.render_locations(population.projects, tier, max_locations)
        )

    if tier is groups.GroupTier.SPECIFIC:
        scope_note = "this finding instance only"
    elif tier is groups.GroupTier.PROJECT:
        repo_name = population.projects[0].repo_name if population.projects else "this project"
        scope_note = (
            f"all {occurrence_count} occurrences of this defect in {repo_name}"
        )
    else:
        scope_note = (
            f"all {occurrence_count} occurrences of this defect across "
            f"{project_count} project(s)"
        )

    footer_lines = [
        "Filed from AuditGitHub.",
        f"Reference finding ID: {finding.finding_uuid}",
        f"Scope: {tier.value} — {scope_note}",
        f"Occurrences counted at filing time: {occurrence_count}"
        f"{'' if org_id else ' (tenant-wide; no organization filter was in effect)'}",
    ]
    if population:
        footer_lines.append(f"Defect identity: {population.identity.key}")
        if len(population.members) > 1:
            # A reviewer decided these rules are one defect. Named, because an
            # issue covering findings from a scanner it does not mention is
            # otherwise unverifiable.
            footer_lines.append(
                "Merged rules (reviewer-approved): "
                + ", ".join(m.key for m in population.members)
            )
        footer_lines.append(f"Projects affected organization-wide: {project_count}")
        if tier is groups.GroupTier.PROJECT and population.exceeds_threshold:
            footer_lines.append(
                f"NOTE: this defect also affects other projects "
                f"({project_count} in total, above the escalation threshold of "
                f"{settings.FILING_PROJECT_ESCALATION_THRESHOLD}). This issue "
                "covers one project only."
            )
        if locations_omitted:
            footer_lines.append(
                f"Locations listed: {settings.FILING_MAX_LOCATIONS} of "
                f"{population.location_count}; {locations_omitted} omitted for length."
            )
    footer_lines.append(
        f"Filed by: {getattr(current_user, 'email', None) or getattr(current_user, 'username', 'unknown')}"
    )
    footer = "\n\n----\n\n" + "\n".join(footer_lines)

    # When the defect was first seen anywhere in scope, not when the finding
    # the filer clicked was first seen. AuditBoard refuses to set this after
    # create, so there is no correcting it later.
    identified = None
    if population:
        identified = groups.earliest_identified_date(db, finding, population, org_id)
    if identified is None:
        first_seen = getattr(finding, "first_seen_at", None) or getattr(finding, "created_at", None)
        identified = (first_seen or datetime.utcnow()).date()
    identified_date = identified.isoformat()

    # Highest severity among the members, per the filing rule: an issue that
    # speaks for a critical finding is not rated by whichever instance the
    # filer happened to open.
    severity = (population.severity if population else None) or finding.severity or "info"

    try:
        payload = auditboard_client.build_payload(
            # Every text field, not only the body: a scanner title and a
            # hand-typed summary can both quote the matched line.
            title=redact_snippet(request.title, finding)[0],
            description=f"{''.join(body_parts)}{footer}",
            severity=severity,
            deficiency_level_id=request.deficiency_level_id,
            executive_summary=(
                redact_snippet(request.executive_summary, finding)[0]
                if request.executive_summary
                else request.executive_summary
            ),
            identified_date=identified_date,
        )
        issue = auditboard_client.create_issue(payload)
    except AuditBoardError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    issue_id = issue.get("id") if isinstance(issue, dict) else None
    level = payload["deficiency_level_id"]
    issue_url = auditboard_client.issue_url(issue_id)

    logger.info(
        "AuditBoard issue %s created from finding %s (tier=%s, identity=%s, "
        "occurrences=%s, projects=%s)",
        issue_id, finding.finding_uuid, tier.value,
        population.identity.key if population else "none",
        occurrence_count, project_count,
    )

    # Record the filing from AuditBoard's response, not from what we asked
    # for. The issue already exists at this point, so a failure to persist
    # must not read as a failure to file — it is logged and the response
    # still carries the issue, otherwise the user files a duplicate chasing
    # a record that is already there.
    filed_by = getattr(current_user, 'email', None) or getattr(current_user, 'username', None)
    try:
        record = models.AuditBoardIssue(
            finding_id=finding.id,
            organization_id=org_id,
            scope=tier.value,
            scanner_name=finding.scanner_name,
            file_path=finding.file_path,
            # The group key. rule_id is what a project- or org-tier issue is
            # matched on; file_path stays populated so a 'specific' row still
            # points at one place.
            rule_id=population.identity.rule_id if population else None,
            # Null at org tier on purpose: the issue is not about one project,
            # so pinning it to the one the filer was looking at would make it
            # match that project only.
            repository_id=(
                finding.repository_id if tier is groups.GroupTier.PROJECT else None
            ),
            location_count=population.location_count if population else None,
            locations_omitted=locations_omitted,
            project_count=project_count,
            issue_id=str(issue_id) if issue_id is not None else "",
            issue_uid=issue.get("linkify_uid") if isinstance(issue, dict) else None,
            issue_url=issue_url,
            issue_status=issue.get("status") if isinstance(issue, dict) else None,
            issue_category_id=payload.get("issue_category_id"),
            deficiency_level_id=level,
            deficiency_level_name=DEFICIENCY_LEVELS.get(level, "Unknown"),
            occurrence_count=occurrence_count,
            filed_by_user_id=getattr(current_user, 'id', None),
            filed_by=filed_by,
        )
        db.add(record)
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error(
            "AuditBoard issue %s was created but could not be recorded locally: %s",
            issue_id, exc,
        )

    return AuditBoardIssueResponse(
        issue_id=str(issue_id) if issue_id is not None else None,
        issue_url=issue_url,
        deficiency_level_id=level,
        deficiency_level_name=DEFICIENCY_LEVELS.get(level, "Unknown"),
        scope=tier.value,
        occurrence_count=occurrence_count,
        project_count=project_count,
        location_count=population.location_count if population else 0,
        locations_omitted=locations_omitted,
        identity_key=population.identity.key if population else None,
    )


class AuditBoardFilingRecord(BaseModel):
    """A filing that already happened, as recorded when AuditBoard confirmed it."""
    issue_id: str = Field(description="AuditBoard issue ID")
    issue_uid: Optional[str] = Field(default=None, description="Label people quote, e.g. 'I#1714'")
    issue_url: Optional[str] = Field(default=None, description="Link to the issue in AuditBoard")
    issue_status: Optional[str] = Field(default=None, description="Status at creation; not kept in sync")
    scope: str = Field(description="Scope the issue was filed at")
    occurrence_count: int = Field(description="Findings it spoke for when filed")
    deficiency_level_id: Optional[int] = None
    deficiency_level_name: Optional[str] = None
    filed_by: Optional[str] = Field(default=None, description="Who filed it")
    filed_at: Optional[str] = Field(default=None, description="When, ISO 8601")
    # False when this row was filed against a sibling finding in the same
    # scanner/file group rather than against this finding directly.
    direct: bool = Field(description="True when filed from this finding itself")


class AuditBoardFilingIndexRow(BaseModel):
    """A filing, with the keys a caller needs to match it to findings itself."""
    finding_id: str = Field(description="Internal finding ID the issue was filed from")
    finding_uuid: Optional[str] = Field(default=None, description="Public finding ID used in URLs, when the finding still exists")
    scanner_name: Optional[str] = None
    file_path: Optional[str] = None
    rule_id: Optional[str] = Field(default=None, description="Rule the defect is keyed on; null on pre-2026-09-16 'global' rows")
    repository_id: Optional[str] = Field(default=None, description="Project a 'project' row is confined to; null at every other tier")
    identity_keys: List[str] = Field(
        default_factory=list,
        description=(
            "Every 'scanner::rule_id' this row covers. More than one only where "
            "a reviewer approved a cross-scanner merge; expanded server-side so "
            "a caller does not need the equivalence table to match correctly."
        ),
    )
    scope: str = Field(description="'specific', 'project', 'org', or 'global' for the retired scanner/file key")
    issue_id: str
    project_count: Optional[int] = Field(default=None, description="Projects the defect affected when filed")
    issue_uid: Optional[str] = None
    issue_url: Optional[str] = None
    issue_status: Optional[str] = None
    deficiency_level_name: Optional[str] = None
    occurrence_count: int = 1
    filed_by: Optional[str] = None
    filed_at: Optional[str] = None


@router.get(
    "/auditboard/filings",
    dependencies=[Depends(require_permissions("findings:read"))],
    response_model=List[AuditBoardFilingIndexRow],
    summary="Every AuditBoard filing, for annotating a findings list",
    responses={**LIST_ERRORS, 403: {"description": "Insufficient permissions - requires findings:read"}},
)
def list_auditboard_filings(db: Session = Depends(get_tenant_db)):
    """Return all recorded filings so a table can show an issue ID per row.

    Deliberately not per-finding. The findings table loads thousands of rows,
    and asking for one filing lookup each would be thousands of requests to
    render one column. This returns the whole filing table instead — it has
    one row per issue ever filed, not one per finding, so it stays small.

    Matching is left to the caller because the two kinds of match mean
    different things and only the caller knows which it wants to show: a
    ``specific`` row matches one finding by ID; a ``project`` row covers every
    finding with the same defect identity in the same ``repository_id``; an
    ``org`` row covers that identity in any project; and a ``global`` row is a
    pre-2026-09-16 filing, still matched on scanner plus file path.

    Match identity against ``identity_keys``, not against ``rule_id`` alone —
    the list is already expanded for reviewer-approved cross-scanner merges,
    so a caller never needs to read the equivalence table.

    ``finding_uuid`` is null when the finding has since been deleted. That is
    not an error — filings outlive scan results by design.
    """
    from ..services import finding_groups as groups

    org_id = get_current_org_id()

    q = db.query(models.AuditBoardIssue)
    if org_id:
        q = q.filter(models.AuditBoardIssue.organization_id == org_id)
    rows = q.all()
    if not rows:
        return []

    equivalence = groups.load_equivalence_map(db, org_id)

    def identity_keys(row) -> List[str]:
        if not row.scanner_name or not row.rule_id:
            return []
        own = groups.Identity(scanner_name=row.scanner_name, rule_id=row.rule_id)
        return [m.key for m in equivalence.members(own)]

    # One lookup for the public IDs rather than one per row.
    ids = {r.finding_id for r in rows if r.finding_id}
    uuid_by_id = {
        f.id: f.finding_uuid
        for f in db.query(models.Finding.id, models.Finding.finding_uuid)
        .filter(models.Finding.id.in_(ids))
        .all()
    } if ids else {}

    return [
        AuditBoardFilingIndexRow(
            finding_id=str(r.finding_id),
            finding_uuid=str(uuid_by_id[r.finding_id]) if uuid_by_id.get(r.finding_id) else None,
            scanner_name=r.scanner_name,
            file_path=r.file_path,
            rule_id=r.rule_id,
            repository_id=str(r.repository_id) if r.repository_id else None,
            identity_keys=identity_keys(r),
            scope=r.scope or "specific",
            issue_id=r.issue_id,
            project_count=r.project_count,
            issue_uid=r.issue_uid,
            issue_url=r.issue_url,
            issue_status=r.issue_status,
            deficiency_level_name=r.deficiency_level_name,
            occurrence_count=r.occurrence_count or 1,
            filed_by=r.filed_by,
            filed_at=r.created_at.isoformat() if r.created_at else None,
        )
        for r in rows
    ]


@router.get(
    "/{finding_id}/auditboard-issues",
    dependencies=[Depends(require_permissions("findings:read"))],
    response_model=List[AuditBoardFilingRecord],
    summary="AuditBoard issues already filed for this finding",
    responses={**LIST_ERRORS, 403: {"description": "Insufficient permissions - requires findings:read"}},
)
def list_auditboard_issues(
    finding_id: str,
    db: Session = Depends(get_tenant_db),
):
    """List the AuditBoard issues this finding has already produced.

    Two kinds of match, and the distinction matters to whoever reads it:

    *   ``direct`` — filed from this finding.
    *   not ``direct`` — a grouped filing made from a sibling finding: same
        defect identity in this project ('project'), the same defect anywhere
        ('org'), or a pre-2026-09-16 filing on the same scanner and file path
        ('global'). The defect is already reported; this instance was covered
        by it without anyone opening it.

    Reports what was recorded locally at filing time. It does not call
    AuditBoard, so a status here is the status at creation — if someone closed
    the issue over there, this will not say so.
    """
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    org_id = get_current_org_id()

    direct_q = db.query(models.AuditBoardIssue).filter(
        models.AuditBoardIssue.finding_id == finding.id
    )

    # A grouped filing covers this finding without anyone having opened it.
    # The tiers, and the retired 'global' key, are all handled by the filing
    # service so this endpoint and the filing endpoint agree on what "already
    # covered" means.
    from ..services import finding_groups as groups

    equivalence = groups.load_equivalence_map(db, org_id)
    own_identity = groups.identity_of(finding)
    members = equivalence.members(own_identity) if own_identity else []

    group_q = db.query(models.AuditBoardIssue).filter(
        and_(
            groups.filing_match_condition(finding, members),
            models.AuditBoardIssue.finding_id != finding.id,
        )
    )
    if org_id:
        direct_q = direct_q.filter(models.AuditBoardIssue.organization_id == org_id)
        group_q = group_q.filter(models.AuditBoardIssue.organization_id == org_id)

    rows = [(r, True) for r in direct_q.all()] + [(r, False) for r in group_q.all()]
    rows.sort(key=lambda pair: pair[0].created_at or datetime.min, reverse=True)

    return [
        AuditBoardFilingRecord(
            issue_id=r.issue_id,
            issue_uid=r.issue_uid,
            issue_url=r.issue_url,
            issue_status=r.issue_status,
            scope=r.scope,
            occurrence_count=r.occurrence_count or 1,
            deficiency_level_id=r.deficiency_level_id,
            deficiency_level_name=r.deficiency_level_name,
            filed_by=r.filed_by,
            filed_at=r.created_at.isoformat() if r.created_at else None,
            direct=direct,
        )
        for r, direct in rows
    ]


# =============================================================================
# Finding Update Models and Endpoints
# =============================================================================

class FindingUpdateRequest(BaseModel):
    """Request to update a finding's fields such as description or severity."""
    description: Optional[str] = Field(default=None, description="New description text for the finding")
    severity: Optional[str] = Field(default=None, description="New severity level: critical, high, medium, low, info, or warning")
    scope: Optional[str] = Field(default="specific", description="Update scope: 'specific' for this finding only or 'global' for all identical findings")

class FindingUpdateResponse(BaseModel):
    """Response after updating a finding."""
    id: str = Field(description="UUID of the updated finding")
    message: str = Field(description="Human-readable result message")
    updated_fields: List[str] = Field(description="List of field names that were modified")
    version_id: Optional[str] = Field(default=None, description="ID of the version history entry created for this change")


@router.patch(
    "/{finding_id}",
    dependencies=[Depends(require_permissions("findings:write"))],
    response_model=FindingUpdateResponse,
    summary="Update a finding",
    responses={**CRUD_ERRORS, 403: {"description": "Insufficient permissions - requires findings:write"}},
)
def update_finding(finding_id: str, update: FindingUpdateRequest, db: Session = Depends(get_tenant_db)):
    """Update a finding's description or severity by UUID.

    Supports 'specific' scope (single finding) or 'global' scope (all identical
    findings in the same repository). Changes are tracked in version history.
    Requires the ``findings:write`` permission.
    """
    # Try to parse UUID
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        # Fallback to check primary key id
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    updated_fields = []
    version_id = None
    
    # 1. Update Description (Specific only)
    if update.description is not None:
        old_description = finding.description
        
        # Save old description to version history if it exists
        if old_description:
            history_entry = models.FindingHistory(
                finding_id=finding.id,
                change_type="description",
                old_value=old_description,
                new_value=update.description,
                comment="Description updated via AI analysis",
                change_metadata={"source": "ai_analysis", "timestamp": datetime.utcnow().isoformat()}
            )
            db.add(history_entry)
            db.flush()  # Get the ID
            version_id = str(history_entry.id)
        
        finding.description = update.description
        updated_fields.append("description")

    # 2. Update Severity (Specific or Global)
    if update.severity is not None:
        new_severity = update.severity.lower()
        if new_severity not in SEVERITY_PRIORITY.keys():
             raise HTTPException(status_code=400, detail=f"Invalid severity. Must be one of: {list(SEVERITY_PRIORITY.keys())}")

        targets = [finding]
        
        if update.scope == "global":
            # Find all identical findings in the same repository
            targets = db.query(models.Finding).filter(
                models.Finding.repository_id == finding.repository_id,
                models.Finding.title == finding.title,
                models.Finding.scanner_name == finding.scanner_name,
                models.Finding.finding_type == finding.finding_type
            ).all()

        for target in targets:
            if target.severity != new_severity:
                # History tracking
                history_entry = models.FindingHistory(
                    finding_id=target.id,
                    change_type="severity",
                    old_value=target.severity,
                    new_value=new_severity,
                    comment=f"Severity manually updated ({update.scope})",
                    change_metadata={
                        "source": "manual_override", 
                        "scope": update.scope,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                )
                db.add(history_entry)
                target.severity = new_severity
        
        updated_fields.append(f"severity ({len(targets)} findings)")
    
    if updated_fields:
        db.commit()
        db.refresh(finding)
        logger.info(f"Updated finding {finding_id}: {updated_fields}")
    
    return FindingUpdateResponse(
        id=str(finding.finding_uuid),
        message=f"Successfully updated finding" if updated_fields else "No fields to update",
        updated_fields=updated_fields,
        version_id=version_id
    )


# =============================================================================
# Include in Report Toggle
# =============================================================================

class IncludeInReportRequest(BaseModel):
    """Request to toggle whether a finding is included in the Critical Insights report."""
    include_in_report: bool = Field(description="Set to true to include this finding in reports, false to exclude it")

class IncludeInReportResponse(BaseModel):
    """Response after toggling the include_in_report flag on a finding."""
    id: str = Field(description="UUID of the finding that was toggled")
    include_in_report: bool = Field(description="Current value of the include_in_report flag after update")
    message: str = Field(description="Human-readable confirmation message")


@router.patch(
    "/{finding_id}/include-in-report",
    dependencies=[Depends(require_permissions("findings:write"))],
    response_model=IncludeInReportResponse,
    summary="Toggle report inclusion for a finding",
    responses={**CRUD_ERRORS, 403: {"description": "Insufficient permissions - requires findings:write"}},
)
def toggle_include_in_report(finding_id: str, request: IncludeInReportRequest, db: Session = Depends(get_tenant_db)):
    """Toggle whether a finding should be included in the Critical Insights section of reports.

    Sets or clears the include_in_report flag and records the change in
    finding history. Requires the ``findings:write`` permission.
    """
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Update the include_in_report flag
    old_value = finding.include_in_report
    finding.include_in_report = request.include_in_report
    
    # Add history entry
    history_entry = models.FindingHistory(
        finding_id=finding.id,
        change_type="include_in_report",
        old_value=str(old_value) if old_value is not None else "null",
        new_value=str(request.include_in_report),
        comment=f"{'Included in' if request.include_in_report else 'Excluded from'} report Critical Insights",
        change_metadata={
            "source": "manual_toggle",
            "timestamp": datetime.utcnow().isoformat()
        }
    )
    db.add(history_entry)
    
    db.commit()
    db.refresh(finding)
    
    logger.info(f"Finding {finding_id} include_in_report set to {request.include_in_report}")
    
    return IncludeInReportResponse(
        id=str(finding.finding_uuid or finding.id),
        include_in_report=finding.include_in_report,
        message=f"Finding {'included in' if request.include_in_report else 'excluded from'} Critical Insights"
    )


# =============================================================================
# Description Version History
# =============================================================================

class DescriptionVersionResponse(BaseModel):
    """A single historical version of a finding's description."""
    id: str = Field(description="Unique identifier for the version history entry")
    description: str = Field(description="The description text at this version")
    created_at: datetime = Field(description="Timestamp when this version was created")
    is_current: bool = Field(default=False, description="Whether this is the currently active description")

class DescriptionVersionListResponse(BaseModel):
    """List of all description versions for a finding, including the current one."""
    finding_id: str = Field(description="UUID of the finding these versions belong to")
    current_description: Optional[str] = Field(default=None, description="The current active description text")
    versions: List[DescriptionVersionResponse] = Field(description="List of previous description versions in reverse chronological order")


@router.get(
    "/{finding_id}/description-versions",
    dependencies=[Depends(require_permissions("findings:read"))],
    response_model=DescriptionVersionListResponse,
    summary="List description version history",
    responses={**CRUD_ERRORS, 403: {"description": "Insufficient permissions - requires findings:read"}},
)
def get_description_versions(finding_id: str, db: Session = Depends(get_tenant_db)):
    """Retrieve all historical description versions for a finding.

    Returns the current description and a chronological list of previous
    versions that can be restored. Requires the ``findings:read`` permission.
    """
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get all description history entries
    history = db.query(models.FindingHistory).filter(
        models.FindingHistory.finding_id == finding.id,
        models.FindingHistory.change_type == "description"
    ).order_by(models.FindingHistory.created_at.desc()).all()

    versions = []
    for h in history:
        # old_value contains the previous description that was replaced
        versions.append(DescriptionVersionResponse(
            id=str(h.id),
            description=h.old_value,
            created_at=h.created_at,
            is_current=False
        ))

    return DescriptionVersionListResponse(
        finding_id=str(finding.finding_uuid),
        current_description=finding.description,
        versions=versions
    )


class RestoreVersionRequest(BaseModel):
    """Request to restore a specific previous description version for a finding."""
    version_id: str = Field(description="UUID of the description version to restore")


@router.post(
    "/{finding_id}/restore-description",
    dependencies=[Depends(require_permissions("findings:write"))],
    response_model=FindingUpdateResponse,
    summary="Restore a previous description version",
    responses={**CRUD_ERRORS, 403: {"description": "Insufficient permissions - requires findings:write"}},
)
def restore_description_version(finding_id: str, request: RestoreVersionRequest, db: Session = Depends(get_tenant_db)):
    """Restore a finding's description to a previous version from its history.

    The current description is saved to history before the restore is applied.
    Requires the ``findings:write`` permission.
    """
    try:
        finding_uuid = uuid.UUID(finding_id)
        version_uuid = uuid.UUID(request.version_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == finding_uuid).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == finding_uuid).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get the version to restore
    version = db.query(models.FindingHistory).filter(
        models.FindingHistory.id == version_uuid,
        models.FindingHistory.finding_id == finding.id,
        models.FindingHistory.change_type == "description"
    ).first()

    if not version:
        raise HTTPException(status_code=404, detail="Version not found")

    # Save current description to history before restoring
    old_description = finding.description
    if old_description:
        history_entry = models.FindingHistory(
            finding_id=finding.id,
            change_type="description",
            old_value=old_description,
            new_value=version.old_value,
            comment="Description restored from version history",
            change_metadata={"source": "version_restore", "restored_version_id": str(version.id), "timestamp": datetime.utcnow().isoformat()}
        )
        db.add(history_entry)

    # Restore the old description
    finding.description = version.old_value
    db.commit()
    db.refresh(finding)
    
    logger.info(f"Restored description for finding {finding_id} from version {request.version_id}")

    return FindingUpdateResponse(
        id=str(finding.finding_uuid),
        message="Successfully restored description from version history",
        updated_fields=["description"],
        version_id=str(version.id)
    )


# =============================================================================
# Exception Management Models
# =============================================================================

class ExceptionRuleRequest(BaseModel):
    """Request to generate a scanner-specific exception rule for a finding."""
    finding_id: str = Field(description="UUID of the finding to generate an exception rule for")
    scope: str = Field(description="Rule scope: 'specific' for this finding only or 'global' for the entire file path")
    reason: Optional[str] = Field(default=None, description="Optional justification for creating the exception")

class ExceptionRuleResponse(BaseModel):
    """Response containing the generated scanner-specific exception rule configuration."""
    scanner_name: str = Field(description="Name of the scanner the rule applies to (e.g. gitleaks, semgrep)")
    rule_type: str = Field(description="Type of exception rule: allowlist, exclude, or ignore")
    rule_content: str = Field(description="The actual rule configuration content (TOML, YAML, or comment format)")
    instruction: str = Field(description="Instructions on where and how to apply this rule in your project")
    affected_count: int = Field(description="Number of existing findings that would be covered by this exception rule")

class DeleteDryRunRequest(BaseModel):
    """Request for a dry-run deletion analysis to preview what would be removed."""
    finding_id: str = Field(description="UUID of the finding to use as the deletion reference")
    scope: str = Field(description="Deletion scope: 'specific' for this finding only or 'global' for all matching scanner/file findings")

class DeleteDryRunAuditBoardIssue(BaseModel):
    """A GRC issue that will outlive the findings behind it.

    Deleting a finding does not touch ``auditboard_issues`` — that record has
    no foreign key precisely so a filing survives the scan result. Which means
    deleting a false positive can leave an open issue in the GRC register with
    nothing left in this app to explain it, and only a person with AuditBoard
    rights can close it.
    """
    issue_id: str = Field(description="AuditBoard issue ID")
    issue_uid: Optional[str] = Field(default=None, description="Label people quote, e.g. 'I#1717'")
    issue_url: Optional[str] = Field(default=None, description="Link to the issue in AuditBoard")
    issue_status: Optional[str] = Field(default=None, description="Status at creation; not kept in sync with AuditBoard")
    scope: str = Field(description="Scope the issue was filed at")
    filed_by: Optional[str] = Field(default=None, description="Who filed it")
    filed_at: Optional[str] = Field(default=None, description="When, ISO 8601")
    direct: bool = Field(description="True when it was filed from one of the findings being deleted")
    remaining_findings: int = Field(
        description=(
            "Findings left in this scanner/file group after the delete. 0 means "
            "the issue is left with no evidence behind it at all."
        )
    )


class DeleteDryRunResponse(BaseModel):
    """Response previewing the findings that would be deleted without actually removing them."""
    count: int = Field(description="Total number of findings that would be deleted")
    scanner_name: str = Field(description="Scanner name of the matched findings")
    file_path: Optional[str] = Field(default=None, description="File path of the matched findings")
    sample_findings: List[dict] = Field(description="Sample of up to 5 findings that would be deleted (id, title, file_path, scanner_name)")
    auditboard_issues: List[DeleteDryRunAuditBoardIssue] = Field(
        default_factory=list,
        description="AuditBoard issues covering these findings, which the delete will not close",
    )

class DeleteFindingsRequest(BaseModel):
    """Request to permanently delete findings. Requires explicit confirmation."""
    finding_id: str = Field(description="UUID of the finding to delete (or use as reference for global scope)")
    scope: str = Field(description="Deletion scope: 'specific' for this finding only or 'global' for all matching scanner/file findings")
    confirmed: bool = Field(default=False, description="Safety flag: must be set to true to proceed with deletion")

class DeleteFindingsResponse(BaseModel):
    """Response confirming how many findings were permanently deleted."""
    deleted_count: int = Field(description="Number of findings that were permanently deleted")
    message: str = Field(description="Human-readable confirmation message")


# =============================================================================
# Exception Rule Generation
# =============================================================================

def generate_gitleaks_rule(finding: models.Finding, scope: str) -> dict:
    """Generate a Gitleaks allowlist rule."""
    if scope == "specific":
        # Specific rule - match exact secret
        secret_value = finding.code_snippet or ""
        # Truncate and escape the secret for regex
        if len(secret_value) > 50:
            regex_pattern = f"{secret_value[:50]}.*"
        else:
            regex_pattern = f".*{secret_value}.*"

        rule_content = f'''[[rules.allowlist]]
description = "Exception for {finding.title}"
regexTarget = "match"
regexes = [
    "{regex_pattern}"
]
paths = [
    "{finding.file_path}"
]'''
    else:
        # Global rule - match file path
        rule_content = f'''[[rules.allowlist]]
description = "Global exception for {finding.file_path}"
paths = [
    "{finding.file_path}"
]'''

    return {
        "rule_type": "allowlist",
        "rule_content": rule_content,
        "instruction": "Add this rule to your gitleaks.toml configuration file in the [allowlist] section."
    }


def generate_trufflehog_rule(finding: models.Finding, scope: str) -> dict:
    """Generate a TruffleHog exclusion rule."""
    if scope == "specific":
        rule_content = f'''# Exception for {finding.title}
exclude:
  paths:
    - "{finding.file_path}"
  detectors:
    - "{finding.finding_type or 'generic'}"'''
    else:
        rule_content = f'''# Global exception for path
exclude:
  paths:
    - "{finding.file_path}"'''

    return {
        "rule_type": "exclude",
        "rule_content": rule_content,
        "instruction": "Add this to your TruffleHog configuration file or .trufflehog-ignore."
    }


def generate_semgrep_rule(finding: models.Finding, scope: str) -> dict:
    """Generate a Semgrep nosemgrep comment or ignore rule."""
    if scope == "specific":
        rule_content = f'''# Add this comment to the specific line in {finding.file_path}:
# nosemgrep: {finding.finding_type or 'rule-id'}

# Or add to .semgrepignore:
{finding.file_path}:{finding.line_start or 1}'''
    else:
        rule_content = f'''# Add to .semgrepignore file:
{finding.file_path}'''

    return {
        "rule_type": "ignore",
        "rule_content": rule_content,
        "instruction": "Add a nosemgrep comment to the code or add the path to .semgrepignore."
    }


def generate_generic_rule(finding: models.Finding, scope: str) -> dict:
    """Generate a generic exception rule for unknown scanners."""
    if scope == "specific":
        rule_content = f'''# Exception for specific finding
# Scanner: {finding.scanner_name}
# File: {finding.file_path}
# Line: {finding.line_start or 'N/A'}
# Title: {finding.title}

# Add to your scanner's ignore/allowlist configuration'''
    else:
        rule_content = f'''# Global exception for path
# Scanner: {finding.scanner_name}
# File: {finding.file_path}

# Add to your scanner's ignore/allowlist configuration'''

    return {
        "rule_type": "ignore",
        "rule_content": rule_content,
        "instruction": f"Consult the {finding.scanner_name} documentation for the appropriate ignore/allowlist format."
    }


@router.post(
    "/exception/generate",
    dependencies=[Depends(require_permissions("findings:write"))],
    response_model=ExceptionRuleResponse,
    summary="Generate an exception rule for a finding",
    responses={**CREATE_ERRORS, 403: {"description": "Insufficient permissions - requires findings:write"}, 404: {"description": "Finding not found"}},
)
def generate_exception_rule(
    request: ExceptionRuleRequest,
    db: Session = Depends(get_tenant_db)
):
    """Generate a scanner-specific exception rule configuration for a finding.

    Produces allowlist, exclude, or ignore rules for Gitleaks, TruffleHog,
    Semgrep, or generic scanners. Requires the ``findings:write`` permission.
    """
    # Get the finding
    try:
        uuid_obj = uuid.UUID(request.finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Validate scope
    if request.scope not in ["specific", "global"]:
        raise HTTPException(status_code=400, detail="Scope must be 'specific' or 'global'")

    scanner_name = (finding.scanner_name or "").lower()

    # Generate rule based on scanner type
    if "gitleaks" in scanner_name:
        rule_data = generate_gitleaks_rule(finding, request.scope)
    elif "trufflehog" in scanner_name:
        rule_data = generate_trufflehog_rule(finding, request.scope)
    elif "semgrep" in scanner_name:
        rule_data = generate_semgrep_rule(finding, request.scope)
    else:
        rule_data = generate_generic_rule(finding, request.scope)

    # Count affected findings
    if request.scope == "specific":
        affected_count = 1
    else:
        # Count all findings with same scanner and file path
        affected_count = db.query(models.Finding).filter(
            and_(
                models.Finding.scanner_name == finding.scanner_name,
                models.Finding.file_path == finding.file_path
            )
        ).count()

    return ExceptionRuleResponse(
        scanner_name=finding.scanner_name or "Unknown",
        rule_type=rule_data["rule_type"],
        rule_content=rule_data["rule_content"],
        instruction=rule_data["instruction"],
        affected_count=affected_count
    )


# =============================================================================
# Delete Findings with Dry-Run Verification
# =============================================================================

@router.post(
    "/exception/delete/dry-run",
    dependencies=[Depends(require_permissions("findings:delete"))],
    response_model=DeleteDryRunResponse,
    summary="Preview findings that would be deleted",
    responses={**CRUD_ERRORS, 403: {"description": "Insufficient permissions - requires findings:delete"}},
)
def delete_findings_dry_run(
    request: DeleteDryRunRequest,
    db: Session = Depends(get_tenant_db)
):
    """Perform a dry-run analysis to show how many findings would be deleted.

    Returns a count and sample of matching findings without actually removing
    anything. Use this as a safety check before calling the delete endpoint.
    Requires the ``findings:delete`` permission.
    """
    # Get the finding
    try:
        uuid_obj = uuid.UUID(request.finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Validate scope
    if request.scope not in ["specific", "global"]:
        raise HTTPException(status_code=400, detail="Scope must be 'specific' or 'global'")

    if request.scope == "specific":
        # Only this specific finding
        count = 1
        target_ids = [finding.id]
        sample_findings = [{
            "id": str(finding.finding_uuid),
            "title": finding.title,
            "file_path": finding.file_path,
            "scanner_name": finding.scanner_name
        }]
    else:
        # Global scope - match scanner AND file path for safety
        query = db.query(models.Finding).filter(
            and_(
                models.Finding.scanner_name == finding.scanner_name,
                models.Finding.file_path == finding.file_path
            )
        )
        count = query.count()
        target_ids = [row.id for row in query.with_entities(models.Finding.id).all()]

        # Get sample of findings (up to 5)
        sample = query.limit(5).all()
        sample_findings = [{
            "id": str(f.finding_uuid),
            "title": f.title,
            "file_path": f.file_path,
            "scanner_name": f.scanner_name
        } for f in sample]

    return DeleteDryRunResponse(
        count=count,
        scanner_name=finding.scanner_name or "Unknown",
        file_path=finding.file_path,
        sample_findings=sample_findings,
        auditboard_issues=_auditboard_issues_covering(db, target_ids, finding),
    )


def _auditboard_issues_covering(
    db: Session,
    finding_ids: List[uuid.UUID],
    finding,
) -> List[DeleteDryRunAuditBoardIssue]:
    """GRC issues that speak for these findings, for a pre-delete warning.

    Two ways an issue covers a finding, matching :func:`list_auditboard_issues`
    so the dry-run and the finding page never disagree:

    *   it was filed from one of these findings (``direct``); or
    *   it was filed at a group tier that includes them — same defect identity
        in this project, the same identity anywhere, or the retired scanner
        plus file path key. The match is delegated to the filing service so
        there is one answer to "already covered" in the codebase.

    ``remaining_findings`` is what makes the warning actionable, and it is
    counted per issue against what *that* issue covers, at the tier it was
    filed at. A delete that leaves siblings behind leaves the issue still
    describing something real; a delete that empties its group leaves an open
    GRC record whose evidence is gone. Only the second is an orphan, and only a
    person with AuditBoard rights can close it — this app cannot, and
    deliberately does not delete the local filing record either.
    """
    if not finding_ids:
        return []

    from ..services import finding_groups as groups

    org_id = get_current_org_id()
    id_set = set(finding_ids)

    equivalence = groups.load_equivalence_map(db, org_id)
    own_identity = groups.identity_of(finding)
    members = equivalence.members(own_identity) if own_identity else []

    q = db.query(models.AuditBoardIssue).filter(
        or_(
            models.AuditBoardIssue.finding_id.in_(finding_ids),
            groups.filing_match_condition(finding, members),
        )
    )
    if org_id:
        q = q.filter(models.AuditBoardIssue.organization_id == org_id)

    rows = q.all()
    if not rows:
        return []

    def remaining_for(row) -> int:
        # Counted, not inferred from `count`: a specific-scope delete removes
        # one finding from a group that may still hold thousands.
        query = db.query(func.count(models.Finding.id)).filter(
            and_(
                groups.findings_covered_condition(row, equivalence),
                ~models.Finding.id.in_(finding_ids),
            )
        )
        if org_id:
            query = query.filter(models.Finding.organization_id == org_id)
        return query.scalar() or 0

    return [
        DeleteDryRunAuditBoardIssue(
            issue_id=r.issue_id,
            issue_uid=r.issue_uid,
            issue_url=r.issue_url,
            issue_status=r.issue_status,
            scope=r.scope or "specific",
            filed_by=r.filed_by,
            filed_at=r.created_at.isoformat() if r.created_at else None,
            direct=r.finding_id in id_set,
            remaining_findings=remaining_for(r),
        )
        for r in rows
    ]


def _delete_findings_by_id(db: Session, finding_ids: List[uuid.UUID]) -> int:
    """Delete findings and everything that references them. Returns the count.

    Every foreign key into ``findings`` is declared NO ACTION, so the database
    refuses to delete a finding that any of these tables still points at:

    *   ``finding_history`` — the per-finding audit trail
    *   ``finding_comments``
    *   ``journal_entries``
    *   ``remediations``

    (``remediation_action_findings`` is the one FK that does cascade, so it is
    not listed here.) The dependents are removed oldest-reference-first and
    the findings last, in one transaction the caller commits.

    Deleting the history is the point, not a side effect: a false positive
    that stays behind as an audit trail for a finding that no longer exists is
    an orphan nobody can interpret. What deliberately does **not** get deleted
    is ``auditboard_issues`` — a GRC issue that was filed really was filed,
    and that record has no foreign key precisely so it outlives the scan
    result. If findings are being deleted as false positives after being
    reported, the issue in AuditBoard still needs closing by hand.
    """
    if not finding_ids:
        return 0

    for model in (
        models.FindingHistory,
        models.FindingComment,
        models.JournalEntry,
        models.Remediation,
    ):
        db.query(model).filter(
            model.finding_id.in_(finding_ids)
        ).delete(synchronize_session=False)

    deleted = db.query(models.Finding).filter(
        models.Finding.id.in_(finding_ids)
    ).delete(synchronize_session=False)

    return deleted


@router.post(
    "/exception/delete",
    dependencies=[Depends(require_permissions("findings:delete"))],
    response_model=DeleteFindingsResponse,
    summary="Permanently delete findings",
    responses={**DELETE_ERRORS, 400: {"description": "Invalid UUID format, invalid scope, or deletion not confirmed"}, 403: {"description": "Insufficient permissions - requires findings:delete"}},
)
def delete_findings(
    request: DeleteFindingsRequest,
    db: Session = Depends(get_tenant_db)
):
    """Permanently delete findings based on scope. Requires confirmed=True for safety.

    Use 'specific' scope to delete only the referenced finding, or 'global' to
    delete all findings sharing the same scanner and file path. Associated
    remediations are also removed. Requires the ``findings:delete`` permission.
    """
    if not request.confirmed:
        raise HTTPException(
            status_code=400,
            detail="Deletion not confirmed. Set confirmed=True after reviewing the dry-run results."
        )

    # Get the finding
    try:
        uuid_obj = uuid.UUID(request.finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Validate scope
    if request.scope not in ["specific", "global"]:
        raise HTTPException(status_code=400, detail="Scope must be 'specific' or 'global'")

    try:
        if request.scope == "specific":
            target_ids = [finding.id]
        else:
            # Global scope - match scanner AND file path for safety
            target_ids = [
                row.id for row in db.query(models.Finding.id).filter(
                    and_(
                        models.Finding.scanner_name == finding.scanner_name,
                        models.Finding.file_path == finding.file_path
                    )
                ).all()
            ]

        deleted_count = _delete_findings_by_id(db, target_ids)

        db.commit()
        logger.info(f"Deleted {deleted_count} finding(s) with scope '{request.scope}'")

        return DeleteFindingsResponse(
            deleted_count=deleted_count,
            message=f"Successfully deleted {deleted_count} finding(s)."
        )

    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting findings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete findings: {str(e)}")


# =============================================================================
# Investigation Status & Journal API
# =============================================================================

class InvestigationStatusUpdate(BaseModel):
    """Request to update the investigation workflow status of a finding."""
    status: str = Field(description="New investigation status: 'triage', 'incident_response', 'resolved', or empty string to clear")

class JournalEntryRequest(BaseModel):
    """Request to create a new journal entry on a finding's investigation timeline."""
    entry_text: str = Field(description="The content text of the journal entry")
    entry_type: Optional[str] = Field(default='note', description="Entry category: 'note', 'status_change', 'ai_response', or 'communication'")
    author_name: Optional[str] = Field(default='Analyst', description="Display name of the entry author")
    is_ai_generated: Optional[bool] = Field(default=False, description="Whether this entry was generated by AI")
    ai_prompt: Optional[str] = Field(default=None, description="The original prompt if this entry was AI-generated")

class JournalEntryResponse(BaseModel):
    """A single journal entry from a finding's investigation timeline."""
    id: str = Field(description="Unique identifier for the journal entry")
    entry_text: str = Field(description="The content text of the journal entry")
    entry_type: str = Field(description="Entry category: note, status_change, ai_response, or communication")
    author_name: str = Field(description="Display name of the entry author")
    is_ai_generated: bool = Field(description="Whether this entry was generated by AI")
    ai_prompt: Optional[str] = Field(default=None, description="The original prompt if this entry was AI-generated")
    created_at: datetime = Field(description="Timestamp when the journal entry was created")

    model_config = {"from_attributes": True}

class InvestigationStatusResponse(BaseModel):
    """Full investigation context for a finding, including status and journal timeline."""
    finding_id: str = Field(description="UUID of the finding")
    investigation_status: Optional[str] = Field(default=None, description="Current investigation status: triage, incident_response, or resolved")
    investigation_started_at: Optional[datetime] = Field(default=None, description="Timestamp when the investigation was first started")
    investigation_resolved_at: Optional[datetime] = Field(default=None, description="Timestamp when the investigation was marked resolved")
    journal_entries: List[JournalEntryResponse] = Field(description="Chronological list of journal entries for this investigation")

class AskJournalAIRequest(BaseModel):
    """Request to ask AI a question about a finding within the investigation journal context."""
    question: str = Field(description="The question to ask the AI assistant about this finding")
    author_name: Optional[str] = Field(default='Analyst', description="Display name of the analyst asking the question")

class JournalEntryUpdateRequest(BaseModel):
    """Request to update the content or metadata of an existing journal entry."""
    entry_text: Optional[str] = Field(default=None, description="New content text for the journal entry")
    entry_type: Optional[str] = Field(default=None, description="New entry category: 'note', 'status_change', 'ai_response', or 'communication'")
    author_name: Optional[str] = Field(default=None, description="New display name for the entry author")


@router.get(
    "/{finding_id}/investigation",
    dependencies=[Depends(require_permissions("findings:read"))],
    response_model=InvestigationStatusResponse,
    summary="Get investigation status and journal",
    responses={**CRUD_ERRORS, 403: {"description": "Insufficient permissions - requires findings:read"}},
)
def get_investigation_status(finding_id: str, db: Session = Depends(get_tenant_db)):
    """Retrieve the investigation status and full journal timeline for a finding.

    Returns the current investigation workflow state (triage, incident_response,
    resolved) along with all journal entries. Requires the ``findings:read`` permission.
    """
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get journal entries
    journal_entries = db.query(models.JournalEntry).filter(
        models.JournalEntry.finding_id == finding.id
    ).order_by(models.JournalEntry.created_at.desc()).all()

    return InvestigationStatusResponse(
        finding_id=str(finding.finding_uuid),
        investigation_status=finding.investigation_status,
        investigation_started_at=finding.investigation_started_at,
        investigation_resolved_at=finding.investigation_resolved_at,
        journal_entries=[JournalEntryResponse(
            id=str(entry.id),
            entry_text=entry.entry_text,
            entry_type=entry.entry_type or 'note',
            author_name=entry.author_name or 'Analyst',
            is_ai_generated=entry.is_ai_generated or False,
            ai_prompt=entry.ai_prompt,
            created_at=entry.created_at
        ) for entry in journal_entries]
    )


@router.patch(
    "/{finding_id}/investigation/status",
    dependencies=[Depends(require_permissions("findings:write"))],
    summary="Update investigation status",
    responses={**CRUD_ERRORS, 403: {"description": "Insufficient permissions - requires findings:write"}},
)
def update_investigation_status(finding_id: str, update: InvestigationStatusUpdate, db: Session = Depends(get_tenant_db)):
    """Transition a finding's investigation status and record a journal entry.

    Valid statuses are 'triage', 'incident_response', and 'resolved'. Starting
    an investigation sets the started_at timestamp; resolving sets resolved_at.
    Requires the ``findings:write`` permission.
    """
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Validate status
    valid_statuses = ['triage', 'incident_response', 'resolved', None, '']
    if update.status and update.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: triage, incident_response, resolved")

    old_status = finding.investigation_status
    new_status = update.status if update.status else None

    # Update timestamps based on status changes
    if new_status and not old_status:
        # Starting investigation
        finding.investigation_started_at = datetime.utcnow()
    
    if new_status == 'resolved' and old_status != 'resolved':
        finding.investigation_resolved_at = datetime.utcnow()
    elif new_status != 'resolved':
        finding.investigation_resolved_at = None

    finding.investigation_status = new_status
    
    # Create a status change journal entry
    if old_status != new_status:
        status_entry = models.JournalEntry(
            finding_id=finding.id,
            entry_text=f"Status changed from **{old_status or 'None'}** to **{new_status or 'None'}**",
            entry_type='status_change',
            author_name='System',
            is_ai_generated=False
        )
        db.add(status_entry)

    db.commit()
    db.refresh(finding)

    return {
        "finding_id": str(finding.finding_uuid),
        "investigation_status": finding.investigation_status,
        "investigation_started_at": finding.investigation_started_at,
        "investigation_resolved_at": finding.investigation_resolved_at,
        "message": f"Status updated to {new_status or 'None'}"
    }


@router.post(
    "/{finding_id}/journal",
    dependencies=[Depends(require_permissions("findings:write"))],
    response_model=JournalEntryResponse,
    summary="Create a journal entry",
    responses={**CREATE_ERRORS, 403: {"description": "Insufficient permissions - requires findings:write"}, 404: {"description": "Finding not found"}},
)
def create_journal_entry(finding_id: str, entry: JournalEntryRequest, db: Session = Depends(get_tenant_db)):
    """Add a new journal entry to a finding's investigation timeline.

    Supports notes, status changes, AI responses, and communication entries.
    Requires the ``findings:write`` permission.
    """
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    journal_entry = models.JournalEntry(
        finding_id=finding.id,
        entry_text=entry.entry_text,
        entry_type=entry.entry_type or 'note',
        author_name=entry.author_name or 'Analyst',
        is_ai_generated=entry.is_ai_generated or False,
        ai_prompt=entry.ai_prompt
    )
    db.add(journal_entry)
    db.commit()
    db.refresh(journal_entry)

    return JournalEntryResponse(
        id=str(journal_entry.id),
        entry_text=journal_entry.entry_text,
        entry_type=journal_entry.entry_type or 'note',
        author_name=journal_entry.author_name or 'Analyst',
        is_ai_generated=journal_entry.is_ai_generated or False,
        ai_prompt=journal_entry.ai_prompt,
        created_at=journal_entry.created_at
    )


@router.post(
    "/{finding_id}/journal/ask-ai",
    dependencies=[Depends(require_permissions("findings:write"))],
    response_model=JournalEntryResponse,
    summary="Ask AI about a finding in journal context",
    responses={**CREATE_ERRORS, 403: {"description": "Insufficient permissions - requires findings:write"}, 404: {"description": "Finding not found"}},
)
async def ask_journal_ai(finding_id: str, request: AskJournalAIRequest, db: Session = Depends(get_tenant_db)):
    """Ask the AI assistant a question about a finding within its journal context.

    The question and AI response are both saved as journal entries. The AI
    receives the finding details and recent journal history as context.
    Requires the ``findings:write`` permission.
    """
    from ..config import settings
    
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get recent journal entries for context
    recent_entries = db.query(models.JournalEntry).filter(
        models.JournalEntry.finding_id == finding.id
    ).order_by(models.JournalEntry.created_at.desc()).limit(10).all()

    # Build context for AI
    journal_context = "\n".join([
        f"[{e.created_at.strftime('%Y-%m-%d %H:%M')}] {e.author_name}: {e.entry_text}"
        for e in reversed(recent_entries)
    ])

    # Prepare the AI prompt
    system_prompt = f"""You are a security analyst assistant helping investigate a security finding.

**Finding Information:**
- Title: {finding.title}
- Severity: {finding.severity}
- Scanner: {finding.scanner_name}
- File: {finding.file_path}
- Description: {finding.description or 'No description'}
- Code Snippet: {finding.code_snippet or 'No code snippet'}

**Recent Journal Entries:**
{journal_context if journal_context else 'No previous journal entries'}

Please provide helpful, actionable advice for the analyst's question. Be concise but thorough."""

    # Call AI provider
    ai_response = None
    try:
        if settings.OPENAI_API_KEY:
            import openai
            client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
            response = client.chat.completions.create(
                model=settings.AI_MODEL or "gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": request.question}
                ],
                max_tokens=1000
            )
            ai_response = response.choices[0].message.content
        elif settings.ANTHROPIC_API_KEY:
            import anthropic
            client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
            response = client.messages.create(
                model=settings.AI_MODEL or "claude-3-haiku-20240307",
                max_tokens=1000,
                system=system_prompt,
                messages=[{"role": "user", "content": request.question}]
            )
            ai_response = response.content[0].text
        else:
            ai_response = "AI assistant is not configured. Please set up OpenAI or Anthropic API keys."
    except Exception as e:
        logger.error(f"AI request failed: {e}")
        ai_response = f"Failed to get AI response: {str(e)}"

    # Save the user's question as a journal entry
    user_entry = models.JournalEntry(
        finding_id=finding.id,
        entry_text=request.question,
        entry_type='note',
        author_name=request.author_name or 'Analyst',
        is_ai_generated=False
    )
    db.add(user_entry)
    
    # Save the AI response as a journal entry
    ai_entry = models.JournalEntry(
        finding_id=finding.id,
        entry_text=ai_response,
        entry_type='ai_response',
        author_name='AI Assistant',
        is_ai_generated=True,
        ai_prompt=request.question
    )
    db.add(ai_entry)
    db.commit()
    db.refresh(ai_entry)

    return JournalEntryResponse(
        id=str(ai_entry.id),
        entry_text=ai_entry.entry_text,
        entry_type=ai_entry.entry_type or 'ai_response',
        author_name=ai_entry.author_name or 'AI Assistant',
        is_ai_generated=True,
        ai_prompt=ai_entry.ai_prompt,
        created_at=ai_entry.created_at
    )


@router.get(
    "/{finding_id}/journal/{entry_id}",
    dependencies=[Depends(require_permissions("findings:read"))],
    response_model=JournalEntryResponse,
    summary="Get a journal entry by ID",
    responses={
        400: {"description": "Invalid UUID format"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions - requires findings:read"},
        404: {"description": "Finding or journal entry not found"},
        500: {"description": "Internal server error"},
    },
)
def get_journal_entry(finding_id: str, entry_id: str, db: Session = Depends(get_tenant_db)):
    """Retrieve a specific journal entry by its UUID within a finding's investigation.

    Returns the full journal entry including text, type, author, and AI metadata.
    Requires the ``findings:read`` permission.
    """
    try:
        finding_uuid = uuid.UUID(finding_id)
        entry_uuid = uuid.UUID(entry_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    # Find the finding
    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == finding_uuid).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == finding_uuid).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Find the journal entry
    journal_entry = db.query(models.JournalEntry).filter(
        models.JournalEntry.id == entry_uuid,
        models.JournalEntry.finding_id == finding.id
    ).first()

    if not journal_entry:
        raise HTTPException(status_code=404, detail="Journal entry not found")

    return JournalEntryResponse(
        id=str(journal_entry.id),
        entry_text=journal_entry.entry_text,
        entry_type=journal_entry.entry_type or 'note',
        author_name=journal_entry.author_name or 'Analyst',
        is_ai_generated=journal_entry.is_ai_generated or False,
        ai_prompt=journal_entry.ai_prompt,
        created_at=journal_entry.created_at
    )


@router.put(
    "/{finding_id}/journal/{entry_id}",
    dependencies=[Depends(require_permissions("findings:write"))],
    response_model=JournalEntryResponse,
    summary="Update a journal entry",
    responses={
        400: {"description": "Invalid UUID format or invalid entry_type"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions or attempt to edit system entries"},
        404: {"description": "Finding or journal entry not found"},
        500: {"description": "Internal server error"},
    },
)
def update_journal_entry(
    finding_id: str,
    entry_id: str,
    update: JournalEntryUpdateRequest,
    db: Session = Depends(get_tenant_db)
):
    """Update the text, type, or author of an existing journal entry.

    System-generated status change entries cannot be modified.
    Requires the ``findings:write`` permission.
    """
    try:
        finding_uuid = uuid.UUID(finding_id)
        entry_uuid = uuid.UUID(entry_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    # Find the finding
    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == finding_uuid).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == finding_uuid).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Find the journal entry
    journal_entry = db.query(models.JournalEntry).filter(
        models.JournalEntry.id == entry_uuid,
        models.JournalEntry.finding_id == finding.id
    ).first()

    if not journal_entry:
        raise HTTPException(status_code=404, detail="Journal entry not found")

    # Prevent editing system-generated status change entries
    if journal_entry.entry_type == 'status_change' and journal_entry.author_name == 'System':
        raise HTTPException(
            status_code=403,
            detail="System-generated status change entries cannot be modified"
        )

    # Update fields if provided
    if update.entry_text is not None:
        journal_entry.entry_text = update.entry_text
    if update.entry_type is not None:
        valid_types = ['note', 'status_change', 'ai_response', 'communication']
        if update.entry_type not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid entry_type. Must be one of: {', '.join(valid_types)}"
            )
        journal_entry.entry_type = update.entry_type
    if update.author_name is not None:
        journal_entry.author_name = update.author_name

    db.commit()
    db.refresh(journal_entry)

    return JournalEntryResponse(
        id=str(journal_entry.id),
        entry_text=journal_entry.entry_text,
        entry_type=journal_entry.entry_type or 'note',
        author_name=journal_entry.author_name or 'Analyst',
        is_ai_generated=journal_entry.is_ai_generated or False,
        ai_prompt=journal_entry.ai_prompt,
        created_at=journal_entry.created_at
    )


@router.delete(
    "/{finding_id}/journal/{entry_id}",
    dependencies=[Depends(require_permissions("findings:delete"))],
    summary="Delete a journal entry",
    responses={
        400: {"description": "Invalid UUID format"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions or attempt to delete system entries"},
        404: {"description": "Finding or journal entry not found"},
        500: {"description": "Internal server error"},
    },
)
def delete_journal_entry(finding_id: str, entry_id: str, db: Session = Depends(get_tenant_db)):
    """Permanently delete a journal entry from a finding's investigation timeline.

    System-generated status change entries cannot be deleted.
    Requires the ``findings:delete`` permission.
    """
    try:
        finding_uuid = uuid.UUID(finding_id)
        entry_uuid = uuid.UUID(entry_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    # Find the finding
    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == finding_uuid).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == finding_uuid).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Find the journal entry
    journal_entry = db.query(models.JournalEntry).filter(
        models.JournalEntry.id == entry_uuid,
        models.JournalEntry.finding_id == finding.id
    ).first()

    if not journal_entry:
        raise HTTPException(status_code=404, detail="Journal entry not found")

    # Prevent deleting system-generated status change entries
    if journal_entry.entry_type == 'status_change' and journal_entry.author_name == 'System':
        raise HTTPException(
            status_code=403,
            detail="System-generated status change entries cannot be deleted"
        )

    db.delete(journal_entry)
    db.commit()

    return {
        "status": "success",
        "message": "Journal entry deleted",
        "deleted_id": entry_id
    }


# =============================================================================
# Snooze & Bulk Actions (Phase 1.2)
# =============================================================================

class SnoozeRequest(BaseModel):
    """Request to temporarily snooze a finding so it is hidden from default views."""
    days: int = Field(default=7, description="Number of days to snooze the finding (1-365)")
    reason: Optional[str] = Field(default=None, description="Optional justification for snoozing this finding")


class SnoozeResponse(BaseModel):
    """Response confirming a finding has been snoozed."""
    id: str = Field(description="UUID of the snoozed finding")
    snoozed_until: datetime = Field(description="Datetime when the snooze expires and the finding becomes visible again")
    reason: Optional[str] = Field(default=None, description="The snooze justification that was provided")


@router.post(
    "/{finding_id}/snooze",
    dependencies=[Depends(require_permissions("findings:write"))],
    response_model=SnoozeResponse,
    summary="Snooze a finding",
    responses={
        400: {"description": "Invalid UUID format or days out of range (1-365)"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions - requires findings:write"},
        404: {"description": "Finding not found"},
        500: {"description": "Internal server error"},
    },
)
def snooze_finding(finding_id: str, request: SnoozeRequest, db: Session = Depends(get_tenant_db)):
    """Temporarily snooze a finding so it is hidden from default listing views.

    The finding will reappear after the specified number of days. The snooze
    action is recorded in finding history. Requires the ``findings:write`` permission.
    """
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if request.days < 1 or request.days > 365:
        raise HTTPException(status_code=400, detail="Days must be between 1 and 365")

    from datetime import timedelta
    snooze_until = datetime.utcnow() + timedelta(days=request.days)
    
    finding.snoozed_until = snooze_until
    finding.snooze_reason = request.reason
    
    # Track in history
    history_entry = models.FindingHistory(
        finding_id=finding.id,
        change_type="snooze",
        old_value=None,
        new_value=snooze_until.isoformat(),
        comment=f"Snoozed for {request.days} days" + (f": {request.reason}" if request.reason else ""),
        change_metadata={"days": request.days, "reason": request.reason}
    )
    db.add(history_entry)
    db.commit()
    
    logger.info(f"Snoozed finding {finding_id} until {snooze_until}")

    return SnoozeResponse(
        id=str(finding.finding_uuid),
        snoozed_until=snooze_until,
        reason=request.reason
    )


@router.post(
    "/{finding_id}/unsnooze",
    dependencies=[Depends(require_permissions("findings:write"))],
    summary="Unsnooze a finding",
    responses={
        400: {"description": "Invalid UUID format"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions - requires findings:write"},
        404: {"description": "Finding not found"},
        500: {"description": "Internal server error"},
    },
)
def unsnooze_finding(finding_id: str, db: Session = Depends(get_tenant_db)):
    """Remove the snooze from a finding, making it visible in default listing views again.

    Clears the snoozed_until and snooze_reason fields.
    Requires the ``findings:write`` permission.
    """
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.snoozed_until = None
    finding.snooze_reason = None
    db.commit()

    return {"status": "success", "message": "Finding unsnoozed"}


class BulkActionRequest(BaseModel):
    """Request to perform the same action on multiple findings at once."""
    finding_ids: List[str] = Field(description="List of finding UUIDs to apply the action to")
    action: str = Field(description="Action to perform: 'resolve', 'reopen', 'snooze', 'unsnooze', or 'update_severity'")
    value: Optional[str] = Field(default=None, description="Action parameter: number of days for snooze, or severity level for update_severity")
    reason: Optional[str] = Field(default=None, description="Optional justification for the bulk action (used with snooze)")


class BulkActionResponse(BaseModel):
    """Response summarizing the results of a bulk action across multiple findings."""
    success_count: int = Field(description="Number of findings successfully updated")
    error_count: int = Field(description="Number of findings that failed to update")
    errors: List[str] = Field(default=[], description="List of error messages for each failed finding")


@router.post(
    "/bulk-action",
    dependencies=[Depends(require_permissions("findings:write"))],
    response_model=BulkActionResponse,
    summary="Perform a bulk action on multiple findings",
    responses={
        400: {"description": "Invalid action type or missing required value"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions - requires findings:write"},
        500: {"description": "Internal server error"},
    },
)
def bulk_action(request: BulkActionRequest, db: Session = Depends(get_tenant_db)):
    """Apply the same action to multiple findings in a single request.

    Supported actions: resolve, reopen, snooze, unsnooze, and update_severity.
    Returns per-finding success/error counts. Requires the ``findings:write`` permission.
    """
    valid_actions = ["resolve", "snooze", "update_severity", "unsnooze", "reopen"]
    if request.action not in valid_actions:
        raise HTTPException(status_code=400, detail=f"Action must be one of: {valid_actions}")

    success_count = 0
    error_count = 0
    errors = []

    for finding_id in request.finding_ids:
        try:
            uuid_obj = uuid.UUID(finding_id)
            finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
            if not finding:
                finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()

            if not finding:
                errors.append(f"{finding_id}: Finding not found")
                error_count += 1
                continue

            if request.action == "resolve":
                finding.status = "resolved"
                finding.resolved_at = datetime.utcnow()
                finding.remediation_completed_at = datetime.utcnow()
                
            elif request.action == "reopen":
                finding.status = "open"
                finding.resolved_at = None
                
            elif request.action == "snooze":
                days = int(request.value) if request.value else 7
                from datetime import timedelta
                finding.snoozed_until = datetime.utcnow() + timedelta(days=days)
                finding.snooze_reason = request.reason
                
            elif request.action == "unsnooze":
                finding.snoozed_until = None
                finding.snooze_reason = None
                
            elif request.action == "update_severity":
                if not request.value:
                    errors.append(f"{finding_id}: Severity value required")
                    error_count += 1
                    continue
                new_severity = request.value.lower()
                if new_severity not in SEVERITY_PRIORITY.keys():
                    errors.append(f"{finding_id}: Invalid severity '{request.value}'")
                    error_count += 1
                    continue
                finding.severity = new_severity

            success_count += 1

        except Exception as e:
            errors.append(f"{finding_id}: {str(e)}")
            error_count += 1

    db.commit()
    logger.info(f"Bulk action '{request.action}' completed: {success_count} success, {error_count} errors")

    return BulkActionResponse(
        success_count=success_count,
        error_count=error_count,
        errors=errors
    )


# =============================================================================
# Calculate & Store Risk Scores (Batch Endpoint)
# =============================================================================

class CalculateRiskScoresRequest(BaseModel):
    """Request to trigger risk score calculation for findings."""
    finding_ids: Optional[List[str]] = Field(default=None, description="List of finding UUIDs to calculate scores for. If omitted, calculates for all unscored findings (up to 500)")


class CalculateRiskScoresResponse(BaseModel):
    """Response summarizing the batch risk score calculation results."""
    calculated_count: int = Field(description="Number of findings for which risk scores were calculated")
    average_score: float = Field(description="Average risk score across all calculated findings")


@router.post(
    "/calculate-risk-scores",
    dependencies=[Depends(require_permissions("findings:write"))],
    response_model=CalculateRiskScoresResponse,
    summary="Batch calculate risk scores",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions - requires findings:write"},
        500: {"description": "Internal server error"},
    },
)
def calculate_and_store_risk_scores(
    request: CalculateRiskScoresRequest = None,
    db: Session = Depends(get_tenant_db)
):
    """Calculate and persist risk scores for a batch of findings.

    If specific finding IDs are provided, scores are calculated for those only.
    Otherwise, scores are calculated for up to 500 unscored findings.
    Requires the ``findings:write`` permission.
    """
    if request and request.finding_ids:
        findings = db.query(models.Finding).filter(
            models.Finding.finding_uuid.in_([uuid.UUID(fid) for fid in request.finding_ids])
        ).all()
    else:
        # Calculate for all findings without a risk score
        findings = db.query(models.Finding).filter(models.Finding.risk_score.is_(None)).limit(500).all()

    scores = []
    for finding in findings:
        score, factors = calculate_risk_score(finding, finding.repository)
        finding.risk_score = score
        finding.risk_factors = factors
        scores.append(score)

    db.commit()

    avg_score = sum(scores) / len(scores) if scores else 0

    return CalculateRiskScoresResponse(
        calculated_count=len(scores),
        average_score=round(avg_score, 1)
    )
