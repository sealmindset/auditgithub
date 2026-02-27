from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import and_, case, func
from typing import List, Optional, Dict
from loguru import logger
from ..dependencies import get_tenant_db
from ..database import get_current_org_id
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

class DeleteDryRunResponse(BaseModel):
    """Response previewing the findings that would be deleted without actually removing them."""
    count: int = Field(description="Total number of findings that would be deleted")
    scanner_name: str = Field(description="Scanner name of the matched findings")
    file_path: Optional[str] = Field(default=None, description="File path of the matched findings")
    sample_findings: List[dict] = Field(description="Sample of up to 5 findings that would be deleted (id, title, file_path, scanner_name)")

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
        sample_findings=sample_findings
    )


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
            # Delete only this specific finding
            # First delete related remediations
            db.query(models.Remediation).filter(models.Remediation.finding_id == finding.id).delete()
            db.delete(finding)
            deleted_count = 1
        else:
            # Global scope - match scanner AND file path for safety
            # Get all matching findings
            matching_findings = db.query(models.Finding).filter(
                and_(
                    models.Finding.scanner_name == finding.scanner_name,
                    models.Finding.file_path == finding.file_path
                )
            ).all()

            deleted_count = len(matching_findings)

            # Delete remediations for all matching findings
            for f in matching_findings:
                db.query(models.Remediation).filter(models.Remediation.finding_id == f.id).delete()

            # Delete the findings
            db.query(models.Finding).filter(
                and_(
                    models.Finding.scanner_name == finding.scanner_name,
                    models.Finding.file_path == finding.file_path
                )
            ).delete()

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
