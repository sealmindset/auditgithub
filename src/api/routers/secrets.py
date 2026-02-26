"""
Secrets Router - Phase 2.1

Provides dedicated endpoints for managing and validating secret findings.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case, or_
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

from ..dependencies import get_tenant_db
from .. import models
from src.rbac.dependencies import require_permissions

router = APIRouter(
    prefix="/secrets",
    tags=["secrets"]
)


# =============================================================================
# Pydantic Models
# =============================================================================

class SecretFinding(BaseModel):
    """A secret finding with validation status."""
    id: str = Field(..., description="Finding UUID")
    title: str = Field(..., description="Title of the secret finding")
    severity: str = Field(..., description="Severity level (critical, high, medium, low)")
    scanner_name: Optional[str] = Field(None, description="Scanner that detected the secret")
    file_path: Optional[str] = Field(None, description="File path containing the secret")
    repo_name: str = Field(..., description="Repository name")
    repository_id: str = Field(..., description="UUID of the repository")
    is_verified_by_scanner: bool = Field(..., description="Whether the scanner verified the secret")
    is_validated_active: Optional[bool] = Field(None, description="Whether the secret is confirmed active (True), revoked (False), or unknown (None)")
    validation_message: Optional[str] = Field(None, description="Message from the validation process")
    validated_at: Optional[datetime] = Field(None, description="Timestamp of last validation")
    created_at: datetime = Field(..., description="When the finding was first created")
    status: str = Field(..., description="Finding status (open, resolved, etc.)")
    risk_score: Optional[int] = Field(None, description="Calculated risk score")

    model_config = {"from_attributes": True}


class SecretStats(BaseModel):
    """Statistics about secrets in the system."""
    total_secrets: int = Field(..., description="Total number of secret findings")
    active_secrets: int = Field(..., description="Secrets confirmed as still active")
    revoked_secrets: int = Field(..., description="Secrets confirmed as revoked")
    unknown_secrets: int = Field(..., description="Secrets with unknown validation status")
    unvalidated_secrets: int = Field(..., description="Secrets that have not been validated yet")
    by_scanner: Dict[str, int] = Field(..., description="Secret counts grouped by scanner name")
    by_severity: Dict[str, int] = Field(..., description="Secret counts grouped by severity level")


class SecretDashboardResponse(BaseModel):
    """Full dashboard response."""
    stats: SecretStats = Field(..., description="Aggregate secret statistics")
    recent_active: List[SecretFinding] = Field(..., description="Recently validated active secrets")
    high_risk_unvalidated: List[SecretFinding] = Field(..., description="High-risk secrets pending validation")


class ValidateSecretRequest(BaseModel):
    """Request to validate a secret."""
    force: bool = Field(False, description="Re-validate even if already validated")


class ValidateSecretResponse(BaseModel):
    """Response after validating a secret."""
    id: str = Field(..., description="Finding UUID")
    is_active: Optional[bool] = Field(None, description="Whether the secret is active (True), revoked (False), or unknown (None)")
    message: str = Field(..., description="Validation result message")
    validated_at: datetime = Field(..., description="Timestamp of the validation")


# =============================================================================
# Helper Functions
# =============================================================================

def is_secret_finding(finding: models.Finding) -> bool:
    """Check if a finding is a secret-related finding."""
    secret_indicators = [
        'secret', 'token', 'key', 'password', 'credential', 'api_key',
        'apikey', 'access_key', 'private_key', 'auth', 'bearer'
    ]
    title_lower = (finding.title or '').lower()
    scanner_lower = (finding.scanner_name or '').lower()
    
    # TruffleHog and Gitleaks are secret scanners
    if scanner_lower in ['trufflehog', 'gitleaks']:
        return True
    
    # Check title for secret indicators
    return any(ind in title_lower for ind in secret_indicators)


def get_secret_query(db: Session):
    """Get base query for secret findings."""
    return db.query(models.Finding).join(models.Repository).filter(
        or_(
            models.Finding.scanner_name.ilike('%trufflehog%'),
            models.Finding.scanner_name.ilike('%gitleaks%'),
            models.Finding.title.ilike('%secret%'),
            models.Finding.title.ilike('%token%'),
            models.Finding.title.ilike('%api_key%'),
            models.Finding.title.ilike('%password%'),
            models.Finding.title.ilike('%credential%')
        )
    )


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/stats", response_model=SecretStats, dependencies=[Depends(require_permissions("findings:read"))],
    summary="Get secret statistics",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:read"}})
def get_secret_stats(db: Session = Depends(get_tenant_db)):
    """
    Get aggregate statistics about secrets in the system.
    Includes counts by validation status, scanner, and severity.
    Requires findings:read permission.
    """
    base_query = get_secret_query(db)
    
    total = base_query.count()
    
    # Count by validation status
    active = base_query.filter(models.Finding.is_validated_active == True).count()
    revoked = base_query.filter(models.Finding.is_validated_active == False).count()
    unvalidated = base_query.filter(models.Finding.validated_at.is_(None)).count()
    unknown = total - active - revoked - unvalidated
    
    # Count by scanner
    scanner_counts = db.query(
        models.Finding.scanner_name,
        func.count(models.Finding.id)
    ).filter(
        or_(
            models.Finding.scanner_name.ilike('%trufflehog%'),
            models.Finding.scanner_name.ilike('%gitleaks%')
        )
    ).group_by(models.Finding.scanner_name).all()
    
    by_scanner = {s[0] or 'Unknown': s[1] for s in scanner_counts}
    
    # Count by severity
    severity_counts = base_query.with_entities(
        models.Finding.severity,
        func.count(models.Finding.id)
    ).group_by(models.Finding.severity).all()
    
    by_severity = {s[0] or 'unknown': s[1] for s in severity_counts}
    
    return SecretStats(
        total_secrets=total,
        active_secrets=active,
        revoked_secrets=revoked,
        unknown_secrets=unknown,
        unvalidated_secrets=unvalidated,
        by_scanner=by_scanner,
        by_severity=by_severity
    )


@router.get("/dashboard", response_model=SecretDashboardResponse, dependencies=[Depends(require_permissions("findings:read"))],
    summary="Get secrets dashboard",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:read"}})
def get_secrets_dashboard(
    limit: int = Query(10, le=50),
    db: Session = Depends(get_tenant_db)
):
    """
    Get the secrets dashboard with statistics, recent active secrets, and high-risk unvalidated secrets.
    Provides a consolidated view for security analysts to prioritize secret remediation.
    Requires findings:read permission.
    """
    stats = get_secret_stats(db)
    
    # Get recent active secrets
    recent_active_query = get_secret_query(db).filter(
        models.Finding.is_validated_active == True
    ).order_by(models.Finding.validated_at.desc()).limit(limit)
    
    recent_active = [SecretFinding(
        id=str(f.finding_uuid),
        title=f.title,
        severity=f.severity,
        scanner_name=f.scanner_name,
        file_path=f.file_path,
        repo_name=f.repository.name if f.repository else "Unknown",
        repository_id=str(f.repository_id),
        is_verified_by_scanner=f.is_verified_by_scanner or False,
        is_validated_active=f.is_validated_active,
        validation_message=f.validation_message,
        validated_at=f.validated_at,
        created_at=f.created_at,
        status=f.status,
        risk_score=f.risk_score
    ) for f in recent_active_query.all()]
    
    # Get high-risk unvalidated secrets
    high_risk_query = get_secret_query(db).filter(
        models.Finding.validated_at.is_(None),
        models.Finding.status == 'open'
    ).order_by(
        case(
            (models.Finding.severity == 'critical', 1),
            (models.Finding.severity == 'high', 2),
            else_=3
        ),
        models.Finding.created_at.desc()
    ).limit(limit)
    
    high_risk_unvalidated = [SecretFinding(
        id=str(f.finding_uuid),
        title=f.title,
        severity=f.severity,
        scanner_name=f.scanner_name,
        file_path=f.file_path,
        repo_name=f.repository.name if f.repository else "Unknown",
        repository_id=str(f.repository_id),
        is_verified_by_scanner=f.is_verified_by_scanner or False,
        is_validated_active=f.is_validated_active,
        validation_message=f.validation_message,
        validated_at=f.validated_at,
        created_at=f.created_at,
        status=f.status,
        risk_score=f.risk_score
    ) for f in high_risk_query.all()]
    
    return SecretDashboardResponse(
        stats=stats,
        recent_active=recent_active,
        high_risk_unvalidated=high_risk_unvalidated
    )


@router.get("/", response_model=List[SecretFinding], dependencies=[Depends(require_permissions("findings:read"))],
    summary="List secret findings with filtering",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:read"}})
def get_secrets(
    status_filter: Optional[str] = Query(None, description="active, revoked, unknown, unvalidated"),
    severity: Optional[str] = None,
    repo_name: Optional[str] = None,
    limit: int = Query(100, le=500),
    skip: int = 0,
    db: Session = Depends(get_tenant_db)
):
    """
    Get all secret findings with optional filtering by status, severity, and repository.
    Results are ordered by validation status, risk score, and creation date.
    Requires findings:read permission.
    """
    query = get_secret_query(db)
    
    # Apply filters
    if status_filter == "active":
        query = query.filter(models.Finding.is_validated_active == True)
    elif status_filter == "revoked":
        query = query.filter(models.Finding.is_validated_active == False)
    elif status_filter == "unvalidated":
        query = query.filter(models.Finding.validated_at.is_(None))
    elif status_filter == "unknown":
        query = query.filter(
            models.Finding.validated_at.isnot(None),
            models.Finding.is_validated_active.is_(None)
        )
    
    if severity:
        query = query.filter(models.Finding.severity == severity.lower())
    
    if repo_name:
        query = query.filter(models.Repository.name.ilike(f"%{repo_name}%"))
    
    # Order by risk
    query = query.order_by(
        models.Finding.is_validated_active.desc().nullslast(),
        models.Finding.risk_score.desc().nullslast(),
        models.Finding.created_at.desc()
    )
    
    findings = query.offset(skip).limit(limit).all()
    
    return [SecretFinding(
        id=str(f.finding_uuid),
        title=f.title,
        severity=f.severity,
        scanner_name=f.scanner_name,
        file_path=f.file_path,
        repo_name=f.repository.name if f.repository else "Unknown",
        repository_id=str(f.repository_id),
        is_verified_by_scanner=f.is_verified_by_scanner or False,
        is_validated_active=f.is_validated_active,
        validation_message=f.validation_message,
        validated_at=f.validated_at,
        created_at=f.created_at,
        status=f.status,
        risk_score=f.risk_score
    ) for f in findings]


@router.post("/{finding_id}/validate", response_model=ValidateSecretResponse, dependencies=[Depends(require_permissions("findings:write"))],
    summary="Validate a secret finding",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:write"}, 400: {"description": "Invalid UUID format or finding is not a secret"}, 404: {"description": "Finding not found"}})
def validate_secret(
    finding_id: str,
    request: ValidateSecretRequest = None,
    db: Session = Depends(get_tenant_db)
):
    """
    Validate a secret to check if it's still active.
    
    Note: Full validation requires implementing provider-specific validators.
    This endpoint currently marks the finding as "manually validated".
    """
    import uuid as uuid_lib
    
    try:
        uuid_obj = uuid_lib.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")
    
    finding = db.query(models.Finding).filter(
        models.Finding.finding_uuid == uuid_obj
    ).first()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    if not is_secret_finding(finding):
        raise HTTPException(status_code=400, detail="Finding is not a secret")
    
    # Check if already validated (unless force=True)
    if finding.validated_at and not (request and request.force):
        return ValidateSecretResponse(
            id=str(finding.finding_uuid),
            is_active=finding.is_validated_active,
            message=f"Already validated: {finding.validation_message or 'No message'}",
            validated_at=finding.validated_at
        )
    
    # For now, mark as "needs manual validation" 
    # TODO: Implement actual secret validation via secret_validators.py
    now = datetime.utcnow()
    finding.validated_at = now
    finding.is_validated_active = None  # Unknown until manually checked
    finding.validation_message = "Pending manual validation - automated validators not yet configured"
    
    db.commit()
    
    return ValidateSecretResponse(
        id=str(finding.finding_uuid),
        is_active=None,
        message="Marked for manual validation. Automated validators coming soon.",
        validated_at=now
    )


@router.post("/{finding_id}/mark-revoked", dependencies=[Depends(require_permissions("findings:write"))],
    summary="Mark a secret as revoked",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:write"}, 400: {"description": "Invalid UUID format"}, 404: {"description": "Finding not found"}})
def mark_secret_revoked(finding_id: str, db: Session = Depends(get_tenant_db)):
    """
    Manually mark a secret as revoked/inactive.
    Updates the validation status and sets a timestamp for audit purposes.
    Requires findings:write permission.
    """
    import uuid as uuid_lib
    
    try:
        uuid_obj = uuid_lib.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")
    
    finding = db.query(models.Finding).filter(
        models.Finding.finding_uuid == uuid_obj
    ).first()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    finding.is_validated_active = False
    finding.validation_message = "Manually marked as revoked"
    finding.validated_at = datetime.utcnow()
    db.commit()
    
    return {"status": "success", "message": "Secret marked as revoked"}


@router.post("/{finding_id}/mark-active", dependencies=[Depends(require_permissions("findings:write"))],
    summary="Mark a secret as active",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:write"}, 400: {"description": "Invalid UUID format"}, 404: {"description": "Finding not found"}})
def mark_secret_active(finding_id: str, db: Session = Depends(get_tenant_db)):
    """
    Manually mark a secret as still active.
    Updates the validation status and sets a timestamp for audit purposes.
    Requires findings:write permission.
    """
    import uuid as uuid_lib
    
    try:
        uuid_obj = uuid_lib.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")
    
    finding = db.query(models.Finding).filter(
        models.Finding.finding_uuid == uuid_obj
    ).first()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    finding.is_validated_active = True
    finding.validation_message = "Manually confirmed as active - REQUIRES IMMEDIATE ROTATION"
    finding.validated_at = datetime.utcnow()
    db.commit()
    
    return {"status": "success", "message": "Secret marked as active - rotation recommended"}
