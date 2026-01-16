"""
Secrets Router - Phase 2.1

Provides dedicated endpoints for managing and validating secret findings.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case, or_
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel

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
    id: str
    title: str
    severity: str
    scanner_name: Optional[str]
    file_path: Optional[str]
    repo_name: str
    repository_id: str
    is_verified_by_scanner: bool
    is_validated_active: Optional[bool]
    validation_message: Optional[str]
    validated_at: Optional[datetime]
    created_at: datetime
    status: str
    risk_score: Optional[int]

    model_config = {"from_attributes": True}


class SecretStats(BaseModel):
    """Statistics about secrets in the system."""
    total_secrets: int
    active_secrets: int
    revoked_secrets: int
    unknown_secrets: int
    unvalidated_secrets: int
    by_scanner: Dict[str, int]
    by_severity: Dict[str, int]


class SecretDashboardResponse(BaseModel):
    """Full dashboard response."""
    stats: SecretStats
    recent_active: List[SecretFinding]
    high_risk_unvalidated: List[SecretFinding]


class ValidateSecretRequest(BaseModel):
    """Request to validate a secret."""
    force: bool = False  # Re-validate even if already validated


class ValidateSecretResponse(BaseModel):
    """Response after validating a secret."""
    id: str
    is_active: Optional[bool]
    message: str
    validated_at: datetime


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

@router.get("/stats", response_model=SecretStats, dependencies=[Depends(require_permissions("findings:read"))])
def get_secret_stats(db: Session = Depends(get_tenant_db)):
    """Get statistics about secrets in the system."""
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


@router.get("/dashboard", response_model=SecretDashboardResponse, dependencies=[Depends(require_permissions("findings:read"))])
def get_secrets_dashboard(
    limit: int = Query(10, le=50),
    db: Session = Depends(get_tenant_db)
):
    """Get the secrets dashboard with stats and key findings."""
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


@router.get("/", response_model=List[SecretFinding], dependencies=[Depends(require_permissions("findings:read"))])
def get_secrets(
    status_filter: Optional[str] = Query(None, description="active, revoked, unknown, unvalidated"),
    severity: Optional[str] = None,
    repo_name: Optional[str] = None,
    limit: int = Query(100, le=500),
    skip: int = 0,
    db: Session = Depends(get_tenant_db)
):
    """Get all secret findings with optional filtering."""
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


@router.post("/{finding_id}/validate", response_model=ValidateSecretResponse, dependencies=[Depends(require_permissions("findings:write"))])
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


@router.post("/{finding_id}/mark-revoked", dependencies=[Depends(require_permissions("findings:write"))])
def mark_secret_revoked(finding_id: str, db: Session = Depends(get_tenant_db)):
    """Manually mark a secret as revoked/inactive."""
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


@router.post("/{finding_id}/mark-active", dependencies=[Depends(require_permissions("findings:write"))])
def mark_secret_active(finding_id: str, db: Session = Depends(get_tenant_db)):
    """Manually mark a secret as still active."""
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
