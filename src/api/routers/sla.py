"""
SLA Router - Phase 2.2

Provides endpoints for tracking Mean Time to Remediate (MTTR) and SLA compliance.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case, and_, or_, extract
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel

from ..dependencies import get_tenant_db
from .. import models
from src.rbac.dependencies import require_permissions

router = APIRouter(
    prefix="/sla",
    tags=["sla"]
)


# =============================================================================
# SLA Configuration (in hours)
# =============================================================================

SLA_HOURS = {
    'critical': 24,      # 1 day
    'high': 168,         # 7 days
    'medium': 720,       # 30 days
    'low': 2160,         # 90 days
    'info': 4320,        # 180 days
}


# =============================================================================
# Pydantic Models
# =============================================================================

class SLAConfig(BaseModel):
    """SLA configuration for each severity level."""
    critical_hours: int = 24
    high_hours: int = 168
    medium_hours: int = 720
    low_hours: int = 2160
    info_hours: int = 4320


class MTTRStats(BaseModel):
    """Mean Time to Remediate statistics."""
    overall_mttr_hours: Optional[float]
    by_severity: Dict[str, Optional[float]]
    by_scanner: Dict[str, Optional[float]]
    by_month: List[Dict[str, Any]]


class SLAComplianceStats(BaseModel):
    """SLA compliance statistics."""
    total_resolved: int
    on_time: int
    overdue: int
    compliance_rate: float
    by_severity: Dict[str, Dict[str, Any]]


class OverdueFinding(BaseModel):
    """A finding that is past its SLA."""
    id: str
    title: str
    severity: str
    repo_name: str
    created_at: datetime
    sla_hours: int
    hours_overdue: float
    assigned_to: Optional[str]


class SLADashboardResponse(BaseModel):
    """Full SLA dashboard response."""
    config: SLAConfig
    mttr: MTTRStats
    compliance: SLAComplianceStats
    overdue_findings: List[OverdueFinding]


# =============================================================================
# Helper Functions
# =============================================================================

def get_sla_hours(severity: str) -> int:
    """Get SLA hours for a severity level."""
    return SLA_HOURS.get(severity.lower() if severity else 'medium', 720)


def calculate_mttr_hours(created_at: datetime, resolved_at: datetime) -> float:
    """Calculate time to remediate in hours."""
    if not created_at or not resolved_at:
        return None
    delta = resolved_at - created_at
    return delta.total_seconds() / 3600


def is_overdue(finding: models.Finding) -> bool:
    """Check if a finding is past its SLA."""
    if finding.status == 'resolved':
        return False
    
    sla_hours = get_sla_hours(finding.severity)
    deadline = finding.created_at + timedelta(hours=sla_hours)
    return datetime.utcnow() > deadline


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/config", response_model=SLAConfig, dependencies=[Depends(require_permissions("reports:read"))])
def get_sla_config():
    """Get current SLA configuration."""
    return SLAConfig(
        critical_hours=SLA_HOURS['critical'],
        high_hours=SLA_HOURS['high'],
        medium_hours=SLA_HOURS['medium'],
        low_hours=SLA_HOURS['low'],
        info_hours=SLA_HOURS['info']
    )


@router.get("/mttr", response_model=MTTRStats, dependencies=[Depends(require_permissions("reports:read"))])
def get_mttr_stats(
    days: int = Query(90, description="Number of days to analyze"),
    db: Session = Depends(get_tenant_db)
):
    """Get Mean Time to Remediate statistics."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    # Get resolved findings
    resolved = db.query(models.Finding).filter(
        models.Finding.status == 'resolved',
        models.Finding.resolved_at.isnot(None),
        models.Finding.resolved_at >= cutoff
    ).all()
    
    # Calculate overall MTTR
    mttr_values = []
    for f in resolved:
        mttr = calculate_mttr_hours(f.created_at, f.resolved_at)
        if mttr is not None:
            mttr_values.append(mttr)
    
    overall_mttr = sum(mttr_values) / len(mttr_values) if mttr_values else None
    
    # MTTR by severity
    by_severity = {}
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        severity_findings = [f for f in resolved if (f.severity or '').lower() == severity]
        if severity_findings:
            values = [calculate_mttr_hours(f.created_at, f.resolved_at) for f in severity_findings]
            values = [v for v in values if v is not None]
            by_severity[severity] = sum(values) / len(values) if values else None
        else:
            by_severity[severity] = None
    
    # MTTR by scanner
    by_scanner = {}
    scanners = set(f.scanner_name for f in resolved if f.scanner_name)
    for scanner in scanners:
        scanner_findings = [f for f in resolved if f.scanner_name == scanner]
        values = [calculate_mttr_hours(f.created_at, f.resolved_at) for f in scanner_findings]
        values = [v for v in values if v is not None]
        by_scanner[scanner] = sum(values) / len(values) if values else None
    
    # MTTR by month
    by_month = []
    for i in range(min(days // 30, 12)):
        month_start = datetime.utcnow().replace(day=1) - timedelta(days=30*i)
        month_end = (month_start + timedelta(days=32)).replace(day=1)
        
        month_findings = [
            f for f in resolved 
            if f.resolved_at and month_start <= f.resolved_at < month_end
        ]
        
        if month_findings:
            values = [calculate_mttr_hours(f.created_at, f.resolved_at) for f in month_findings]
            values = [v for v in values if v is not None]
            avg = sum(values) / len(values) if values else None
        else:
            avg = None
        
        by_month.append({
            "month": month_start.strftime("%Y-%m"),
            "mttr_hours": round(avg, 1) if avg else None,
            "count": len(month_findings)
        })
    
    return MTTRStats(
        overall_mttr_hours=round(overall_mttr, 1) if overall_mttr else None,
        by_severity={k: round(v, 1) if v else None for k, v in by_severity.items()},
        by_scanner={k: round(v, 1) if v else None for k, v in by_scanner.items()},
        by_month=list(reversed(by_month))
    )


@router.get("/compliance", response_model=SLAComplianceStats, dependencies=[Depends(require_permissions("reports:read"))])
def get_sla_compliance(
    days: int = Query(90, description="Number of days to analyze"),
    db: Session = Depends(get_tenant_db)
):
    """Get SLA compliance statistics."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    # Get resolved findings
    resolved = db.query(models.Finding).filter(
        models.Finding.status == 'resolved',
        models.Finding.resolved_at.isnot(None),
        models.Finding.resolved_at >= cutoff
    ).all()
    
    on_time = 0
    overdue = 0
    by_severity = {}
    
    for f in resolved:
        sla_hours = get_sla_hours(f.severity)
        mttr = calculate_mttr_hours(f.created_at, f.resolved_at)
        
        severity = (f.severity or 'unknown').lower()
        if severity not in by_severity:
            by_severity[severity] = {"total": 0, "on_time": 0, "overdue": 0}
        
        by_severity[severity]["total"] += 1
        
        if mttr is not None and mttr <= sla_hours:
            on_time += 1
            by_severity[severity]["on_time"] += 1
        else:
            overdue += 1
            by_severity[severity]["overdue"] += 1
    
    total = on_time + overdue
    compliance_rate = (on_time / total * 100) if total > 0 else 0
    
    # Add compliance rate to each severity
    for sev in by_severity:
        total_sev = by_severity[sev]["total"]
        on_time_sev = by_severity[sev]["on_time"]
        by_severity[sev]["compliance_rate"] = round(on_time_sev / total_sev * 100, 1) if total_sev > 0 else 0
    
    return SLAComplianceStats(
        total_resolved=total,
        on_time=on_time,
        overdue=overdue,
        compliance_rate=round(compliance_rate, 1),
        by_severity=by_severity
    )


@router.get("/overdue", response_model=List[OverdueFinding], dependencies=[Depends(require_permissions("reports:read"))])
def get_overdue_findings(
    limit: int = Query(50, le=200),
    severity: Optional[str] = None,
    db: Session = Depends(get_tenant_db)
):
    """Get findings that are past their SLA."""
    query = db.query(models.Finding).join(models.Repository).filter(
        models.Finding.status == 'open'
    )
    
    if severity:
        query = query.filter(models.Finding.severity == severity.lower())
    
    # Get all open findings and filter in Python (more flexible for SLA calculation)
    open_findings = query.all()
    
    overdue_list = []
    now = datetime.utcnow()
    
    for f in open_findings:
        sla_hours = get_sla_hours(f.severity)
        deadline = f.created_at + timedelta(hours=sla_hours)
        
        if now > deadline:
            hours_overdue = (now - deadline).total_seconds() / 3600
            overdue_list.append({
                "finding": f,
                "hours_overdue": hours_overdue,
                "sla_hours": sla_hours
            })
    
    # Sort by hours overdue (most overdue first)
    overdue_list.sort(key=lambda x: x["hours_overdue"], reverse=True)
    overdue_list = overdue_list[:limit]
    
    return [OverdueFinding(
        id=str(item["finding"].finding_uuid),
        title=item["finding"].title,
        severity=item["finding"].severity,
        repo_name=item["finding"].repository.name if item["finding"].repository else "Unknown",
        created_at=item["finding"].created_at,
        sla_hours=item["sla_hours"],
        hours_overdue=round(item["hours_overdue"], 1),
        assigned_to=None  # TODO: Add assignee resolution
    ) for item in overdue_list]


@router.get("/dashboard", response_model=SLADashboardResponse, dependencies=[Depends(require_permissions("reports:read"))])
def get_sla_dashboard(
    days: int = Query(90, description="Number of days to analyze"),
    overdue_limit: int = Query(20, le=50),
    db: Session = Depends(get_tenant_db)
):
    """Get the full SLA dashboard."""
    config = get_sla_config()
    mttr = get_mttr_stats(days=days, db=db)
    compliance = get_sla_compliance(days=days, db=db)
    overdue = get_overdue_findings(limit=overdue_limit, db=db)
    
    return SLADashboardResponse(
        config=config,
        mttr=mttr,
        compliance=compliance,
        overdue_findings=overdue
    )


@router.post("/start-remediation/{finding_id}", dependencies=[Depends(require_permissions("admin:manage"))])
def start_remediation(finding_id: str, db: Session = Depends(get_tenant_db)):
    """Mark remediation as started for MTTR tracking."""
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
    
    if finding.remediation_started_at:
        return {
            "status": "already_started",
            "started_at": finding.remediation_started_at
        }
    
    finding.remediation_started_at = datetime.utcnow()
    db.commit()
    
    return {
        "status": "success",
        "started_at": finding.remediation_started_at
    }
