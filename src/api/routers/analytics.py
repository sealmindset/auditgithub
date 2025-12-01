from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any
from datetime import datetime, timedelta
from ..database import get_db
from .. import models

router = APIRouter(
    prefix="/analytics",
    tags=["analytics"]
)

@router.get("/summary")
async def get_summary_metrics(db: Session = Depends(get_db)):
    """Get high-level summary metrics for the dashboard."""
    total_findings = db.query(models.Finding).filter(models.Finding.status == 'open').count()
    critical_count = db.query(models.Finding).filter(
        models.Finding.status == 'open', 
        models.Finding.severity == 'critical'
    ).count()
    repos_count = db.query(models.Repository).count()
    
    # Calculate MTTR (Mean Time To Resolve)
    resolved_findings = db.query(models.Finding).filter(models.Finding.status == 'resolved').all()
    mttr_days = 0
    if resolved_findings:
        total_resolution_time = sum(
            (f.resolved_at - f.created_at).total_seconds() 
            for f in resolved_findings 
            if f.resolved_at and f.created_at
        )
        avg_seconds = total_resolution_time / len(resolved_findings)
        mttr_days = round(avg_seconds / 86400, 1)

    return {
        "total_open_findings": total_findings,
        "critical_open_findings": critical_count,
        "repositories_scanned": repos_count,
        "mttr_days": mttr_days
    }

@router.get("/severity-distribution")
async def get_severity_distribution(db: Session = Depends(get_db)):
    """Get count of findings by severity."""
    results = db.query(
        models.Finding.severity, 
        func.count(models.Finding.id)
    ).filter(models.Finding.status == 'open').group_by(models.Finding.severity).all()
    
    return [{"name": r[0].capitalize(), "count": r[1]} for r in results]

@router.get("/trends")
async def get_finding_trends(days: int = 7, db: Session = Depends(get_db)):
    """Get finding trends over the last N days."""
    # This is a simplified implementation. 
    # In a real system, you'd likely have a separate 'snapshots' table 
    # or use time-series queries on the history table.
    
    trends = []
    now = datetime.utcnow()
    
    for i in range(days):
        date = now - timedelta(days=i)
        date_str = date.strftime("%Y-%m-%d")
        
        # Mocking trend data for now as we don't have historical snapshots yet
        # In production, query `finding_history` or a daily snapshot table
        import random
        trends.append({
            "date": date_str,
            "findings": random.randint(100, 200)  # Placeholder
        })
        
    return list(reversed(trends))

@router.get("/recent-findings")
async def get_recent_findings(limit: int = 5, db: Session = Depends(get_db)):
    """Get recent critical/high findings."""
    findings = db.query(models.Finding).join(models.Repository).filter(
        models.Finding.status == 'open',
        models.Finding.severity.in_(['critical', 'high'])
    ).order_by(models.Finding.created_at.desc()).limit(limit).all()
    
    return [{
        "id": str(f.finding_uuid),
        "title": f.title,
        "severity": f.severity.capitalize(),
        "repo": f.repository.name,
        "status": f.status.capitalize(),
        "date": f.created_at.strftime("%Y-%m-%d")
    } for f in findings]
