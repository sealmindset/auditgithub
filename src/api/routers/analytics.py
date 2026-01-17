from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, and_, or_, case, desc
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel
from loguru import logger
from ..dependencies import get_tenant_db
from ..database import  get_request_org_id
from .. import models
from src.rbac.dependencies import require_permissions


def apply_org_filter(query, model):
    """Apply organization filter to query if an org is selected via request context."""
    org_id = get_request_org_id()  # Uses request-scoped org ID from middleware
    if org_id and hasattr(model, 'organization_id'):
        return query.filter(model.organization_id == org_id)
    return query

router = APIRouter(
    prefix="/analytics",
    tags=["analytics"]
)


# =============================================================================
# Pydantic Models for Hollywood Dashboard
# =============================================================================

class HeroMetricsResponse(BaseModel):
    repositories: int
    criticalFindings: int
    underInvestigation: int
    aiAnalysesToday: int
    trends: Dict[str, Dict[str, Any]]


class RepoRiskItem(BaseModel):
    id: str
    name: str
    riskScore: int
    riskLevel: str
    criticalFindings: int
    highFindings: int
    secretsCount: int
    isArchived: bool
    isAbandoned: bool


class AIInsightItem(BaseModel):
    id: str
    type: str
    title: str
    description: str
    timestamp: datetime
    severity: Optional[str] = None
    link: Optional[str] = None
    repoName: Optional[str] = None


class ThreatRadarResponse(BaseModel):
    critical: int
    high: int
    medium: int
    secrets: int
    abandoned: int
    staleContributors: int
    overallScore: int  # 0-100 (higher = better security posture)


class ImmediateActionItem(BaseModel):
    title: str
    count: int
    description: str
    severity: str
    link: str


class TrendItem(BaseModel):
    label: str
    value: str
    direction: str  # "up", "down", "neutral"
    isGood: bool


class PostureData(BaseModel):
    grade: str
    score: int
    summary: str


class ExecutiveSummaryResponse(BaseModel):
    immediateActions: List[ImmediateActionItem]
    trends: List[TrendItem]
    posture: PostureData


class ComponentFeedback(BaseModel):
    component_id: str
    component_name: str
    vote: str  # "up" or "down"
    timestamp: str

@router.get("/summary", dependencies=[Depends(require_permissions("reports:read"))])
async def get_summary_metrics(db: Session = Depends(get_tenant_db)):
    """Get high-level summary metrics for the dashboard."""
    findings_query = apply_org_filter(db.query(models.Finding), models.Finding)
    repos_query = apply_org_filter(db.query(models.Repository), models.Repository)
    
    total_findings = findings_query.filter(models.Finding.status == 'open').count()
    critical_count = findings_query.filter(
        models.Finding.status == 'open', 
        models.Finding.severity == 'critical'
    ).count()
    repos_count = repos_query.count()
    
    # Calculate MTTR (Mean Time To Resolve)
    resolved_findings = findings_query.filter(models.Finding.status == 'resolved').all()
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

@router.get("/severity-distribution", dependencies=[Depends(require_permissions("reports:read"))])
async def get_severity_distribution(db: Session = Depends(get_tenant_db)):
    """Get count of findings by severity with trend data."""
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    two_weeks_ago = now - timedelta(days=14)

    # Define severity order for consistent output
    severity_order = ['info', 'low', 'warning', 'medium', 'high', 'critical']

    # Current counts - with org filter
    base_query = apply_org_filter(db.query(models.Finding), models.Finding)
    current_results = base_query.with_entities(
        models.Finding.severity,
        func.count(models.Finding.id)
    ).filter(models.Finding.status == 'open').group_by(models.Finding.severity).all()

    current_counts = {r[0].lower(): r[1] for r in current_results}

    # Previous week counts (findings that existed a week ago)
    previous_results = db.query(
        models.Finding.severity,
        func.count(models.Finding.id)
    ).filter(
        models.Finding.status == 'open',
        models.Finding.created_at < week_ago
    ).group_by(models.Finding.severity).all()

    previous_counts = {r[0].lower(): r[1] for r in previous_results}

    # Build response with trend percentages
    response = []
    for severity in severity_order:
        current = current_counts.get(severity, 0)
        previous = previous_counts.get(severity, 0)

        # Calculate trend (percentage change)
        if previous > 0:
            trend = int(((current - previous) / previous) * 100)
        elif current > 0:
            trend = 100  # New findings where there were none
        else:
            trend = 0

        if current > 0 or severity in ['high', 'critical', 'medium']:  # Always show important severities
            response.append({
                "name": severity.capitalize(),
                "count": current,
                "trend": trend
            })

    return response


@router.get("/severity-trend", dependencies=[Depends(require_permissions("reports:read"))])
async def get_severity_trend(db: Session = Depends(get_tenant_db)):
    """Get trend data for all findings over the lifetime of repos."""
    now = datetime.utcnow()

    # Find the earliest repository creation date
    earliest_repo = db.query(func.min(models.Repository.created_at)).scalar()

    if not earliest_repo:
        # No repos, return empty data
        return {
            "startDate": now.isoformat(),
            "endDate": now.isoformat(),
            "totalFindings": 0,
            "timeline": []
        }

    # Calculate the time span
    total_days = (now - earliest_repo).days
    if total_days < 1:
        total_days = 1

    # Determine date format based on time span
    if total_days <= 30:
        date_format = "%m/%d"
    elif total_days <= 365:
        date_format = "%b %d"
    else:
        date_format = "%b '%y"

    # Generate timeline data points - aim for 8-12 data points
    num_points = min(12, max(8, total_days))
    actual_interval = max(1, total_days // num_points)

    timeline = []
    for i in range(num_points + 1):
        if i == num_points:
            # Final point is current state
            point_end = now
        else:
            point_end = earliest_repo + timedelta(days=i * actual_interval)
            # Don't go past current time
            if point_end > now:
                continue

        # Count cumulative findings up to this point
        cumulative_count = db.query(models.Finding).filter(
            models.Finding.created_at <= point_end
        ).count()

        # Count open findings at this point (created before, not resolved before)
        open_at_point = db.query(models.Finding).filter(
            models.Finding.created_at <= point_end,
            or_(
                models.Finding.resolved_at.is_(None),
                models.Finding.resolved_at > point_end
            )
        ).count()

        timeline.append({
            "date": point_end.strftime(date_format),
            "cumulative": cumulative_count,
            "open": open_at_point
        })

    # Remove duplicate dates (keep the last one)
    seen_dates = {}
    for item in timeline:
        seen_dates[item["date"]] = item
    timeline = list(seen_dates.values())

    # Get current totals
    current_total = db.query(models.Finding).count()
    current_open = db.query(models.Finding).filter(
        models.Finding.status == 'open'
    ).count()

    return {
        "startDate": earliest_repo.isoformat(),
        "endDate": now.isoformat(),
        "totalFindings": current_total,
        "openFindings": current_open,
        "timeline": timeline,
        "intervalDays": actual_interval,
        "totalDays": total_days
    }

@router.get("/repo-growth", dependencies=[Depends(require_permissions("reports:read"))])
async def get_repo_growth(db: Session = Depends(get_tenant_db)):
    """Get repository growth over the lifetime of the GitHub organization."""
    now = datetime.utcnow()

    # Find the earliest repository creation date (use github_created_at for actual GitHub dates)
    earliest_repo = db.query(func.min(models.Repository.github_created_at)).filter(
        models.Repository.github_created_at.isnot(None)
    ).scalar()

    # Fallback to created_at if github_created_at not available
    if not earliest_repo:
        earliest_repo = db.query(func.min(models.Repository.created_at)).scalar()

    if not earliest_repo:
        return {
            "startYear": now.year,
            "endYear": now.year,
            "totalRepos": 0,
            "timeline": []
        }

    # Calculate total years
    start_year = earliest_repo.year
    end_year = now.year
    total_years = end_year - start_year + 1

    # Get total repo count
    total_repos = db.query(models.Repository).count()

    # Generate yearly data points
    timeline = []

    for year in range(start_year, end_year + 1):
        year_end = datetime(year, 12, 31, 23, 59, 59)
        if year == end_year:
            year_end = now

        year_start = datetime(year, 1, 1, 0, 0, 0)

        # Count cumulative repos created up to this year (use github_created_at)
        cumulative_repos = db.query(models.Repository).filter(
            or_(
                models.Repository.github_created_at <= year_end,
                and_(
                    models.Repository.github_created_at.is_(None),
                    models.Repository.created_at <= year_end
                )
            )
        ).count()

        # Count repos created in this specific year
        repos_this_year = db.query(models.Repository).filter(
            or_(
                and_(
                    models.Repository.github_created_at >= year_start,
                    models.Repository.github_created_at <= year_end
                ),
                and_(
                    models.Repository.github_created_at.is_(None),
                    models.Repository.created_at >= year_start,
                    models.Repository.created_at <= year_end
                )
            )
        ).count()

        timeline.append({
            "year": str(year),
            "repos": cumulative_repos,
            "newRepos": repos_this_year
        })

    return {
        "startYear": start_year,
        "endYear": end_year,
        "totalYears": total_years,
        "totalRepos": total_repos,
        "timeline": timeline
    }


@router.get("/trends", dependencies=[Depends(require_permissions("reports:read"))])
async def get_finding_trends(days: int = 7, db: Session = Depends(get_tenant_db)):
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

@router.get("/recent-findings", dependencies=[Depends(require_permissions("reports:read"))])
async def get_recent_findings(limit: int = 5, db: Session = Depends(get_tenant_db)):
    """Get recent critical/high findings."""
    # Apply org filter
    base_query = apply_org_filter(db.query(models.Finding), models.Finding)
    findings = base_query.join(models.Repository).filter(
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


# =============================================================================
# Hollywood Dashboard Endpoints
# =============================================================================

@router.get("/hero-metrics", response_model=HeroMetricsResponse, dependencies=[Depends(require_permissions("reports:read"))])
async def get_hero_metrics(db: Session = Depends(get_tenant_db)):
    """Get hero metrics for the Hollywood dashboard with trend data."""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = now - timedelta(days=7)
    yesterday = now - timedelta(days=1)

    # Current counts - with org filter
    repos_count = apply_org_filter(db.query(models.Repository), models.Repository).count()
    critical_query = apply_org_filter(db.query(models.Finding), models.Finding)
    critical_count = critical_query.filter(
        models.Finding.status == 'open',
        models.Finding.severity == 'critical'
    ).count()

    # Under investigation (triage or incident_response) - with org filter
    investigation_query = apply_org_filter(db.query(models.Finding), models.Finding)
    investigation_count = investigation_query.filter(
        models.Finding.investigation_status.in_(['triage', 'incident_response'])
    ).count()

    # AI analyses today - count findings with AI-enhanced descriptions or remediations created today
    ai_query = apply_org_filter(db.query(models.Finding), models.Finding)
    ai_analyses_today = ai_query.filter(
        or_(
            models.Finding.description.like('%**AI Security Analysis%'),
            models.Finding.updated_at >= today_start
        )
    ).count()

    # Also count zero-day analyses created today
    try:
        zda_today = db.query(models.ZeroDayAnalysis).filter(
            models.ZeroDayAnalysis.created_at >= today_start
        ).count()
        ai_analyses_today += zda_today
    except AttributeError as e:
        logger.debug(f"ZeroDayAnalysis model not available: {str(e)}")

    # Also count remediations created today
    remediation_today = db.query(models.Remediation).filter(
        models.Remediation.created_at >= today_start
    ).count()
    ai_analyses_today += remediation_today

    # Trends - compare to last week - with org filter
    # Repos trend (new repos this week)
    new_repos_query = apply_org_filter(db.query(models.Repository), models.Repository)
    new_repos_week = new_repos_query.filter(
        models.Repository.created_at >= week_ago
    ).count()

    # Critical findings trend (compare to last week)
    critical_trend_query = apply_org_filter(db.query(models.Finding), models.Finding)
    critical_week_ago = critical_trend_query.filter(
        models.Finding.status == 'open',
        models.Finding.severity == 'critical',
        models.Finding.created_at < week_ago
    ).count()
    findings_trend = critical_count - critical_week_ago

    # Investigations started this week
    inv_trend_query = apply_org_filter(db.query(models.Finding), models.Finding)
    new_investigations = inv_trend_query.filter(
        models.Finding.investigation_started_at >= week_ago
    ).count()

    # AI analyses yesterday for trend
    yesterday_start = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
    ai_yesterday = db.query(models.Remediation).filter(
        models.Remediation.created_at >= yesterday_start,
        models.Remediation.created_at < today_start
    ).count()
    ai_trend = ai_analyses_today - ai_yesterday

    return HeroMetricsResponse(
        repositories=repos_count,
        criticalFindings=critical_count,
        underInvestigation=investigation_count,
        aiAnalysesToday=ai_analyses_today,
        trends={
            "repositories": {"value": new_repos_week, "label": "this week"},
            "findings": {"value": findings_trend, "label": "vs last week"},
            "investigations": {"value": new_investigations, "label": "this week"},
            "aiAnalyses": {"value": ai_trend, "label": "vs yesterday"}
        }
    )


@router.get("/risk-heatmap", response_model=List[RepoRiskItem], dependencies=[Depends(require_permissions("reports:read"))])
async def get_risk_heatmap(
    limit: int = Query(50, le=100),
    db: Session = Depends(get_tenant_db)
):
    """Get repository risk data for the heatmap visualization."""
    now = datetime.utcnow()
    one_year_ago = now - timedelta(days=365)

    # Get repos with finding counts
    repos_data = db.query(
        models.Repository,
        func.count(case((models.Finding.severity == 'critical', 1))).label('critical_count'),
        func.count(case((models.Finding.severity == 'high', 1))).label('high_count'),
        func.count(case((models.Finding.scanner_name == 'trufflehog', 1))).label('secrets_count'),
        func.count(models.Finding.id).label('total_findings')
    ).outerjoin(
        models.Finding,
        and_(
            models.Finding.repository_id == models.Repository.id,
            models.Finding.status.in_(['open', 'confirmed'])
        )
    ).group_by(models.Repository.id).all()

    results = []
    for repo, critical, high, secrets, total in repos_data:
        # Calculate risk score
        risk_score = 0
        risk_factors = []

        # Critical findings
        if critical > 0:
            risk_score += min(40, critical * 15)
            risk_factors.append(f"{critical} critical")

        # High findings
        if high > 0:
            risk_score += min(25, high * 5)
            risk_factors.append(f"{high} high")

        # Secrets
        if secrets > 0:
            risk_score += min(20, secrets * 10)
            # Extra penalty for public repos with secrets
            if repo.visibility == 'public':
                risk_score += 15

        # Abandoned/archived
        is_abandoned = repo.pushed_at is None or repo.pushed_at < one_year_ago
        if is_abandoned:
            risk_score += 10
        if repo.is_archived and (critical > 0 or secrets > 0):
            risk_score += 10

        # Cap at 100
        risk_score = min(100, risk_score)

        # Determine risk level
        if risk_score >= 70:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Only include repos with some risk or findings
        if risk_score > 0 or total > 0:
            results.append(RepoRiskItem(
                id=str(repo.id),
                name=repo.name,
                riskScore=risk_score,
                riskLevel=risk_level,
                criticalFindings=critical or 0,
                highFindings=high or 0,
                secretsCount=secrets or 0,
                isArchived=repo.is_archived or False,
                isAbandoned=is_abandoned
            ))

    # Sort by risk score descending
    results.sort(key=lambda x: x.riskScore, reverse=True)

    return results[:limit]


@router.get("/ai-insights", response_model=List[AIInsightItem], dependencies=[Depends(require_permissions("reports:read"))])
async def get_ai_insights(
    limit: int = Query(10, le=50),
    db: Session = Depends(get_tenant_db)
):
    """Get recent AI activity for the insights panel."""
    insights = []
    now = datetime.utcnow()

    # Recent critical/high findings (type: finding) - with org filter
    findings_query = apply_org_filter(db.query(models.Finding), models.Finding)
    recent_findings = findings_query.join(models.Repository).filter(
        models.Finding.status == 'open',
        models.Finding.severity.in_(['critical', 'high']),
        models.Finding.created_at >= now - timedelta(hours=24)
    ).order_by(models.Finding.created_at.desc()).limit(5).all()

    for f in recent_findings:
        secret_type = ""
        if f.scanner_name == 'trufflehog' and f.title:
            secret_type = f.title.replace('Secret found: ', '')
        insights.append(AIInsightItem(
            id=f"finding-{f.id}",
            type="finding",
            title=f"Found {secret_type or f.title[:50]}",
            description=f"in {f.file_path or 'repository'}" if f.file_path else f.title[:80],
            timestamp=f.created_at,
            severity=f.severity,
            link=f"/findings/{f.finding_uuid}",
            repoName=f.repository.name if f.repository else None
        ))

    # Recent remediations (type: remediation) - with org filter via finding
    remediation_query = apply_org_filter(db.query(models.Remediation).join(models.Finding), models.Finding)
    recent_remediations = remediation_query.join(models.Repository).filter(
        models.Remediation.created_at >= now - timedelta(hours=24)
    ).order_by(models.Remediation.created_at.desc()).limit(5).all()

    for r in recent_remediations:
        insights.append(AIInsightItem(
            id=f"remediation-{r.id}",
            type="remediation",
            title="Remediation generated",
            description=f"for {r.finding.title[:50]}..." if r.finding else "for finding",
            timestamp=r.created_at,
            link=f"/findings/{r.finding.finding_uuid}" if r.finding else None,
            repoName=r.finding.repository.name if r.finding and r.finding.repository else None
        ))

    # Recent zero-day analyses (type: analysis)
    try:
        recent_zda = db.query(models.ZeroDayAnalysis).filter(
            models.ZeroDayAnalysis.created_at >= now - timedelta(hours=48)
        ).order_by(models.ZeroDayAnalysis.created_at.desc()).limit(3).all()

        for z in recent_zda:
            affected_count = len(z.affected_repos) if z.affected_repos else 0
            insights.append(AIInsightItem(
                id=f"zda-{z.id}",
                type="analysis",
                title=f"Zero-day analysis: {z.cve_id or 'Custom'}",
                description=f"Analyzed {affected_count} potentially affected repositories",
                timestamp=z.created_at,
                link="/zero-day/reports"
            ))
    except AttributeError as e:
        logger.debug(f"ZeroDayAnalysis model not available: {str(e)}")

    # Recent investigations started (type: alert) - with org filter
    inv_query = apply_org_filter(db.query(models.Finding), models.Finding)
    recent_investigations = inv_query.join(models.Repository).filter(
        models.Finding.investigation_started_at >= now - timedelta(hours=24),
        models.Finding.investigation_status.in_(['triage', 'incident_response'])
    ).order_by(models.Finding.investigation_started_at.desc()).limit(3).all()

    for f in recent_investigations:
        status_label = "Incident Response" if f.investigation_status == 'incident_response' else "Triage"
        insights.append(AIInsightItem(
            id=f"investigation-{f.id}",
            type="alert",
            title=f"{status_label} started",
            description=f"for {f.title[:50]}...",
            timestamp=f.investigation_started_at,
            severity=f.severity,
            link=f"/findings/{f.finding_uuid}",
            repoName=f.repository.name if f.repository else None
        ))

    # Sort all insights by timestamp descending
    insights.sort(key=lambda x: x.timestamp, reverse=True)

    return insights[:limit]


@router.get("/threat-radar", response_model=ThreatRadarResponse, dependencies=[Depends(require_permissions("reports:read"))])
async def get_threat_radar(db: Session = Depends(get_tenant_db)):
    """Get threat radar data for the animated visualization."""
    now = datetime.utcnow()
    one_year_ago = now - timedelta(days=365)
    ninety_days_ago = now - timedelta(days=90)

    # Critical findings - with org filter
    critical_query = apply_org_filter(db.query(models.Finding), models.Finding)
    critical_count = critical_query.filter(
        models.Finding.status == 'open',
        models.Finding.severity == 'critical'
    ).count()

    # High findings - with org filter
    high_query = apply_org_filter(db.query(models.Finding), models.Finding)
    high_count = high_query.filter(
        models.Finding.status == 'open',
        models.Finding.severity == 'high'
    ).count()

    # Medium findings - with org filter
    medium_query = apply_org_filter(db.query(models.Finding), models.Finding)
    medium_count = medium_query.filter(
        models.Finding.status == 'open',
        models.Finding.severity == 'medium'
    ).count()

    # Secrets (TruffleHog findings) - with org filter
    secrets_query = apply_org_filter(db.query(models.Finding), models.Finding)
    secrets_count = secrets_query.filter(
        models.Finding.scanner_name == 'trufflehog',
        models.Finding.status == 'open'
    ).count()

    # Abandoned repos (no push in 1+ year) - with org filter
    abandoned_query = apply_org_filter(db.query(models.Repository), models.Repository)
    abandoned_count = abandoned_query.filter(
        or_(
            models.Repository.pushed_at < one_year_ago,
            models.Repository.pushed_at.is_(None)
        )
    ).count()

    # Stale contributors (no commit in 90 days) - with org filter
    # Get unique contributors with no recent activity
    contrib_query = apply_org_filter(db.query(func.count(func.distinct(models.Contributor.email))), models.Contributor)
    total_contributors = contrib_query.scalar() or 0
    active_query = apply_org_filter(db.query(func.count(func.distinct(models.Contributor.email))), models.Contributor)
    active_contributors = active_query.filter(
        models.Contributor.last_commit_at >= ninety_days_ago
    ).scalar() or 0
    stale_contributors = total_contributors - active_contributors

    # Calculate overall security score (0-100, higher = better)
    # Start at 100 and deduct points for issues
    score = 100

    # Deduct for critical findings (heavy penalty)
    score -= min(critical_count * 2, 30)

    # Deduct for high findings
    score -= min(high_count * 0.5, 15)

    # Deduct for secrets
    score -= min(secrets_count * 1, 20)

    # Deduct for abandoned repos (as percentage) - with org filter
    total_repos = apply_org_filter(db.query(models.Repository), models.Repository).count()
    if total_repos > 0:
        abandoned_pct = (abandoned_count / total_repos) * 100
        score -= min(abandoned_pct * 0.2, 15)

    # Deduct for stale contributors (as percentage)
    if total_contributors > 0:
        stale_pct = (stale_contributors / total_contributors) * 100
        score -= min(stale_pct * 0.1, 10)

    # Ensure score is between 0-100
    score = max(0, min(100, int(score)))

    return ThreatRadarResponse(
        critical=critical_count,
        high=high_count,
        medium=medium_count,
        secrets=secrets_count,
        abandoned=abandoned_count,
        staleContributors=stale_contributors,
        overallScore=score
    )


@router.get("/executive-summary", response_model=ExecutiveSummaryResponse, dependencies=[Depends(require_permissions("reports:read"))])
async def get_executive_summary(db: Session = Depends(get_tenant_db)):
    """Get executive summary data for the 'What Matters Now' cards."""
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    two_weeks_ago = now - timedelta(days=14)
    one_year_ago = now - timedelta(days=365)

    # === IMMEDIATE ACTIONS === (with org filter)
    immediate_actions = []

    # Public repos with secrets - with org filter
    public_secrets_query = apply_org_filter(db.query(func.count(func.distinct(models.Repository.id))), models.Repository)
    public_repos_with_secrets = public_secrets_query.join(
        models.Finding,
        models.Finding.repository_id == models.Repository.id
    ).filter(
        models.Repository.visibility == 'public',
        models.Finding.scanner_name == 'trufflehog',
        models.Finding.status == 'open'
    ).scalar() or 0

    if public_repos_with_secrets > 0:
        immediate_actions.append(ImmediateActionItem(
            title="public repos with exposed secrets",
            count=public_repos_with_secrets,
            description="Secrets in public repositories are exposed to the internet",
            severity="critical",
            link="/findings?scanner=trufflehog&visibility=public"
        ))

    # Critical findings not in investigation - with org filter
    critical_inv_query = apply_org_filter(db.query(models.Finding), models.Finding)
    critical_not_investigated = critical_inv_query.filter(
        models.Finding.status == 'open',
        models.Finding.severity == 'critical',
        or_(
            models.Finding.investigation_status.is_(None),
            models.Finding.investigation_status == 'none'
        )
    ).count()

    if critical_not_investigated > 0:
        immediate_actions.append(ImmediateActionItem(
            title="critical findings need investigation",
            count=critical_not_investigated,
            description="Critical vulnerabilities requiring immediate triage",
            severity="critical",
            link="/findings?severity=critical&investigation_status=none"
        ))

    # Abandoned repos with findings - with org filter
    abandoned_query = apply_org_filter(db.query(func.count(func.distinct(models.Repository.id))), models.Repository)
    abandoned_with_findings = abandoned_query.join(
        models.Finding,
        models.Finding.repository_id == models.Repository.id
    ).filter(
        or_(
            models.Repository.pushed_at < one_year_ago,
            models.Repository.pushed_at.is_(None)
        ),
        models.Finding.status == 'open',
        models.Finding.severity.in_(['critical', 'high'])
    ).scalar() or 0

    if abandoned_with_findings > 0:
        immediate_actions.append(ImmediateActionItem(
            title="abandoned repos with vulnerabilities",
            count=abandoned_with_findings,
            description="Unmaintained repositories with open security issues",
            severity="high",
            link="/attack-surface?filter=abandoned"
        ))

    # If no immediate actions, add a positive message
    if not immediate_actions:
        immediate_actions.append(ImmediateActionItem(
            title="action items",
            count=0,
            description="No critical items requiring immediate attention",
            severity="medium",
            link="/findings"
        ))

    # === WEEKLY TRENDS === (with org filter)
    trends = []

    # Critical findings trend - with org filter
    critical_week_query = apply_org_filter(db.query(models.Finding), models.Finding)
    critical_this_week = critical_week_query.filter(
        models.Finding.status == 'open',
        models.Finding.severity == 'critical',
        models.Finding.created_at >= week_ago
    ).count()

    critical_last_query = apply_org_filter(db.query(models.Finding), models.Finding)
    critical_last_week = critical_last_query.filter(
        models.Finding.status == 'open',
        models.Finding.severity == 'critical',
        models.Finding.created_at >= two_weeks_ago,
        models.Finding.created_at < week_ago
    ).count()

    if critical_last_week > 0:
        pct_change = ((critical_this_week - critical_last_week) / critical_last_week) * 100
        direction = "down" if pct_change < 0 else "up" if pct_change > 0 else "neutral"
        is_good = pct_change <= 0
        trends.append(TrendItem(
            label="Critical findings",
            value=f"{abs(int(pct_change))}% {'fewer' if pct_change < 0 else 'more'}",
            direction=direction,
            isGood=is_good
        ))
    else:
        trends.append(TrendItem(
            label="Critical findings",
            value=f"{critical_this_week} this week",
            direction="neutral",
            isGood=critical_this_week == 0
        ))

    # New repos scanned - with org filter
    new_repos_query = apply_org_filter(db.query(models.Repository), models.Repository)
    new_repos = new_repos_query.filter(
        models.Repository.created_at >= week_ago
    ).count()

    trends.append(TrendItem(
        label="New repos scanned",
        value=f"+{new_repos}",
        direction="up",
        isGood=True
    ))

    # Scan coverage - with org filter
    total_repos = apply_org_filter(db.query(models.Repository), models.Repository).count()
    scanned_query = apply_org_filter(db.query(func.count(func.distinct(models.Finding.repository_id))), models.Finding)
    scanned_repos = scanned_query.scalar() or 0

    if total_repos > 0:
        coverage_pct = int((scanned_repos / total_repos) * 100)
        trends.append(TrendItem(
            label="Scan coverage",
            value=f"{coverage_pct}%",
            direction="neutral",
            isGood=coverage_pct >= 80
        ))

    # Remediation rate (findings resolved this week) - with org filter
    resolved_query = apply_org_filter(db.query(models.Finding), models.Finding)
    resolved_this_week = resolved_query.filter(
        models.Finding.status == 'resolved',
        models.Finding.resolved_at >= week_ago
    ).count()

    if resolved_this_week > 0:
        trends.append(TrendItem(
            label="Findings resolved",
            value=f"+{resolved_this_week}",
            direction="up",
            isGood=True
        ))

    # === SECURITY POSTURE === (with org filter)
    # Calculate overall score and grade
    score = 100

    # Critical findings penalty - with org filter
    critical_posture_query = apply_org_filter(db.query(models.Finding), models.Finding)
    critical_total = critical_posture_query.filter(
        models.Finding.status == 'open',
        models.Finding.severity == 'critical'
    ).count()
    score -= min(critical_total * 2, 30)

    # High findings penalty - with org filter
    high_posture_query = apply_org_filter(db.query(models.Finding), models.Finding)
    high_total = high_posture_query.filter(
        models.Finding.status == 'open',
        models.Finding.severity == 'high'
    ).count()
    score -= min(high_total * 0.5, 15)

    # Secrets penalty - with org filter
    secrets_posture_query = apply_org_filter(db.query(models.Finding), models.Finding)
    secrets_total = secrets_posture_query.filter(
        models.Finding.scanner_name == 'trufflehog',
        models.Finding.status == 'open'
    ).count()
    score -= min(secrets_total, 20)

    # Abandoned repos penalty - with org filter
    abandoned_posture_query = apply_org_filter(db.query(models.Repository), models.Repository)
    abandoned_total = abandoned_posture_query.filter(
        or_(
            models.Repository.pushed_at < one_year_ago,
            models.Repository.pushed_at.is_(None)
        )
    ).count()
    if total_repos > 0:
        abandoned_pct = (abandoned_total / total_repos) * 100
        score -= min(abandoned_pct * 0.2, 15)

    score = max(0, min(100, int(score)))

    # Determine grade
    if score >= 90:
        grade = "A"
    elif score >= 85:
        grade = "A-"
    elif score >= 80:
        grade = "B+"
    elif score >= 75:
        grade = "B"
    elif score >= 70:
        grade = "B-"
    elif score >= 65:
        grade = "C+"
    elif score >= 60:
        grade = "C"
    elif score >= 55:
        grade = "C-"
    elif score >= 50:
        grade = "D+"
    elif score >= 45:
        grade = "D"
    elif score >= 40:
        grade = "D-"
    else:
        grade = "F"

    # Generate summary
    if score >= 80:
        summary = "Strong security posture with minimal issues"
    elif score >= 60:
        summary = f"Good, but {critical_total} critical items need attention"
    elif score >= 40:
        summary = f"Needs improvement - {critical_total} critical, {high_total} high findings"
    else:
        summary = f"Critical attention required - {critical_total} critical findings"

    return ExecutiveSummaryResponse(
        immediateActions=immediate_actions[:3],  # Limit to 3
        trends=trends[:4],  # Limit to 4
        posture=PostureData(
            grade=grade,
            score=score,
            summary=summary
        )
    )


@router.get("/recent-scans", dependencies=[Depends(require_permissions("scans:read"))])
async def get_recent_scans(limit: int = 10, db: Session = Depends(get_tenant_db)):
    """Get recent scan runs across all repositories."""
    query = db.query(models.ScanRun).options(
        joinedload(models.ScanRun.repository)
    )

    # Apply org filter for multi-tenant
    query = apply_org_filter(query, models.ScanRun)

    # Order by created_at desc, limit results
    scans = query.order_by(models.ScanRun.created_at.desc()).limit(limit).all()

    return [
        {
            "id": str(scan.id),
            "repository_name": scan.repository.name if scan.repository else "Unknown",
            "scan_type": scan.scan_type,
            "status": scan.status,
            "findings_count": scan.findings_count or 0,
            "new_findings_count": scan.new_findings_count or 0,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": scan.duration_seconds,
            "triggered_by": scan.triggered_by
        }
        for scan in scans
    ]


@router.get("/finding-trends", dependencies=[Depends(require_permissions("reports:read"))])
async def get_finding_trends(days: int = 30, db: Session = Depends(get_tenant_db)):
    """Get finding counts by severity over time for trend charts."""
    now = datetime.utcnow()
    start_date = now - timedelta(days=days)

    # Generate date buckets (daily for 30 days, weekly for longer)
    if days <= 30:
        interval_days = 1
        date_format = "%m/%d"
    elif days <= 90:
        interval_days = 7
        date_format = "%m/%d"
    else:
        interval_days = 30
        date_format = "%b '%y"

    severities = ["critical", "high", "medium", "low"]
    timeline = []

    current_date = start_date
    while current_date <= now:
        bucket_end = min(current_date + timedelta(days=interval_days), now)

        # Count findings by severity created in this bucket
        counts = {"date": current_date.strftime(date_format)}
        for severity in severities:
            base_query = apply_org_filter(db.query(models.Finding), models.Finding)
            count = base_query.filter(
                models.Finding.severity == severity,
                models.Finding.created_at >= current_date,
                models.Finding.created_at < bucket_end
            ).count()
            counts[severity] = count

        # Also count total open at this point
        base_query = apply_org_filter(db.query(models.Finding), models.Finding)
        counts["total_open"] = base_query.filter(
            models.Finding.created_at <= bucket_end,
            or_(
                models.Finding.resolved_at.is_(None),
                models.Finding.resolved_at > bucket_end
            )
        ).count()

        timeline.append(counts)
        current_date = bucket_end

    # Get current totals by severity
    totals = {}
    for severity in severities:
        base_query = apply_org_filter(db.query(models.Finding), models.Finding)
        totals[severity] = base_query.filter(
            models.Finding.severity == severity,
            models.Finding.status == "open"
        ).count()

    return {
        "days": days,
        "timeline": timeline,
        "current_totals": totals
    }
