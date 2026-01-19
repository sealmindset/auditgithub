"""
Schedule API Endpoints

Provides REST API for:
- Viewing scan schedules
- Updating schedule configuration
- Managing manual overrides
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum

from ..dependencies import get_tenant_db
from .. import models
from src.auth.dependencies import get_current_user
from src.rbac.dependencies import require_permissions
from src.auth.models import User

router = APIRouter(prefix="/schedules", tags=["schedules"])


# Enums for validation
class ScheduleType(str, Enum):
    ai = "ai"
    manual = "manual"


class Frequency(str, Enum):
    daily = "daily"
    weekly = "weekly"
    bi_weekly = "bi-weekly"
    monthly = "monthly"
    annually = "annually"


class TimeWindow(str, Enum):
    morning = "morning"
    afternoon = "afternoon"
    evening = "evening"
    night = "night"


# Pydantic Schemas
class ScheduleBase(BaseModel):
    frequency: Frequency
    day_of_week: Optional[int] = Field(None, ge=0, le=6, description="0=Monday, 6=Sunday")
    time_window: TimeWindow
    scan_arguments: Optional[dict] = None


class ScheduleUpdate(ScheduleBase):
    """Request to update a schedule."""
    override_reason: Optional[str] = Field(None, description="Reason for manual override")


class ScheduleCreate(BaseModel):
    """Request to create a new schedule."""
    repository_id: str
    frequency: Frequency
    day_of_week: Optional[int] = Field(None, ge=0, le=6, description="0=Monday, 6=Sunday")
    time_window: TimeWindow
    schedule_type: ScheduleType = ScheduleType.manual
    use_ai_recommendation: bool = False


class AIRecommendationResponse(BaseModel):
    """AI recommendation for a repository schedule."""
    frequency: str
    time_window: str
    day_of_week: Optional[int] = None  # 0=Monday, 6=Sunday - derived from last commit date
    confidence: float
    reasoning: str
    factors_considered: List[str]
    anniversary_date: Optional[datetime] = None  # For annual scans: when to scan (anniversary of last commit)


class ScheduleResponse(BaseModel):
    """Response for a single schedule."""
    id: str
    repository_id: str
    repository_name: str
    schedule_type: ScheduleType
    frequency: Frequency
    day_of_week: Optional[int]
    time_window: TimeWindow
    scan_arguments: Optional[dict]
    next_scheduled_at: Optional[datetime]
    last_executed_at: Optional[datetime]
    last_execution_status: Optional[str]
    is_locked: bool
    locked_at: Optional[datetime]
    locked_by_email: Optional[str]
    ai_reasoning: Optional[str]
    ai_confidence: Optional[float]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScheduleListResponse(BaseModel):
    """Response for schedule list."""
    schedules: List[ScheduleResponse]
    total: int


class OverrideCreate(BaseModel):
    """Request to create a manual override (lock)."""
    reason: str = Field(..., min_length=1, description="Reason for locking the schedule")


class OverrideHistoryItem(BaseModel):
    """Single override history entry."""
    id: str
    previous_frequency: Optional[str]
    previous_day_of_week: Optional[int]
    previous_time_window: Optional[str]
    new_frequency: Optional[str]
    new_day_of_week: Optional[int]
    new_time_window: Optional[str]
    override_reason: Optional[str]
    overridden_by_email: str
    created_at: datetime

    model_config = {"from_attributes": True}


class OverrideHistoryResponse(BaseModel):
    """Response for override history."""
    schedule_id: str
    repository_name: str
    overrides: List[OverrideHistoryItem]


# Schema for repository with schedule info
class RepositoryScheduleInfo(BaseModel):
    """Repository with optional schedule information."""
    repository_id: str
    repository_name: str
    pushed_at: Optional[datetime] = None  # Last commit from GitHub
    last_scanned_at: Optional[datetime] = None
    is_archived: bool = False

    # Schedule info (null if no schedule exists)
    has_schedule: bool
    schedule_id: Optional[str] = None
    schedule_type: Optional[ScheduleType] = None
    frequency: Optional[Frequency] = None
    day_of_week: Optional[int] = None
    time_window: Optional[TimeWindow] = None
    next_scheduled_at: Optional[datetime] = None
    last_executed_at: Optional[datetime] = None
    last_execution_status: Optional[str] = None
    is_locked: bool = False
    ai_confidence: Optional[float] = None

    model_config = {"from_attributes": True}


class RepositoryScheduleListResponse(BaseModel):
    """Response for repository schedule list."""
    repositories: List[RepositoryScheduleInfo]
    total: int
    scheduled_count: int
    unscheduled_count: int


@router.get("/repositories", response_model=RepositoryScheduleListResponse)
def list_repositories_with_schedules(
    filter: Optional[str] = None,  # 'scheduled', 'unscheduled', or None for all
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    List all repositories with their schedule information.

    Returns all repos with LEFT JOIN to schedules, showing schedule status for each.
    Use filter param to show only scheduled or unscheduled repos.
    Filters by the currently selected organization.
    """
    from sqlalchemy.orm import aliased
    from sqlalchemy import outerjoin
    from ..database import get_current_org_id

    # Get current organization context
    org_id = get_current_org_id()

    # Build query with LEFT JOIN to schedules
    query = (
        db.query(
            models.Repository,
            models.ScanSchedule
        )
        .outerjoin(
            models.ScanSchedule,
            (models.Repository.id == models.ScanSchedule.repository_id) &
            (models.ScanSchedule.is_active == True)
        )
    )

    # Filter by organization if context is set
    if org_id:
        query = query.filter(models.Repository.organization_id == org_id)

    query = query.order_by(models.Repository.name)

    results = query.all()

    repositories = []
    scheduled_count = 0
    unscheduled_count = 0

    for repo, schedule in results:
        has_schedule = schedule is not None

        if has_schedule:
            scheduled_count += 1
        else:
            unscheduled_count += 1

        # Apply filter
        if filter == "scheduled" and not has_schedule:
            continue
        if filter == "unscheduled" and has_schedule:
            continue

        repo_info = RepositoryScheduleInfo(
            repository_id=str(repo.id),
            repository_name=repo.name,
            pushed_at=repo.pushed_at,
            last_scanned_at=repo.last_scanned_at,
            is_archived=repo.is_archived or False,
            has_schedule=has_schedule,
            schedule_id=str(schedule.id) if schedule else None,
            schedule_type=schedule.schedule_type if schedule else None,
            frequency=schedule.frequency if schedule else None,
            day_of_week=schedule.day_of_week if schedule else None,
            time_window=schedule.time_window if schedule else None,
            next_scheduled_at=schedule.next_scheduled_at if schedule else None,
            last_executed_at=schedule.last_executed_at if schedule else None,
            last_execution_status=schedule.last_execution_status if schedule else None,
            is_locked=schedule.is_locked if schedule else False,
            ai_confidence=float(schedule.ai_confidence) if schedule and schedule.ai_confidence else None,
        )
        repositories.append(repo_info)

    return RepositoryScheduleListResponse(
        repositories=repositories,
        total=len(repositories),
        scheduled_count=scheduled_count,
        unscheduled_count=unscheduled_count
    )


def _calculate_next_run(frequency: str, time_window: str, day_of_week: Optional[int], repo_pushed_at: Optional[datetime] = None) -> datetime:
    """Calculate next scheduled run time based on frequency and time window.

    For weekly/bi-weekly scans without a specified day_of_week, uses the day of week
    from the last commit (repo_pushed_at) to intelligently distribute scans across
    the week based on when developers typically work on each repository.
    """
    from datetime import timedelta

    now = datetime.utcnow()

    # Map time window to hour
    time_window_hours = {
        "morning": 9,      # 9 AM
        "afternoon": 14,   # 2 PM
        "evening": 19,     # 7 PM
        "night": 2,        # 2 AM
    }
    target_hour = time_window_hours.get(time_window, 2)

    if frequency == "annually":
        # Annual scans run on anniversary of last commit
        if repo_pushed_at:
            # Use month and day from last commit
            this_year_anniversary = repo_pushed_at.replace(year=now.year, hour=target_hour, minute=0, second=0, microsecond=0)
            if this_year_anniversary <= now:
                # Anniversary passed this year, schedule for next year
                return repo_pushed_at.replace(year=now.year + 1, hour=target_hour, minute=0, second=0, microsecond=0)
            return this_year_anniversary
        else:
            # No commit date, fallback to January 1st next year
            return now.replace(year=now.year + 1, month=1, day=1, hour=target_hour, minute=0, second=0, microsecond=0)

    # Find next occurrence for other frequencies
    next_run = now.replace(hour=target_hour, minute=0, second=0, microsecond=0)
    if next_run <= now:
        next_run += timedelta(days=1)

    # Adjust for day_of_week for weekly/bi-weekly scans
    if frequency in ("weekly", "bi-weekly"):
        # Use explicit day_of_week if provided, otherwise derive from last commit date
        # This distributes scans across the week based on when developers typically push
        effective_day = day_of_week
        if effective_day is None and repo_pushed_at:
            # Use the day of week from the last commit
            effective_day = repo_pushed_at.weekday()

        if effective_day is not None:
            while next_run.weekday() != effective_day:
                next_run += timedelta(days=1)

    # For monthly, adjust to 1st of next month if needed
    if frequency == "monthly":
        if now.day > 1:
            # Move to 1st of next month
            if now.month == 12:
                next_run = now.replace(year=now.year + 1, month=1, day=1, hour=target_hour, minute=0, second=0, microsecond=0)
            else:
                next_run = now.replace(month=now.month + 1, day=1, hour=target_hour, minute=0, second=0, microsecond=0)
        else:
            next_run = now.replace(day=1, hour=target_hour, minute=0, second=0, microsecond=0)
            if next_run <= now:
                if now.month == 12:
                    next_run = now.replace(year=now.year + 1, month=1, day=1, hour=target_hour, minute=0, second=0, microsecond=0)
                else:
                    next_run = now.replace(month=now.month + 1, day=1, hour=target_hour, minute=0, second=0, microsecond=0)

    return next_run


@router.post("/", response_model=ScheduleResponse, dependencies=[Depends(require_permissions("schedules:create"))])
async def create_schedule(
    schedule_create: ScheduleCreate,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new scan schedule for a repository.

    If use_ai_recommendation is True, the AI recommendation will be fetched
    and used to set the frequency, time_window, and reasoning.

    Args:
        schedule_create: Schedule configuration
    """
    import uuid

    # Check if repo exists
    repo = db.query(models.Repository).filter(
        models.Repository.id == schedule_create.repository_id
    ).first()

    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Check if schedule already exists
    existing = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.repository_id == schedule_create.repository_id)
        .filter(models.ScanSchedule.is_active == True)
        .first()
    )

    if existing:
        raise HTTPException(status_code=400, detail="Schedule already exists for this repository")

    # Get AI recommendation if requested
    frequency = schedule_create.frequency.value
    time_window = schedule_create.time_window.value
    day_of_week = schedule_create.day_of_week
    schedule_type = schedule_create.schedule_type.value
    ai_reasoning = None
    ai_confidence = None

    if schedule_create.use_ai_recommendation:
        # Fetch AI recommendation
        recommendation = await _get_ai_recommendation_internal(repo, db)
        frequency = recommendation["frequency"]
        time_window = recommendation["time_window"]
        ai_reasoning = recommendation["reasoning"]
        ai_confidence = recommendation["confidence"]
        schedule_type = "ai"

        # Skip disabled repos
        if frequency == "disabled":
            raise HTTPException(
                status_code=400,
                detail=f"AI recommends disabling scans for this repository: {ai_reasoning}"
            )

    # Calculate next_scheduled_at
    next_run = _calculate_next_run(frequency, time_window, day_of_week, repo.pushed_at)

    # Create the schedule
    schedule = models.ScanSchedule(
        id=uuid.uuid4(),
        repository_id=schedule_create.repository_id,
        organization_id=repo.organization_id,
        schedule_type=schedule_type,
        frequency=frequency,
        day_of_week=day_of_week,
        time_window=time_window,
        next_scheduled_at=next_run,
        is_active=True,
        is_locked=schedule_type == "manual",
        locked_by=current_user.id if schedule_type == "manual" else None,
        locked_at=datetime.utcnow() if schedule_type == "manual" else None,
        ai_reasoning=ai_reasoning,
        ai_confidence=ai_confidence,
    )

    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    return ScheduleResponse(
        id=str(schedule.id),
        repository_id=str(schedule.repository_id),
        repository_name=repo.name,
        schedule_type=schedule.schedule_type,
        frequency=schedule.frequency,
        day_of_week=schedule.day_of_week,
        time_window=schedule.time_window,
        scan_arguments=schedule.scan_arguments,
        next_scheduled_at=schedule.next_scheduled_at,
        last_executed_at=schedule.last_executed_at,
        last_execution_status=schedule.last_execution_status,
        is_locked=schedule.is_locked,
        locked_at=schedule.locked_at,
        locked_by_email=current_user.email if schedule.is_locked else None,
        ai_reasoning=schedule.ai_reasoning,
        ai_confidence=float(schedule.ai_confidence) if schedule.ai_confidence else None,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at
    )


async def _get_ai_recommendation_internal(repo: models.Repository, db: Session) -> dict:
    """
    Internal function to get AI recommendation for a repository.

    Returns a dict with: frequency, time_window, confidence, reasoning, factors, anniversary_date
    """
    from sqlalchemy import func

    # Get finding counts efficiently
    finding_counts = {}
    severity_counts = db.query(
        models.Finding.severity,
        func.count(models.Finding.id)
    ).filter(
        models.Finding.repository_id == repo.id
    ).group_by(models.Finding.severity).all()

    for severity, count in severity_counts:
        if severity:
            finding_counts[severity.lower()] = count

    critical = finding_counts.get("critical", 0)
    high = finding_counts.get("high", 0)
    total = sum(finding_counts.values())

    factors = []
    now = datetime.utcnow()
    anniversary_date = None

    # PRIMARY FACTOR: Repository activity (last commit/push)
    last_activity = repo.pushed_at or repo.github_created_at or repo.created_at
    days_since_activity = (now - last_activity).days if last_activity else 9999

    # Helper function to calculate next anniversary date
    def get_next_anniversary(last_commit_date: datetime) -> datetime:
        """Calculate the next anniversary of the last commit date."""
        this_year_anniversary = last_commit_date.replace(year=now.year)
        if this_year_anniversary <= now:
            return last_commit_date.replace(year=now.year + 1)
        return this_year_anniversary

    # Classify repository by activity level
    if repo.is_archived:
        frequency = "disabled"
        factors.append(f"Repository is archived - scanning disabled")
        reasoning = "This repository is archived and should not be scanned. Consider removing it from the scan schedule."
        confidence = 0.95

    elif days_since_activity > 365:  # No activity in 1+ years
        frequency = "annually"
        if last_activity:
            anniversary_date = get_next_anniversary(last_activity)
            factors.append(f"No commits in {days_since_activity} days ({days_since_activity // 365} years)")
            factors.append(f"Annual scan scheduled for {anniversary_date.strftime('%B %d')} (anniversary of last commit)")
        else:
            factors.append(f"No commit history available")

        if days_since_activity > 365 * 2:
            factors.append("Consider archiving this repository")
            reasoning = f"Repository has had no activity for {days_since_activity // 365} years. Annual scan on the anniversary of the last commit ({anniversary_date.strftime('%B %d') if anniversary_date else 'unknown'}). Consider archiving if no longer in use."
        else:
            reasoning = f"Repository inactive for {days_since_activity} days. Annual scan recommended on the anniversary of the last commit ({anniversary_date.strftime('%B %d') if anniversary_date else 'unknown'})."
        confidence = 0.90

    elif days_since_activity > 180:  # No activity in 6-12 months
        frequency = "bi-weekly"
        factors.append(f"Low activity ({days_since_activity} days since last commit)")
        reasoning = f"Repository has low activity ({days_since_activity} days since last commit). Bi-weekly scans are appropriate."
        confidence = 0.80

    elif days_since_activity > 30:  # Activity within 1-6 months
        if critical > 0:
            frequency = "weekly"
            factors.append(f"Moderate activity with {critical} critical findings")
        else:
            frequency = "bi-weekly"
            factors.append(f"Moderate activity ({days_since_activity} days since last commit)")
        reasoning = f"Repository has moderate activity. "
        if critical > 0:
            reasoning += f"Weekly scans recommended due to {critical} critical findings."
        else:
            reasoning += "Bi-weekly scans are sufficient."
        confidence = 0.80

    else:  # Active within last 30 days
        if days_since_activity <= 7:
            if critical > 0:
                frequency = "daily"
                factors.append(f"Very active repo with {critical} critical findings")
            else:
                frequency = "weekly"
                factors.append(f"Very active repo (last commit {days_since_activity} days ago)")
            reasoning = f"Repository is very active (last commit {days_since_activity} days ago). "
            if critical > 0:
                reasoning += f"Daily scans recommended due to {critical} critical findings."
            else:
                reasoning += "Weekly scans recommended to catch new issues."
            confidence = 0.85
        else:
            if critical > 5:
                frequency = "daily"
                factors.append(f"Active repo with {critical} critical findings")
            elif critical > 0 or high > 10:
                frequency = "weekly"
                factors.append(f"Active repo with security concerns ({critical} critical, {high} high)")
            else:
                frequency = "weekly"
                factors.append(f"Active repo (last commit {days_since_activity} days ago)")
            reasoning = f"Repository is active (last commit {days_since_activity} days ago). "
            if critical > 5:
                reasoning += f"Daily scans recommended due to {critical} critical findings."
            elif critical > 0:
                reasoning += f"Weekly scans recommended. {critical} critical findings need attention."
            else:
                reasoning += "Weekly scans recommended."
            confidence = 0.80

    # Add finding summary to factors
    if total > 0:
        factors.append(f"Total findings: {total} ({critical} critical, {high} high)")

    # Time window recommendation
    time_window = "night"
    factors.append("Night window recommended for minimal disruption")

    return {
        "frequency": frequency,
        "time_window": time_window,
        "confidence": confidence,
        "reasoning": reasoning.strip(),
        "factors": factors,
        "anniversary_date": anniversary_date
    }


@router.get("/{repo_id}/recommend", response_model=AIRecommendationResponse)
async def get_ai_recommendation(
    repo_id: str,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get AI-powered schedule recommendation for a repository.

    Primary factor: Repository activity (last commit date)
    Secondary factor: Critical findings (only for active repos)

    Inactive repos should be scanned infrequently or flagged for archival.

    Args:
        repo_id: Repository UUID
    """
    repo = db.query(models.Repository).filter(models.Repository.id == repo_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    result = await _get_ai_recommendation_internal(repo, db)

    # Derive day_of_week from last commit date for weekly/bi-weekly scans
    derived_day_of_week = None
    if result["frequency"] in ("weekly", "bi-weekly") and repo.pushed_at:
        derived_day_of_week = repo.pushed_at.weekday()

    return AIRecommendationResponse(
        frequency=result["frequency"],
        time_window=result["time_window"],
        day_of_week=derived_day_of_week,
        confidence=result["confidence"],
        reasoning=result["reasoning"],
        factors_considered=result["factors"],
        anniversary_date=result["anniversary_date"]
    )


@router.get("/", response_model=ScheduleListResponse)
def list_schedules(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    List all scan schedules for the current organization.

    Returns schedules with repository names and lock status.
    Filters by the currently selected organization.
    """
    from ..database import get_current_org_id

    # Get current organization context
    org_id = get_current_org_id()

    query = (
        db.query(models.ScanSchedule, models.Repository.name)
        .join(models.Repository, models.ScanSchedule.repository_id == models.Repository.id)
        .filter(models.ScanSchedule.is_active == True)
    )

    # Filter by organization if context is set
    if org_id:
        query = query.filter(models.Repository.organization_id == org_id)

    query = query.offset(skip).limit(limit)

    results = query.all()
    total = db.query(models.ScanSchedule).filter(models.ScanSchedule.is_active == True).count()

    schedules = []
    for schedule, repo_name in results:
        # Get locked_by email if locked
        locked_by_email = None
        if schedule.locked_by:
            user = db.query(User).filter(User.id == schedule.locked_by).first()
            locked_by_email = user.email if user else None

        schedules.append(ScheduleResponse(
            id=str(schedule.id),
            repository_id=str(schedule.repository_id),
            repository_name=repo_name,
            schedule_type=schedule.schedule_type,
            frequency=schedule.frequency,
            day_of_week=schedule.day_of_week,
            time_window=schedule.time_window,
            scan_arguments=schedule.scan_arguments,
            next_scheduled_at=schedule.next_scheduled_at,
            last_executed_at=schedule.last_executed_at,
            last_execution_status=schedule.last_execution_status,
            is_locked=schedule.is_locked,
            locked_at=schedule.locked_at,
            locked_by_email=locked_by_email,
            ai_reasoning=schedule.ai_reasoning,
            ai_confidence=float(schedule.ai_confidence) if schedule.ai_confidence else None,
            created_at=schedule.created_at,
            updated_at=schedule.updated_at
        ))

    return ScheduleListResponse(schedules=schedules, total=total)


# Batch operation models
class BatchScheduleResult(BaseModel):
    """Result for a single repository in batch operation."""
    repository_id: str
    repository_name: str
    status: str  # "created", "skipped", "error"
    frequency: Optional[str] = None
    next_scheduled_at: Optional[datetime] = None
    error: Optional[str] = None


class BatchScheduleResponse(BaseModel):
    """Response for batch schedule creation."""
    total_processed: int
    created: int
    skipped: int
    errors: int
    results: List[BatchScheduleResult]


@router.post("/batch/apply-ai", response_model=BatchScheduleResponse, dependencies=[Depends(require_permissions("schedules:create"))])
async def batch_apply_ai_schedules(
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Apply AI-recommended schedules to all unscheduled repositories.

    This creates scan schedules for all repositories that don't have one,
    using AI recommendations based on activity and findings.

    Archived repos and repos with "disabled" recommendations are skipped.
    """
    import uuid
    from ..database import get_current_org_id

    org_id = get_current_org_id()

    # Get all repositories without active schedules
    scheduled_repo_ids = (
        db.query(models.ScanSchedule.repository_id)
        .filter(models.ScanSchedule.is_active == True)
        .subquery()
    )

    query = (
        db.query(models.Repository)
        .filter(~models.Repository.id.in_(scheduled_repo_ids))
        .filter(
            (models.Repository.is_archived == False) |
            (models.Repository.is_archived.is_(None))
        )
    )

    if org_id:
        query = query.filter(models.Repository.organization_id == org_id)

    unscheduled_repos = query.all()

    results = []
    created = 0
    skipped = 0
    errors = 0

    for repo in unscheduled_repos:
        try:
            # Get AI recommendation
            recommendation = await _get_ai_recommendation_internal(repo, db)

            # Skip disabled repos
            if recommendation["frequency"] == "disabled":
                results.append(BatchScheduleResult(
                    repository_id=str(repo.id),
                    repository_name=repo.name,
                    status="skipped",
                    error="AI recommends disabled (archived or inactive)"
                ))
                skipped += 1
                continue

            # Derive day_of_week from last commit date for weekly/bi-weekly scans
            # This distributes scans across the week based on when developers typically push
            derived_day_of_week = None
            if recommendation["frequency"] in ("weekly", "bi-weekly") and repo.pushed_at:
                derived_day_of_week = repo.pushed_at.weekday()

            # Calculate next run time
            next_run = _calculate_next_run(
                recommendation["frequency"],
                recommendation["time_window"],
                derived_day_of_week,
                repo.pushed_at
            )

            # Create the schedule
            schedule = models.ScanSchedule(
                id=uuid.uuid4(),
                repository_id=repo.id,
                organization_id=repo.organization_id,
                schedule_type="ai",
                frequency=recommendation["frequency"],
                day_of_week=derived_day_of_week,
                time_window=recommendation["time_window"],
                next_scheduled_at=next_run,
                is_active=True,
                is_locked=False,
                ai_reasoning=recommendation["reasoning"],
                ai_confidence=recommendation["confidence"],
            )

            db.add(schedule)
            db.flush()  # Get ID without committing

            results.append(BatchScheduleResult(
                repository_id=str(repo.id),
                repository_name=repo.name,
                status="created",
                frequency=recommendation["frequency"],
                next_scheduled_at=next_run
            ))
            created += 1

        except Exception as e:
            results.append(BatchScheduleResult(
                repository_id=str(repo.id),
                repository_name=repo.name,
                status="error",
                error=str(e)
            ))
            errors += 1

    # Commit all changes
    db.commit()

    return BatchScheduleResponse(
        total_processed=len(unscheduled_repos),
        created=created,
        skipped=skipped,
        errors=errors,
        results=results
    )


@router.post("/batch/refresh-ai", response_model=BatchScheduleResponse, dependencies=[Depends(require_permissions("schedules:update"))])
async def batch_refresh_ai_schedules(
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Refresh AI recommendations for all unlocked AI-managed schedules.

    This updates schedules that are:
    - Not locked (manual override)
    - Using AI management

    Locked schedules are preserved as-is.
    """
    from ..database import get_current_org_id

    org_id = get_current_org_id()

    # Get all unlocked AI schedules
    query = (
        db.query(models.ScanSchedule, models.Repository)
        .join(models.Repository, models.ScanSchedule.repository_id == models.Repository.id)
        .filter(models.ScanSchedule.is_active == True)
        .filter(models.ScanSchedule.is_locked == False)
        .filter(models.ScanSchedule.schedule_type == "ai")
    )

    if org_id:
        query = query.filter(models.Repository.organization_id == org_id)

    schedules_with_repos = query.all()

    results = []
    updated = 0
    skipped = 0
    errors = 0

    for schedule, repo in schedules_with_repos:
        try:
            # Get fresh AI recommendation
            recommendation = await _get_ai_recommendation_internal(repo, db)

            # Handle disabled recommendation
            if recommendation["frequency"] == "disabled":
                schedule.is_active = False
                results.append(BatchScheduleResult(
                    repository_id=str(repo.id),
                    repository_name=repo.name,
                    status="skipped",
                    error="AI recommends disabled - schedule deactivated"
                ))
                skipped += 1
                continue

            # Update schedule with new recommendation
            schedule.frequency = recommendation["frequency"]
            schedule.time_window = recommendation["time_window"]
            schedule.ai_reasoning = recommendation["reasoning"]
            schedule.ai_confidence = recommendation["confidence"]

            # Derive day_of_week from last commit date for weekly/bi-weekly scans
            # if not already set, to distribute scans across the week
            if schedule.day_of_week is None and recommendation["frequency"] in ("weekly", "bi-weekly") and repo.pushed_at:
                schedule.day_of_week = repo.pushed_at.weekday()

            # Recalculate next run time
            next_run = _calculate_next_run(
                recommendation["frequency"],
                recommendation["time_window"],
                schedule.day_of_week,
                repo.pushed_at
            )
            schedule.next_scheduled_at = next_run

            results.append(BatchScheduleResult(
                repository_id=str(repo.id),
                repository_name=repo.name,
                status="created",  # "updated" would be more accurate but reusing model
                frequency=recommendation["frequency"],
                next_scheduled_at=next_run
            ))
            updated += 1

        except Exception as e:
            results.append(BatchScheduleResult(
                repository_id=str(repo.id),
                repository_name=repo.name,
                status="error",
                error=str(e)
            ))
            errors += 1

    db.commit()

    return BatchScheduleResponse(
        total_processed=len(schedules_with_repos),
        created=updated,  # Reusing field as "updated"
        skipped=skipped,
        errors=errors,
        results=results
    )


# Today's Scans Models - MUST BE BEFORE /{repo_id} routes for correct routing
class TodayScanItem(BaseModel):
    """A single scan scheduled for today or currently running."""
    schedule_id: str
    repository_id: str
    repository_name: str
    organization_name: Optional[str] = None
    scheduled_time: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str  # scheduled, running, completed, failed
    frequency: str
    time_window: str
    progress_percent: Optional[int] = None  # 0-100 for running scans
    error_message: Optional[str] = None
    duration_seconds: Optional[int] = None
    findings_count: Optional[int] = None


class TodayScansResponse(BaseModel):
    """Response for today's scans."""
    scans: List[TodayScanItem]
    total_scheduled: int
    total_running: int
    total_completed: int
    total_failed: int
    current_time: datetime


@router.get("/today", response_model=TodayScansResponse)
def get_todays_scans(
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all scans scheduled for today and any currently running scans.

    Returns scans grouped by status: scheduled, running, completed, failed.
    Includes progress information for running scans.
    """
    from datetime import date, timedelta
    from ..database import get_current_org_id

    org_id = get_current_org_id()
    now = datetime.now()
    today_start = datetime.combine(date.today(), datetime.min.time())
    today_end = datetime.combine(date.today(), datetime.max.time())

    # Query schedules with next_scheduled_at today
    query = (
        db.query(models.ScanSchedule, models.Repository, models.Organization)
        .join(models.Repository, models.ScanSchedule.repository_id == models.Repository.id)
        .join(models.Organization, models.Repository.organization_id == models.Organization.id)
        .filter(models.ScanSchedule.is_active == True)
    )

    if org_id:
        query = query.filter(models.Repository.organization_id == org_id)

    all_schedules = query.all()

    scans = []
    total_scheduled = 0
    total_running = 0
    total_completed = 0
    total_failed = 0

    for schedule, repo, org in all_schedules:
        # Check if scheduled for today
        scheduled_today = (
            schedule.next_scheduled_at and
            today_start <= schedule.next_scheduled_at <= today_end
        )

        # Check if ran today
        ran_today = (
            schedule.last_executed_at and
            today_start <= schedule.last_executed_at <= today_end
        )

        # Check if currently running
        is_running = schedule.last_execution_status == "running"

        # Determine status
        if is_running:
            status = "running"
            total_running += 1
            # Estimate progress based on typical scan duration (rough estimate)
            if schedule.last_executed_at:
                elapsed = (now - schedule.last_executed_at).total_seconds()
                # Assume average scan takes ~5 minutes
                progress = min(95, int((elapsed / 300) * 100))
            else:
                progress = 10
        elif ran_today and schedule.last_execution_status == "success":
            status = "completed"
            total_completed += 1
            progress = 100
        elif ran_today and schedule.last_execution_status == "failed":
            status = "failed"
            total_failed += 1
            progress = None
        elif scheduled_today:
            status = "scheduled"
            total_scheduled += 1
            progress = 0
        else:
            # Not relevant for today
            continue

        # Calculate duration for completed scans
        duration = None
        if status == "completed" and schedule.last_executed_at:
            # We don't have exact completion time, estimate based on next schedule
            duration = None

        scans.append(TodayScanItem(
            schedule_id=str(schedule.id),
            repository_id=str(repo.id),
            repository_name=repo.name,
            organization_name=org.name,
            scheduled_time=schedule.next_scheduled_at if status == "scheduled" else None,
            started_at=schedule.last_executed_at if status in ("running", "completed", "failed") else None,
            completed_at=None,  # We don't track exact completion time currently
            status=status,
            frequency=schedule.frequency,
            time_window=schedule.time_window,
            progress_percent=progress,
            error_message=None,  # Could add error tracking
            duration_seconds=duration,
            findings_count=None  # Would need to query findings
        ))

    # Sort: running first, then scheduled by time, then completed
    status_order = {"running": 0, "scheduled": 1, "completed": 2, "failed": 3}
    scans.sort(key=lambda x: (status_order.get(x.status, 4), x.scheduled_time or x.started_at or now))

    return TodayScansResponse(
        scans=scans,
        total_scheduled=total_scheduled,
        total_running=total_running,
        total_completed=total_completed,
        total_failed=total_failed,
        current_time=now
    )


@router.get("/{repo_id}", response_model=ScheduleResponse)
def get_schedule(
    repo_id: str,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get the scan schedule for a specific repository.

    Args:
        repo_id: Repository UUID
    """
    schedule = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.repository_id == repo_id)
        .filter(models.ScanSchedule.is_active == True)
        .first()
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found for this repository")

    # Get repository name
    repo = db.query(models.Repository).filter(models.Repository.id == repo_id).first()
    repo_name = repo.name if repo else "Unknown"

    # Get locked_by email
    locked_by_email = None
    if schedule.locked_by:
        user = db.query(User).filter(User.id == schedule.locked_by).first()
        locked_by_email = user.email if user else None

    return ScheduleResponse(
        id=str(schedule.id),
        repository_id=str(schedule.repository_id),
        repository_name=repo_name,
        schedule_type=schedule.schedule_type,
        frequency=schedule.frequency,
        day_of_week=schedule.day_of_week,
        time_window=schedule.time_window,
        scan_arguments=schedule.scan_arguments,
        next_scheduled_at=schedule.next_scheduled_at,
        last_executed_at=schedule.last_executed_at,
        last_execution_status=schedule.last_execution_status,
        is_locked=schedule.is_locked,
        locked_at=schedule.locked_at,
        locked_by_email=locked_by_email,
        ai_reasoning=schedule.ai_reasoning,
        ai_confidence=float(schedule.ai_confidence) if schedule.ai_confidence else None,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at
    )


@router.put("/{repo_id}", response_model=ScheduleResponse, dependencies=[Depends(require_permissions("schedules:update"))])
def update_schedule(
    repo_id: str,
    update: ScheduleUpdate,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update the scan schedule for a repository.

    This creates a manual override and locks the schedule from AI changes.

    Args:
        repo_id: Repository UUID
        update: New schedule configuration
    """
    schedule = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.repository_id == repo_id)
        .filter(models.ScanSchedule.is_active == True)
        .first()
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found for this repository")

    # Create override audit record
    override = models.ScheduleOverride(
        schedule_id=schedule.id,
        previous_frequency=schedule.frequency,
        previous_day_of_week=schedule.day_of_week,
        previous_time_window=schedule.time_window,
        previous_scan_arguments=schedule.scan_arguments,
        new_frequency=update.frequency.value,
        new_day_of_week=update.day_of_week,
        new_time_window=update.time_window.value,
        new_scan_arguments=update.scan_arguments,
        override_reason=update.override_reason,
        overridden_by=current_user.id
    )
    db.add(override)

    # Update schedule
    schedule.frequency = update.frequency.value
    schedule.day_of_week = update.day_of_week
    schedule.time_window = update.time_window.value
    if update.scan_arguments is not None:
        schedule.scan_arguments = update.scan_arguments

    # Mark as manual and lock
    schedule.schedule_type = "manual"
    schedule.is_locked = True
    schedule.locked_at = datetime.utcnow()
    schedule.locked_by = current_user.id

    db.commit()
    db.refresh(schedule)

    # Get repository name for response
    repo = db.query(models.Repository).filter(models.Repository.id == repo_id).first()
    repo_name = repo.name if repo else "Unknown"

    return ScheduleResponse(
        id=str(schedule.id),
        repository_id=str(schedule.repository_id),
        repository_name=repo_name,
        schedule_type=schedule.schedule_type,
        frequency=schedule.frequency,
        day_of_week=schedule.day_of_week,
        time_window=schedule.time_window,
        scan_arguments=schedule.scan_arguments,
        next_scheduled_at=schedule.next_scheduled_at,
        last_executed_at=schedule.last_executed_at,
        last_execution_status=schedule.last_execution_status,
        is_locked=schedule.is_locked,
        locked_at=schedule.locked_at,
        locked_by_email=current_user.email,
        ai_reasoning=schedule.ai_reasoning,
        ai_confidence=float(schedule.ai_confidence) if schedule.ai_confidence else None,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at
    )


@router.post("/{repo_id}/lock", response_model=ScheduleResponse, dependencies=[Depends(require_permissions("schedules:override"))])
def lock_schedule(
    repo_id: str,
    lock_request: OverrideCreate,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lock a schedule to prevent AI modifications.

    Use this to preserve the current schedule settings without changing them.

    Args:
        repo_id: Repository UUID
        lock_request: Reason for locking
    """
    schedule = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.repository_id == repo_id)
        .filter(models.ScanSchedule.is_active == True)
        .first()
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found for this repository")

    if schedule.is_locked:
        raise HTTPException(status_code=400, detail="Schedule is already locked")

    # Create override record (values stay the same)
    override = models.ScheduleOverride(
        schedule_id=schedule.id,
        previous_frequency=schedule.frequency,
        previous_day_of_week=schedule.day_of_week,
        previous_time_window=schedule.time_window,
        previous_scan_arguments=schedule.scan_arguments,
        new_frequency=schedule.frequency,
        new_day_of_week=schedule.day_of_week,
        new_time_window=schedule.time_window,
        new_scan_arguments=schedule.scan_arguments,
        override_reason=f"Locked: {lock_request.reason}",
        overridden_by=current_user.id
    )
    db.add(override)

    # Lock the schedule
    schedule.schedule_type = "manual"
    schedule.is_locked = True
    schedule.locked_at = datetime.utcnow()
    schedule.locked_by = current_user.id

    db.commit()
    db.refresh(schedule)

    # Get repository name
    repo = db.query(models.Repository).filter(models.Repository.id == repo_id).first()
    repo_name = repo.name if repo else "Unknown"

    return ScheduleResponse(
        id=str(schedule.id),
        repository_id=str(schedule.repository_id),
        repository_name=repo_name,
        schedule_type=schedule.schedule_type,
        frequency=schedule.frequency,
        day_of_week=schedule.day_of_week,
        time_window=schedule.time_window,
        scan_arguments=schedule.scan_arguments,
        next_scheduled_at=schedule.next_scheduled_at,
        last_executed_at=schedule.last_executed_at,
        last_execution_status=schedule.last_execution_status,
        is_locked=schedule.is_locked,
        locked_at=schedule.locked_at,
        locked_by_email=current_user.email,
        ai_reasoning=schedule.ai_reasoning,
        ai_confidence=float(schedule.ai_confidence) if schedule.ai_confidence else None,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at
    )


@router.delete("/{repo_id}/lock", response_model=ScheduleResponse, dependencies=[Depends(require_permissions("schedules:override"))])
def unlock_schedule(
    repo_id: str,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Unlock a schedule to allow AI modifications.

    This returns the schedule to AI management.

    Args:
        repo_id: Repository UUID
    """
    schedule = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.repository_id == repo_id)
        .filter(models.ScanSchedule.is_active == True)
        .first()
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found for this repository")

    if not schedule.is_locked:
        raise HTTPException(status_code=400, detail="Schedule is not locked")

    # Create override record for unlock
    override = models.ScheduleOverride(
        schedule_id=schedule.id,
        previous_frequency=schedule.frequency,
        previous_day_of_week=schedule.day_of_week,
        previous_time_window=schedule.time_window,
        previous_scan_arguments=schedule.scan_arguments,
        new_frequency=schedule.frequency,
        new_day_of_week=schedule.day_of_week,
        new_time_window=schedule.time_window,
        new_scan_arguments=schedule.scan_arguments,
        override_reason="Unlocked - returned to AI management",
        overridden_by=current_user.id
    )
    db.add(override)

    # Unlock the schedule
    schedule.schedule_type = "ai"
    schedule.is_locked = False
    schedule.locked_at = None
    schedule.locked_by = None

    db.commit()
    db.refresh(schedule)

    # Get repository name
    repo = db.query(models.Repository).filter(models.Repository.id == repo_id).first()
    repo_name = repo.name if repo else "Unknown"

    return ScheduleResponse(
        id=str(schedule.id),
        repository_id=str(schedule.repository_id),
        repository_name=repo_name,
        schedule_type=schedule.schedule_type,
        frequency=schedule.frequency,
        day_of_week=schedule.day_of_week,
        time_window=schedule.time_window,
        scan_arguments=schedule.scan_arguments,
        next_scheduled_at=schedule.next_scheduled_at,
        last_executed_at=schedule.last_executed_at,
        last_execution_status=schedule.last_execution_status,
        is_locked=schedule.is_locked,
        locked_at=schedule.locked_at,
        locked_by_email=None,
        ai_reasoning=schedule.ai_reasoning,
        ai_confidence=float(schedule.ai_confidence) if schedule.ai_confidence else None,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at
    )


@router.get("/{repo_id}/history", response_model=OverrideHistoryResponse)
def get_override_history(
    repo_id: str,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get the override history for a schedule.

    Shows all manual changes made to the schedule.

    Args:
        repo_id: Repository UUID
    """
    schedule = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.repository_id == repo_id)
        .first()
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found for this repository")

    # Get repository name
    repo = db.query(models.Repository).filter(models.Repository.id == repo_id).first()
    repo_name = repo.name if repo else "Unknown"

    # Get override history
    overrides = (
        db.query(models.ScheduleOverride)
        .filter(models.ScheduleOverride.schedule_id == schedule.id)
        .order_by(models.ScheduleOverride.created_at.desc())
        .all()
    )

    history_items = []
    for override in overrides:
        # Get user email
        user = db.query(User).filter(User.id == override.overridden_by).first()
        user_email = user.email if user else "Unknown"

        history_items.append(OverrideHistoryItem(
            id=str(override.id),
            previous_frequency=override.previous_frequency,
            previous_day_of_week=override.previous_day_of_week,
            previous_time_window=override.previous_time_window,
            new_frequency=override.new_frequency,
            new_day_of_week=override.new_day_of_week,
            new_time_window=override.new_time_window,
            override_reason=override.override_reason,
            overridden_by_email=user_email,
            created_at=override.created_at
        ))

    return OverrideHistoryResponse(
        schedule_id=str(schedule.id),
        repository_name=repo_name,
        overrides=history_items
    )


# Scanner information models
class ScannerInfo(BaseModel):
    """Information about an available scanner."""
    id: str
    name: str
    category: str
    description: str


# Available scanners grouped by category
AVAILABLE_SCANNERS: List[ScannerInfo] = [
    # Secrets detection
    ScannerInfo(id="trufflehog", name="TruffleHog", category="secrets", description="Detect secrets and credentials in code"),
    ScannerInfo(id="whispers", name="Whispers", category="secrets", description="Identify hardcoded secrets and passwords"),
    # SAST - Static Application Security Testing
    ScannerInfo(id="semgrep", name="Semgrep", category="sast", description="Lightweight static analysis for many languages"),
    ScannerInfo(id="codeql", name="CodeQL", category="sast", description="GitHub's semantic code analysis engine"),
    ScannerInfo(id="horusec", name="Horusec", category="sast", description="Open-source SAST tool by ZUP"),
    ScannerInfo(id="bearer", name="Bearer", category="sast", description="Detect security risks and sensitive data flows"),
    # Dependency scanning
    ScannerInfo(id="safety", name="Safety", category="deps", description="Check Python dependencies for known vulnerabilities"),
    ScannerInfo(id="pip-audit", name="pip-audit", category="deps", description="Audit Python packages for known vulnerabilities"),
    ScannerInfo(id="npm-audit", name="npm-audit", category="deps", description="Audit Node.js dependencies for vulnerabilities"),
    ScannerInfo(id="retirejs", name="Retire.js", category="deps", description="Detect JavaScript libraries with known vulnerabilities"),
    ScannerInfo(id="govulncheck", name="govulncheck", category="deps", description="Check Go dependencies for vulnerabilities"),
    ScannerInfo(id="bundle-audit", name="bundle-audit", category="deps", description="Audit Ruby bundler dependencies"),
    ScannerInfo(id="dependency-check", name="OWASP Dependency-Check", category="deps", description="OWASP dependency vulnerability scanner"),
    ScannerInfo(id="syft", name="Syft", category="deps", description="Generate SBOMs from container images and filesystems"),
    ScannerInfo(id="grype", name="Grype", category="deps", description="Vulnerability scanner for container images and filesystems"),
    # Infrastructure as Code
    ScannerInfo(id="checkov", name="Checkov", category="iac", description="IaC security scanner for Terraform, CloudFormation, etc."),
    ScannerInfo(id="trivy", name="Trivy", category="iac", description="Comprehensive vulnerability scanner for containers and IaC"),
    ScannerInfo(id="terrascan", name="Terrascan", category="iac", description="Detect compliance and security violations in IaC"),
    ScannerInfo(id="dockle", name="Dockle", category="iac", description="Container image linter for security best practices"),
    # API security
    ScannerInfo(id="api-audit", name="API Audit", category="api", description="Audit API endpoints for security issues"),
    ScannerInfo(id="nuclei", name="Nuclei", category="api", description="Fast vulnerability scanner with community templates"),
    # Mobile security
    ScannerInfo(id="mobsf", name="MobSF", category="mobile", description="Mobile Security Framework for Android/iOS"),
    # Go-specific tools
    ScannerInfo(id="gosec", name="Gosec", category="go", description="Go security checker inspecting AST"),
    ScannerInfo(id="golangci-lint", name="golangci-lint", category="go", description="Fast Go linter with security rules"),
    # Other tools
    ScannerInfo(id="cloc", name="CLOC", category="other", description="Count lines of code"),
    ScannerInfo(id="ossgadget", name="OSS Gadget", category="other", description="Microsoft's OSS tools collection"),
]


class ScannerListResponse(BaseModel):
    """Response for scanner list."""
    scanners: List[ScannerInfo]
    total: int


@router.get("/scanners", response_model=ScannerListResponse)
def list_scanners():
    """
    List all available scanners with their metadata.

    Returns categorized scanner information for UI selection.
    No authentication required - scanner list is not sensitive.
    """
    return ScannerListResponse(
        scanners=AVAILABLE_SCANNERS,
        total=len(AVAILABLE_SCANNERS)
    )


class TriggerResponse(BaseModel):
    """Response for manual scan trigger."""
    status: str
    message: str


@router.post("/{repo_id}/trigger", response_model=TriggerResponse, dependencies=[Depends(require_permissions("schedules:trigger"))])
async def trigger_scan(
    repo_id: str,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Trigger an immediate scan for a repository.

    This runs the scan now, regardless of the schedule.

    Args:
        repo_id: Repository UUID
    """
    schedule = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.repository_id == repo_id)
        .filter(models.ScanSchedule.is_active == True)
        .first()
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found for this repository")

    from src.api.scheduler import get_scheduler
    scheduler_service = get_scheduler()

    if not scheduler_service.schedule_executor:
        raise HTTPException(status_code=503, detail="Scheduler not running")

    success = await scheduler_service.schedule_executor.trigger_immediate(str(schedule.id))

    if not success:
        raise HTTPException(status_code=500, detail="Failed to trigger scan")

    return TriggerResponse(status="triggered", message="Scan triggered for repository")
