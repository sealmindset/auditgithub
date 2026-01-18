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
    confidence: float
    reasoning: str
    factors_considered: List[str]


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
    """
    from sqlalchemy.orm import aliased
    from sqlalchemy import outerjoin

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
        .order_by(models.Repository.name)
    )

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


@router.post("/", response_model=ScheduleResponse, dependencies=[Depends(require_permissions("schedules:create"))])
def create_schedule(
    schedule_create: ScheduleCreate,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new scan schedule for a repository.

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

    # Calculate next_scheduled_at based on frequency and time window
    from datetime import timedelta
    now = datetime.utcnow()

    # Map time window to hour
    time_window_hours = {
        "morning": 9,      # 9 AM
        "afternoon": 14,   # 2 PM
        "evening": 19,     # 7 PM
        "night": 2,        # 2 AM
    }
    target_hour = time_window_hours.get(schedule_create.time_window.value, 2)

    # Find next occurrence
    next_run = now.replace(hour=target_hour, minute=0, second=0, microsecond=0)
    if next_run <= now:
        next_run += timedelta(days=1)

    # Adjust for day_of_week if specified (weekly/bi-weekly)
    if schedule_create.day_of_week is not None and schedule_create.frequency in (Frequency.weekly, Frequency.bi_weekly):
        while next_run.weekday() != schedule_create.day_of_week:
            next_run += timedelta(days=1)

    # Create the schedule
    schedule = models.ScanSchedule(
        id=uuid.uuid4(),
        repository_id=schedule_create.repository_id,
        schedule_type=schedule_create.schedule_type.value,
        frequency=schedule_create.frequency.value,
        day_of_week=schedule_create.day_of_week,
        time_window=schedule_create.time_window.value,
        next_scheduled_at=next_run,
        is_active=True,
        is_locked=schedule_create.schedule_type == ScheduleType.manual,
        locked_by=current_user.id if schedule_create.schedule_type == ScheduleType.manual else None,
        locked_at=datetime.utcnow() if schedule_create.schedule_type == ScheduleType.manual else None,
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


@router.get("/{repo_id}/recommend", response_model=AIRecommendationResponse)
async def get_ai_recommendation(
    repo_id: str,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get AI-powered schedule recommendation for a repository.

    Analyzes commit patterns, finding history, and risk scores to recommend
    optimal scan frequency and timing.

    Args:
        repo_id: Repository UUID
    """
    from src.services.schedule_recommender import ScheduleRecommender
    from src.ai_agent.agent import AIAgent
    from src.github.models import ScheduleInput, CommitAnalysisResult
    from src.services.commit_analyzer import CommitAnalyzer
    from src.github.client import get_github_client

    # Get repository
    repo = db.query(models.Repository).filter(models.Repository.id == repo_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Get finding counts
    finding_counts = {}
    findings = db.query(models.Finding).filter(models.Finding.repository_id == repo_id).all()
    for f in findings:
        severity = f.severity.lower() if f.severity else "unknown"
        finding_counts[severity] = finding_counts.get(severity, 0) + 1

    # Calculate risk score (simplified)
    critical = finding_counts.get("critical", 0)
    high = finding_counts.get("high", 0)
    medium = finding_counts.get("medium", 0)
    risk_score = min(1.0, (critical * 0.4 + high * 0.2 + medium * 0.05))

    # Try to get commit analysis
    commit_analysis = None
    try:
        github_client = get_github_client()
        if github_client:
            analyzer = CommitAnalyzer(github_client)
            commit_analysis = await analyzer.analyze_repository(repo.full_name or repo.name)
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to get commit analysis: {e}")

    # Build schedule input
    schedule_input = ScheduleInput(
        repository_name=repo.name,
        commit_analysis=commit_analysis,
        finding_counts=finding_counts,
        risk_score=risk_score,
        last_scan_date=repo.last_scanned_at,
        is_new_repo=commit_analysis is None
    )

    # Get recommendation
    try:
        ai_agent = AIAgent()
        recommender = ScheduleRecommender(ai_agent)
        recommendation = await recommender.recommend_schedule(schedule_input)

        return AIRecommendationResponse(
            frequency=recommendation.frequency,
            time_window=recommendation.time_window,
            confidence=recommendation.confidence,
            reasoning=recommendation.reasoning,
            factors_considered=recommendation.factors_considered
        )
    except Exception as e:
        # Return heuristic fallback
        return AIRecommendationResponse(
            frequency="weekly",
            time_window="night",
            confidence=0.5,
            reasoning=f"Fallback recommendation (AI unavailable: {str(e)})",
            factors_considered=["fallback_defaults"]
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
    """
    query = (
        db.query(models.ScanSchedule, models.Repository.name)
        .join(models.Repository, models.ScanSchedule.repository_id == models.Repository.id)
        .filter(models.ScanSchedule.is_active == True)
        .offset(skip)
        .limit(limit)
    )

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
