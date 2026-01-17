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
