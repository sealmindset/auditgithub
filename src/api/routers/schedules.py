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
