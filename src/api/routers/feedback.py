from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from datetime import datetime
import json
import os
from loguru import logger
from ..dependencies import get_tenant_db
from src.rbac.dependencies import require_permissions

router = APIRouter(
    prefix="/feedback",
    tags=["feedback"]
)


class ComponentFeedback(BaseModel):
    """Request model for submitting feedback on a dashboard component."""
    component_id: str = Field(..., description="Unique identifier of the dashboard component")
    component_name: str = Field(..., description="Display name of the dashboard component")
    vote: str = Field(..., description="Vote direction: 'up' or 'down'")
    timestamp: str = Field(..., description="ISO-8601 timestamp when the vote was cast")


# Simple file-based storage for feedback (no DB migration needed)
FEEDBACK_FILE = "/app/data/component_feedback.json"


def load_feedback() -> list:
    """Load feedback from file."""
    if os.path.exists(FEEDBACK_FILE):
        try:
            with open(FEEDBACK_FILE, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load feedback from {FEEDBACK_FILE}: {str(e)}")
            return []
    return []


def save_feedback(feedback_list: list):
    """Save feedback to file."""
    os.makedirs(os.path.dirname(FEEDBACK_FILE), exist_ok=True)
    with open(FEEDBACK_FILE, 'w') as f:
        json.dump(feedback_list, f, indent=2)


@router.post(
    "/component",
    dependencies=[Depends(require_permissions("projects:write"))],
    summary="Submit component feedback",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Missing projects:write permission"},
        500: {"description": "Failed to persist feedback to storage"},
    },
)
async def submit_component_feedback(feedback: ComponentFeedback):
    """Record an up or down vote for a dashboard component.

    Requires the **projects:write** permission. Feedback is appended to a
    JSON file on disk and used to compute component satisfaction scores.
    """
    feedback_list = load_feedback()

    feedback_entry = {
        "component_id": feedback.component_id,
        "component_name": feedback.component_name,
        "vote": feedback.vote,
        "timestamp": feedback.timestamp,
        "received_at": datetime.utcnow().isoformat()
    }

    feedback_list.append(feedback_entry)
    save_feedback(feedback_list)

    return {"status": "success", "message": "Feedback recorded"}


@router.get(
    "/component/summary",
    dependencies=[Depends(require_permissions("projects:read"))],
    summary="Get component feedback summary",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Missing projects:read permission"},
    },
)
async def get_feedback_summary():
    """Return aggregated feedback scores for all dashboard components.

    Requires the **projects:read** permission. Groups votes by component and
    calculates up-vote count, down-vote count, total votes, and a percentage score.
    """
    feedback_list = load_feedback()

    # Aggregate by component
    summary = {}
    for entry in feedback_list:
        comp_id = entry["component_id"]
        if comp_id not in summary:
            summary[comp_id] = {
                "component_id": comp_id,
                "component_name": entry["component_name"],
                "up_votes": 0,
                "down_votes": 0
            }

        if entry["vote"] == "up":
            summary[comp_id]["up_votes"] += 1
        else:
            summary[comp_id]["down_votes"] += 1

    # Calculate scores
    for comp_id in summary:
        total = summary[comp_id]["up_votes"] + summary[comp_id]["down_votes"]
        summary[comp_id]["total_votes"] = total
        summary[comp_id]["score"] = (summary[comp_id]["up_votes"] / total * 100) if total > 0 else 0

    return list(summary.values())


@router.get(
    "/component/raw",
    dependencies=[Depends(require_permissions("projects:read"))],
    summary="Get raw feedback entries",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Missing projects:read permission"},
    },
)
async def get_raw_feedback():
    """Return all individual feedback entries for detailed analysis.

    Requires the **projects:read** permission. Returns the complete list of
    feedback records including component ID, vote direction, and timestamps.
    """
    return load_feedback()
