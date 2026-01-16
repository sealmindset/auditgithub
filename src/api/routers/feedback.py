from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
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
    component_id: str
    component_name: str
    vote: str  # "up" or "down"
    timestamp: str


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


@router.post("/component", dependencies=[Depends(require_permissions("projects:write"))])
async def submit_component_feedback(feedback: ComponentFeedback):
    """Submit feedback for a dashboard component."""
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


@router.get("/component/summary", dependencies=[Depends(require_permissions("projects:read"))])
async def get_feedback_summary():
    """Get summary of all component feedback."""
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


@router.get("/component/raw", dependencies=[Depends(require_permissions("projects:read"))])
async def get_raw_feedback():
    """Get all raw feedback entries for analysis."""
    return load_feedback()
