"""
Sandbox management router.

Provides endpoints to list pre-generated sandbox API keys,
reset the sandbox database, and check sandbox status.
"""

import os
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from src.api.database import get_db
from src.api.sandbox import SANDBOX_AUTO_RESET_HOURS

router = APIRouter(prefix="/api/sandbox", tags=["Sandbox"])


@router.get(
    "/keys",
    summary="List sandbox API keys",
    description="Returns all pre-generated sandbox API keys with plaintext values and usage examples. This endpoint is public.",
    responses={
        200: {"description": "List of sandbox API keys with usage examples"},
    },
)
def list_sandbox_keys(db: Session = Depends(get_db)):
    """Return all sandbox API keys with plaintext values and usage examples."""
    from src.api.models import SandboxApiKey

    keys = db.query(SandboxApiKey).filter(SandboxApiKey.is_active.is_(True)).all()

    results = []
    for k in keys:
        results.append({
            "name": k.name,
            "role": k.role,
            "key": k.key_value,
            "description": k.description,
            "examples": {
                "curl": f'curl -H "X-API-Key: {k.key_value}" {os.getenv("SANDBOX_API_URL", "http://localhost:8001")}/api/repositories',
                "python": (
                    f'import requests\n'
                    f'r = requests.get("{os.getenv("SANDBOX_API_URL", "http://localhost:8001")}/api/repositories",\n'
                    f'    headers={{"X-API-Key": "{k.key_value}"}})\n'
                    f'print(r.json())'
                ),
            },
        })

    return {"keys": results, "note": "These keys only work in the sandbox environment."}


@router.post(
    "/reset",
    summary="Reset sandbox data",
    description="Drop all tables and re-seed the sandbox database with fresh dummy data. Requires super_admin role.",
    responses={
        200: {"description": "Sandbox reset completed successfully"},
        403: {"description": "Insufficient permissions — requires super_admin role"},
    },
)
async def reset_sandbox(request: Request, db: Session = Depends(get_db)):
    """Reset the sandbox database (admin-only)."""
    role = getattr(request.state, "sandbox_key_role", None)
    if role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the admin sandbox key can reset the sandbox.",
        )

    from src.api.sandbox_seed import reset_and_seed

    await reset_and_seed(db)
    return {"status": "ok", "message": "Sandbox has been reset and re-seeded."}


@router.get(
    "/status",
    summary="Sandbox environment status",
    description="Returns current sandbox configuration including auto-reset interval, database name, and AI provider.",
    responses={
        200: {"description": "Current sandbox configuration"},
    },
)
def sandbox_status():
    """Return sandbox configuration info."""
    return {
        "sandbox_mode": True,
        "auto_reset_hours": SANDBOX_AUTO_RESET_HOURS,
        "database": os.environ.get("POSTGRES_DB", "auditgh_sandbox"),
        "redis_db": os.environ.get("REDIS_URL", "redis://redis:6379/1"),
        "ai_provider": os.environ.get("AI_PROVIDER", "mock"),
        "scheduler_enabled": os.environ.get("SCHEDULER_ENABLED", "false"),
    }
