"""
Prompt Management System - FastAPI Router

API endpoints for centralized AI prompt management, versioning,
usage tracking, testing, analytics, and audit logging.

IMPORTANT: Static routes (/tags, /audit, /agents, /analytics/overview,
/export, /import, /search) MUST be declared BEFORE the /{slug} catch-all
route. FastAPI/Starlette matches routes in declaration order, so /{slug}
would shadow any static path declared after it.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from typing import Optional, List

from src.api.database import get_db
from src.api.dependencies import get_tenant_db
from src.auth.dependencies import get_current_user
from src.rbac.dependencies import require_permissions
from src.api.schemas.common import (
    ErrorResponse, LIST_ERRORS, CRUD_ERRORS, CREATE_ERRORS, DELETE_ERRORS
)
from src.api.schemas.prompt import (
    PromptCreate, PromptUpdate, PromptResponse, PromptListResponse,
    PromptVersionResponse, PromptVersionListResponse,
    PromptDiffResponse, PromptRestoreRequest,
    PromptUsageResponse, PromptUsageCreate,
    TagCount, TagListResponse, TagAddRequest,
    PromptTestCaseCreate, PromptTestCaseResponse,
    PromptTestRunRequest, PromptTestRunResponse,
    PromptAuditLogResponse, PromptAuditLogListResponse,
    AgentSummary, AgentListResponse,
    PromptAnalyticsOverview,
    PromptImportRequest, PromptImportResponse,
    PromptExportItem,
)
from src.services.prompt_service import PromptService

router = APIRouter(
    prefix="/prompts",
    tags=["prompts"],
)


def _get_service(db: Session = Depends(get_db)) -> PromptService:
    """Dependency to get prompt service instance."""
    return PromptService(db)


def _prompt_to_response(prompt, service: PromptService) -> dict:
    """Convert a Prompt ORM object to a response dict with computed fields."""
    tags = service.get_tags_for_prompt(prompt.id)
    usages = service.list_usages(prompt.id)
    total_calls = sum(u.call_count or 0 for u in usages)
    versions = service.list_versions(prompt.id)

    return {
        "id": str(prompt.id),
        "api_id": prompt.api_id,
        "slug": prompt.slug,
        "name": prompt.name,
        "description": prompt.description,
        "category": prompt.category,
        "subcategory": prompt.subcategory,
        "agent_id": prompt.agent_id,
        "provider": prompt.provider,
        "model": prompt.model,
        "current_version": prompt.current_version,
        "is_active": prompt.is_active,
        "is_locked": prompt.is_locked,
        "locked_by": prompt.locked_by,
        "locked_reason": prompt.locked_reason,
        "source_file": prompt.source_file,
        "source_line": prompt.source_line,
        "created_by": prompt.created_by,
        "updated_by": prompt.updated_by,
        "created_at": prompt.created_at,
        "updated_at": prompt.updated_at,
        "tags": tags,
        "usage_count": total_calls,
        "version_count": len(versions),
    }


# =============================================================================
# List & Search (no path params — must be before /{slug})
# =============================================================================

@router.get("/", response_model=PromptListResponse, responses=LIST_ERRORS)
def list_prompts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    category: Optional[str] = Query(None),
    agent_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    model: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: str = Query("updated_at"),
    sort_dir: str = Query("desc"),
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    List all managed prompts with filtering, search, and pagination.

    **Required permissions:** prompts:read
    """
    prompts, total = service.list_prompts(
        skip=skip, limit=limit, category=category, agent_id=agent_id,
        provider=provider, model=model, tag=tag, is_active=is_active,
        search=search, sort_by=sort_by, sort_dir=sort_dir,
    )
    items = [_prompt_to_response(p, service) for p in prompts]
    return {"items": items, "total": total, "skip": skip, "limit": limit}


@router.get("/search", response_model=PromptListResponse, responses=LIST_ERRORS)
def search_prompts(
    q: str = Query(..., min_length=1, description="Search query"),
    limit: int = Query(20, ge=1, le=100),
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Search prompts by name, slug, description, or agent.

    **Required permissions:** prompts:read
    """
    prompts, total = service.list_prompts(search=q, limit=limit)
    items = [_prompt_to_response(p, service) for p in prompts]
    return {"items": items, "total": total, "skip": 0, "limit": limit}


# =============================================================================
# Tags (static path — must be before /{slug})
# =============================================================================

@router.get("/tags", response_model=TagListResponse, responses=LIST_ERRORS)
def list_tags(
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    List all tags with usage counts.

    **Required permissions:** prompts:read
    """
    tags = service.list_tags()
    return {"items": tags}


# =============================================================================
# Audit Log (static path — must be before /{slug})
# =============================================================================

@router.get("/audit", response_model=PromptAuditLogListResponse, responses=LIST_ERRORS)
def list_audit_log(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    user_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    View the full prompt audit trail. Admin access required.

    **Required permissions:** prompts:admin
    """
    entries, total = service.list_audit_log(user_id=user_id, action=action, skip=skip, limit=limit)
    items = [{
        "id": str(e.id),
        "action": e.action,
        "prompt_id": str(e.prompt_id),
        "prompt_slug": e.prompt_slug,
        "version": e.version,
        "user_id": e.user_id,
        "user_email": e.user_email,
        "old_value": e.old_value,
        "new_value": e.new_value,
        "ip_address": e.ip_address,
        "created_at": e.created_at,
    } for e in entries]
    return {"items": items, "total": total, "skip": skip, "limit": limit}


# =============================================================================
# Agents & Analytics (static paths — must be before /{slug})
# =============================================================================

@router.get("/agents", response_model=AgentListResponse, responses=LIST_ERRORS)
def list_agents(
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    List all agents with prompt counts and usage statistics.

    **Required permissions:** prompts:read
    """
    agents = service.list_agents()
    # Enrich each agent's prompts with full response data
    for agent in agents:
        agent["prompts"] = [
            _prompt_to_response(p, service) for p in agent.get("_prompt_objs", [])
        ]
        agent.pop("_prompt_objs", None)
    return {"items": agents}


@router.get("/agents/{agent_id}", response_model=AgentSummary, responses=CRUD_ERRORS)
def get_agent(
    agent_id: str,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Get agent detail with all bound prompts.

    **Required permissions:** prompts:read
    """
    summary = service.get_agent_summary(agent_id)
    if summary["prompt_count"] == 0:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    summary["prompts"] = [_prompt_to_response(p, service) for p in summary["prompts"]]
    return summary


@router.get("/analytics/overview", response_model=PromptAnalyticsOverview, responses=LIST_ERRORS)
def get_analytics_overview(
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Get system-wide prompt analytics and statistics.

    **Required permissions:** prompts:read
    """
    overview = service.get_analytics_overview()

    # Recent changes
    recent, _ = service.list_audit_log(limit=10)
    overview["recent_changes"] = [{
        "id": str(e.id),
        "action": e.action,
        "prompt_id": str(e.prompt_id),
        "prompt_slug": e.prompt_slug,
        "version": e.version,
        "user_id": e.user_id,
        "user_email": e.user_email,
        "old_value": e.old_value,
        "new_value": e.new_value,
        "ip_address": e.ip_address,
        "created_at": e.created_at,
    } for e in recent]

    # Top prompts by usage
    top_prompts, _ = service.list_prompts(limit=5, sort_by="updated_at", sort_dir="desc")
    overview["top_prompts"] = [_prompt_to_response(p, service) for p in top_prompts]

    return overview


# =============================================================================
# Import/Export (static paths — must be before /{slug})
# =============================================================================

@router.get("/export", response_model=List[PromptExportItem], responses=LIST_ERRORS)
def export_prompts(
    slugs: Optional[str] = Query(None, description="Comma-separated slugs to export (all if empty)"),
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Export prompts in portable JSON format.

    **Required permissions:** prompts:admin
    """
    slug_list = [s.strip() for s in slugs.split(",")] if slugs else None
    return service.export_prompts(slug_list)


@router.post("/import", response_model=PromptImportResponse, responses=CREATE_ERRORS)
def import_prompts(
    body: PromptImportRequest,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Bulk import prompts from JSON.

    **Required permissions:** prompts:admin
    """
    result = service.import_prompts(
        items=[p.model_dump() for p in body.prompts],
        overwrite=body.overwrite,
        user_sub=current_user.sub,
        user_email=getattr(current_user, "email", None),
    )
    return result


# =============================================================================
# Prompt CRUD (/{slug} catch-all — MUST be after all static routes)
# =============================================================================

@router.post("/", response_model=PromptResponse, status_code=201, responses=CREATE_ERRORS)
def create_prompt(
    data: PromptCreate,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Create a new managed prompt with initial version.

    **Required permissions:** prompts:write
    """
    existing = service.get_prompt(data.slug)
    if existing:
        raise HTTPException(status_code=409, detail=f"Prompt with slug '{data.slug}' already exists")

    prompt = service.create_prompt(
        data=data.model_dump(),
        user_sub=current_user.sub,
        user_email=getattr(current_user, "email", None),
    )
    return _prompt_to_response(prompt, service)


@router.get("/{slug}", response_model=PromptResponse, responses=CRUD_ERRORS)
def get_prompt(
    slug: str,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Get a prompt by its slug.

    **Required permissions:** prompts:read
    """
    prompt = service.get_prompt(slug)
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")
    return _prompt_to_response(prompt, service)


@router.put("/{slug}", response_model=PromptResponse, responses=CRUD_ERRORS)
def update_prompt(
    slug: str,
    data: PromptUpdate,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Update a prompt — creates a new immutable version.
    The previous version is preserved and can be restored.

    **Required permissions:** prompts:write
    """
    try:
        prompt = service.update_prompt(
            slug=slug,
            data=data.model_dump(exclude_unset=True),
            user_sub=current_user.sub,
            user_email=getattr(current_user, "email", None),
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=423, detail=str(e))

    return _prompt_to_response(prompt, service)


@router.delete("/{slug}", responses=DELETE_ERRORS)
def delete_prompt(
    slug: str,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Soft-delete (deactivate) a prompt. Can be reactivated later.

    **Required permissions:** prompts:delete
    """
    if not service.delete_prompt(slug, current_user.sub, getattr(current_user, "email", None)):
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")
    return {"detail": f"Prompt '{slug}' deactivated"}


@router.patch("/{slug}/activate", response_model=PromptResponse, responses=CRUD_ERRORS)
def activate_prompt(
    slug: str,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Reactivate a deactivated prompt.

    **Required permissions:** prompts:write
    """
    prompt = service.activate_prompt(slug, current_user.sub, getattr(current_user, "email", None))
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")
    return _prompt_to_response(prompt, service)


@router.patch("/{slug}/lock", response_model=PromptResponse, responses=CRUD_ERRORS)
def lock_prompt(
    slug: str,
    reason: str = Query(..., description="Reason for locking"),
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Lock a prompt to prevent edits.

    **Required permissions:** prompts:admin
    """
    prompt = service.lock_prompt(slug, reason, current_user.sub, getattr(current_user, "email", None))
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")
    return _prompt_to_response(prompt, service)


@router.patch("/{slug}/unlock", response_model=PromptResponse, responses=CRUD_ERRORS)
def unlock_prompt(
    slug: str,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Unlock a locked prompt.

    **Required permissions:** prompts:admin
    """
    prompt = service.unlock_prompt(slug, current_user.sub, getattr(current_user, "email", None))
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")
    return _prompt_to_response(prompt, service)


# =============================================================================
# Version Management (/{slug}/... — after /{slug})
# =============================================================================

@router.get("/{slug}/versions", response_model=PromptVersionListResponse, responses=CRUD_ERRORS)
def list_versions(
    slug: str,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    List all versions of a prompt, newest first.

    **Required permissions:** prompts:read
    """
    prompt = service.get_prompt(slug)
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")

    versions = service.list_versions(prompt.id)
    items = [{
        "id": str(v.id),
        "prompt_id": str(v.prompt_id),
        "version": v.version,
        "content": v.content,
        "system_message": v.system_message,
        "parameters": v.parameters,
        "model": v.model,
        "input_schema": v.input_schema,
        "output_schema": v.output_schema,
        "change_summary": v.change_summary,
        "created_by": v.created_by,
        "created_at": v.created_at,
    } for v in versions]
    return {"items": items, "total": len(items)}


@router.get("/{slug}/versions/{version}", response_model=PromptVersionResponse, responses=CRUD_ERRORS)
def get_version(
    slug: str,
    version: int,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Get a specific version of a prompt.

    **Required permissions:** prompts:read
    """
    prompt = service.get_prompt(slug)
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")

    v = service.get_version(prompt.id, version)
    if not v:
        raise HTTPException(status_code=404, detail=f"Version {version} not found")

    return {
        "id": str(v.id),
        "prompt_id": str(v.prompt_id),
        "version": v.version,
        "content": v.content,
        "system_message": v.system_message,
        "parameters": v.parameters,
        "model": v.model,
        "input_schema": v.input_schema,
        "output_schema": v.output_schema,
        "change_summary": v.change_summary,
        "created_by": v.created_by,
        "created_at": v.created_at,
    }


@router.post("/{slug}/restore/{version}", response_model=PromptResponse, responses=CRUD_ERRORS)
def restore_version(
    slug: str,
    version: int,
    body: PromptRestoreRequest = None,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Restore a prompt to a previous version. Creates a new version with the old content.

    **Required permissions:** prompts:write
    """
    try:
        change_summary = body.change_summary if body else None
        prompt = service.restore_version(
            slug, version, current_user.sub,
            getattr(current_user, "email", None), change_summary,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")

    return _prompt_to_response(prompt, service)


@router.get("/{slug}/diff/{v1}/{v2}", response_model=PromptDiffResponse, responses=CRUD_ERRORS)
def diff_versions(
    slug: str,
    v1: int,
    v2: int,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Get a diff between two versions of a prompt.

    **Required permissions:** prompts:read
    """
    prompt = service.get_prompt(slug)
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")

    try:
        diff = service.diff_versions(prompt.id, v1, v2)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {
        "slug": slug,
        "version_from": v1,
        "version_to": v2,
        **diff,
    }


# =============================================================================
# Usage Tracking (/{slug}/...)
# =============================================================================

@router.get("/{slug}/usages", response_model=List[PromptUsageResponse], responses=CRUD_ERRORS)
def list_usages(
    slug: str,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    List all usage locations and runtime statistics for a prompt.

    **Required permissions:** prompts:read
    """
    prompt = service.get_prompt(slug)
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")

    usages = service.list_usages(prompt.id)
    return [{
        "id": str(u.id),
        "prompt_id": str(u.prompt_id),
        "usage_type": u.usage_type,
        "location": u.location,
        "description": u.description,
        "is_primary": u.is_primary,
        "last_called_at": u.last_called_at,
        "call_count": u.call_count or 0,
        "avg_latency_ms": u.avg_latency_ms,
        "avg_tokens_in": u.avg_tokens_in,
        "avg_tokens_out": u.avg_tokens_out,
        "total_tokens": u.total_tokens or 0,
        "error_count": u.error_count or 0,
        "last_model_used": u.last_model_used,
        "last_provider_used": u.last_provider_used,
        "created_at": u.created_at,
        "updated_at": u.updated_at,
    } for u in usages]


# =============================================================================
# Tags per prompt (/{slug}/tags/...)
# =============================================================================

@router.post("/{slug}/tags", status_code=201, responses=CRUD_ERRORS)
def add_tag(
    slug: str,
    body: TagAddRequest,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Add a tag to a prompt.

    **Required permissions:** prompts:write
    """
    prompt = service.get_prompt(slug)
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")

    if not service.add_tag(prompt.id, body.tag):
        raise HTTPException(status_code=409, detail=f"Tag '{body.tag}' already exists on this prompt")

    return {"detail": f"Tag '{body.tag}' added"}


@router.delete("/{slug}/tags/{tag}", responses=DELETE_ERRORS)
def remove_tag(
    slug: str,
    tag: str,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Remove a tag from a prompt.

    **Required permissions:** prompts:write
    """
    prompt = service.get_prompt(slug)
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")

    if not service.remove_tag(prompt.id, tag):
        raise HTTPException(status_code=404, detail=f"Tag '{tag}' not found on this prompt")

    return {"detail": f"Tag '{tag}' removed"}


# =============================================================================
# Test Cases (/{slug}/test-cases/...)
# =============================================================================

@router.get("/{slug}/test-cases", response_model=List[PromptTestCaseResponse], responses=CRUD_ERRORS)
def list_test_cases(
    slug: str,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    List saved test cases for a prompt.

    **Required permissions:** prompts:read
    """
    prompt = service.get_prompt(slug)
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")

    cases = service.list_test_cases(prompt.id)
    return [{
        "id": str(c.id),
        "prompt_id": str(c.prompt_id),
        "name": c.name,
        "input_data": c.input_data,
        "expected_output": c.expected_output,
        "notes": c.notes,
        "created_by": c.created_by,
        "created_at": c.created_at,
    } for c in cases]


@router.post("/{slug}/test-cases", response_model=PromptTestCaseResponse, status_code=201, responses=CREATE_ERRORS)
def create_test_case(
    slug: str,
    body: PromptTestCaseCreate,
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    Save a test case for a prompt.

    **Required permissions:** prompts:write
    """
    prompt = service.get_prompt(slug)
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")

    tc = service.create_test_case(prompt.id, body.model_dump(), current_user.sub)
    return {
        "id": str(tc.id),
        "prompt_id": str(tc.prompt_id),
        "name": tc.name,
        "input_data": tc.input_data,
        "expected_output": tc.expected_output,
        "notes": tc.notes,
        "created_by": tc.created_by,
        "created_at": tc.created_at,
    }


# =============================================================================
# Per-prompt Audit Log (/{slug}/audit)
# =============================================================================

@router.get("/{slug}/audit", response_model=PromptAuditLogListResponse, responses=CRUD_ERRORS)
def list_prompt_audit_log(
    slug: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    service: PromptService = Depends(_get_service),
    current_user=Depends(get_current_user),
):
    """
    View audit trail for a specific prompt.

    **Required permissions:** prompts:read
    """
    prompt = service.get_prompt(slug)
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt '{slug}' not found")

    entries, total = service.list_audit_log(prompt_id=prompt.id, skip=skip, limit=limit)
    items = [{
        "id": str(e.id),
        "action": e.action,
        "prompt_id": str(e.prompt_id),
        "prompt_slug": e.prompt_slug,
        "version": e.version,
        "user_id": e.user_id,
        "user_email": e.user_email,
        "old_value": e.old_value,
        "new_value": e.new_value,
        "ip_address": e.ip_address,
        "created_at": e.created_at,
    } for e in entries]
    return {"items": items, "total": total, "skip": skip, "limit": limit}
