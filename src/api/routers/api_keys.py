"""
API Key management router.

Provides CRUD endpoints for creating, listing, updating, rotating, and
revoking API keys with tool scoping, repository scoping, and rate limiting.
"""

import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from src.api.database import SessionLocal
from src.api.models import ApiKey, ApiKeyAuditLog, User as DBUser
from src.api.constants.tool_categories import TOOL_CATEGORIES, ALL_TOOL_NAMES, ALL_CATEGORY_NAMES
from src.auth.dependencies import get_current_user, get_db_user

from src.api.schemas.common import LIST_ERRORS, CREATE_ERRORS, CRUD_ERRORS, DELETE_ERRORS

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/api-keys", tags=["api-keys"])


# =============================================================================
# Pydantic Schemas
# =============================================================================

class CreateApiKeyRequest(BaseModel):
    """Request body for creating a new API key."""
    name: str = Field(..., min_length=1, max_length=255, description="Human-readable name for the API key")
    allowed_tool_categories: Optional[List[str]] = Field(default=None, description="Tool categories this key can access (None = all categories)")
    allowed_tools: Optional[List[str]] = Field(default=None, description="Individual tools this key can access (None = all tools)")
    allowed_repository_ids: Optional[List[str]] = Field(default=None, description="Repository UUIDs this key can access (None = all repos)")
    permission_overrides: Optional[List[str]] = Field(default=None, description="Permission overrides (admin-only)")
    rate_limit_per_hour: int = Field(default=1000, ge=100, le=100000, description="Maximum requests per hour (100-100000)")
    expires_in_days: Optional[int] = Field(default=90, ge=1, le=365, description="Days until key expires (1-365, None = never for admins)")

    @field_validator('allowed_tool_categories')
    @classmethod
    def validate_categories(cls, v):
        if v is not None:
            invalid = [c for c in v if c not in ALL_CATEGORY_NAMES]
            if invalid:
                raise ValueError(f"Invalid tool categories: {invalid}")
        return v

    @field_validator('allowed_tools')
    @classmethod
    def validate_tools(cls, v):
        if v is not None:
            invalid = [t for t in v if t not in ALL_TOOL_NAMES]
            if invalid:
                raise ValueError(f"Invalid tools: {invalid}")
        return v


class CreateApiKeyResponse(BaseModel):
    """Response returned after creating a new API key. Contains the raw key shown only once."""
    id: str = Field(..., description="Unique identifier for the API key (UUID)")
    name: str = Field(..., description="Human-readable name for the API key")
    key: str = Field(..., description="Raw API key value (shown only on creation -- store securely)")
    key_prefix: str = Field(..., description="Key prefix for identification (e.g. agh_abcd1234)")
    expires_at: Optional[str] = Field(default=None, description="ISO-8601 expiration timestamp, or null if non-expiring")
    created_at: str = Field(..., description="ISO-8601 creation timestamp")


class ApiKeyResponse(BaseModel):
    """Full API key details (excludes the raw key value)."""
    id: str = Field(..., description="Unique identifier for the API key (UUID)")
    name: str = Field(..., description="Human-readable name for the API key")
    key_prefix: str = Field(..., description="Key prefix for identification (e.g. agh_abcd1234)")
    user_id: str = Field(..., description="UUID of the user who owns this key")
    user_email: str = Field(..., description="Email of the key owner")
    is_service_account: bool = Field(..., description="Whether the owner is a service account")
    organization_id: str = Field(..., description="UUID of the organization this key belongs to")
    allowed_tool_categories: Optional[List[str]] = Field(default=None, description="Tool categories this key can access")
    allowed_tools: Optional[List[str]] = Field(default=None, description="Individual tools this key can access")
    allowed_repository_ids: Optional[List[str]] = Field(default=None, description="Repository UUIDs this key can access")
    permission_overrides: Optional[List[str]] = Field(default=None, description="Permission overrides applied to this key")
    rate_limit_per_hour: int = Field(..., description="Maximum requests per hour")
    is_active: bool = Field(..., description="Whether the key is currently active")
    expires_at: Optional[str] = Field(default=None, description="ISO-8601 expiration timestamp")
    last_used_at: Optional[str] = Field(default=None, description="ISO-8601 timestamp of last use")
    created_at: str = Field(..., description="ISO-8601 creation timestamp")
    updated_at: str = Field(..., description="ISO-8601 last update timestamp")


class UpdateApiKeyRequest(BaseModel):
    """Request body for updating an existing API key's settings."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=255, description="Updated human-readable name")
    allowed_tool_categories: Optional[List[str]] = Field(default=None, description="Updated tool category scoping")
    allowed_tools: Optional[List[str]] = Field(default=None, description="Updated individual tool scoping")
    allowed_repository_ids: Optional[List[str]] = Field(default=None, description="Updated repository scoping")
    permission_overrides: Optional[List[str]] = Field(default=None, description="Updated permission overrides (admin-only)")
    rate_limit_per_hour: Optional[int] = Field(default=None, ge=100, le=100000, description="Updated rate limit per hour")
    is_active: Optional[bool] = Field(default=None, description="Set active/inactive status")


# =============================================================================
# Helpers
# =============================================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def generate_api_key() -> tuple:
    """Generate a new API key. Returns (raw_key, key_hash, key_prefix)."""
    random_part = secrets.token_hex(20)  # 40 hex chars
    raw_key = f"agh_{random_part}"  # 44 chars total
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = f"agh_{random_part[:8]}"  # "agh_" + first 8 hex chars
    return raw_key, key_hash, key_prefix


def _format_dt(dt) -> Optional[str]:
    """Format a datetime to ISO string or None."""
    if dt is None:
        return None
    return dt.isoformat()


def _key_to_response(key: ApiKey, user: DBUser) -> ApiKeyResponse:
    """Convert an ApiKey model to response schema."""
    return ApiKeyResponse(
        id=str(key.id),
        name=key.name,
        key_prefix=key.key_prefix,
        user_id=str(key.user_id),
        user_email=user.email or "",
        is_service_account=getattr(user, 'is_service_account', False),
        organization_id=str(key.organization_id),
        allowed_tool_categories=key.allowed_tool_categories,
        allowed_tools=key.allowed_tools,
        allowed_repository_ids=key.allowed_repository_ids,
        permission_overrides=key.permission_overrides,
        rate_limit_per_hour=key.rate_limit_per_hour,
        is_active=key.is_active,
        expires_at=_format_dt(key.expires_at),
        last_used_at=_format_dt(key.last_used_at),
        created_at=_format_dt(key.created_at),
        updated_at=_format_dt(key.updated_at),
    )


def _log_audit_event(
    db: Session,
    api_key_id,
    actor_user_id,
    event_type: str,
    event_detail: dict,
    request: Request,
):
    """Write an entry to the api_key_audit_log table."""
    log_entry = ApiKeyAuditLog(
        api_key_id=api_key_id,
        actor_user_id=actor_user_id,
        event_type=event_type,
        event_detail=event_detail,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:500],
    )
    db.add(log_entry)


def _is_admin(user: DBUser) -> bool:
    return user.role in ('admin', 'super_admin')


def _validate_admin_only_fields(request_data, db_user: DBUser):
    """Validate fields that require admin privileges."""
    if _is_admin(db_user):
        return

    # Non-admins cannot set no-expiration
    if hasattr(request_data, 'expires_in_days') and request_data.expires_in_days is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create keys without expiration"
        )

    # Non-admins cannot set rate limit > 1000
    if hasattr(request_data, 'rate_limit_per_hour') and request_data.rate_limit_per_hour is not None:
        if request_data.rate_limit_per_hour > 1000:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can set rate limits above 1000/hr"
            )

    # Non-admins cannot set permission overrides
    if hasattr(request_data, 'permission_overrides') and request_data.permission_overrides is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can set permission overrides on API keys"
        )

    # Non-admins cannot set all-repos (None means all repos)
    if hasattr(request_data, 'allowed_repository_ids') and request_data.allowed_repository_ids is not None:
        pass  # Explicitly setting repos is fine
    # Note: None = all repos is allowed for non-admins (inherits their own access)


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/tool-categories", summary="List tool categories for scoping", responses={**LIST_ERRORS})
async def get_tool_categories(
    db_user: DBUser = Depends(get_db_user),
):
    """Return the available tool category definitions for use in key scoping.

    Used by the UI to populate dropdown menus when creating or editing API keys.
    """
    return TOOL_CATEGORIES


@router.post("", response_model=CreateApiKeyResponse, status_code=status.HTTP_201_CREATED, summary="Generate a new API key", responses={**CREATE_ERRORS, 400: {"description": "No organization context"}, 403: {"description": "Admin-only field used by non-admin"}, 409: {"description": "Key name already exists"}})
async def create_api_key(
    body: CreateApiKeyRequest,
    request: Request,
    db_user: DBUser = Depends(get_db_user),
    db: Session = Depends(get_db),
):
    """Generate a new API key scoped to the current user and organization.

    The raw key value is returned only once in the response. Store it securely.
    Non-admin users are subject to restrictions on expiration and rate limits.
    Requires at least analyst role (user role cannot create API keys).
    """
    if db_user.role == 'user':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key generation requires at least analyst role"
        )

    # Validate admin-only fields
    _validate_admin_only_fields(body, db_user)

    # Get org_id from request state (set by OrganizationContextMiddleware)
    org_id = getattr(request.state, 'org_id', None)
    if not org_id:
        # Fall back to first org if not set
        from src.api.models import Organization
        org = db.query(Organization).first()
        if not org:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No organization context found"
            )
        org_id = str(org.id)

    # Check for duplicate name
    existing = db.query(ApiKey).filter(
        ApiKey.user_id == db_user.id,
        ApiKey.organization_id == org_id,
        ApiKey.name == body.name,
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"API key with name '{body.name}' already exists"
        )

    # Generate key
    raw_key, key_hash, key_prefix = generate_api_key()

    # Calculate expiration
    expires_at = None
    if body.expires_in_days is not None:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    # Create key record
    api_key = ApiKey(
        user_id=db_user.id,
        organization_id=org_id,
        name=body.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        allowed_tool_categories=body.allowed_tool_categories,
        allowed_tools=body.allowed_tools,
        allowed_repository_ids=body.allowed_repository_ids,
        permission_overrides=body.permission_overrides,
        rate_limit_per_hour=body.rate_limit_per_hour,
        expires_at=expires_at,
    )
    db.add(api_key)
    db.flush()  # Get the ID

    # Audit log
    _log_audit_event(
        db, api_key.id, db_user.id, "created",
        {"name": body.name, "key_prefix": key_prefix},
        request,
    )

    db.commit()
    db.refresh(api_key)

    logger.info(f"API key created: {key_prefix} for user {db_user.email}")

    return CreateApiKeyResponse(
        id=str(api_key.id),
        name=api_key.name,
        key=raw_key,
        key_prefix=key_prefix,
        expires_at=_format_dt(api_key.expires_at),
        created_at=_format_dt(api_key.created_at),
    )


@router.get("", response_model=List[ApiKeyResponse], summary="List API keys", responses={**LIST_ERRORS})
async def list_api_keys(
    request: Request,
    db_user: DBUser = Depends(get_db_user),
    db: Session = Depends(get_db),
):
    """List API keys for the current organization.

    Admins see all keys in the organization; non-admin users see only their own keys.
    Results are ordered by creation date descending.
    """
    query = db.query(ApiKey)

    org_id = getattr(request.state, 'org_id', None)
    if org_id:
        query = query.filter(ApiKey.organization_id == org_id)

    # Non-admins only see their own keys
    if not _is_admin(db_user):
        query = query.filter(ApiKey.user_id == db_user.id)

    keys = query.order_by(ApiKey.created_at.desc()).all()

    # Build responses with user info
    results = []
    user_cache = {}
    for key in keys:
        user_id = str(key.user_id)
        if user_id not in user_cache:
            user = db.query(DBUser).filter(DBUser.id == key.user_id).first()
            user_cache[user_id] = user
        results.append(_key_to_response(key, user_cache[user_id]))

    return results


@router.get("/{key_id}", response_model=ApiKeyResponse, summary="Get API key details", responses={**CRUD_ERRORS, 403: {"description": "Access denied -- not owner or admin"}, 404: {"description": "API key not found"}})
async def get_api_key(
    key_id: UUID,
    db_user: DBUser = Depends(get_db_user),
    db: Session = Depends(get_db),
):
    """Retrieve details of a specific API key by its UUID.

    Users can view their own keys; admins can view any key in the organization.
    """
    api_key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    # Authorization: owner or admin
    if api_key.user_id != db_user.id and not _is_admin(db_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    owner = db.query(DBUser).filter(DBUser.id == api_key.user_id).first()
    return _key_to_response(api_key, owner)


@router.patch("/{key_id}", response_model=ApiKeyResponse, summary="Update API key settings", responses={**CRUD_ERRORS, 403: {"description": "Access denied or admin-only field used by non-admin"}, 404: {"description": "API key not found"}})
async def update_api_key(
    key_id: UUID,
    body: UpdateApiKeyRequest,
    request: Request,
    db_user: DBUser = Depends(get_db_user),
    db: Session = Depends(get_db),
):
    """Update an API key's name, scoping, rate limit, or active status.

    Only the key owner or an admin can update a key. Admin-only fields
    (permission_overrides, high rate limits) are validated server-side.
    """
    api_key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    # Authorization: owner or admin
    if api_key.user_id != db_user.id and not _is_admin(db_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    # Validate admin-only fields on update
    _validate_admin_only_fields(body, db_user)

    # Apply updates
    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(api_key, field, value)

    api_key.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(api_key)

    owner = db.query(DBUser).filter(DBUser.id == api_key.user_id).first()
    return _key_to_response(api_key, owner)


@router.delete("/{key_id}", status_code=status.HTTP_200_OK, summary="Revoke an API key", responses={**DELETE_ERRORS, 403: {"description": "Access denied -- not owner or admin"}})
async def revoke_api_key(
    key_id: UUID,
    request: Request,
    db_user: DBUser = Depends(get_db_user),
    db: Session = Depends(get_db),
):
    """Revoke an API key by setting it to inactive (soft-delete).

    The key record is preserved for audit purposes but can no longer
    authenticate requests. Only the key owner or an admin can revoke.
    """
    api_key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    # Authorization: owner or admin
    if api_key.user_id != db_user.id and not _is_admin(db_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    api_key.is_active = False
    api_key.updated_at = datetime.now(timezone.utc)

    # Audit log
    _log_audit_event(
        db, api_key.id, db_user.id, "revoked",
        {"name": api_key.name, "key_prefix": api_key.key_prefix},
        request,
    )

    db.commit()

    logger.info(f"API key revoked: {api_key.key_prefix} by {db_user.email}")
    return {"detail": "API key revoked", "key_prefix": api_key.key_prefix}


@router.post("/{key_id}/rotate", response_model=CreateApiKeyResponse, summary="Rotate an API key", responses={**CREATE_ERRORS, 400: {"description": "Cannot rotate a revoked key"}, 403: {"description": "Access denied -- not owner or admin"}, 404: {"description": "API key not found"}})
async def rotate_api_key(
    key_id: UUID,
    request: Request,
    db_user: DBUser = Depends(get_db_user),
    db: Session = Depends(get_db),
):
    """Rotate an API key by revoking the old key and generating a new one.

    The new key inherits all scoping, rate limits, and expiration from the
    original. The new raw key is returned only once in the response.
    """
    api_key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    # Authorization: owner or admin
    if api_key.user_id != db_user.id and not _is_admin(db_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    if not api_key.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot rotate a revoked key"
        )

    # Revoke old key
    api_key.is_active = False
    api_key.updated_at = datetime.now(timezone.utc)

    # Generate new key with same config
    raw_key, key_hash, key_prefix = generate_api_key()

    new_key = ApiKey(
        user_id=api_key.user_id,
        organization_id=api_key.organization_id,
        name=api_key.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        allowed_tool_categories=api_key.allowed_tool_categories,
        allowed_tools=api_key.allowed_tools,
        allowed_repository_ids=api_key.allowed_repository_ids,
        permission_overrides=api_key.permission_overrides,
        rate_limit_per_hour=api_key.rate_limit_per_hour,
        expires_at=api_key.expires_at,
    )
    db.add(new_key)
    db.flush()

    # Audit log for rotation
    _log_audit_event(
        db, new_key.id, db_user.id, "rotated",
        {
            "old_key_id": str(api_key.id),
            "old_key_prefix": api_key.key_prefix,
            "new_key_prefix": key_prefix,
        },
        request,
    )

    db.commit()
    db.refresh(new_key)

    logger.info(f"API key rotated: {api_key.key_prefix} -> {key_prefix} by {db_user.email}")

    return CreateApiKeyResponse(
        id=str(new_key.id),
        name=new_key.name,
        key=raw_key,
        key_prefix=key_prefix,
        expires_at=_format_dt(new_key.expires_at),
        created_at=_format_dt(new_key.created_at),
    )
