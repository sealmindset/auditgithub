"""
Tenants Admin Router for Multi-Tenant Architecture.

Provides endpoints for managing tenants:
- List all tenants
- Create new tenant
- Get tenant details
- Update tenant
- Provision tenant database
- Get migration health status
"""
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from loguru import logger

from ..database import get_metadata_db
from ..models import Tenant
from ..database_router import database_router
from src.api.schemas.common import LIST_ERRORS, CREATE_ERRORS, CRUD_ERRORS, DELETE_ERRORS
from src.rbac.dependencies import require_permissions
from src.auth.dependencies import require_admin, get_current_user

router = APIRouter(prefix="/tenants", tags=["Tenants"])


# =============================================================================
# Pydantic Models
# =============================================================================

class TenantBase(BaseModel):
    """Base model for tenant data."""
    name: str = Field(..., min_length=1, max_length=255, description="Display name of the tenant")
    github_org: str = Field(..., min_length=1, max_length=255, description="GitHub organization name associated with this tenant")
    description: Optional[str] = Field(None, description="Optional description of the tenant")


class TenantCreate(TenantBase):
    """Model for creating a new tenant."""
    slug: str = Field(..., min_length=1, max_length=50, pattern=r"^[a-z0-9-]+$", description="URL-safe slug identifier (lowercase alphanumeric and hyphens only)")
    database_host: Optional[str] = Field("db", description="PostgreSQL host for the tenant database")
    database_port: Optional[int] = Field(5432, description="PostgreSQL port for the tenant database")
    database_name: Optional[str] = Field(None, description="Database name; auto-generated from slug if not provided")
    database_user: Optional[str] = Field("auditgh", description="Database user for the tenant schema")
    database_password: Optional[str] = Field("auditgh_secret", description="Database password for the tenant schema")
    auto_provision: bool = Field(True, description="Automatically provision the database schema after creation")


class TenantUpdate(BaseModel):
    """Model for updating a tenant."""
    name: Optional[str] = Field(None, min_length=1, max_length=255, description="Updated display name")
    github_org: Optional[str] = Field(None, min_length=1, max_length=255, description="Updated GitHub organization name")
    description: Optional[str] = Field(None, description="Updated description")
    is_active: Optional[bool] = Field(None, description="Set active/inactive status")


class TenantResponse(TenantBase):
    """Model for tenant response."""
    id: str = Field(..., description="Unique tenant identifier")
    slug: str = Field(..., description="URL-safe slug identifier")
    database_name: str = Field(..., description="Name of the tenant's PostgreSQL database")
    is_active: bool = Field(..., description="Whether the tenant is currently active")
    is_provisioned: bool = Field(..., description="Whether the tenant database has been provisioned")
    schema_version: Optional[str] = Field(None, description="Current database schema version")
    migration_status: Optional[str] = Field(None, description="Migration status (current, behind, error, pending)")
    created_at: datetime = Field(..., description="Timestamp when the tenant was created")
    updated_at: datetime = Field(..., description="Timestamp when the tenant was last updated")
    
    model_config = {"from_attributes": True}


class TenantListResponse(BaseModel):
    """Model for tenant list response."""
    total: int = Field(..., description="Total number of tenants matching the query")
    tenants: List[TenantResponse] = Field(..., description="List of tenant records")


class TenantHealthResponse(BaseModel):
    """Model for tenant health check response."""
    total_tenants: int = Field(..., description="Total number of active tenants")
    current: int = Field(..., description="Number of tenants with up-to-date schemas")
    behind: int = Field(..., description="Number of tenants with outdated schemas")
    error: int = Field(..., description="Number of tenants in error state")
    pending: int = Field(..., description="Number of tenants pending provisioning")
    latest_version: Optional[str] = Field(None, description="Latest schema version across all tenants")
    tenants: List[dict] = Field(..., description="Per-tenant migration status details")


class ProvisionResponse(BaseModel):
    """Model for provision response."""
    success: bool = Field(..., description="Whether the provisioning request was accepted")
    message: str = Field(..., description="Human-readable status message")
    tenant_slug: str = Field(..., description="Slug of the tenant being provisioned")


# =============================================================================
# Endpoints
# =============================================================================

@router.get(
    "",
    response_model=TenantListResponse,
    dependencies=[Depends(get_current_user)],
    summary="List all tenants",
    responses={
        **LIST_ERRORS,
        401: {"description": "Not authenticated"},
    },
)
def list_tenants(
    skip: int = 0,
    limit: int = 100,
    include_inactive: bool = False,
    db: Session = Depends(get_metadata_db)
):
    """Return a paginated list of all registered tenants.

    Requires the **admin:manage** permission. By default only active tenants
    are returned; set `include_inactive=true` to include deactivated tenants.
    """
    query = db.query(Tenant)
    
    if not include_inactive:
        query = query.filter(Tenant.is_active == True)
    
    total = query.count()
    tenants = query.order_by(Tenant.name).offset(skip).limit(limit).all()
    
    return TenantListResponse(
        total=total,
        tenants=[TenantResponse(
            id=str(t.id),
            slug=t.slug,
            name=t.name,
            github_org=t.github_org,
            description=t.description,
            database_name=t.database_name,
            is_active=t.is_active,
            is_provisioned=t.is_provisioned,
            schema_version=t.schema_version,
            migration_status=t.migration_status,
            created_at=t.created_at,
            updated_at=t.updated_at
        ) for t in tenants]
    )


@router.post(
    "",
    response_model=TenantResponse,
    status_code=201,
    dependencies=[Depends(require_admin)],
    summary="Create a new tenant",
    responses={
        **CREATE_ERRORS,
        400: {"description": "Invalid slug format"},
        401: {"description": "Not authenticated"},
        403: {"description": "Requires admin or super_admin role"},
        409: {"description": "Tenant slug or GitHub org already exists"},
    },
)
def create_tenant(
    tenant_data: TenantCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_metadata_db)
):
    """
    Create a new tenant with schema-per-tenant isolation.

    Requires the **admin:manage** permission. Creates a tenant record and
    provisions a PostgreSQL schema in the background. The slug must be
    lowercase, alphanumeric, and may contain hyphens.
    """
    import re

    # Validate slug format: ^[a-z0-9-]+$
    if not re.match(r'^[a-z0-9-]+$', tenant_data.slug):
        raise HTTPException(
            status_code=400,
            detail="Tenant slug must be lowercase, alphanumeric, and may contain hyphens only"
        )

    # Check if slug already exists
    existing = db.query(Tenant).filter(Tenant.slug == tenant_data.slug).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Tenant with slug '{tenant_data.slug}' already exists"
        )

    # Check if github_org already exists
    existing_org = db.query(Tenant).filter(Tenant.github_org == tenant_data.github_org).first()
    if existing_org:
        raise HTTPException(
            status_code=409,
            detail=f"Tenant for GitHub org '{tenant_data.github_org}' already exists"
        )

    # Auto-generate database name if not provided
    database_name = tenant_data.database_name or f"auditgh_{tenant_data.slug.replace('-', '_')}"

    # Create tenant record with is_provisioned=False initially
    tenant = Tenant(
        slug=tenant_data.slug,
        name=tenant_data.name,
        github_org=tenant_data.github_org,
        description=tenant_data.description,
        database_host=tenant_data.database_host,
        database_port=tenant_data.database_port,
        database_name=database_name,
        database_user=tenant_data.database_user,
        database_password=tenant_data.database_password,
        is_active=True,
        is_provisioned=False,
        migration_status="pending"
    )

    db.add(tenant)
    db.commit()
    db.refresh(tenant)

    logger.bind(router="tenants", endpoint="create_tenant").info(f"Created tenant: {tenant.slug}")

    # Queue schema provisioning in background
    from ..utils.tenant_provisioning import provision_tenant_schema
    if tenant_data.auto_provision:
        background_tasks.add_task(provision_tenant_schema, tenant.slug)
        logger.bind(router="tenants", endpoint="create_tenant").info(f"Queued schema provisioning for tenant: {tenant.slug}")

    return TenantResponse(
        id=str(tenant.id),
        slug=tenant.slug,
        name=tenant.name,
        github_org=tenant.github_org,
        description=tenant.description,
        database_name=tenant.database_name,
        is_active=tenant.is_active,
        is_provisioned=tenant.is_provisioned,
        schema_version=tenant.schema_version,
        migration_status=tenant.migration_status,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at
    )


@router.get(
    "/health",
    response_model=TenantHealthResponse,
    dependencies=[Depends(require_admin)],
    summary="Get tenant migration health",
    responses={
        **LIST_ERRORS,
        401: {"description": "Not authenticated"},
        403: {"description": "Requires admin or super_admin role"},
    },
)
def get_tenant_health(db: Session = Depends(get_metadata_db)):
    """Return migration health status for all active tenants.

    Requires the **admin:manage** permission. Reports how many tenants are
    current, behind, in error, or pending, along with per-tenant details.
    """
    tenants = db.query(Tenant).filter(Tenant.is_active == True).all()
    
    status_counts = {
        "current": 0,
        "behind": 0,
        "error": 0,
        "pending": 0
    }
    
    tenant_statuses = []
    latest_version = None
    
    for tenant in tenants:
        status = tenant.migration_status or "pending"
        if status in status_counts:
            status_counts[status] += 1
        else:
            status_counts["pending"] += 1
        
        if tenant.schema_version and (not latest_version or tenant.schema_version > latest_version):
            latest_version = tenant.schema_version
        
        tenant_statuses.append({
            "slug": tenant.slug,
            "name": tenant.name,
            "status": status,
            "version": tenant.schema_version,
            "last_migration_at": tenant.last_migration_at.isoformat() if tenant.last_migration_at else None,
            "error": tenant.migration_error
        })
    
    return TenantHealthResponse(
        total_tenants=len(tenants),
        current=status_counts["current"],
        behind=status_counts["behind"],
        error=status_counts["error"],
        pending=status_counts["pending"],
        latest_version=latest_version,
        tenants=tenant_statuses
    )


@router.get(
    "/{slug}",
    response_model=TenantResponse,
    dependencies=[Depends(require_admin)],
    summary="Get tenant by slug",
    responses={
        **CRUD_ERRORS,
        401: {"description": "Not authenticated"},
        403: {"description": "Requires admin or super_admin role"},
        404: {"description": "Tenant not found"},
    },
)
def get_tenant(slug: str, db: Session = Depends(get_metadata_db)):
    """Retrieve full details for a single tenant identified by its slug.

    Requires the **admin:manage** permission. Returns the tenant record
    including database provisioning and migration status.
    """
    tenant = db.query(Tenant).filter(Tenant.slug == slug).first()
    
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant not found: {slug}")
    
    return TenantResponse(
        id=str(tenant.id),
        slug=tenant.slug,
        name=tenant.name,
        github_org=tenant.github_org,
        description=tenant.description,
        database_name=tenant.database_name,
        is_active=tenant.is_active,
        is_provisioned=tenant.is_provisioned,
        schema_version=tenant.schema_version,
        migration_status=tenant.migration_status,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at
    )


@router.put(
    "/{slug}",
    response_model=TenantResponse,
    dependencies=[Depends(require_admin)],
    summary="Update a tenant",
    responses={
        **CRUD_ERRORS,
        401: {"description": "Not authenticated"},
        403: {"description": "Requires admin or super_admin role"},
        404: {"description": "Tenant not found"},
    },
)
def update_tenant(
    slug: str,
    tenant_data: TenantUpdate,
    db: Session = Depends(get_metadata_db)
):
    """Update mutable fields on an existing tenant.

    Requires the **admin:manage** permission. Only fields included in the
    request body are modified; omitted fields remain unchanged.
    """
    tenant = db.query(Tenant).filter(Tenant.slug == slug).first()
    
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant not found: {slug}")
    
    # Update fields if provided
    if tenant_data.name is not None:
        tenant.name = tenant_data.name
    if tenant_data.github_org is not None:
        tenant.github_org = tenant_data.github_org
    if tenant_data.description is not None:
        tenant.description = tenant_data.description
    if tenant_data.is_active is not None:
        tenant.is_active = tenant_data.is_active
    
    db.commit()
    db.refresh(tenant)
    
    # Refresh router cache
    database_router.refresh_tenant_cache(slug)

    logger.bind(router="tenants", endpoint="update_tenant").info(f"Updated tenant: {slug}")
    
    return TenantResponse(
        id=str(tenant.id),
        slug=tenant.slug,
        name=tenant.name,
        github_org=tenant.github_org,
        description=tenant.description,
        database_name=tenant.database_name,
        is_active=tenant.is_active,
        is_provisioned=tenant.is_provisioned,
        schema_version=tenant.schema_version,
        migration_status=tenant.migration_status,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at
    )


@router.post(
    "/{slug}/provision",
    response_model=ProvisionResponse,
    dependencies=[Depends(require_admin)],
    summary="Provision tenant database",
    responses={
        **CRUD_ERRORS,
        401: {"description": "Not authenticated"},
        403: {"description": "Requires admin or super_admin role"},
        404: {"description": "Tenant not found"},
    },
)
def provision_tenant(
    slug: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_metadata_db)
):
    """Manually trigger database schema provisioning for a tenant.

    Requires the **admin:manage** permission. If the tenant is already
    provisioned, returns a success message without re-provisioning.
    """
    tenant = db.query(Tenant).filter(Tenant.slug == slug).first()
    
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant not found: {slug}")
    
    if tenant.is_provisioned:
        return ProvisionResponse(
            success=True,
            message="Tenant database is already provisioned",
            tenant_slug=slug
        )
    
    # Queue provisioning in background
    background_tasks.add_task(provision_tenant_database, slug)
    
    return ProvisionResponse(
        success=True,
        message="Database provisioning started. Check tenant status for completion.",
        tenant_slug=slug
    )


@router.delete(
    "/{slug}",
    dependencies=[Depends(require_admin)],
    summary="Deactivate a tenant",
    responses={
        **DELETE_ERRORS,
        401: {"description": "Not authenticated"},
        403: {"description": "Requires admin or super_admin role"},
        404: {"description": "Tenant not found"},
    },
)
def deactivate_tenant(slug: str, db: Session = Depends(get_metadata_db)):
    """Soft-delete a tenant by setting it to inactive.

    Requires the **admin:manage** permission. The tenant record is preserved
    but marked inactive and removed from the database router cache.
    """
    tenant = db.query(Tenant).filter(Tenant.slug == slug).first()
    
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant not found: {slug}")
    
    tenant.is_active = False
    db.commit()
    
    # Remove from router cache
    database_router.dispose_engine(slug)

    logger.bind(router="tenants", endpoint="deactivate_tenant").info(f"Deactivated tenant: {slug}")
    
    return {"message": f"Tenant '{slug}' has been deactivated"}


# =============================================================================
# Background Tasks
# =============================================================================

def provision_tenant_database(slug: str):
    """Background task to provision tenant database."""
    from ..database import SessionLocal
    
    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.slug == slug).first()
        if not tenant:
            logger.bind(router="tenants", task="provision_tenant_database").error(f"Tenant not found for provisioning: {slug}")
            return

        success = database_router.provision_database(tenant)

        if success:
            tenant.is_provisioned = True
            tenant.migration_status = "current"
            tenant.last_migration_at = datetime.utcnow()
            logger.bind(router="tenants", task="provision_tenant_database").info(f"Successfully provisioned database for tenant: {slug}")
        else:
            tenant.migration_status = "error"
            tenant.migration_error = "Failed to provision database"
            logger.bind(router="tenants", task="provision_tenant_database").error(f"Failed to provision database for tenant: {slug}")
        
        db.commit()
        
    except Exception as e:
        logger.bind(router="tenants", task="provision_tenant_database").exception(f"Error provisioning tenant database: {slug}")
        try:
            tenant = db.query(Tenant).filter(Tenant.slug == slug).first()
            if tenant:
                tenant.migration_status = "error"
                tenant.migration_error = str(e)
                db.commit()
        except:
            pass
    finally:
        db.close()
