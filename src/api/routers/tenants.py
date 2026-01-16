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
from src.rbac.dependencies import require_permissions

router = APIRouter(prefix="/tenants", tags=["Tenants"])


# =============================================================================
# Pydantic Models
# =============================================================================

class TenantBase(BaseModel):
    """Base model for tenant data."""
    name: str = Field(..., min_length=1, max_length=255)
    github_org: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class TenantCreate(TenantBase):
    """Model for creating a new tenant."""
    slug: str = Field(..., min_length=1, max_length=50, pattern=r"^[a-z0-9-]+$")
    database_host: Optional[str] = "db"
    database_port: Optional[int] = 5432
    database_name: Optional[str] = None  # Auto-generated if not provided
    database_user: Optional[str] = "auditgh"
    database_password: Optional[str] = "auditgh_secret"
    auto_provision: bool = True  # Automatically provision database


class TenantUpdate(BaseModel):
    """Model for updating a tenant."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    github_org: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    is_active: Optional[bool] = None


class TenantResponse(TenantBase):
    """Model for tenant response."""
    id: str
    slug: str
    database_name: str
    is_active: bool
    is_provisioned: bool
    schema_version: Optional[str]
    migration_status: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}


class TenantListResponse(BaseModel):
    """Model for tenant list response."""
    total: int
    tenants: List[TenantResponse]


class TenantHealthResponse(BaseModel):
    """Model for tenant health check response."""
    total_tenants: int
    current: int
    behind: int
    error: int
    pending: int
    latest_version: Optional[str]
    tenants: List[dict]


class ProvisionResponse(BaseModel):
    """Model for provision response."""
    success: bool
    message: str
    tenant_slug: str


# =============================================================================
# Endpoints
# =============================================================================

@router.get("", response_model=TenantListResponse, dependencies=[Depends(require_permissions("admin:manage"))])
def list_tenants(
    skip: int = 0,
    limit: int = 100,
    include_inactive: bool = False,
    db: Session = Depends(get_metadata_db)
):
    """List all registered tenants."""
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


@router.post("", response_model=TenantResponse, status_code=201, dependencies=[Depends(require_permissions("admin:manage"))])
def create_tenant(
    tenant_data: TenantCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_metadata_db)
):
    """
    Create a new tenant with schema-per-tenant isolation.

    Creates a tenant record and provisions a PostgreSQL schema in the background.
    The slug must be lowercase, alphanumeric, and may contain hyphens.
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


@router.get("/health", response_model=TenantHealthResponse, dependencies=[Depends(require_permissions("admin:manage"))])
def get_tenant_health(db: Session = Depends(get_metadata_db)):
    """Get migration health status for all tenants."""
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


@router.get("/{slug}", response_model=TenantResponse, dependencies=[Depends(require_permissions("admin:manage"))])
def get_tenant(slug: str, db: Session = Depends(get_metadata_db)):
    """Get tenant details by slug."""
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


@router.put("/{slug}", response_model=TenantResponse, dependencies=[Depends(require_permissions("admin:manage"))])
def update_tenant(
    slug: str,
    tenant_data: TenantUpdate,
    db: Session = Depends(get_metadata_db)
):
    """Update tenant details."""
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


@router.post("/{slug}/provision", response_model=ProvisionResponse, dependencies=[Depends(require_permissions("admin:manage"))])
def provision_tenant(
    slug: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_metadata_db)
):
    """Manually trigger database provisioning for a tenant."""
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


@router.delete("/{slug}", dependencies=[Depends(require_permissions("admin:manage"))])
def deactivate_tenant(slug: str, db: Session = Depends(get_metadata_db)):
    """Deactivate a tenant (soft delete)."""
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
