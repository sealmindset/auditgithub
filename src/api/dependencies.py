"""
FastAPI dependencies for database session management and tenant routing.

Provides dependency injection functions for:
- Tenant-scoped database access (get_tenant_db) with SET LOCAL search_path
- Public schema access (get_public_db) for RBAC and metadata tables
"""

from fastapi import Request, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
import logging
from src.api.database import get_db
from src.auth.dependencies import get_current_user  # Phase 2 integration

logger = logging.getLogger(__name__)


def get_tenant_db(
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)  # Ensures authentication required
) -> Session:
    """
    Set PostgreSQL search_path to the tenant's schema.

    Extracts tenant_slug from request.state (set by TenantMiddleware)
    and configures the database session to query only that tenant's data.

    Security: Uses SET LOCAL for transaction-scoped search_path.
    Connection pooling is safe because search_path resets on transaction end.

    Args:
        request: FastAPI request with tenant_slug in state
        db: SQLAlchemy session from get_db dependency
        user: Current authenticated user (ensures auth before tenant access)

    Returns:
        Database session configured for tenant schema

    Raises:
        HTTPException 400: If tenant context not available
        HTTPException 500: If search_path configuration fails

    Usage:
        @router.get("/repositories")
        async def list_repositories(db: Session = Depends(get_tenant_db)):
            # All queries will automatically use tenant_{slug} schema
            repos = db.query(Repository).all()
            return repos

    Integration:
        - TenantMiddleware (Phase 4): Sets request.state.tenant_slug
        - get_current_user (Phase 2): Validates JWT and authenticates user
        - Phase 3 RBAC: Permission checks happen after tenant routing
    """
    import os

    tenant_slug = getattr(request.state, "tenant_slug", None)

    if not tenant_slug:
        # Check if auth is disabled - use default public schema
        auth_disabled = os.getenv("AUTH_DISABLED", "false").lower() == "true"
        multi_tenant = os.getenv("MULTI_TENANT_ENABLED", "false").lower() == "true"

        if auth_disabled or not multi_tenant:
            logger.debug("AUTH_DISABLED or single-tenant mode, using public schema")
            # For single-tenant or auth-disabled mode, just return db without changing schema
            yield db
            return

        raise HTTPException(
            status_code=400,
            detail="Tenant context not available. Ensure valid JWT with tenant_id claim."
        )

    # Construct schema name
    schema_name = f"tenant_{tenant_slug}"

    # Set search_path for this transaction (SET LOCAL - transaction-scoped)
    # CRITICAL: Use parameterized query to prevent SQL injection
    try:
        db.execute(
            text("SET LOCAL search_path = :schema, public"),
            {"schema": schema_name}
        )

        logger.debug(f"Set search_path to {schema_name} for user {user.sub}")

    except Exception as e:
        logger.error(f"Failed to set search_path for tenant {tenant_slug}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to configure tenant database access"
        )

    return db


def get_public_db(db: Session = Depends(get_db)) -> Session:
    """
    Database session for public schema (RBAC tables, metadata).

    Does not set search_path, uses default public schema.
    Use this for accessing tenant-agnostic tables like:
    - Tenants table (tenant metadata)
    - UserRole table (RBAC - Phase 3)
    - Permission table (RBAC - Phase 3)

    Args:
        db: SQLAlchemy session from get_db dependency

    Returns:
        Database session using default public schema

    Usage:
        @router.get("/tenants")
        async def list_tenants(db: Session = Depends(get_public_db)):
            # Queries use public schema
            tenants = db.query(Tenant).all()
            return tenants
    """
    return db
