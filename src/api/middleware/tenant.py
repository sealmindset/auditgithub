"""
Tenant Middleware for Multi-Tenant Architecture.

This middleware extracts tenant context from incoming requests and makes it
available throughout the request lifecycle.

Tenant identification order:
1. JWT Bearer token (tenant_id claim from OIDC)
2. X-Tenant-ID header (API clients, backward compatibility)
3. tenant_slug cookie (browser sessions)
4. Default tenant from environment
"""
import os
from typing import Optional

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from loguru import logger

from ..database import SessionLocal
from ..models import Tenant
from src.auth.middleware import validate_jwt_token

# Default tenant slug when none is specified
DEFAULT_TENANT_SLUG = os.environ.get("DEFAULT_TENANT_SLUG", "default")

# Routes that don't require tenant context
TENANT_EXEMPT_PATHS = {
    "/",
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/tenants",  # Tenant management endpoints
}


class TenantMiddleware(BaseHTTPMiddleware):
    """
    Middleware to extract and validate tenant context from requests.
    
    Sets request.state.tenant and request.state.tenant_slug for use
    by downstream handlers.
    """
    
    async def dispatch(self, request: Request, call_next):
        # Skip tenant validation for exempt paths
        path = request.url.path
        if self._is_exempt_path(path):
            request.state.tenant = None
            request.state.tenant_slug = None
            request.state.tenant_id = None
            return await call_next(request)

        # Priority 1: Try JWT extraction first (Phase 2 OIDC integration)
        tenant_slug = await self._extract_tenant_from_jwt(request)

        # Priority 2: Fall back to header/cookie extraction (backward compatibility)
        if not tenant_slug:
            tenant_slug = self._extract_tenant_slug(request)

        if not tenant_slug:
            # No tenant specified - proceed without tenant context (uses default DB)
            logger.bind(middleware="TenantMiddleware").debug("No tenant specified, proceeding without tenant context")
            request.state.tenant = None
            request.state.tenant_slug = None
            request.state.tenant_id = None
            return await call_next(request)

        # Validate tenant exists and is active
        tenant = self._get_tenant(tenant_slug)

        if not tenant:
            logger.bind(
                middleware="TenantMiddleware",
                tenant_slug=tenant_slug
            ).warning(f"Tenant validation failed: {tenant_slug} - not found")
            raise HTTPException(
                status_code=404,
                detail=f"Tenant not found: {tenant_slug}"
            )

        if not tenant.is_active:
            logger.bind(
                middleware="TenantMiddleware",
                tenant_slug=tenant_slug,
                tenant_id=str(tenant.id)
            ).warning(f"Tenant validation failed: {tenant_slug} - inactive")
            raise HTTPException(
                status_code=403,
                detail=f"Tenant is inactive: {tenant_slug}"
            )

        if not tenant.is_provisioned:
            logger.bind(
                middleware="TenantMiddleware",
                tenant_slug=tenant_slug,
                tenant_id=str(tenant.id)
            ).warning(f"Tenant validation failed: {tenant_slug} - not provisioned")
            raise HTTPException(
                status_code=503,
                detail=f"Tenant database is being set up: {tenant_slug}"
            )

        # Set tenant context in request state
        request.state.tenant = tenant
        request.state.tenant_slug = tenant_slug
        request.state.tenant_id = tenant.id  # Store UUID for downstream use

        logger.bind(
            middleware="TenantMiddleware",
            tenant_slug=tenant_slug,
            tenant_id=str(tenant.id)
        ).info(f"Tenant validated: {tenant_slug}")

        response = await call_next(request)
        return response
    
    def _is_exempt_path(self, path: str) -> bool:
        """Check if path is exempt from tenant validation."""
        # Exact match
        if path in TENANT_EXEMPT_PATHS:
            return True

        # Check if path starts with any exempt prefix
        for exempt_path in TENANT_EXEMPT_PATHS:
            if path.startswith(exempt_path + "/"):
                return True

        return False

    async def _extract_tenant_from_jwt(self, request: Request) -> Optional[str]:
        """
        Extract tenant_slug from JWT Bearer token (Phase 2 OIDC integration).

        This method extracts the tenant_id claim from the JWT and looks up the
        corresponding Tenant record to validate access and retrieve the slug.

        Args:
            request: FastAPI request with Authorization header

        Returns:
            Optional[str]: Tenant slug if valid JWT with tenant_id, None otherwise

        Raises:
            HTTPException 403: If tenant exists but is inactive or not provisioned

        Security:
            - Reuses Phase 2 JWT validation (validate_jwt_token)
            - Validates tenant is_active and is_provisioned before allowing access
            - Gracefully handles missing JWT (returns None for unauthenticated routes)
        """
        # Extract Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None

        token = auth_header.replace("Bearer ", "").strip()
        if not token:
            return None

        db = SessionLocal()
        try:
            # Try to validate JWT with each registered provider
            # Don't know which provider issued token, so try all
            from src.auth.config import settings as auth_settings
            claims = None
            for provider in auth_settings.registered_provider_names:
                try:
                    claims = await validate_jwt_token(token, provider)
                    logger.bind(middleware="TenantMiddleware", provider=provider).debug(f"JWT validated with provider {provider}")
                    break
                except HTTPException:
                    # Validation failed, try next provider
                    continue
                except Exception as e:
                    # Unexpected error, log and try next provider
                    logger.bind(middleware="TenantMiddleware", provider=provider).debug(f"JWT validation error with {provider}: {e}")
                    continue

            # If no provider validated the token, return None (let Phase 2 auth handle 401)
            if not claims:
                logger.bind(middleware="TenantMiddleware").debug("JWT validation failed with all providers, no tenant context")
                return None

            # Extract tenant_id from JWT claims
            tenant_id = claims.get("tenant_id")
            if not tenant_id:
                logger.bind(middleware="TenantMiddleware").debug("JWT valid but no tenant_id claim found")
                return None

            # Look up Tenant by ID
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()

            if not tenant:
                logger.bind(middleware="TenantMiddleware", tenant_id=tenant_id).warning(f"JWT contains tenant_id {tenant_id} but Tenant not found")
                return None

            # Validate tenant is active
            if not tenant.is_active:
                logger.bind(
                    middleware="TenantMiddleware",
                    tenant_slug=tenant.slug,
                    tenant_id=str(tenant.id)
                ).warning(f"Tenant {tenant.slug} is inactive")
                raise HTTPException(
                    status_code=403,
                    detail=f"Tenant '{tenant.name}' is inactive"
                )

            # Validate tenant is provisioned
            if not tenant.is_provisioned:
                logger.bind(
                    middleware="TenantMiddleware",
                    tenant_slug=tenant.slug,
                    tenant_id=str(tenant.id)
                ).warning(f"Tenant {tenant.slug} database not provisioned")
                raise HTTPException(
                    status_code=403,
                    detail=f"Tenant '{tenant.name}' database is not provisioned"
                )

            logger.bind(
                middleware="TenantMiddleware",
                tenant_slug=tenant.slug,
                tenant_id=tenant_id
            ).debug(f"Extracted tenant_slug '{tenant.slug}' from JWT (tenant_id={tenant_id})")
            return tenant.slug

        except HTTPException:
            # Re-raise HTTP exceptions (403 for inactive/unprovisioned tenants)
            raise
        except Exception as e:
            # Log unexpected errors but don't block the request
            # Let individual routes enforce tenant requirements
            logger.bind(middleware="TenantMiddleware").warning(f"Error extracting tenant from JWT: {e}")
            return None
        finally:
            db.close()

    def _extract_tenant_slug(self, request: Request) -> Optional[str]:
        """Extract tenant slug from request headers or cookies."""
        # Priority 1: X-Tenant-ID header
        tenant_header = request.headers.get("X-Tenant-ID")
        if tenant_header:
            return tenant_header.strip()
        
        # Priority 2: tenant_slug cookie
        tenant_cookie = request.cookies.get("tenant_slug")
        if tenant_cookie:
            return tenant_cookie.strip()
        
        # Priority 3: Query parameter (for debugging/testing)
        tenant_param = request.query_params.get("tenant")
        if tenant_param:
            return tenant_param.strip()
        
        return None
    
    def _get_tenant(self, slug: str) -> Optional[Tenant]:
        """Fetch tenant from database."""
        db = SessionLocal()
        try:
            return db.query(Tenant).filter(Tenant.slug == slug).first()
        finally:
            db.close()


def get_current_tenant(request: Request) -> Tenant:
    """
    Dependency function to get the current tenant from request state.
    
    Usage:
        @app.get("/items")
        def get_items(tenant: Tenant = Depends(get_current_tenant)):
            ...
    """
    tenant = getattr(request.state, "tenant", None)
    if not tenant:
        raise HTTPException(
            status_code=400,
            detail="Tenant context not available"
        )
    return tenant


def get_current_tenant_slug(request: Request) -> str:
    """
    Dependency function to get the current tenant slug from request state.
    
    Usage:
        @app.get("/items")
        def get_items(tenant_slug: str = Depends(get_current_tenant_slug)):
            ...
    """
    tenant_slug = getattr(request.state, "tenant_slug", None)
    if not tenant_slug:
        raise HTTPException(
            status_code=400,
            detail="Tenant context not available"
        )
    return tenant_slug
