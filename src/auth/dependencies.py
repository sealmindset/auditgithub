"""
FastAPI security dependencies for authentication.

Provides dependency injection functions for protected routes with support for:
- Session-based authentication (cookies, for browser apps)
- Token-based authentication (Bearer tokens, for API clients)
"""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from src.auth.models import User
from src.auth.middleware import security, validate_jwt_token
from jose import JWTError
import logging

logger = logging.getLogger(__name__)


async def get_current_user_from_session(request: Request) -> User:
    """
    Extract current user from session (cookie-based auth) with expiry enforcement.

    Args:
        request: FastAPI request object

    Returns:
        User: Authenticated user from session

    Raises:
        HTTPException 401: If user is not authenticated or session expired

    Usage:
        @router.get("/protected")
        async def protected_route(user: User = Depends(get_current_user_from_session)):
            return {"user": user.email}

    Security:
        - Session-based auth is simpler for browser apps
        - Session data set during OAuth callback flow
        - Enforces dual timeout (absolute + idle)
        - Checks session metadata for expiry
        - WWW-Authenticate header required by RFC 6750
    """
    # Get user data from session
    user_data = request.session.get('user')

    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Check session metadata for expiry
    session_id = request.cookies.get('session')  # Starlette session cookie
    if session_id:
        from src.auth.session import get_session_metadata, update_last_activity, delete_session
        from src.auth.config import settings

        metadata = get_session_metadata(session_id)

        if not metadata:
            # Session metadata missing - treat as expired
            request.session.clear()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired (metadata not found)",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Check expiry
        is_expired, reason = metadata.is_expired(
            settings.session_absolute_timeout_hours,
            settings.session_idle_timeout_minutes
        )

        if is_expired:
            # Clear session and raise 401
            request.session.clear()
            delete_session(session_id)

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Session expired ({reason} timeout)",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Update last activity (async to avoid blocking request)
        update_last_activity(session_id)

    # Return User model
    return User(**user_data)


async def get_current_user_from_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """
    Extract current user from Bearer token (token-based auth).

    Args:
        request: FastAPI request object (for storing jti/exp in state)
        credentials: HTTP Authorization credentials (Bearer token)

    Returns:
        User: Authenticated user from validated token

    Raises:
        HTTPException 401: If token is invalid, missing, or blacklisted

    Usage:
        @router.get("/api/data")
        async def api_endpoint(user: User = Depends(get_current_user_from_token)):
            return {"data": "protected", "user": user.email}

    Security:
        - Token-based auth is standard for API clients
        - Tries both OIDC providers (entra, okta) and self-signed tokens
        - Checks token blacklist for revoked tokens
        - Stores jti and exp in request.state for revocation endpoint
        - WWW-Authenticate header required by RFC 6750
        - Does not expose validation errors to prevent information leakage
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = credentials.credentials

    # First try validating as self-signed token (from our /auth/refresh endpoint)
    import os
    from jose import jwt
    from src.auth.tokens import is_token_blacklisted

    secret_key = os.getenv("JWT_SECRET_KEY")
    if secret_key:
        try:
            # Try decoding as self-signed token
            claims = jwt.decode(token, secret_key, algorithms=["HS256"])

            # Check if token is blacklisted
            jti = claims.get("jti")
            if jti and is_token_blacklisted(jti):
                logger.warning(f"Attempted to use blacklisted token (jti: {jti})")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"}
                )

            # Store jti and exp in request.state for revocation endpoint
            if jti:
                request.state.token_jti = jti
                request.state.token_exp = claims.get("exp", 0)
                request.state.user_sub = claims.get("sub", "")

            # Extract user info from claims
            user = User(
                email=claims.get('email', ''),
                name=claims.get('name', ''),
                sub=claims['sub'],  # Required claim
                provider=claims.get('provider', 'self-signed')
            )

            logger.debug(f"Self-signed token validated successfully")
            return user

        except JWTError:
            # Not a self-signed token, continue to OIDC providers
            logger.debug("Token is not self-signed, trying OIDC providers")
            pass

    # Try validating with each OIDC provider
    # We don't know which IdP issued the token without parsing claims first
    for provider in ["entra", "okta"]:
        try:
            # Validate token with this provider
            claims = await validate_jwt_token(token, provider)

            # Extract user info from claims
            user = User(
                email=claims.get('email', ''),
                name=claims.get('name', ''),
                sub=claims['sub'],  # Required claim
                provider=provider
            )

            logger.debug(f"Token validated successfully with provider {provider}")
            return user

        except HTTPException as e:
            # If this is not a validation error, re-raise immediately
            if e.status_code != status.HTTP_401_UNAUTHORIZED:
                raise

            # Otherwise, continue to next provider
            logger.debug(f"Token validation failed with {provider}, trying next provider")
            continue

        except JWTError as e:
            # JWT validation failed, try next provider
            logger.debug(f"JWT error with {provider}: {e}")
            continue

    # No provider could validate the token
    logger.warning("Token validation failed with all providers")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token",
        headers={"WWW-Authenticate": "Bearer"}
    )


async def get_current_user_with_bypass(request: Request) -> User:
    """
    Get current user with multi-method authentication support.

    Authentication chain (checked in order):
    1. X-API-Key header -> validate_api_key()
    2. AUTH_DISABLED env -> mock admin bypass
    3. Session cookie -> get_current_user_from_session()
    """
    import os

    # 1. Check for API key authentication (first — cheapest to validate)
    try:
        from src.auth.api_key_auth import validate_api_key
        api_key_user = await validate_api_key(request)
        if api_key_user is not None:
            logger.debug(f"Authenticated via API key: {api_key_user.email}")
            return api_key_user
    except HTTPException:
        # Re-raise HTTP exceptions (invalid key, rate limit, etc.)
        raise
    except Exception as e:
        # Log but don't block — fall through to other auth methods
        logger.warning(f"API key auth check failed: {e}")

    # 2. Check if authentication is disabled
    auth_disabled = os.getenv("AUTH_DISABLED", "false").lower() == "true"

    if auth_disabled:
        # Return a mock admin user when auth is disabled
        logger.debug("AUTH_DISABLED is true, returning mock admin user")
        return User(
            email="admin@localhost",
            name="Admin User (Auth Disabled)",
            sub="auth-disabled-admin",
            provider="bypass"
        )

    # 3. Normal session-based authentication flow
    return await get_current_user_from_session(request)


# Default to session-based auth with AUTH_DISABLED bypass
# Most endpoints will use cookies (browser-based auth)
# API clients can explicitly use get_current_user_from_token
get_current_user = get_current_user_with_bypass


# =========================================================================
# RBAC (Role-Based Access Control) Functions
# =========================================================================

from sqlalchemy.orm import Session
from src.api.database import SessionLocal
from src.api.models import User as DBUser, UserRepositoryAccess
from uuid import UUID
from typing import Callable


def get_db_user(request: Request) -> DBUser:
    """
    Get full database User model with RBAC fields.

    Fetches the complete User record from the database based on the
    authenticated user's email from the session/token.

    Args:
        request: FastAPI request object

    Returns:
        DBUser: Full User model from database with role, access_type, etc.

    Raises:
        HTTPException 401: If user not found in database
        HTTPException 403: If user is inactive

    Usage:
        @router.get("/admin/users")
        async def list_users(db_user: DBUser = Depends(get_db_user)):
            # db_user has role, access_type, and all RBAC fields
            return {"role": db_user.role}
    """
    import os
    from fastapi import HTTPException

    # Check if auth is disabled (dev mode)
    auth_disabled = os.getenv("AUTH_DISABLED", "false").lower() == "true"
    if auth_disabled:
        # Return mock super admin for dev mode
        logger.debug("AUTH_DISABLED is true, returning mock super admin")
        return DBUser(
            email="dev@localhost",
            username="devuser",
            full_name="Dev User",
            role="super_admin",
            access_type="both",
            auth_provider="local",
            is_active=True
        )

    # Check if already resolved via API key auth
    if getattr(request.state, 'auth_method', None) == 'api_key':
        db_user_from_key = getattr(request.state, 'db_user', None)
        if db_user_from_key:
            request.state.is_break_glass = False
            return db_user_from_key

    # Get authenticated user from session/token
    user_data = request.session.get('user')
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    # Fetch full user from database
    db = SessionLocal()
    try:
        db_user = db.query(DBUser).filter(DBUser.email == user_data.get('email')).first()

        if not db_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found in database"
            )

        if not db_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive"
            )

        # Store break glass flag in request state
        request.state.is_break_glass = user_data.get('is_break_glass', False)

        return db_user

    finally:
        db.close()


def require_role(*allowed_roles: str) -> Callable:
    """
    Dependency factory to require specific role(s).

    Args:
        *allowed_roles: One or more role names (e.g., 'admin', 'manager')

    Returns:
        Dependency function that checks user role

    Raises:
        HTTPException 403: If user role not in allowed_roles

    Usage:
        @router.post("/findings/{id}/delete")
        async def delete_finding(
            finding_id: UUID,
            user: DBUser = Depends(require_role('analyst', 'admin', 'super_admin'))
        ):
            # Only analysts, admins, and super admins can access
            pass
    """
    def role_checker(
        request: Request,
        db_user: DBUser = Depends(get_db_user)
    ) -> DBUser:
        if db_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {', '.join(allowed_roles)}. Your role: {db_user.role}"
            )
        return db_user

    return role_checker


def require_admin(request: Request, db_user: DBUser = Depends(get_db_user)) -> DBUser:
    """
    Dependency to require admin or super_admin role.

    Args:
        request: FastAPI request
        db_user: Database user from get_db_user

    Returns:
        DBUser if user is admin or super_admin

    Raises:
        HTTPException 403: If user is not admin/super_admin

    Usage:
        @router.post("/invitations")
        async def send_invitation(
            body: InvitationRequest,
            admin_user: DBUser = Depends(require_admin)
        ):
            # Only admins can send invitations
            pass
    """
    if db_user.role not in ['admin', 'super_admin']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Admin access required. Your role: {db_user.role}"
        )
    return db_user


def require_super_admin(request: Request, db_user: DBUser = Depends(get_db_user)) -> DBUser:
    """
    Dependency to require super_admin role only.

    Args:
        request: FastAPI request
        db_user: Database user from get_db_user

    Returns:
        DBUser if user is super_admin

    Raises:
        HTTPException 403: If user is not super_admin

    Usage:
        @router.patch("/users/{id}/role")
        async def change_user_role(
            user_id: UUID,
            body: UpdateRoleRequest,
            super_admin: DBUser = Depends(require_super_admin)
        ):
            # Only super admins can change roles
            pass
    """
    if db_user.role != 'super_admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Super Admin access required. Your role: {db_user.role}"
        )
    return db_user


def check_repository_access(repository_id: UUID, action: str) -> Callable:
    """
    Dependency factory to check repository-level access.

    Verifies user has access to specific repository and can perform action.

    Args:
        repository_id: Repository UUID to check access for
        action: Action being performed (view, scan, manage_findings, etc.)

    Returns:
        Dependency function that checks access

    Raises:
        HTTPException 403: If user lacks repository access or permission

    Usage:
        @router.post("/scans")
        async def trigger_scan(
            body: ScanRequest,
            user: DBUser = Depends(get_db_user),
            has_access: bool = Depends(check_repository_access(body.repository_id, 'run_scan'))
        ):
            # User can only trigger scan if they have access
            pass

    Permissions Matrix:
        - super_admin, admin: All actions on all repositories
        - manager: manage_findings, run_scan, view
        - analyst: submit_jira, mark_exception, delete_finding, run_scan, view
        - developer: run_scan, view_details, view
        - user: view only
    """
    def access_checker(
        request: Request,
        db_user: DBUser = Depends(get_db_user)
    ) -> bool:
        # Super Admin and Admin - full access to all repositories
        if db_user.role in ['super_admin', 'admin']:
            return True

        # Check if user has access to this repository
        db = SessionLocal()
        try:
            access = db.query(UserRepositoryAccess).filter(
                UserRepositoryAccess.user_id == db_user.id,
                UserRepositoryAccess.repository_id == repository_id
            ).first()

            if not access:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"No access to repository {repository_id}"
                )

            # Check access type (UI vs API)
            request_path = request.url.path
            if request_path.startswith('/api/'):
                # API request
                if db_user.access_type == 'ui_only':
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="API access not permitted. Your access type: ui_only"
                    )
            else:
                # UI request
                if db_user.access_type == 'api_only':
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="UI access not permitted. Your access type: api_only"
                    )

            # Check role-based action permissions
            if not can_perform_action(db_user.role, action):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions for action '{action}'. Your role: {db_user.role}"
                )

            return True

        finally:
            db.close()

    return access_checker


def can_perform_action(role: str, action: str) -> bool:
    """
    Check if role can perform action.

    Permission matrix:
        - super_admin, admin: All actions
        - manager: manage_findings, run_scan, view, view_details
        - analyst: submit_jira, mark_exception, delete_finding, run_scan, view, view_details
        - developer: run_scan, view_details, view
        - user: view only

    Args:
        role: User role (super_admin, admin, manager, analyst, developer, user)
        action: Action to check (view, run_scan, delete_finding, etc.)

    Returns:
        True if role can perform action, False otherwise

    Usage:
        if can_perform_action(user.role, 'delete_finding'):
            # User can delete findings
            pass
    """
    permissions = {
        'super_admin': ['*'],  # Wildcard: all actions
        'admin': ['*'],  # Wildcard: all actions
        'manager': ['manage_findings', 'run_scan', 'view', 'view_details'],
        'analyst': ['submit_jira', 'mark_exception', 'delete_finding', 'run_scan', 'view', 'view_details'],
        'developer': ['run_scan', 'view_details', 'view'],
        'user': ['view']
    }

    role_perms = permissions.get(role, [])
    return '*' in role_perms or action in role_perms
