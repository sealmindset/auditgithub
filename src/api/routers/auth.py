"""
Authentication router for OIDC/OAuth2 login flows and token management.

Implements:
- /auth/providers - List available OIDC providers
- /auth/login/{provider} - Initiate OIDC login with PKCE
- /auth/callback/{provider} - Handle OAuth callback and token exchange
- /auth/accept-invite - Accept invitation and redirect to OIDC login
- /auth/logout - Clear session
- /auth/me - Get current user info
- /auth/refresh - Refresh access and refresh tokens
- /auth/revoke - Revoke current user's token
"""

import os
from fastapi import APIRouter, Request, HTTPException, Depends, status, Form
from starlette.responses import RedirectResponse
from pydantic import BaseModel, Field
from src.auth.providers import oauth
from src.auth.config import settings
from src.auth.tokens import rotate_refresh_token, revoke_token, generate_access_token
from src.auth.dependencies import get_current_user
from src.auth.models import User
from src.auth.break_glass import verify_break_glass_password
from src.auth.invitations import accept_invitation, get_invitation_by_token
from src.api.database import SessionLocal
from src.api.models import AuthAuditLog
from loguru import logger
from datetime import datetime

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.get("/providers", summary="List available OIDC providers", responses={200: {"description": "List of available providers"}})
async def list_providers():
    """
    Return list of available authentication providers.

    Used by the frontend login page to display provider options dynamically.
    """
    return {
        "providers": [
            {"name": p["name"], "display_name": p["name"].replace("-", " ").title()}
            for p in settings.oidc_providers
        ]
    }


@router.get("/login/{provider}", summary="Initiate OIDC login", responses={400: {"description": "Invalid provider"}})
async def login(provider: str, request: Request):
    """
    Initiate OIDC login flow with specified provider.

    Supports any registered OIDC provider (mock-oidc, entra, okta).
    Passes login_hint parameter when provided (used by mock-oidc for automated testing).

    Args:
        provider: Identity provider name (must be registered)
        request: FastAPI request object

    Returns:
        RedirectResponse to identity provider's authorization endpoint

    Raises:
        HTTPException 400 if provider is not registered

    Security: Forces PKCE with S256 algorithm to prevent authorization code
    interception attacks.
    """
    # Validate provider against dynamic whitelist
    if provider not in settings.registered_provider_names:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid provider '{provider}'. Available: {settings.registered_provider_names}"
        )

    # Build callback URL using APP_URL so it routes through the frontend proxy
    app_url = os.environ.get('APP_URL', '').rstrip('/')
    if app_url:
        redirect_uri = f"{app_url}/api/proxy/auth/callback/{provider}"
    else:
        redirect_uri = str(request.url_for('callback', provider=provider))

    # Build extra authorization params
    extra_params = {}
    if login_hint := request.query_params.get("login_hint"):
        extra_params["login_hint"] = login_hint

    # Initiate OAuth flow with forced PKCE (S256 = SHA-256)
    provider_client = getattr(oauth, provider)
    return await provider_client.authorize_redirect(
        request,
        redirect_uri,
        code_challenge_method='S256',
        **extra_params
    )


@router.get("/accept-invite", summary="Accept invitation and redirect to OIDC login", responses={400: {"description": "Invalid or expired invitation"}})
async def accept_invite(token: str, request: Request, provider: str = ""):
    """
    First step of invitation acceptance — stores invite token in session
    and redirects to OIDC login.

    The callback handler will check for this token and create the user
    with the role specified in the invitation.

    Args:
        token: Invitation token from email link
        provider: Optional OIDC provider name (defaults to first available)
        request: FastAPI request object

    Returns:
        RedirectResponse to OIDC login endpoint
    """
    db = SessionLocal()
    try:
        invitation = get_invitation_by_token(db, token)
        if not invitation or invitation.status != 'pending':
            raise HTTPException(status_code=400, detail="Invalid or expired invitation")

        # Store invite token in session for callback to find
        request.session['invite_token'] = token

        # Determine which provider to use
        if not provider:
            provider = settings.registered_provider_names[0] if settings.registered_provider_names else "entra"

        # Build login URL, with login_hint for mock-oidc to auto-select user
        login_url = f"/auth/login/{provider}"
        if provider == "mock-oidc":
            login_url += f"?login_hint={invitation.email}"

        return RedirectResponse(url=login_url, status_code=303)
    finally:
        db.close()


@router.post("/break-glass/login", summary="Break glass emergency login", responses={401: {"description": "Invalid credentials"}, 403: {"description": "Email not authorized for break glass"}})
async def break_glass_login(
    email: str = Form(...),
    password: str = Form(...),
    request: Request = None
):
    """
    Break glass login with local password.

    Emergency authentication for ravance@gmail.com when OIDC providers are unavailable.
    All break glass access is prominently logged and audited.

    Args:
        email: User email (must be ravance@gmail.com)
        password: Local password
        request: FastAPI request object

    Returns:
        RedirectResponse to homepage (/) with 303 See Other status

    Raises:
        HTTPException 403: If email is not ravance@gmail.com
        HTTPException 401: If credentials are invalid
    """
    # Only allow ravance@gmail.com
    if email != "ravance@gmail.com":
        # Audit failed attempt
        db = SessionLocal()
        try:
            audit_log = AuthAuditLog(
                email=email,
                event_type='login',
                auth_method='break_glass',
                success=False,
                failure_reason='Break glass access denied (not authorized email)',
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get('user-agent'),
                is_break_glass=True
            )
            db.add(audit_log)
            db.commit()
        finally:
            db.close()

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Break glass access denied"
        )

    # Verify password
    db = SessionLocal()
    try:
        user = verify_break_glass_password(db, email, password)

        if not user:
            # Audit failed attempt
            audit_log = AuthAuditLog(
                email=email,
                event_type='login',
                auth_method='break_glass',
                success=False,
                failure_reason='Invalid credentials',
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get('user-agent'),
                is_break_glass=True
            )
            db.add(audit_log)
            db.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # Store in session with break glass flag
        request.session['user'] = {
            'provider': 'local',
            'email': user.email,
            'name': user.full_name,
            'sub': str(user.id),
            'role': user.role,
            'access_type': user.access_type,
            'is_break_glass': True
        }

        # Update last login
        user.last_login_at = datetime.utcnow()
        db.commit()

        # Audit successful login
        audit_log = AuthAuditLog(
            user_id=user.id,
            email=user.email,
            event_type='login',
            auth_method='break_glass',
            success=True,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get('user-agent'),
            is_break_glass=True
        )
        db.add(audit_log)
        db.commit()

        logger.warning(
            f"BREAK GLASS LOGIN: {user.email} from {request.client.host if request.client else 'unknown'}"
        )

        return RedirectResponse(url='/', status_code=303)

    finally:
        db.close()


@router.get("/callback/{provider}", name="callback", summary="Handle OAuth callback", responses={400: {"description": "Invalid provider or email not verified"}, 401: {"description": "Authentication failed"}, 403: {"description": "No invitation found"}})
async def callback(provider: str, request: Request):
    """
    Handle OAuth callback and exchange authorization code for tokens.

    Provider-agnostic: works with mock-oidc, Entra ID, Okta, or any registered provider.

    Enhanced to support RBAC invitation system:
    - Checks if user exists in database
    - If not, checks for pending invitation
    - Creates user account if invitation valid (with assigned role)
    - Stores role and access_type in session

    Args:
        provider: Identity provider name (must be registered)
        request: FastAPI request object

    Returns:
        RedirectResponse to homepage (/) with 303 See Other status

    Raises:
        HTTPException 400 if provider is invalid or email not verified
        HTTPException 401 if authentication fails
        HTTPException 403 if no invitation found

    Security:
    - Validates email_verified claim before trusting email
    - Stores session data with RBAC fields (role, access_type)
    - Uses 303 redirect to prevent browser re-POST on refresh
    - Requires invitation for new users
    """
    # Validate provider against dynamic whitelist
    if provider not in settings.registered_provider_names:
        raise HTTPException(status_code=400, detail=f"Invalid provider '{provider}'")

    try:
        # Exchange authorization code for tokens
        # Authlib automatically validates state parameter and PKCE code_verifier
        provider_client = getattr(oauth, provider)
        token = await provider_client.authorize_access_token(request)

        # Get user info from token response or parse ID token
        user_info = token.get('userinfo')
        if not user_info:
            # Parse ID token if userinfo not included in response
            user_info = provider_client.parse_id_token(
                token,
                nonce=request.session.get('nonce')
            )

        # Validate email_verified claim before trusting email
        # Mock OIDC always sets email_verified=true; skip check if not present
        if user_info.get('email') and user_info.get('email_verified') is False:
            raise HTTPException(
                status_code=400,
                detail="Email not verified by identity provider"
            )

        # Check if user exists in database
        db = SessionLocal()
        try:
            from src.api.models import User as DBUser

            user = db.query(DBUser).filter(DBUser.email == user_info['email']).first()

            if not user:
                # User doesn't exist - check for invitation
                invite_token = request.session.get('invite_token')

                if not invite_token:
                    # No invitation - reject
                    logger.warning(f"Login rejected: no invitation for {user_info['email']}")
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="No invitation found. Please contact administrator."
                    )

                # Accept invitation and create user (provider-agnostic)
                try:
                    user = accept_invitation(db, invite_token, user_info, provider=provider)

                    # Clear invitation token from session
                    request.session.pop('invite_token', None)

                    logger.info(f"User created via invitation: {user.email} (provider={provider})")

                except ValueError as e:
                    logger.warning(f"Invitation acceptance failed: {e}")
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=str(e)
                    )
            else:
                # Existing user — update OIDC fields if not set
                if not user.oidc_subject and user_info.get('sub'):
                    user.oidc_subject = user_info['sub']
                    user.oidc_issuer = user_info.get('iss', '')

            # Update last login
            user.last_login_at = datetime.utcnow()
            db.commit()

            # Audit log successful login (provider-agnostic)
            audit_log = AuthAuditLog(
                user_id=user.id,
                email=user.email,
                event_type='login',
                auth_method=provider,
                success=True,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get('user-agent'),
                is_break_glass=False
            )
            db.add(audit_log)
            db.commit()

            # Store session data with RBAC fields
            request.session['user'] = {
                'provider': provider,
                'email': user.email,
                'name': user.full_name,
                'sub': user_info['sub'],
                'role': user.role,
                'access_type': user.access_type,
                'user_id': str(user.id),
                'is_break_glass': False
            }

            # Store access token for API calls
            request.session['access_token'] = token.get('access_token', '')

            logger.info(f"Login successful: {user.email} (role={user.role}, provider={provider})")

            # Redirect to frontend homepage with 303 See Other (POST-redirect-GET pattern)
            app_url = os.environ.get('APP_URL', 'http://localhost:3000')
            return RedirectResponse(url=app_url, status_code=303)

        finally:
            db.close()

    except HTTPException:
        # Re-raise HTTP exceptions
        raise

    except Exception as e:
        logger.bind(router="auth", endpoint="callback").exception(f"Authentication failed for provider {provider}: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail=f"Authentication failed: {str(e)}"
        )


@router.get("/logout", summary="Logout and clear session", responses={401: {"description": "Not authenticated"}})
async def logout(request: Request):
    """
    Clear user session (client-side logout).

    Args:
        request: FastAPI request object

    Returns:
        RedirectResponse to homepage (/) with 303 See Other status
    """
    # Clear all session data including tokens
    request.session.clear()

    # Redirect to homepage with 303 See Other
    return RedirectResponse(url='/', status_code=303)


@router.get("/me", summary="Get current user info", responses={401: {"description": "Not authenticated"}})
async def get_current_user_info(request: Request):
    """
    Get current authenticated user information.

    Args:
        request: FastAPI request object

    Returns:
        dict: User information (email, name, sub, provider, role, access_type)

    Raises:
        HTTPException 401 if user is not authenticated
    """
    # Get user from session
    user = request.session.get('user')

    # Return 401 if not authenticated
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Return user info (email, name, sub, provider)
    return user


# ============================================================================
# Token Management Endpoints (Phase 5)
# ============================================================================


class RefreshRequest(BaseModel):
    """Request body for token refresh."""
    refresh_token: str = Field(..., description="Current refresh token to rotate")


class RefreshResponse(BaseModel):
    """Response body for token refresh."""
    refresh_token: str = Field(..., description="New refresh token (old one is invalidated)")
    access_token: str = Field(..., description="New short-lived access token")
    token_type: str = Field("bearer", description="Token type, always 'bearer'")


@router.post("/refresh", response_model=RefreshResponse, summary="Refresh access token", responses={401: {"description": "Invalid, expired, or already-used refresh token"}})
async def refresh_tokens(request: RefreshRequest):
    """
    Refresh access and refresh tokens.

    Validates the provided refresh token, rotates it (one-time use),
    and returns new access and refresh tokens.

    Security:
    - Rotates refresh token on every use (one-time use)
    - Validates old token before issuing new one
    - Prevents token reuse attacks
    - Checks blacklist for revoked tokens
    """
    try:
        # Rotate refresh token (validates and generates new one)
        new_refresh_token, user_claims = rotate_refresh_token(request.refresh_token)

        # Generate new access token
        access_token = generate_access_token(
            user_sub=user_claims["sub"],
            tenant_id=user_claims.get("tenant_id", ""),
            email=user_claims.get("email", ""),
            name=user_claims.get("name", "")
        )

        logger.bind(router="auth", endpoint="refresh").info(f"Tokens refreshed for user {user_claims['sub']}")

        return RefreshResponse(
            refresh_token=new_refresh_token,
            access_token=access_token
        )

    except HTTPException:
        # Re-raise HTTPExceptions from rotate_refresh_token
        raise
    except Exception as e:
        logger.bind(router="auth", endpoint="refresh").exception(f"Token refresh failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token refresh failed: {str(e)}"
        )


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke current access token", responses={400: {"description": "No token JTI in request"}, 401: {"description": "Not authenticated"}})
async def revoke_current_token(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """
    Revoke the current user's access token.

    Adds the token's JTI to the blacklist, preventing further use.

    Security:
    - Instant revocation across all API instances (Redis-backed)
    - Blacklist entry expires at token's natural expiry (auto-cleanup)
    - Requires authentication (only user can revoke their own token)
    """
    try:
        # Extract JTI from request state (set by get_current_user_from_token)
        if not hasattr(request.state, 'token_jti'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No token JTI found in request (session-based auth cannot be revoked via this endpoint)"
            )

        jti = request.state.token_jti
        exp = request.state.token_exp

        # Add to blacklist
        revoke_token(jti, exp)

        logger.bind(router="auth", endpoint="revoke").info(f"Token revoked for user {current_user.sub} (jti: {jti})")

        return None  # 204 No Content

    except HTTPException:
        raise
    except Exception as e:
        logger.bind(router="auth", endpoint="revoke").exception(f"Token revocation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke token: {str(e)}"
        )
