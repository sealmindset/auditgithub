"""
Authentication router for OIDC/OAuth2 login flows and token management.

Implements:
- /auth/login/{provider} - Initiate OIDC login with PKCE
- /auth/callback/{provider} - Handle OAuth callback and token exchange
- /auth/logout - Clear session
- /auth/me - Get current user info
- /auth/refresh - Refresh access and refresh tokens
- /auth/revoke - Revoke current user's token
"""

from fastapi import APIRouter, Request, HTTPException, Depends, status
from starlette.responses import RedirectResponse
from pydantic import BaseModel
from src.auth.providers import oauth
from src.auth.tokens import rotate_refresh_token, revoke_token, generate_access_token
from src.auth.dependencies import get_current_user
from src.auth.models import User
from loguru import logger

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.get("/login/{provider}")
async def login(provider: str, request: Request):
    """
    Initiate OIDC login flow with specified provider.

    Args:
        provider: Identity provider name ("entra" or "okta")
        request: FastAPI request object

    Returns:
        RedirectResponse to identity provider's authorization endpoint

    Raises:
        HTTPException 400 if provider is not in whitelist

    Security: Forces PKCE with S256 algorithm to prevent authorization code
    interception attacks (see RESEARCH.md "Common Pitfalls #4").
    """
    # Validate provider against whitelist to prevent SSRF attacks
    if provider not in ["entra", "okta"]:
        raise HTTPException(status_code=400, detail="Invalid provider")

    # Get callback URL for this provider
    redirect_uri = str(request.url_for('callback', provider=provider))

    # Initiate OAuth flow with forced PKCE (S256 = SHA-256)
    # Authlib enables PKCE automatically, but explicit is better for security-critical code
    provider_client = getattr(oauth, provider)
    return await provider_client.authorize_redirect(
        request,
        redirect_uri,
        code_challenge_method='S256'
    )


@router.get("/callback/{provider}", name="callback")
async def callback(provider: str, request: Request):
    """
    Handle OAuth callback and exchange authorization code for tokens.

    Args:
        provider: Identity provider name ("entra" or "okta")
        request: FastAPI request object

    Returns:
        RedirectResponse to homepage (/) with 303 See Other status

    Raises:
        HTTPException 400 if provider is invalid or email not verified
        HTTPException 401 if authentication fails

    Security:
    - Validates email_verified claim before trusting email (RESEARCH.md "Pitfalls #3")
    - Stores minimal session data (user info + access_token only)
    - Uses 303 redirect to prevent browser re-POST on refresh
    - Does not store refresh_token (session-based auth, not needed yet)
    """
    # Validate provider against whitelist
    if provider not in ["entra", "okta"]:
        raise HTTPException(status_code=400, detail="Invalid provider")

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
        # Not all providers verify emails by default (security risk)
        if user_info.get('email') and not user_info.get('email_verified'):
            raise HTTPException(
                status_code=400,
                detail="Email not verified"
            )

        # Store minimal session data for authorization
        request.session['user'] = {
            'provider': provider,
            'email': user_info['email'],
            'name': user_info.get('name', ''),
            'sub': user_info['sub']  # Subject claim (unique user ID)
        }

        # Store access token for API calls
        request.session['access_token'] = token['access_token']

        # Redirect to homepage with 303 See Other (POST-redirect-GET pattern)
        return RedirectResponse(url='/', status_code=303)

    except Exception as e:
        logger.bind(router="auth", endpoint="callback").exception(f"Authentication failed for provider {provider}: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail=f"Authentication failed: {str(e)}"
        )


@router.get("/logout")
async def logout(request: Request):
    """
    Clear user session (client-side logout).

    Args:
        request: FastAPI request object

    Returns:
        RedirectResponse to homepage (/) with 303 See Other status

    Note: This is client-side logout only. It clears the session but does not
    perform IdP logout (sign out from Entra ID/Okta). Full SSO logout with
    token revocation will be implemented in Phase 5.
    """
    # Clear all session data including tokens
    request.session.clear()

    # Redirect to homepage with 303 See Other
    return RedirectResponse(url='/', status_code=303)


@router.get("/me")
async def get_current_user_info(request: Request):
    """
    Get current authenticated user information.

    Args:
        request: FastAPI request object

    Returns:
        dict: User information (email, name, sub, provider)

    Raises:
        HTTPException 401 if user is not authenticated

    Note: This endpoint uses session-based authentication. For JWT-based
    authentication with Bearer tokens, see Phase 2 Plan 3 (JWT Validation).
    Does not return access_token (tokens stay in backend session only).
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
    refresh_token: str


class RefreshResponse(BaseModel):
    """Response body for token refresh."""
    refresh_token: str
    access_token: str
    token_type: str = "bearer"


@router.post("/refresh", response_model=RefreshResponse)
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

    Args:
        request: RefreshRequest with refresh_token

    Returns:
        RefreshResponse with new refresh_token and access_token

    Raises:
        HTTPException 401: If refresh token is invalid, expired, blacklisted, or already used
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


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_current_token(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """
    Revoke the current user's access token.

    Adds the token's JTI to the blacklist, preventing further use.
    Useful for logout or security incidents.

    Security:
    - Instant revocation across all API instances (Redis-backed)
    - Blacklist entry expires at token's natural expiry (auto-cleanup)
    - Requires authentication (only user can revoke their own token)

    Args:
        request: FastAPI Request object (contains token metadata)
        current_user: Current authenticated user (from dependency)

    Returns:
        204 No Content on success

    Raises:
        HTTPException 400: If token JTI not found in request
        HTTPException 500: If revocation fails
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
