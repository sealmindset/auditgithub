"""
Device Flow Authentication Router

Implements RFC 8628 OAuth 2.0 Device Authorization Grant Flow endpoints.
Enables CLI/device authentication via browser-based OIDC login.

Endpoints:
- POST /auth/device/code - Initiate device flow
- POST /auth/device/token - Poll for token
- GET /auth/device/verify - Verification page (enter code)
- POST /auth/device/verify-code - Validate code and start OIDC
- GET /auth/device/approve-ui - Approval dialog (post-OIDC)
- POST /auth/device/approve - Handle approval/denial
- GET /auth/device/authorizations - List user's devices
- DELETE /auth/device/authorizations/{device_id} - Revoke device
- PATCH /auth/device/authorizations/{device_id} - Rename device
"""
from fastapi import APIRouter, Request, HTTPException, Depends, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from loguru import logger

from src.api.database import get_db
from src.auth.dependencies import get_current_user
from src.auth.models import User
from src.auth import device_flow
from src.api.models import DeviceAuthorization, DeviceFlowRequest
from src.auth.tokens import revoke_token


router = APIRouter(prefix="/auth/device", tags=["device-flow"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class DeviceCodeRequest(BaseModel):
    """Request body for initiating the device authorization flow."""
    client_id: str = Field(..., description="Application client identifier", examples=["auditgh-cli"])
    client_name: str = Field(..., description="Human-readable application name", examples=["AuditGH CLI"])
    scopes: Optional[List[str]] = Field([], description="Requested OAuth scopes")


class DeviceCodeResponse(BaseModel):
    """Codes and URLs returned to the device for user verification."""
    device_code: str = Field(..., description="Long device code for token polling (128 chars)")
    user_code: str = Field(..., description="Short user code for manual entry (ABCD-1234 format)")
    verification_uri: str = Field(..., description="URL where the user enters the code")
    verification_uri_complete: str = Field(..., description="URL with code pre-filled")
    expires_in: int = Field(..., description="Code validity in seconds (default 600)")
    interval: int = Field(..., description="Recommended polling interval in seconds")


class DeviceTokenRequest(BaseModel):
    """Request body for polling the device token endpoint."""
    grant_type: str = Field(..., description="Must be 'urn:ietf:params:oauth:grant-type:device_code'")
    device_code: str = Field(..., description="Device code from POST /auth/device/code")
    client_id: str = Field(..., description="Application client identifier")


class DeviceTokenResponse(BaseModel):
    """Token response returned after user approval."""
    access_token: str = Field(..., description="Short-lived JWT access token")
    refresh_token: str = Field(..., description="Long-lived refresh token for token rotation")
    token_type: str = Field("bearer", description="Token type, always 'bearer'")
    expires_in: int = Field(..., description="Access token lifetime in seconds")


class DeviceAuthorizationResponse(BaseModel):
    """Device authorization record for the management UI."""
    id: UUID = Field(..., description="Device authorization UUID")
    device_name: str = Field(..., description="User-assigned device name")
    client_name: str = Field(..., description="Application that requested access")
    created_at: datetime = Field(..., description="When the device was authorized")
    last_used_at: datetime = Field(..., description="Last API call using this device's token")
    is_active: bool = Field(..., description="Whether the device authorization is active")
    provider: str = Field(..., description="Identity provider used for authorization")
    user_agent: Optional[str] = Field(None, description="User-Agent from the authorizing browser")
    token_refresh_count: int = Field(..., description="Number of token refreshes performed")


class RenameDeviceRequest(BaseModel):
    """Request body for renaming a device."""
    device_name: str = Field(..., description="New device name", examples=["My Laptop"])


# =============================================================================
# DEVICE FLOW INITIATION
# =============================================================================

@router.post("/code", response_model=DeviceCodeResponse, summary="Initiate device authorization flow", responses={500: {"description": "No organization configured"}})
async def request_device_code(
    request: Request,
    body: DeviceCodeRequest,
    db: Session = Depends(get_db)
):
    """
    Initiate device flow - returns codes and verification URL.

    Creates a device flow request and returns:
    - device_code: Long code for token polling (128 chars)
    - user_code: Short code for user entry (ABCD-1234 format)
    - verification_uri: URL where user enters code
    - verification_uri_complete: Direct URL with code pre-filled
    - expires_in: Code validity period (600 seconds = 10 minutes)
    - interval: Recommended polling interval (5 seconds)

    Security:
    - Rate limited to 5 requests/minute per IP (TODO: implement rate limiting)
    - Requires valid organization context
    - Codes expire after 10 minutes

    Args:
        request: FastAPI request object
        body: DeviceCodeRequest with client_id, client_name, scopes
        db: Database session

    Returns:
        DeviceCodeResponse with codes and verification URLs
    """
    # TODO: Get organization_id from authenticated context or default org
    # For now, using a placeholder - should be resolved from session/token
    from src.api.models import Organization
    org = db.query(Organization).first()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No organization found. Please configure organization first."
        )

    # Create device flow request
    flow_request = device_flow.create_device_flow_request(
        db=db,
        organization_id=org.id,
        client_id=body.client_id,
        client_name=body.client_name,
        scopes=body.scopes
    )

    # Build verification URLs
    base_url = str(request.base_url).rstrip('/')
    verification_uri = f"{base_url}/auth/device/verify"
    verification_uri_complete = f"{verification_uri}?user_code={flow_request.user_code}"

    logger.bind(router="device_flow", endpoint="code").info(
        f"Device code requested: client={body.client_name}, user_code={flow_request.user_code}"
    )

    return DeviceCodeResponse(
        device_code=flow_request.device_code,
        user_code=flow_request.user_code,
        verification_uri=verification_uri,
        verification_uri_complete=verification_uri_complete,
        expires_in=600,  # 10 minutes
        interval=5  # Poll every 5 seconds
    )


# =============================================================================
# TOKEN POLLING
# =============================================================================

@router.post("/token", response_model=DeviceTokenResponse, summary="Poll for device token", responses={400: {"description": "authorization_pending, slow_down, access_denied, or expired_token (RFC 8628)"}})
async def poll_device_token(
    body: DeviceTokenRequest,
    db: Session = Depends(get_db)
):
    """
    Poll for token after user approval.

    Clients poll this endpoint every 5 seconds until approved.

    Args:
        body: DeviceTokenRequest with grant_type, device_code, client_id

    Returns:
        DeviceTokenResponse: {access_token, refresh_token, token_type, expires_in}

    Error Responses (RFC 8628):
        - 400 "authorization_pending": User hasn't approved yet (keep polling)
        - 400 "slow_down": Polling too fast, increase interval by 5 seconds
        - 400 "access_denied": User denied authorization
        - 400 "expired_token": Device code expired (10 minutes)
    """
    # Validate grant_type
    if body.grant_type != "urn:ietf:params:oauth:grant-type:device_code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant"
        )

    # Update polling stats
    device_flow.update_device_poll(db, body.device_code)

    try:
        # Attempt to issue tokens (handles all status checks)
        tokens = device_flow.issue_device_tokens(
            db=db,
            device_code=body.device_code,
            device_name=f"{body.client_id} Device",  # Default name
            user_agent=None,  # Could extract from request headers
            ip_address=None  # Could extract from request.client.host
        )

        logger.bind(router="device_flow", endpoint="token").info(
            f"Device tokens issued: client={body.client_id}"
        )

        return DeviceTokenResponse(**tokens)

    except HTTPException as e:
        # Re-raise RFC 8628 error codes
        if e.detail in ["authorization_pending", "expired_token", "access_denied"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=e.detail
            )
        raise


# =============================================================================
# USER VERIFICATION FLOW
# =============================================================================

@router.get("/verify", response_class=HTMLResponse, summary="Device verification page (HTML)", responses={200: {"description": "HTML form for entering device code"}})
async def device_verification_page(
    user_code: Optional[str] = None
):
    """
    HTML page for entering user code.

    Displays a form where users enter their 8-character device code.
    Pre-fills code if provided in URL query parameter.

    Args:
        user_code: Optional code to pre-fill (from verification_uri_complete)

    Returns:
        HTMLResponse: Verification form page
    """
    pre_filled_code = user_code if user_code else ""

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Device Authorization - AuditGitHub</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-50 flex items-center justify-center min-h-screen">
        <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full">
            <div class="text-center mb-6">
                <h1 class="text-3xl font-bold text-gray-900 mb-2">Device Authorization</h1>
                <p class="text-gray-600">Enter the code displayed on your device</p>
            </div>

            <form method="POST" action="/auth/device/verify-code" class="space-y-4">
                <div>
                    <label for="user_code" class="block text-sm font-medium text-gray-700 mb-2">
                        Authorization Code
                    </label>
                    <input
                        type="text"
                        id="user_code"
                        name="user_code"
                        value="{pre_filled_code}"
                        placeholder="ABCD-1234"
                        pattern="[A-Z0-9]{{4}}-[A-Z0-9]{{4}}"
                        class="w-full px-4 py-3 text-center text-2xl font-mono uppercase border-2 border-gray-300 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 outline-none"
                        required
                        autocomplete="off"
                        spellcheck="false"
                    >
                    <p class="mt-2 text-sm text-gray-500">Format: XXXX-XXXX (8 characters)</p>
                </div>

                <button
                    type="submit"
                    class="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition duration-200"
                >
                    Continue
                </button>
            </form>

            <div class="mt-6 pt-6 border-t border-gray-200">
                <p class="text-sm text-gray-500 text-center">
                    After entering the code, you'll be redirected to sign in with your organization's identity provider.
                </p>
            </div>
        </div>

        <script>
            // Auto-format input: add dash after 4 characters
            const input = document.getElementById('user_code');
            input.addEventListener('input', (e) => {{
                let value = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
                if (value.length > 4) {{
                    value = value.slice(0, 4) + '-' + value.slice(4, 8);
                }}
                e.target.value = value;
            }});
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content)


@router.post("/verify-code", summary="Validate user code and redirect to OIDC", responses={404: {"description": "Invalid code"}, 400: {"description": "Expired or already-processed code"}})
async def verify_user_code(
    request: Request,
    user_code: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Validate user code and redirect to OIDC login.

    Checks if user_code exists and is valid (not expired).
    Stores user_code in session for post-auth approval.
    Redirects to /auth/login/entra (or okta based on org config).

    Args:
        request: FastAPI request object
        user_code: 8-character user code from form
        db: Database session

    Returns:
        RedirectResponse to /auth/login/{provider}

    Raises:
        HTTPException 404: Invalid code
        HTTPException 400: Expired code
    """
    # Normalize code (uppercase, add dash if missing)
    user_code = user_code.upper().strip()
    if '-' not in user_code and len(user_code) == 8:
        user_code = f"{user_code[:4]}-{user_code[4:]}"

    # Validate code exists
    flow_request = db.query(DeviceFlowRequest).filter(
        DeviceFlowRequest.user_code == user_code
    ).first()

    if not flow_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid code. Please check the code and try again."
        )

    # Check expiration
    if flow_request.expires_at < datetime.utcnow():
        flow_request.status = 'expired'
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code has expired. Please restart the authentication process on your device."
        )

    # Check status
    if flow_request.status != 'pending':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"This code has already been {flow_request.status}."
        )

    # Store user_code in session for post-auth approval
    request.session['device_flow_user_code'] = user_code

    # TODO: Determine provider based on organization config
    # For now, default to entra
    provider = 'entra'

    logger.bind(router="device_flow", endpoint="verify-code").info(
        f"User code validated, redirecting to OIDC: {user_code}"
    )

    # Redirect to OIDC login
    return RedirectResponse(url=f'/auth/login/{provider}', status_code=303)


@router.get("/approve-ui", response_class=HTMLResponse, summary="Show device approval dialog (HTML)", responses={400: {"description": "No device flow in progress"}, 401: {"description": "Not authenticated"}})
async def show_approval_page(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Show approval dialog after OIDC authentication.

    Retrieves user_code from session (set by verify-code).
    Displays device info, requested scopes, and approve/deny buttons.

    Args:
        request: FastAPI request object
        current_user: Authenticated user from session
        db: Database session

    Returns:
        HTMLResponse: Approval dialog page

    Raises:
        HTTPException 400: If no device flow in progress
    """
    # Get user_code from session
    user_code = request.session.get('device_flow_user_code')
    if not user_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No device authorization in progress"
        )

    # Get flow request
    flow_request = db.query(DeviceFlowRequest).filter(
        DeviceFlowRequest.user_code == user_code
    ).first()

    if not flow_request or flow_request.status != 'pending':
        # Clear session
        request.session.pop('device_flow_user_code', None)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device authorization request not found or already processed"
        )

    # Render approval dialog
    scopes_html = "".join([f"<li class='text-sm text-gray-700'>{scope}</li>" for scope in flow_request.scopes]) if flow_request.scopes else "<li class='text-sm text-gray-500'>No specific scopes requested</li>"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authorize Device - AuditGitHub</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-50 flex items-center justify-center min-h-screen">
        <div class="bg-white p-8 rounded-lg shadow-lg max-w-lg w-full">
            <div class="text-center mb-6">
                <h1 class="text-2xl font-bold text-gray-900 mb-2">Authorize Device</h1>
                <p class="text-gray-600">Review the device requesting access</p>
            </div>

            <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
                <p class="text-sm text-gray-600 mb-1">Signed in as</p>
                <p class="font-semibold text-gray-900">{current_user.email}</p>
            </div>

            <div class="border border-gray-200 rounded-lg p-4 mb-6 space-y-3">
                <div>
                    <p class="text-sm text-gray-600">Application</p>
                    <p class="font-semibold text-gray-900">{flow_request.client_name}</p>
                </div>
                <div>
                    <p class="text-sm text-gray-600">Authorization Code</p>
                    <p class="font-mono text-lg text-gray-900">{flow_request.user_code}</p>
                </div>
                <div>
                    <p class="text-sm text-gray-600">Client ID</p>
                    <p class="text-sm text-gray-700">{flow_request.client_id}</p>
                </div>
            </div>

            <div class="mb-6">
                <h2 class="font-semibold text-gray-900 mb-2">Requested Permissions</h2>
                <ul class="list-disc list-inside space-y-1">
                    {scopes_html}
                </ul>
            </div>

            <form method="POST" action="/auth/device/approve" class="space-y-3">
                <button
                    type="submit"
                    name="action"
                    value="approve"
                    class="w-full bg-green-600 text-white py-3 rounded-lg font-semibold hover:bg-green-700 transition duration-200"
                >
                    Approve & Continue
                </button>
                <button
                    type="submit"
                    name="action"
                    value="deny"
                    class="w-full bg-red-600 text-white py-3 rounded-lg font-semibold hover:bg-red-700 transition duration-200"
                >
                    Deny Access
                </button>
            </form>

            <div class="mt-6 pt-6 border-t border-gray-200">
                <p class="text-xs text-gray-500 text-center">
                    By approving, you grant this device access to your AuditGitHub account.
                    You can revoke access anytime from your account settings.
                </p>
            </div>
        </div>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content)


@router.post("/approve", summary="Approve or deny device authorization", responses={400: {"description": "No device flow in progress or invalid action"}, 401: {"description": "Not authenticated"}})
async def approve_device(
    request: Request,
    action: str = Form(...),  # "approve" or "deny"
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Handle device approval or denial.

    Updates DeviceFlowRequest status based on user action.
    Clears session device_flow_user_code.
    Redirects to success/denied confirmation page.

    Args:
        request: FastAPI request object
        action: "approve" or "deny"
        current_user: Authenticated user
        db: Database session

    Returns:
        RedirectResponse to confirmation page

    Raises:
        HTTPException 400: If no device flow in progress or invalid action
    """
    # Get user_code from session
    user_code = request.session.get('device_flow_user_code')
    if not user_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No device authorization in progress"
        )

    if action == "approve":
        # Approve device flow
        device_flow.approve_device_flow(
            db=db,
            user_code=user_code,
            user=current_user,
            provider=current_user.provider
        )

        logger.bind(router="device_flow", endpoint="approve").info(
            f"Device approved: user_code={user_code}, user={current_user.email}"
        )

        message = "Device authorized successfully! You can now return to your device."
        bg_color = "bg-green-50"
        border_color = "border-green-200"
        text_color = "text-green-900"

    elif action == "deny":
        # Deny device flow
        device_flow.deny_device_flow(db=db, user_code=user_code)

        logger.bind(router="device_flow", endpoint="approve").info(
            f"Device denied: user_code={user_code}, user={current_user.email}"
        )

        message = "Device authorization denied. The device will not have access to your account."
        bg_color = "bg-red-50"
        border_color = "border-red-200"
        text_color = "text-red-900"

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid action"
        )

    # Clear session
    request.session.pop('device_flow_user_code', None)

    # Return confirmation page
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authorization Complete - AuditGitHub</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-50 flex items-center justify-center min-h-screen">
        <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full">
            <div class="{bg_color} border {border_color} rounded-lg p-6 mb-6">
                <p class="{text_color} text-center font-semibold">{message}</p>
            </div>
            <div class="text-center">
                <a href="/" class="text-blue-600 hover:underline">Return to Dashboard</a>
            </div>
        </div>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content)


# =============================================================================
# DEVICE MANAGEMENT
# =============================================================================

@router.get("/authorizations", response_model=List[DeviceAuthorizationResponse], summary="List authorized devices", responses={401: {"description": "Not authenticated"}})
async def list_my_devices(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List user's authorized devices.

    Filters by user_sub and organization_id for multi-tenant isolation.
    Returns all devices (active and revoked) for audit trail.

    Args:
        current_user: Authenticated user
        db: Database session

    Returns:
        List[DeviceAuthorizationResponse]: User's device authorizations
    """
    # TODO: Get organization_id from current_user context
    from src.api.models import Organization
    org = db.query(Organization).first()

    devices = db.query(DeviceAuthorization).filter(
        DeviceAuthorization.user_sub == current_user.sub,
        DeviceAuthorization.organization_id == org.id
    ).order_by(DeviceAuthorization.created_at.desc()).all()

    return [
        DeviceAuthorizationResponse(
            id=device.id,
            device_name=device.device_name,
            client_name=device.client_name,
            created_at=device.created_at,
            last_used_at=device.last_used_at,
            is_active=device.is_active,
            provider=device.provider,
            user_agent=device.user_agent,
            token_refresh_count=device.token_refresh_count
        )
        for device in devices
    ]


@router.delete("/authorizations/{device_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke device authorization", responses={400: {"description": "Device already revoked"}, 401: {"description": "Not authenticated"}, 404: {"description": "Device not found"}})
async def revoke_device(
    device_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Revoke device authorization.

    Blacklists current refresh token JTI (if present).
    Sets is_active=False and records revocation metadata.
    Users can only revoke their own devices.

    Args:
        device_id: UUID of device authorization
        current_user: Authenticated user
        db: Database session

    Returns:
        204 No Content

    Raises:
        HTTPException 404: Device not found or not owned by user
    """
    # Find device
    device = db.query(DeviceAuthorization).filter(
        DeviceAuthorization.id == device_id,
        DeviceAuthorization.user_sub == current_user.sub
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    if not device.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device already revoked"
        )

    # Blacklist refresh token if exists
    if device.current_refresh_token_jti:
        try:
            # Token exp can be calculated (7 days from now for safety)
            from datetime import timedelta
            exp_timestamp = int((datetime.utcnow() + timedelta(days=7)).timestamp())
            revoke_token(device.current_refresh_token_jti, exp_timestamp)
        except Exception as e:
            logger.bind(router="device_flow", endpoint="revoke").warning(
                f"Failed to blacklist token JTI {device.current_refresh_token_jti}: {e}"
            )

    # Update device record
    device.is_active = False
    device.revoked_at = datetime.utcnow()
    device.revoked_by = current_user.email
    device.revoked_reason = "User revoked via device management"

    db.commit()

    logger.bind(router="device_flow", endpoint="revoke").info(
        f"Device revoked: device_id={device_id}, user={current_user.email}"
    )

    return None


@router.patch("/authorizations/{device_id}", response_model=DeviceAuthorizationResponse, summary="Rename device", responses={401: {"description": "Not authenticated"}, 404: {"description": "Device not found"}})
async def rename_device(
    device_id: UUID,
    body: RenameDeviceRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Rename device for easier identification.

    Updates device_name field.
    Users can only rename their own devices.

    Args:
        device_id: UUID of device authorization
        body: RenameDeviceRequest with new device_name
        current_user: Authenticated user
        db: Database session

    Returns:
        DeviceAuthorizationResponse: Updated device

    Raises:
        HTTPException 404: Device not found or not owned by user
    """
    # Find device
    device = db.query(DeviceAuthorization).filter(
        DeviceAuthorization.id == device_id,
        DeviceAuthorization.user_sub == current_user.sub
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    # Update name
    device.device_name = body.device_name
    db.commit()
    db.refresh(device)

    logger.bind(router="device_flow", endpoint="rename").info(
        f"Device renamed: device_id={device_id}, new_name={body.device_name}"
    )

    return DeviceAuthorizationResponse(
        id=device.id,
        device_name=device.device_name,
        client_name=device.client_name,
        created_at=device.created_at,
        last_used_at=device.last_used_at,
        is_active=device.is_active,
        provider=device.provider,
        user_agent=device.user_agent,
        token_refresh_count=device.token_refresh_count
    )
