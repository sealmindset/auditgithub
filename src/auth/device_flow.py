"""
OAuth 2.0 Device Authorization Grant Flow (RFC 8628) - Core Business Logic

Implements device flow operations for CLI/device authentication with browser-based OIDC.
Provides functions for generating codes, managing requests, and issuing tokens.
"""
import secrets
from datetime import datetime, timedelta
from typing import List, Tuple, Optional
from uuid import UUID
from sqlalchemy.orm import Session
from sqlalchemy import and_
from fastapi import HTTPException, status
from loguru import logger

from src.api.models import DeviceFlowRequest, DeviceAuthorization
from src.auth.models import User
from src.auth.tokens import generate_access_token, generate_refresh_token


# Configuration constants
DEVICE_CODE_LENGTH = 96  # bytes -> 128 chars base64url
USER_CODE_CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Excludes confusing: 0,O,1,I,l
USER_CODE_LENGTH = 8
DEVICE_CODE_EXPIRY_MINUTES = 10
MAX_GENERATION_RETRIES = 5


def generate_device_code() -> str:
    """
    Generate cryptographically secure 128-character device code.

    Uses secrets.token_urlsafe for cryptographic randomness.
    96 bytes -> 128 characters in base64url encoding.
    Provides ~576 bits of entropy.

    Returns:
        str: 128-character base64url-encoded device code
    """
    return secrets.token_urlsafe(DEVICE_CODE_LENGTH)


def generate_user_code() -> str:
    """
    Generate 8-character human-friendly user code in ABCD-1234 format.

    Excludes confusing characters (0, O, 1, I, l) to prevent user errors.
    Character set: ABCDEFGHJKLMNPQRSTUVWXYZ23456789 (32 characters)
    Total combinations: 32^8 = ~1.2 trillion

    Format: XXXX-YYYY (dash added for readability)

    Returns:
        str: 9-character user code (8 alphanumeric + 1 dash)
    """
    code = ''.join(secrets.choice(USER_CODE_CHARSET) for _ in range(USER_CODE_LENGTH))
    return f"{code[:4]}-{code[4:]}"  # Add dash: ABCD-1234


def create_device_flow_request(
    db: Session,
    organization_id: UUID,
    client_id: str,
    client_name: str,
    scopes: Optional[List[str]] = None
) -> DeviceFlowRequest:
    """
    Create a new device flow request with unique codes.

    Generates device_code and user_code with collision detection.
    Retries up to MAX_GENERATION_RETRIES times on collision (extremely rare).
    Sets expiration to DEVICE_CODE_EXPIRY_MINUTES from creation.

    Args:
        db: SQLAlchemy database session
        organization_id: UUID of the organization (multi-tenant scope)
        client_id: Client identifier (e.g., "auditgh-cli")
        client_name: Human-readable client name (e.g., "AuditGitHub CLI")
        scopes: List of requested OAuth scopes (optional)

    Returns:
        DeviceFlowRequest: Created request with device_code, user_code, and expiry

    Raises:
        HTTPException 500: If unable to generate unique codes after MAX_GENERATION_RETRIES
    """
    if scopes is None:
        scopes = []

    expires_at = datetime.utcnow() + timedelta(minutes=DEVICE_CODE_EXPIRY_MINUTES)

    # Retry loop for code generation (handles rare collisions)
    for attempt in range(MAX_GENERATION_RETRIES):
        device_code = generate_device_code()
        user_code = generate_user_code()

        # Check for existing codes (collision detection)
        existing = db.query(DeviceFlowRequest).filter(
            and_(
                (DeviceFlowRequest.device_code == device_code) |
                (DeviceFlowRequest.user_code == user_code),
                DeviceFlowRequest.expires_at > datetime.utcnow()  # Only check non-expired
            )
        ).first()

        if not existing:
            # Codes are unique - create request
            request = DeviceFlowRequest(
                device_code=device_code,
                user_code=user_code,
                client_id=client_id,
                client_name=client_name,
                scopes=scopes,
                organization_id=organization_id,
                expires_at=expires_at,
                status='pending'
            )

            db.add(request)
            db.commit()
            db.refresh(request)

            logger.bind(module="device_flow").info(
                f"Created device flow request: user_code={user_code}, client={client_name}"
            )

            return request

    # Failed to generate unique codes after max retries (extremely unlikely)
    logger.bind(module="device_flow").error(
        f"Failed to generate unique device codes after {MAX_GENERATION_RETRIES} attempts"
    )
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to generate unique device codes. Please try again."
    )


def approve_device_flow(
    db: Session,
    user_code: str,
    user: User,
    provider: str
) -> DeviceFlowRequest:
    """
    Mark device flow request as approved with user information.

    Validates:
    - User code exists
    - Request not expired
    - Status is 'pending' (not already approved/denied/consumed)

    Updates request with user identity information and sets status to 'approved'.

    Args:
        db: SQLAlchemy database session
        user_code: 8-character user code (ABCD-1234)
        user: Authenticated User object from session
        provider: Identity provider name ('entra' or 'okta')

    Returns:
        DeviceFlowRequest: Updated request with status='approved'

    Raises:
        HTTPException 404: If user code not found
        HTTPException 400: If code expired or already processed
    """
    # Find request by user code
    request = db.query(DeviceFlowRequest).filter(
        DeviceFlowRequest.user_code == user_code
    ).first()

    if not request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid user code"
        )

    # Check expiration
    if request.expires_at < datetime.utcnow():
        request.status = 'expired'
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device code has expired. Please restart the authentication process."
        )

    # Check status
    if request.status != 'pending':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Device authorization already {request.status}"
        )

    # Update request with user information
    request.status = 'approved'
    request.user_sub = user.sub
    request.user_email = user.email
    request.user_name = user.name
    request.provider = provider
    request.approved_at = datetime.utcnow()

    db.commit()
    db.refresh(request)

    logger.bind(module="device_flow").info(
        f"Device flow approved: user_code={user_code}, user={user.email}"
    )

    return request


def issue_device_tokens(
    db: Session,
    device_code: str,
    device_name: str = "Unknown Device",
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None
) -> dict:
    """
    Issue access and refresh tokens for an approved device.

    Validates:
    - Device code exists
    - Request is approved (not pending/denied/expired)
    - Not already consumed

    Creates DeviceAuthorization record and generates tokens.
    Marks request as 'consumed' to prevent reuse.

    Args:
        db: SQLAlchemy database session
        device_code: 128-character device code
        device_name: User-friendly device name (default: "Unknown Device")
        user_agent: HTTP User-Agent header (optional)
        ip_address: Client IP address (optional)

    Returns:
        dict: Token response with structure:
            {
                "access_token": str,
                "refresh_token": str,
                "token_type": "bearer",
                "expires_in": int  # seconds
            }

    Raises:
        HTTPException 400: If device code invalid, expired, or not approved
    """
    # Find request by device code
    request = db.query(DeviceFlowRequest).filter(
        DeviceFlowRequest.device_code == device_code
    ).first()

    if not request:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid device code"
        )

    # Check if expired
    if request.expires_at < datetime.utcnow():
        if request.status != 'expired':
            request.status = 'expired'
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="expired_token"  # RFC 8628 error code
        )

    # Check status
    if request.status == 'pending':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="authorization_pending"  # RFC 8628 error code
        )
    elif request.status == 'denied':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="access_denied"  # RFC 8628 error code
        )
    elif request.status == 'consumed':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device code already used"
        )
    elif request.status != 'approved':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status: {request.status}"
        )

    # Generate tokens
    access_token = generate_access_token(
        user_sub=request.user_sub,
        tenant_id=str(request.organization_id),
        email=request.user_email,
        name=request.user_name
    )

    refresh_token = generate_refresh_token(
        user_sub=request.user_sub,
        tenant_id=str(request.organization_id),
        email=request.user_email,
        name=request.user_name,
        provider=request.provider
    )

    # Create DeviceAuthorization record
    authorization = DeviceAuthorization(
        organization_id=request.organization_id,
        user_sub=request.user_sub,
        user_email=request.user_email,
        user_name=request.user_name,
        provider=request.provider,
        device_name=device_name,
        client_id=request.client_id,
        client_name=request.client_name,
        # current_refresh_token_jti will be set when token is refreshed
        user_agent=user_agent,
        ip_address=ip_address,
        is_active=True
    )

    db.add(authorization)

    # Mark request as consumed
    request.status = 'consumed'

    db.commit()

    logger.bind(module="device_flow").info(
        f"Device tokens issued: user={request.user_email}, device={device_name}"
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 3600  # 1 hour (access token lifetime)
    }


def cleanup_expired_requests(db: Session) -> int:
    """
    Mark expired device flow requests.

    Finds all requests with:
    - status = 'pending'
    - expires_at < current time

    Updates their status to 'expired' for cleanup tracking.
    Should be called periodically by background task.

    Args:
        db: SQLAlchemy database session

    Returns:
        int: Number of requests marked as expired
    """
    now = datetime.utcnow()

    expired_count = db.query(DeviceFlowRequest).filter(
        and_(
            DeviceFlowRequest.status == 'pending',
            DeviceFlowRequest.expires_at < now
        )
    ).update({'status': 'expired'})

    db.commit()

    if expired_count > 0:
        logger.bind(module="device_flow").info(
            f"Marked {expired_count} device flow requests as expired"
        )

    return expired_count


def deny_device_flow(
    db: Session,
    user_code: str
) -> DeviceFlowRequest:
    """
    Mark device flow request as denied by user.

    Args:
        db: SQLAlchemy database session
        user_code: 8-character user code (ABCD-1234)

    Returns:
        DeviceFlowRequest: Updated request with status='denied'

    Raises:
        HTTPException 404: If user code not found
        HTTPException 400: If code expired or already processed
    """
    request = db.query(DeviceFlowRequest).filter(
        DeviceFlowRequest.user_code == user_code
    ).first()

    if not request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid user code"
        )

    # Check expiration
    if request.expires_at < datetime.utcnow():
        request.status = 'expired'
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device code has expired"
        )

    # Check status
    if request.status != 'pending':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Device authorization already {request.status}"
        )

    # Update status to denied
    request.status = 'denied'
    db.commit()
    db.refresh(request)

    logger.bind(module="device_flow").info(
        f"Device flow denied: user_code={user_code}"
    )

    return request


def update_device_poll(
    db: Session,
    device_code: str
) -> None:
    """
    Update polling statistics for rate limiting.

    Increments poll_count and updates last_poll_at.
    Used to implement slow_down error for excessive polling.

    Args:
        db: SQLAlchemy database session
        device_code: 128-character device code
    """
    request = db.query(DeviceFlowRequest).filter(
        DeviceFlowRequest.device_code == device_code
    ).first()

    if request:
        request.poll_count += 1
        request.last_poll_at = datetime.utcnow()
        db.commit()
