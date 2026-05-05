"""
Invitation Management API

Endpoints for admins to manage user invitations.
Allows sending, listing, and revoking invitations.
"""
import os

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from sqlalchemy.orm import Session

from src.api.database import get_db
from src.api.models import User, UserInvitation
from src.api.schemas.common import CREATE_ERRORS, LIST_ERRORS, DELETE_ERRORS, CRUD_ERRORS
from src.auth.dependencies import require_admin, get_db_user
from src.auth.invitations import (
    create_invitation,
    revoke_invitation as revoke_invitation_service,
    list_pending_invitations,
    get_invitation_by_token
)
from loguru import logger

router = APIRouter(prefix="/api/invitations", tags=["invitations"])


# =========================================================================
# Request/Response Models
# =========================================================================

class SendInvitationRequest(BaseModel):
    """Request body for sending invitation."""
    email: EmailStr = Field(..., description="Email address to send the invitation to")
    role: str = Field('user', description="Role to assign to the invited user (user, developer, analyst, manager, admin)")
    access_type: str = Field('ui_only', description="Access type for the invited user (ui_only, api_only, both)")

    class Config:
        schema_extra = {
            "example": {
                "email": "developer@example.com",
                "role": "developer",
                "access_type": "both"
            }
        }


class InvitationResponse(BaseModel):
    """Response model for invitation."""
    id: str = Field(..., description="Unique invitation identifier (UUID)")
    email: str = Field(..., description="Invited user's email address")
    role: str = Field(..., description="Role assigned to the invitation")
    access_type: str = Field(..., description="Access type assigned to the invitation")
    status: str = Field(..., description="Invitation status (pending, accepted, revoked, expired)")
    invited_by_email: str = Field(..., description="Email of the admin who sent the invitation")
    created_at: datetime = Field(..., description="When the invitation was created")
    expires_at: datetime = Field(..., description="When the invitation expires")
    accepted_at: Optional[datetime] = Field(None, description="When the invitation was accepted, if applicable")

    class Config:
        schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "email": "developer@example.com",
                "role": "developer",
                "access_type": "both",
                "status": "pending",
                "invited_by_email": "admin@example.com",
                "created_at": "2025-02-04T10:00:00Z",
                "expires_at": "2025-02-11T10:00:00Z",
                "accepted_at": None
            }
        }


class SendInvitationResponse(BaseModel):
    """Response for sending invitation."""
    message: str = Field(..., description="Success message")
    invitation_id: str = Field(..., description="Unique ID of the created invitation")
    expires_at: datetime = Field(..., description="Expiration timestamp for the invitation")
    invitation_link: str = Field(..., description="URL link for the invitee to accept the invitation")


class ValidateInvitationResponse(BaseModel):
    """Response for validating invitation token."""
    valid: bool = Field(..., description="Whether the invitation token is valid and still pending")
    email: Optional[str] = Field(None, description="Invited email address (if valid)")
    role: Optional[str] = Field(None, description="Role assigned to the invitation (if valid)")
    access_type: Optional[str] = Field(None, description="Access type assigned (if valid)")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp (if valid)")
    invited_by_email: Optional[str] = Field(None, description="Email of the admin who sent the invitation (if valid)")
    message: Optional[str] = Field(None, description="Status message when the invitation is invalid or expired")


# =========================================================================
# Endpoints
# =========================================================================

@router.post(
    "",
    response_model=SendInvitationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Send a user invitation",
    responses={
        **CREATE_ERRORS,
        400: {"description": "Invalid role/access type, or user already exists"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions - admin role required"},
    },
)
async def send_invitation(
    body: SendInvitationRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Send invitation email to new user.

    Only admins and super admins can send invitations.
    Validates:
    - Email not already registered
    - Role is valid
    - Access type is valid

    Args:
        body: Invitation details (email, role, access_type)
        current_user: Current admin user (from dependency)
        db: Database session

    Returns:
        Invitation details with unique link

    Raises:
        HTTPException 400: If user already exists or validation fails
        HTTPException 403: If user is not admin
    """
    # Validate role
    valid_roles = ['user', 'developer', 'analyst', 'manager', 'admin']
    if body.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}"
        )

    # Validate access type
    valid_access_types = ['ui_only', 'api_only', 'both']
    if body.access_type not in valid_access_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid access type. Must be one of: {', '.join(valid_access_types)}"
        )

    try:
        # Create invitation
        invitation = create_invitation(
            db=db,
            email=body.email,
            invited_by_user=current_user,
            role=body.role,
            access_type=body.access_type
        )

        logger.info(
            f"Invitation sent to {body.email} by {current_user.email} "
            f"(role={body.role}, access={body.access_type})"
        )

        # Generate invitation link
        app_url = os.getenv("APP_URL", "http://localhost:3001")
        invitation_link = f"{app_url}/invite/{invitation.invite_token}"

        return SendInvitationResponse(
            message="Invitation sent successfully",
            invitation_id=str(invitation.id),
            expires_at=invitation.expires_at,
            invitation_link=invitation_link
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get(
    "",
    response_model=List[InvitationResponse],
    summary="List all pending invitations",
    responses={
        **LIST_ERRORS,
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions - admin role required"},
    },
)
async def list_invitations(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    List all pending invitations.

    Requires the **admin** role. Returns all invitations with a status of
    ``pending``, including the inviter's email and expiration timestamp.

    Args:
        current_user: Current admin user (from dependency)
        db: Database session

    Returns:
        List of pending invitations
    """
    invitations = list_pending_invitations(db)

    return [
        InvitationResponse(
            id=str(inv.id),
            email=inv.email,
            role=inv.invited_role,
            access_type=inv.invited_access_type,
            status=inv.status,
            invited_by_email=inv.inviter.email,
            created_at=inv.created_at,
            expires_at=inv.expires_at,
            accepted_at=inv.accepted_at
        )
        for inv in invitations
    ]


@router.delete(
    "/{invitation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a pending invitation",
    responses={
        **DELETE_ERRORS,
        400: {"description": "Invitation cannot be revoked (already accepted or expired)"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions - admin role required"},
        404: {"description": "Invitation not found"},
    },
)
async def revoke_invitation(
    invitation_id: UUID,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Revoke pending invitation.

    Only admins can revoke invitations.

    Args:
        invitation_id: Invitation UUID
        current_user: Current admin user (from dependency)
        db: Database session

    Returns:
        204 No Content on success

    Raises:
        HTTPException 404: If invitation not found
        HTTPException 400: If invitation cannot be revoked (already accepted/expired)
    """
    try:
        revoke_invitation_service(db, str(invitation_id), current_user)

        logger.info(f"Invitation {invitation_id} revoked by {current_user.email}")

        return None  # 204 No Content

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get(
    "/validate/{token}",
    response_model=ValidateInvitationResponse,
    summary="Validate an invitation token",
    responses={
        400: {"description": "Bad request - malformed token"},
        500: {"description": "Internal server error"},
    },
)
async def validate_invitation(
    token: str,
    db: Session = Depends(get_db)
):
    """
    Validate an invitation token (public endpoint -- no authentication required).

    Used by the invitation acceptance page to display invitation details
    before the user authenticates. Returns ``valid=false`` with a message
    when the token is invalid, expired, or already consumed rather than
    raising an HTTP error.

    **Permissions:** none (public).

    Args:
        token: Invitation token from email link
        db: Database session

    Returns:
        Invitation details if valid, or a ``valid=false`` payload with a
        descriptive message otherwise.
    """
    invitation = get_invitation_by_token(db, token)

    if not invitation:
        return ValidateInvitationResponse(
            valid=False,
            message="Invalid or expired invitation"
        )

    if invitation.status != 'pending':
        return ValidateInvitationResponse(
            valid=False,
            message=f"Invitation {invitation.status}"
        )

    return ValidateInvitationResponse(
        valid=True,
        email=invitation.email,
        role=invitation.invited_role,
        access_type=invitation.invited_access_type,
        expires_at=invitation.expires_at,
        invited_by_email=invitation.inviter.email
    )
