"""
Invitation Management API

Endpoints for admins to manage user invitations.
Allows sending, listing, and revoking invitations.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from sqlalchemy.orm import Session

from src.api.database import get_db
from src.api.models import User, UserInvitation
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
    email: EmailStr
    role: str = 'user'
    access_type: str = 'ui_only'

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
    id: str
    email: str
    role: str
    access_type: str
    status: str
    invited_by_email: str
    created_at: datetime
    expires_at: datetime
    accepted_at: Optional[datetime] = None

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
    message: str
    invitation_id: str
    expires_at: datetime
    invitation_link: str


class ValidateInvitationResponse(BaseModel):
    """Response for validating invitation token."""
    valid: bool
    email: Optional[str] = None
    role: Optional[str] = None
    access_type: Optional[str] = None
    expires_at: Optional[datetime] = None
    invited_by_email: Optional[str] = None
    message: Optional[str] = None


# =========================================================================
# Endpoints
# =========================================================================

@router.post("", response_model=SendInvitationResponse, status_code=status.HTTP_201_CREATED)
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
        # TODO: Get base URL from settings
        invitation_link = f"http://localhost:3000/invite/{invitation.invite_token}"

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


@router.get("", response_model=List[InvitationResponse])
async def list_invitations(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    List all pending invitations.

    Only admins can view invitations.

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


@router.delete("/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT)
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


@router.get("/validate/{token}", response_model=ValidateInvitationResponse)
async def validate_invitation(
    token: str,
    db: Session = Depends(get_db)
):
    """
    Validate invitation token (public endpoint).

    Used by invitation acceptance page to display invitation details
    before user authenticates.

    Args:
        token: Invitation token from email link
        db: Database session

    Returns:
        Invitation details if valid

    Note: This is a public endpoint (no auth required)
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
