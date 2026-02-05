"""
User Invitation System

Email-based user onboarding with unique invitation links (7-day expiry).
Admins can invite users with specific roles and access types.
"""
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict
from sqlalchemy.orm import Session
from loguru import logger

from src.api.models import User, UserInvitation
from src.auth.email_service import email_service


def create_invitation(
    db: Session,
    email: str,
    invited_by_user: User,
    role: str = 'user',
    access_type: str = 'ui_only'
) -> UserInvitation:
    """
    Create invitation and send email.

    Args:
        db: Database session
        email: Invitee email address
        invited_by_user: User sending invite (must be admin/super_admin)
        role: Initial role to assign (user, developer, analyst, manager, admin)
        access_type: Access type (ui_only, api_only, both)

    Returns:
        UserInvitation record

    Raises:
        ValueError: If user already exists or inviter lacks permissions
    """
    # Validate inviter has admin permissions
    if invited_by_user.role not in ['admin', 'super_admin']:
        raise ValueError("Only admins can send invitations")

    # Check if user already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise ValueError(f"User with email {email} already exists")

    # Check if there's already a pending invitation
    existing_invitation = db.query(UserInvitation).filter(
        UserInvitation.email == email,
        UserInvitation.status == 'pending'
    ).first()

    if existing_invitation:
        # Revoke old invitation
        existing_invitation.status = 'revoked'
        logger.info(f"Revoked previous invitation for {email}")

    # Generate cryptographic token (64 characters)
    invite_token = secrets.token_urlsafe(48)

    # Create invitation
    invitation = UserInvitation(
        email=email,
        invite_token=invite_token,
        invited_by=invited_by_user.id,
        invited_role=role,
        invited_access_type=access_type,
        status='pending',
        expires_at=datetime.utcnow() + timedelta(days=7)
    )

    db.add(invitation)
    db.commit()
    db.refresh(invitation)

    logger.info(
        f"Invitation created for {email} by {invited_by_user.email} "
        f"(role={role}, access={access_type})"
    )

    # Send invitation email
    try:
        email_sent = email_service.send_invitation_email(
            recipient_email=email,
            invite_token=invite_token,
            inviter_name=invited_by_user.full_name or invited_by_user.email,
            role=role,
            access_type=access_type,
            expires_in_days=7
        )

        if not email_sent:
            logger.warning(f"Failed to send invitation email to {email}, but invitation was created")
    except Exception as e:
        logger.error(f"Error sending invitation email to {email}: {e}")
        # Don't fail the invitation creation if email fails

    return invitation


def accept_invitation(
    db: Session,
    invite_token: str,
    entra_user_info: Dict
) -> User:
    """
    Accept invitation after Entra ID authentication.

    Args:
        db: Database session
        invite_token: Unique invitation token from email link
        entra_user_info: User info from Entra ID OAuth (contains sub, email, name, upn)

    Returns:
        Newly created User

    Raises:
        ValueError: If invitation invalid, expired, or email mismatch
    """
    # Find invitation
    invitation = db.query(UserInvitation).filter(
        UserInvitation.invite_token == invite_token,
        UserInvitation.status == 'pending'
    ).first()

    if not invitation:
        raise ValueError("Invalid or expired invitation")

    # Check expiration
    if invitation.expires_at < datetime.utcnow():
        invitation.status = 'expired'
        db.commit()
        raise ValueError("Invitation expired")

    # Verify email matches
    if invitation.email.lower() != entra_user_info.get('email', '').lower():
        raise ValueError(
            f"Email mismatch: invitation for {invitation.email}, "
            f"authenticated as {entra_user_info.get('email')}"
        )

    # Check if user already exists (race condition protection)
    existing_user = db.query(User).filter(User.email == invitation.email).first()
    if existing_user:
        raise ValueError("User already exists")

    # Create user
    user = User(
        email=invitation.email,
        username=entra_user_info.get('preferred_username', invitation.email.split('@')[0]),
        full_name=entra_user_info.get('name', ''),
        role=invitation.invited_role,
        access_type=invitation.invited_access_type,
        entra_id_object_id=entra_user_info.get('sub'),
        entra_id_upn=entra_user_info.get('upn'),
        auth_provider='entra',
        is_active=True,
        is_invited=True,
        first_login_at=datetime.utcnow()
    )

    db.add(user)

    # Mark invitation accepted
    invitation.status = 'accepted'
    invitation.accepted_at = datetime.utcnow()

    db.commit()
    db.refresh(user)

    logger.info(
        f"Invitation accepted: {user.email} created with role {user.role} "
        f"(invited by user_id={invitation.invited_by})"
    )

    return user


def get_invitation_by_token(
    db: Session,
    invite_token: str
) -> Optional[UserInvitation]:
    """
    Get invitation details by token.

    Args:
        db: Database session
        invite_token: Invitation token

    Returns:
        UserInvitation if found and pending, None otherwise
    """
    invitation = db.query(UserInvitation).filter(
        UserInvitation.invite_token == invite_token
    ).first()

    if not invitation:
        return None

    # Auto-expire old invitations
    if invitation.status == 'pending' and invitation.expires_at < datetime.utcnow():
        invitation.status = 'expired'
        db.commit()

    return invitation


def revoke_invitation(
    db: Session,
    invitation_id: str,
    revoked_by_user: User
) -> UserInvitation:
    """
    Revoke pending invitation.

    Args:
        db: Database session
        invitation_id: Invitation UUID
        revoked_by_user: User revoking invite (must be admin)

    Returns:
        Updated UserInvitation

    Raises:
        ValueError: If invitation not found or user lacks permissions
    """
    if revoked_by_user.role not in ['admin', 'super_admin']:
        raise ValueError("Only admins can revoke invitations")

    invitation = db.query(UserInvitation).filter(
        UserInvitation.id == invitation_id
    ).first()

    if not invitation:
        raise ValueError("Invitation not found")

    if invitation.status != 'pending':
        raise ValueError(f"Cannot revoke invitation with status: {invitation.status}")

    invitation.status = 'revoked'
    db.commit()
    db.refresh(invitation)

    logger.info(
        f"Invitation revoked for {invitation.email} by {revoked_by_user.email}"
    )

    return invitation


def list_pending_invitations(
    db: Session
) -> list[UserInvitation]:
    """
    List all pending invitations.

    Args:
        db: Database session

    Returns:
        List of pending UserInvitation objects
    """
    invitations = db.query(UserInvitation).filter(
        UserInvitation.status == 'pending'
    ).order_by(UserInvitation.created_at.desc()).all()

    # Auto-expire old invitations
    for inv in invitations:
        if inv.expires_at < datetime.utcnow():
            inv.status = 'expired'

    db.commit()

    return [inv for inv in invitations if inv.status == 'pending']


def cleanup_expired_invitations(db: Session) -> int:
    """
    Mark all expired invitations as 'expired'.

    Args:
        db: Database session

    Returns:
        Number of invitations marked as expired
    """
    expired_invitations = db.query(UserInvitation).filter(
        UserInvitation.status == 'pending',
        UserInvitation.expires_at < datetime.utcnow()
    ).all()

    count = 0
    for invitation in expired_invitations:
        invitation.status = 'expired'
        count += 1

    db.commit()

    if count > 0:
        logger.info(f"Marked {count} expired invitations")

    return count
