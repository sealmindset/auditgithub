"""
Development authentication bootstrapping.

Seeds the database with initial invitations and users for mock OIDC development.
Only runs when OIDC_PROVIDER_NAME=mock-oidc (development mode).

Usage:
    python scripts/seed_dev_auth.py

What it does:
    1. Creates a bootstrap super_admin invitation for admin@zapper.local
    2. Creates analyst and user invitations for testing
    3. Optionally provisions matching users in the mock OIDC provider
"""

import os
import sys
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loguru import logger


# Mock OIDC pre-seeded users that we create invitations for
# Must match the users seeded in mocksvcs/mock_oidc/store.py
DEV_INVITATIONS = [
    {
        "email": "superadmin@zapper.local",
        "role": "super_admin",
        "access_type": "both",
        "description": "Super Admin (matches mock-oidc mock-super-admin user)",
    },
    {
        "email": "admin@zapper.local",
        "role": "admin",
        "access_type": "both",
        "description": "Admin (matches mock-oidc mock-admin user)",
    },
    {
        "email": "manager@zapper.local",
        "role": "manager",
        "access_type": "both",
        "description": "Manager (matches mock-oidc mock-manager user)",
    },
    {
        "email": "analyst@zapper.local",
        "role": "analyst",
        "access_type": "both",
        "description": "Analyst (matches mock-oidc mock-analyst user)",
    },
    {
        "email": "user@zapper.local",
        "role": "user",
        "access_type": "ui_only",
        "description": "Read-only user (matches mock-oidc mock-user user)",
    },
]


def seed_dev_invitations():
    """Create development invitations for mock OIDC users."""
    provider_name = os.getenv("OIDC_PROVIDER_NAME", "")
    if provider_name != "mock-oidc":
        logger.info("OIDC_PROVIDER_NAME is not 'mock-oidc', skipping dev auth seed.")
        return

    from src.api.database import SessionLocal
    from src.api.models import User, UserInvitation

    db = SessionLocal()
    try:
        # Check if any users already exist (skip if DB is already populated)
        user_count = db.query(User).count()
        if user_count > 0:
            logger.info(f"Database already has {user_count} users, skipping dev auth seed.")
            return

        # Check if invitations already exist
        existing_invitations = db.query(UserInvitation).filter(
            UserInvitation.status == 'pending'
        ).count()
        if existing_invitations > 0:
            logger.info(f"Already have {existing_invitations} pending invitations, skipping.")
            return

        created = 0
        for inv_data in DEV_INVITATIONS:
            # Check if invitation already exists for this email
            existing = db.query(UserInvitation).filter(
                UserInvitation.email == inv_data["email"]
            ).first()
            if existing:
                logger.debug(f"Invitation already exists for {inv_data['email']}, skipping.")
                continue

            invitation = UserInvitation(
                email=inv_data["email"],
                invite_token=f"dev-bootstrap-{inv_data['role']}",
                invited_by=None,  # System-generated bootstrap invitation
                invited_role=inv_data["role"],
                invited_access_type=inv_data["access_type"],
                status="pending",
                expires_at=datetime.utcnow() + timedelta(days=365),  # Long-lived for dev
            )
            db.add(invitation)
            created += 1
            logger.info(
                f"Created dev invitation: {inv_data['email']} "
                f"(role={inv_data['role']}, {inv_data['description']})"
            )

        db.commit()

        if created > 0:
            logger.info(f"Seeded {created} development auth invitations.")
            logger.info("")
            logger.info("To complete setup, visit:")
            logger.info("  http://localhost:8000/auth/accept-invite?token=dev-bootstrap-super_admin")
            logger.info("")
            logger.info("This will redirect you to mock OIDC to pick a user,")
            logger.info("then create your account with the assigned role.")
        else:
            logger.info("No new invitations needed.")

    except Exception as e:
        logger.error(f"Failed to seed dev auth: {e}")
        db.rollback()
    finally:
        db.close()


def provision_mock_oidc_user(email: str, name: str = ""):
    """
    Provision a user in the mock OIDC provider via its management API.

    Args:
        email: User email (must match invitation email)
        name: Display name
    """
    import httpx

    mock_oidc_url = os.getenv("OIDC_DISCOVERY_URL", "").replace(
        "/.well-known/openid-configuration", ""
    )
    if not mock_oidc_url:
        logger.warning("OIDC_DISCOVERY_URL not set, cannot provision mock OIDC user.")
        return

    username = email.split("@")[0]
    if not name:
        name = username.replace("-", " ").replace("_", " ").title()

    try:
        resp = httpx.post(
            f"{mock_oidc_url}/api/users",
            json={
                "username": username,
                "email": email,
                "name": name,
            },
            timeout=5.0,
        )
        if resp.status_code in (200, 201):
            logger.info(f"Provisioned mock OIDC user: {email}")
        elif resp.status_code == 409:
            logger.debug(f"Mock OIDC user already exists: {email}")
        else:
            logger.warning(f"Failed to provision mock OIDC user {email}: {resp.status_code} {resp.text}")
    except Exception as e:
        logger.warning(f"Could not reach mock OIDC to provision user {email}: {e}")


if __name__ == "__main__":
    seed_dev_invitations()
