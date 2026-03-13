"""
Bootstrap Script for Super Admin Accounts

Creates Super Admin accounts on first run or when manually executed.
Run with: python -m src.auth.bootstrap
"""
import os
import sys
from sqlalchemy.orm import Session
from loguru import logger

from src.api.database import SessionLocal
from src.api.models import User
from src.auth.break_glass import create_break_glass_user

BREAK_GLASS_EMAIL = os.environ.get("BREAK_GLASS_EMAIL", "admin@example.com")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@company.example")


def bootstrap_super_admins() -> None:
    """
    Create Super Admin accounts on first run.

    Creates:
    - BREAK_GLASS_EMAIL (with local password for break glass)
    - ADMIN_EMAIL (Entra ID only)

    Safe to run multiple times - checks if users exist first.
    """
    db = SessionLocal()

    try:
        # Check if Super Admins already exist
        existing = db.query(User).filter(
            User.email.in_([BREAK_GLASS_EMAIL, ADMIN_EMAIL])
        ).all()

        if len(existing) >= 2:
            logger.info("Super Admins already exist, skipping bootstrap")
            for user in existing:
                logger.info(f"  - {user.email} (role={user.role}, provider={user.auth_provider})")
            return

        # Get break glass password from environment or use default
        break_glass_password = os.getenv('BREAK_GLASS_PASSWORD', 'ChangeMe123!')

        # Check if break glass user exists
        ravance = db.query(User).filter(User.email == BREAK_GLASS_EMAIL).first()
        if not ravance:
            # Create break glass user with password
            try:
                ravance = create_break_glass_user(
                    db=db,
                    email=BREAK_GLASS_EMAIL,
                    password=break_glass_password,
                    full_name='Rob Vance (Break Glass)'
                )
                logger.info(f"✓ Created break glass user: {BREAK_GLASS_EMAIL}")
            except Exception as e:
                logger.error(f"Failed to create break glass user: {e}")
        else:
            logger.info(f"✓ Break glass user already exists: {BREAK_GLASS_EMAIL}")

        # Check if admin user exists
        rob_vance = db.query(User).filter(User.email == ADMIN_EMAIL).first()
        if not rob_vance:
            # Create admin user (Entra ID)
            rob_vance = User(
                email=ADMIN_EMAIL,
                username='rob.vance',
                full_name='Rob Vance',
                role='super_admin',
                access_type='both',
                auth_provider='entra',
                is_active=True
            )
            db.add(rob_vance)
            db.commit()
            logger.info(f"✓ Created Entra ID super admin: {ADMIN_EMAIL}")
        else:
            logger.info(f"✓ Entra ID super admin already exists: rob.vance@sleepnumber.com")

        logger.success("Super Admin bootstrap completed successfully")

    except Exception as e:
        logger.exception(f"Failed to bootstrap Super Admins: {e}")
        db.rollback()
        raise

    finally:
        db.close()


def main():
    """Main entry point for bootstrap script."""
    logger.info("Starting Super Admin bootstrap...")

    try:
        bootstrap_super_admins()
        logger.success("Bootstrap completed successfully")
        return 0
    except Exception as e:
        logger.error(f"Bootstrap failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
