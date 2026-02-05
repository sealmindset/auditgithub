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


def bootstrap_super_admins() -> None:
    """
    Create Super Admin accounts on first run.

    Creates:
    - ravance@gmail.com (with local password for break glass)
    - rob.vance@sleepnumber.com (Entra ID only)

    Safe to run multiple times - checks if users exist first.
    """
    db = SessionLocal()

    try:
        # Check if Super Admins already exist
        existing = db.query(User).filter(
            User.email.in_(['ravance@gmail.com', 'rob.vance@sleepnumber.com'])
        ).all()

        if len(existing) >= 2:
            logger.info("Super Admins already exist, skipping bootstrap")
            for user in existing:
                logger.info(f"  - {user.email} (role={user.role}, provider={user.auth_provider})")
            return

        # Get break glass password from environment or use default
        break_glass_password = os.getenv('BREAK_GLASS_PASSWORD', 'ChangeMe123!')

        # Check if ravance@gmail.com exists
        ravance = db.query(User).filter(User.email == 'ravance@gmail.com').first()
        if not ravance:
            # Create ravance@gmail.com with break glass password
            try:
                ravance = create_break_glass_user(
                    db=db,
                    email='ravance@gmail.com',
                    password=break_glass_password,
                    full_name='Rob Vance (Break Glass)'
                )
                logger.info(f"✓ Created break glass user: ravance@gmail.com")
            except Exception as e:
                logger.error(f"Failed to create break glass user: {e}")
        else:
            logger.info(f"✓ Break glass user already exists: ravance@gmail.com")

        # Check if rob.vance@sleepnumber.com exists
        rob_vance = db.query(User).filter(User.email == 'rob.vance@sleepnumber.com').first()
        if not rob_vance:
            # Create rob.vance@sleepnumber.com (Entra ID)
            rob_vance = User(
                email='rob.vance@sleepnumber.com',
                username='rob.vance',
                full_name='Rob Vance',
                role='super_admin',
                access_type='both',
                auth_provider='entra',
                is_active=True
            )
            db.add(rob_vance)
            db.commit()
            logger.info(f"✓ Created Entra ID super admin: rob.vance@sleepnumber.com")
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
