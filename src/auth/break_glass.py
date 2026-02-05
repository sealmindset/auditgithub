"""
Break Glass Authentication

Emergency local authentication for ravance@gmail.com when Entra ID is unavailable.
All break glass access is audited and prominently displayed.
"""
import bcrypt
from sqlalchemy.orm import Session
from typing import Optional
from loguru import logger

from src.api.models import User


def create_break_glass_user(
    db: Session,
    email: str,
    password: str,
    full_name: str = "Break Glass Admin"
) -> User:
    """
    Create break glass user with local password.

    Args:
        db: Database session
        email: User email (must be ravance@gmail.com)
        password: Plain text password to hash
        full_name: Display name

    Returns:
        Created User object

    Raises:
        ValueError: If email is not allowed for break glass
    """
    if email != "ravance@gmail.com":
        raise ValueError("Break glass access only allowed for ravance@gmail.com")

    # Check if user already exists
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        logger.warning(f"Break glass user {email} already exists")
        return existing

    # Hash password with bcrypt (salt rounds = 12)
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # Create user
    user = User(
        email=email,
        username=email.split('@')[0],
        full_name=full_name,
        role='super_admin',
        access_type='both',
        local_password_hash=password_hash,
        auth_provider='local',
        is_active=True
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info(f"Break glass user created: {email}")
    return user


def verify_break_glass_password(
    db: Session,
    email: str,
    password: str
) -> Optional[User]:
    """
    Verify break glass local password.

    Args:
        db: Database session
        email: User email
        password: Plain text password to verify

    Returns:
        User object if credentials valid, None otherwise

    Raises:
        ValueError: If email is not allowed for break glass
    """
    if email != "ravance@gmail.com":
        raise ValueError("Break glass access only allowed for ravance@gmail.com")

    # Find user
    user = db.query(User).filter(User.email == email).first()
    if not user:
        logger.warning(f"Break glass login failed: user {email} not found")
        return None

    if not user.local_password_hash:
        logger.warning(f"Break glass login failed: no password set for {email}")
        return None

    if not user.is_active:
        logger.warning(f"Break glass login failed: user {email} is inactive")
        return None

    # Verify password
    if bcrypt.checkpw(password.encode(), user.local_password_hash.encode()):
        logger.info(f"Break glass login successful: {email}")
        return user
    else:
        logger.warning(f"Break glass login failed: invalid password for {email}")
        return None


def update_break_glass_password(
    db: Session,
    email: str,
    new_password: str
) -> User:
    """
    Update break glass password.

    Args:
        db: Database session
        email: User email
        new_password: New plain text password

    Returns:
        Updated User object

    Raises:
        ValueError: If email is not allowed or user not found
    """
    if email != "ravance@gmail.com":
        raise ValueError("Break glass access only allowed for ravance@gmail.com")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise ValueError(f"User {email} not found")

    # Hash new password
    password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    user.local_password_hash = password_hash

    db.commit()
    db.refresh(user)

    logger.info(f"Break glass password updated for {email}")
    return user
