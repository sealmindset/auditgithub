"""
Session lifecycle management with expiry tracking and activity monitoring.

Implements:
- Session metadata storage (created_at, last_activity) in Redis
- Dual timeout enforcement (absolute + idle)
- Activity tracking for idle timeout calculations
- Session cleanup helpers
"""

from pydantic import BaseModel
from datetime import datetime
import json
from typing import Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# Import Redis client from tokens module
from src.auth.tokens import redis_client


class SessionMetadata(BaseModel):
    """
    Session metadata for expiry and activity tracking.

    Stored separately from session cookie to reduce cookie size
    and enable server-side timeout enforcement.
    """
    user_sub: str
    tenant_id: str
    created_at: datetime
    last_activity: datetime
    provider: str

    def is_expired(
        self,
        absolute_timeout_hours: int,
        idle_timeout_minutes: int
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if session is expired based on absolute or idle timeout.

        Args:
            absolute_timeout_hours: Maximum session lifetime (e.g., 8 hours)
            idle_timeout_minutes: Maximum idle time (e.g., 30 minutes)

        Returns:
            (is_expired, reason): Tuple of (bool, str or None)
                - is_expired: True if session expired
                - reason: "absolute" or "idle" if expired, None otherwise

        Example:
            >>> metadata = SessionMetadata(...)
            >>> is_expired, reason = metadata.is_expired(8, 30)
            >>> if is_expired:
            ...     print(f"Session expired due to {reason} timeout")
        """
        now = datetime.utcnow()

        # Check absolute timeout (max session lifetime)
        age_hours = (now - self.created_at).total_seconds() / 3600
        if age_hours > absolute_timeout_hours:
            logger.debug(f"Session expired: absolute timeout ({age_hours:.1f}h > {absolute_timeout_hours}h)")
            return (True, "absolute")

        # Check idle timeout (inactivity)
        idle_minutes = (now - self.last_activity).total_seconds() / 60
        if idle_minutes > idle_timeout_minutes:
            logger.debug(f"Session expired: idle timeout ({idle_minutes:.1f}m > {idle_timeout_minutes}m)")
            return (True, "idle")

        return (False, None)


def get_session_metadata(session_id: str) -> Optional[SessionMetadata]:
    """
    Fetch session metadata from Redis.

    Args:
        session_id: Session identifier (from Starlette session cookie)

    Returns:
        SessionMetadata if found, None otherwise
    """
    try:
        data = redis_client.get(f"session:{session_id}")
        if data:
            return SessionMetadata(**json.loads(data))
        return None
    except Exception as e:
        logger.warning(f"Failed to fetch session metadata for {session_id}: {e}")
        return None


def set_session_metadata(
    session_id: str,
    metadata: SessionMetadata,
    ttl_hours: int
):
    """
    Store session metadata in Redis with TTL.

    Args:
        session_id: Session identifier
        metadata: SessionMetadata to store
        ttl_hours: Time-to-live in hours (should match absolute timeout)

    Note:
        TTL provides automatic cleanup for abandoned sessions.
        Redis will auto-delete the key after TTL expires.
    """
    try:
        redis_client.setex(
            f"session:{session_id}",
            ttl_hours * 3600,  # Convert hours to seconds
            json.dumps(metadata.dict(), default=str)
        )
        logger.debug(f"Session metadata stored for {session_id} (TTL: {ttl_hours}h)")
    except Exception as e:
        logger.error(f"Failed to store session metadata for {session_id}: {e}")
        raise


def update_last_activity(session_id: str):
    """
    Update last_activity timestamp for a session.

    Args:
        session_id: Session identifier

    Note:
        Called on every authenticated request to track activity
        for idle timeout calculations. Non-blocking - logs warning
        on failure but doesn't block request.
    """
    try:
        metadata = get_session_metadata(session_id)
        if metadata:
            metadata.last_activity = datetime.utcnow()

            # Update metadata in Redis with same TTL
            from src.auth.config import settings
            set_session_metadata(
                session_id,
                metadata,
                settings.session_absolute_timeout_hours if hasattr(settings, 'session_absolute_timeout_hours') else 8
            )
            logger.debug(f"Updated last_activity for session {session_id}")
        else:
            logger.debug(f"Session metadata not found for {session_id}, skipping activity update")
    except Exception as e:
        logger.warning(f"Failed to update activity for session {session_id}: {e}")
        # Don't raise - activity update failure shouldn't block requests


def delete_session(session_id: str):
    """
    Delete session metadata from Redis.

    Args:
        session_id: Session identifier

    Use cases:
        - Manual session cleanup (logout, revocation)
        - Expired session removal
    """
    try:
        redis_client.delete(f"session:{session_id}")
        logger.debug(f"Deleted session metadata for {session_id}")
    except Exception as e:
        logger.warning(f"Failed to delete session metadata for {session_id}: {e}")


def create_session_metadata(
    session_id: str,
    user_sub: str,
    tenant_id: str,
    provider: str
):
    """
    Create new session metadata on login.

    Args:
        session_id: Session identifier
        user_sub: User's unique identifier (sub claim)
        tenant_id: Tenant UUID
        provider: OIDC provider name ("entra", "okta")

    Note:
        Should be called during OAuth callback flow after successful
        authentication to initialize session tracking.
    """
    from src.auth.config import settings

    metadata = SessionMetadata(
        user_sub=user_sub,
        tenant_id=tenant_id,
        created_at=datetime.utcnow(),
        last_activity=datetime.utcnow(),
        provider=provider
    )

    absolute_timeout = settings.session_absolute_timeout_hours if hasattr(settings, 'session_absolute_timeout_hours') else 8
    set_session_metadata(session_id, metadata, absolute_timeout)

    logger.info(f"Created session metadata for {user_sub} (session: {session_id})")
