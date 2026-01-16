#!/usr/bin/env python3
"""
Background job to clean up expired sessions from Redis.

Runs every 5 minutes and removes session metadata for expired sessions.
This prevents Redis memory leaks from abandoned sessions.

Usage:
    python -m src.auth.cleanup

Docker:
    Add to docker-compose.yml as a separate service that runs continuously.
"""

import schedule
import time
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def cleanup_expired_sessions():
    """
    Scan Redis for expired sessions and delete them.

    Uses SCAN cursor to avoid blocking Redis on large datasets.
    This is a belt-and-suspenders approach - Redis TTL provides
    automatic cleanup, but this job catches any stragglers.
    """
    from src.auth.tokens import redis_client
    from src.auth.session import SessionMetadata
    from src.auth.config import settings
    import json

    logger.info("Running session cleanup job...")

    cleaned_count = 0
    scanned_count = 0
    cursor = 0

    try:
        while True:
            # SCAN for session keys (cursor-based to avoid blocking)
            cursor, keys = redis_client.scan(
                cursor=cursor,
                match="session:*",
                count=100  # Process 100 keys per iteration
            )

            for key in keys:
                scanned_count += 1

                try:
                    # Check if key still exists (may have auto-expired via TTL)
                    if not redis_client.exists(key):
                        continue

                    # Fetch metadata
                    data = redis_client.get(key)
                    if not data:
                        continue

                    metadata = SessionMetadata(**json.loads(data))

                    # Check if expired
                    is_expired, reason = metadata.is_expired(
                        settings.session_absolute_timeout_hours,
                        settings.session_idle_timeout_minutes
                    )

                    if is_expired:
                        redis_client.delete(key)
                        cleaned_count += 1
                        logger.debug(f"Cleaned session {key} (reason: {reason})")

                except Exception as e:
                    logger.warning(f"Error checking session {key}: {e}")

            # Break if cursor returned to 0 (full scan complete)
            if cursor == 0:
                break

        logger.info(
            f"Session cleanup complete: {cleaned_count} sessions removed "
            f"({scanned_count} scanned)"
        )

    except Exception as e:
        logger.error(f"Session cleanup job failed: {e}")


def start_cleanup_scheduler():
    """
    Start background scheduler for session cleanup.

    Runs cleanup job every 5 minutes to prevent Redis memory leaks
    from abandoned sessions.
    """
    # Run every 5 minutes
    schedule.every(5).minutes.do(cleanup_expired_sessions)

    logger.info("Session cleanup scheduler started (runs every 5 minutes)")

    # Run immediately on startup
    cleanup_expired_sessions()

    # Keep running
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute


if __name__ == "__main__":
    start_cleanup_scheduler()
