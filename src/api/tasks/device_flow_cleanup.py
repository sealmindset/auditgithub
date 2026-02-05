"""
Device Flow Cleanup Task

Periodic background task to mark expired device flow requests.
Runs every hour to clean up pending requests that have passed their expiration time.

This prevents the database from accumulating stale pending requests
and provides better user feedback when codes expire.
"""
import schedule
import time
from datetime import datetime
from loguru import logger

from src.api.database import SessionLocal
from src.auth.device_flow import cleanup_expired_requests


def run_cleanup():
    """
    Mark expired device flow requests.

    Finds all device_flow_requests with:
    - status = 'pending'
    - expires_at < current time

    Updates their status to 'expired' for tracking and analytics.
    """
    db = SessionLocal()
    try:
        expired_count = cleanup_expired_requests(db)

        if expired_count > 0:
            logger.bind(task="device_flow_cleanup").info(
                f"Marked {expired_count} expired device flow requests"
            )

    except Exception as e:
        logger.bind(task="device_flow_cleanup").error(
            f"Error during cleanup: {e}"
        )
    finally:
        db.close()


def start_scheduler():
    """
    Start the background cleanup scheduler.

    Runs cleanup every hour indefinitely.
    Should be started as a separate process or background thread.
    """
    # Schedule cleanup every hour
    schedule.every(1).hours.do(run_cleanup)

    logger.bind(task="device_flow_cleanup").info(
        "Device flow cleanup scheduler started (runs every hour)"
    )

    # Run immediately on startup
    run_cleanup()

    # Main scheduler loop
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute


if __name__ == "__main__":
    """
    Run as standalone process:
    python -m src.api.tasks.device_flow_cleanup
    """
    logger.info("Starting device flow cleanup task...")
    start_scheduler()
