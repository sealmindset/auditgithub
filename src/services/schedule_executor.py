"""
Schedule Executor service.
Bridges ScanSchedule records with APScheduler for automatic scan execution.
"""
import asyncio
import logging
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, TYPE_CHECKING

# APScheduler imports (optional at import time for environments without it)
try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.date import DateTrigger
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False
    AsyncIOScheduler = None
    CronTrigger = None
    DateTrigger = None

from sqlalchemy.orm import Session

from src.api import models
from src.api.database import SessionLocal

logger = logging.getLogger(__name__)


class ScheduleExecutor:
    """Executes scans based on ScanSchedule records."""

    # Time window to hour mapping
    TIME_WINDOWS = {
        "morning": 8,
        "afternoon": 14,
        "evening": 20,
        "night": 2,
    }

    def __init__(self, scheduler: AsyncIOScheduler):
        """Initialize with APScheduler instance."""
        self.scheduler = scheduler
        self.logger = logging.getLogger(__name__)
        self._job_prefix = "schedule_"

    async def sync_schedules(self) -> int:
        """Load all active schedules and register with APScheduler."""
        db = SessionLocal()
        try:
            schedules = (
                db.query(models.ScanSchedule)
                .filter(models.ScanSchedule.is_active == True)
                .all()
            )

            count = 0
            for schedule in schedules:
                self._register_schedule(schedule, db)
                count += 1

            self.logger.info(f"Synced {count} schedules with APScheduler")
            return count
        finally:
            db.close()

    def _register_schedule(self, schedule: models.ScanSchedule, db: Session):
        """Register a single schedule with APScheduler."""
        job_id = f"{self._job_prefix}{schedule.id}"

        # Remove existing job if present
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)

        # Build cron trigger
        trigger = self._build_trigger(schedule, db)
        if not trigger:
            self.logger.warning(f"Could not build trigger for schedule {schedule.id}")
            return

        # Get repository info
        repo = db.query(models.Repository).filter(models.Repository.id == schedule.repository_id).first()
        org = db.query(models.Organization).filter(models.Organization.id == schedule.organization_id).first()

        if not repo or not org:
            self.logger.warning(f"Missing repo/org for schedule {schedule.id}")
            return

        # Register the job
        self.scheduler.add_job(
            self._execute_scan,
            trigger=trigger,
            id=job_id,
            name=f"Scan {repo.name}",
            kwargs={
                "schedule_id": str(schedule.id),
                "org_name": org.name,
                "repo_name": repo.name,
                "scan_arguments": schedule.scan_arguments or {},
            },
            replace_existing=True
        )

        # Update next_scheduled_at
        next_run = trigger.get_next_fire_time(None, datetime.now(timezone.utc))
        if next_run:
            schedule.next_scheduled_at = next_run
            db.commit()

    def _build_trigger(self, schedule: models.ScanSchedule, db: Session) -> Optional[CronTrigger]:
        """Convert schedule to APScheduler CronTrigger."""
        hour = self.TIME_WINDOWS.get(schedule.time_window, 2)
        day_of_week = schedule.day_of_week  # 0=Mon, 6=Sun

        try:
            if schedule.frequency == "daily":
                return CronTrigger(hour=hour, minute=0)
            elif schedule.frequency == "weekly":
                dow = day_of_week if day_of_week is not None else 0
                return CronTrigger(day_of_week=dow, hour=hour, minute=0)
            elif schedule.frequency == "bi-weekly":
                # APScheduler doesn't have bi-weekly; use weekly + skip logic in executor
                dow = day_of_week if day_of_week is not None else 0
                return CronTrigger(day_of_week=dow, hour=hour, minute=0)
            elif schedule.frequency == "monthly":
                return CronTrigger(day=1, hour=hour, minute=0)
            elif schedule.frequency == "annually":
                # Annual scan on anniversary of last commit
                repo = db.query(models.Repository).filter(models.Repository.id == schedule.repository_id).first()
                if repo and repo.pushed_at:
                    # Use month and day from last commit date
                    return CronTrigger(month=repo.pushed_at.month, day=repo.pushed_at.day, hour=hour, minute=0)
                else:
                    # Fallback to January 1st if no commit date
                    return CronTrigger(month=1, day=1, hour=hour, minute=0)
            else:
                self.logger.warning(f"Unknown frequency: {schedule.frequency}")
                return None
        except Exception as e:
            self.logger.error(f"Error building trigger: {e}")
            return None

    async def _execute_scan(
        self,
        schedule_id: str,
        org_name: str,
        repo_name: str,
        scan_arguments: Dict
    ):
        """Execute a scan for a scheduled repository."""
        self.logger.info(f"Executing scheduled scan: {org_name}/{repo_name}")

        db = SessionLocal()
        try:
            # Get the schedule and check bi-weekly skip
            schedule = db.query(models.ScanSchedule).filter(
                models.ScanSchedule.id == schedule_id
            ).first()

            if not schedule:
                self.logger.error(f"Schedule {schedule_id} not found")
                return

            # Bi-weekly skip logic
            if schedule.frequency == "bi-weekly" and schedule.last_executed_at:
                days_since_last = (datetime.now(timezone.utc) - schedule.last_executed_at).days
                if days_since_last < 10:  # Less than ~1.5 weeks
                    self.logger.info(f"Skipping bi-weekly scan (only {days_since_last} days since last)")
                    return

            # Build command
            cmd = ["python", "scripts/scanning/scan_repos.py", "--target", org_name, "--repo", repo_name]

            # Add custom arguments
            if scan_arguments.get("overridescan"):
                cmd.append("--overridescan")

            # Execute scan
            schedule.last_execution_status = "running"
            db.commit()

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600 * 2  # 2 hour timeout per repo
            )

            # Update status
            schedule.last_executed_at = datetime.now(timezone.utc)
            if result.returncode == 0:
                schedule.last_execution_status = "success"
                self.logger.info(f"Scan completed: {org_name}/{repo_name}")
            else:
                schedule.last_execution_status = "failed"
                self.logger.error(f"Scan failed: {result.stderr[-500:]}")

            # Update next_scheduled_at
            job = self.scheduler.get_job(f"{self._job_prefix}{schedule_id}")
            if job:
                next_run = job.next_run_time
                schedule.next_scheduled_at = next_run

            db.commit()

        except subprocess.TimeoutExpired:
            self.logger.error(f"Scan timed out: {org_name}/{repo_name}")
            if schedule:
                schedule.last_execution_status = "failed"
                schedule.last_executed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            if schedule:
                schedule.last_execution_status = "failed"
                db.commit()
        finally:
            db.close()

    async def trigger_immediate(self, schedule_id: str) -> bool:
        """Trigger an immediate scan for a schedule."""
        db = SessionLocal()
        try:
            schedule = db.query(models.ScanSchedule).filter(
                models.ScanSchedule.id == schedule_id
            ).first()

            if not schedule:
                return False

            repo = db.query(models.Repository).filter(
                models.Repository.id == schedule.repository_id
            ).first()
            org = db.query(models.Organization).filter(
                models.Organization.id == schedule.organization_id
            ).first()

            if not repo or not org:
                return False

            # Add one-time job
            self.scheduler.add_job(
                self._execute_scan,
                trigger=DateTrigger(run_date=datetime.now(timezone.utc) + timedelta(seconds=5)),
                id=f"immediate_{schedule_id}",
                kwargs={
                    "schedule_id": str(schedule.id),
                    "org_name": org.name,
                    "repo_name": repo.name,
                    "scan_arguments": schedule.scan_arguments or {},
                },
                replace_existing=True
            )
            return True
        finally:
            db.close()

    def remove_schedule(self, schedule_id: str):
        """Remove a schedule from APScheduler."""
        job_id = f"{self._job_prefix}{schedule_id}"
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)
            self.logger.info(f"Removed schedule job: {job_id}")
