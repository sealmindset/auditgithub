"""
Scheduler Service for AuditGH

Provides configurable cron-based scheduling for:
- Self-Annealing Data Integrity Agent
- Automated Repository Scanning
- New Repository Auto-Scanning
- Organization Backups

Configuration via environment variables:
- SCHEDULER_ENABLED: Master switch for scheduler
- ANNEALING_CRON/ENABLED: Data integrity checks
- SCAN_CRON/ENABLED: Repository scanning
- SCAN_NEW_REPOS_CRON/ENABLED: New repo auto-scanning
- BACKUP_CRON/ENABLED: Organization backups
"""

import os
import sys
import logging
import asyncio
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from src.services.schedule_executor import ScheduleExecutor
from dataclasses import dataclass, field
from threading import Thread

# APScheduler for cron-based scheduling
try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ScheduledJob:
    """Configuration for a scheduled job."""
    name: str
    cron_expression: str
    enabled: bool
    handler: Callable
    description: str
    last_run: Optional[datetime] = None
    last_status: str = "never_run"
    last_error: Optional[str] = None
    run_count: int = 0
    error_count: int = 0


class SchedulerService:
    """
    Manages scheduled tasks for AuditGH.
    
    Uses APScheduler with AsyncIO for non-blocking execution.
    Falls back to a simple threading-based scheduler if APScheduler unavailable.
    """
    
    def __init__(self):
        self.enabled = os.getenv("SCHEDULER_ENABLED", "true").lower() == "true"
        # Off by default: registering every repository schedule as a cron job
        # points ~2500 scans at one shared GitHub PAT. See src/api/utils/github_budget.py.
        self.auto_register_repo_scans = (
            os.getenv("SCHEDULER_AUTO_REGISTER_REPO_SCANS", "false").lower() == "true"
        )
        self.jobs: Dict[str, ScheduledJob] = {}
        self.scheduler: Optional[AsyncIOScheduler] = None
        self.schedule_executor: Optional['ScheduleExecutor'] = None
        self._running = False

        if not APSCHEDULER_AVAILABLE:
            logger.warning("APScheduler not installed. Run: pip install apscheduler")
            self.enabled = False
    
    def configure(self):
        """Configure all scheduled jobs from environment variables."""
        if not self.enabled:
            logger.info("Scheduler is disabled (SCHEDULER_ENABLED=false)")
            return
        
        # Data Integrity Agent (Self-Annealing)
        self._add_job(
            name="annealing",
            cron_env="ANNEALING_CRON",
            enabled_env="ANNEALING_ENABLED",
            default_cron="0 3 * * *",
            handler=self._run_annealing,
            description="Self-Annealing Data Integrity Agent"
        )
        
        # Automated Scanning
        self._add_job(
            name="scan",
            cron_env="SCAN_CRON",
            enabled_env="SCAN_ENABLED",
            default_cron="0 */6 * * *",
            handler=self._run_scan,
            description="Automated Repository Scanning"
        )
        
        # Organization Backups
        self._add_job(
            name="backup",
            cron_env="BACKUP_CRON",
            enabled_env="BACKUP_ENABLED",
            default_cron="0 2 * * 0",
            handler=self._run_backup,
            description="Organization Backup"
        )

        # New Repo Auto-Scanner
        self._add_job(
            name="scan_new_repos",
            cron_env="SCAN_NEW_REPOS_CRON",
            enabled_env="SCAN_NEW_REPOS_ENABLED",
            default_cron="0 2 * * *",  # 2 AM daily
            handler=self._run_scan_new_repos,
            description="Auto-scan new repositories"
        )

        logger.info(f"Scheduler configured with {len([j for j in self.jobs.values() if j.enabled])} active jobs")
    
    def _add_job(
        self,
        name: str,
        cron_env: str,
        enabled_env: str,
        default_cron: str,
        handler: Callable,
        description: str
    ):
        """Add a job to the scheduler configuration."""
        cron_expr = os.getenv(cron_env, default_cron)
        enabled = os.getenv(enabled_env, "false").lower() == "true"
        
        self.jobs[name] = ScheduledJob(
            name=name,
            cron_expression=cron_expr,
            enabled=enabled,
            handler=handler,
            description=description
        )
        
        status = "✓ enabled" if enabled else "○ disabled"
        logger.info(f"  [{status}] {name}: {cron_expr} - {description}")
    
    async def start(self):
        """Start the scheduler."""
        if not self.enabled or self._running:
            return
        
        if not APSCHEDULER_AVAILABLE:
            logger.error("Cannot start scheduler: APScheduler not installed")
            return
        
        self.scheduler = AsyncIOScheduler()
        
        # Add event listeners
        self.scheduler.add_listener(self._on_job_executed, EVENT_JOB_EXECUTED)
        self.scheduler.add_listener(self._on_job_error, EVENT_JOB_ERROR)
        
        # Register enabled jobs
        for job_name, job in self.jobs.items():
            if job.enabled:
                try:
                    trigger = CronTrigger.from_crontab(job.cron_expression)
                    self.scheduler.add_job(
                        job.handler,
                        trigger=trigger,
                        id=job_name,
                        name=job.description,
                        replace_existing=True
                    )
                    logger.info(f"Scheduled job: {job_name} ({job.cron_expression})")
                except Exception as e:
                    logger.error(f"Failed to schedule {job_name}: {e}")
        
        self.scheduler.start()
        self._running = True
        logger.info("Scheduler started")

        # Initialize ScheduleExecutor for database-driven schedules. The executor
        # is always constructed so on-demand runs (/schedules/{id}/run) work, but
        # the ~2500 per-repository cron jobs are only registered when explicitly
        # enabled: they all share one GitHub PAT and one 5000/hr rate limit, and
        # registering them drained the whole budget in a single window, starving
        # interactive and operator-triggered work.
        from src.services.schedule_executor import ScheduleExecutor
        self.schedule_executor = ScheduleExecutor(self.scheduler)

        if self.auto_register_repo_scans:
            await self.schedule_executor.sync_schedules()
            self.scheduler.add_job(
                self.schedule_executor.sync_schedules,
                trigger=CronTrigger(minute=0),  # Every hour
                id="schedule_sync",
                name="Sync Repository Schedules",
                replace_existing=True
            )
        else:
            pending = self.schedule_executor.count_active_schedules()
            logger.info(
                "Repository scan cron jobs NOT registered "
                "(SCHEDULER_AUTO_REGISTER_REPO_SCANS=false): %d active schedules "
                "remain on-demand only. They are still visible in the API and can "
                "be run via POST /schedules/{id}/run.",
                pending,
            )
    
    async def stop(self):
        """Stop the scheduler."""
        if self.scheduler and self._running:
            self.scheduler.shutdown(wait=False)
            self._running = False
            logger.info("Scheduler stopped")
    
    def _on_job_executed(self, event):
        """Handle successful job execution."""
        job_name = event.job_id
        if job_name in self.jobs:
            job = self.jobs[job_name]
            job.last_run = datetime.now(timezone.utc)
            job.last_status = "success"
            job.run_count += 1
            logger.info(f"Job completed: {job_name}")
    
    def _on_job_error(self, event):
        """Handle job execution error."""
        job_name = event.job_id
        if job_name in self.jobs:
            job = self.jobs[job_name]
            job.last_run = datetime.now(timezone.utc)
            job.last_status = "error"
            job.last_error = str(event.exception)
            job.error_count += 1
            logger.error(f"Job failed: {job_name} - {event.exception}")
    
    # -------------------------------------------------------------------------
    # Job Handlers
    # -------------------------------------------------------------------------
    
    async def _run_annealing(self):
        """Execute the self-annealing data integrity agent."""
        logger.info("=" * 60)
        logger.info("SCHEDULED: Self-Annealing Data Integrity Agent")
        logger.info("=" * 60)
        
        dry_run = os.getenv("ANNEALING_DRY_RUN", "false").lower() == "true"
        
        try:
            # Import and run the agent
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from scripts.self_annealing_agent import SelfAnnealingAgent
            
            with SelfAnnealingAgent(dry_run=dry_run) as agent:
                report = agent.run()
                
            logger.info(f"Annealing complete: {report.issues_repaired} repaired, "
                       f"{len(report.issues_failed)} failed, "
                       f"Quality Score: {report.data_quality_score:.1f}%")
            
            return {
                "status": "success",
                "issues_detected": len(report.issues_detected),
                "issues_repaired": len(report.issues_repaired),
                "data_quality_score": report.data_quality_score
            }
            
        except Exception as e:
            logger.error(f"Annealing failed: {e}")
            raise
    
    async def _run_scan(self):
        """Execute automated repository scanning."""
        logger.info("=" * 60)
        logger.info("SCHEDULED: Automated Repository Scanning")
        logger.info("=" * 60)
        
        target = os.getenv("SCAN_TARGET", "").strip()
        
        try:
            cmd = ["python", "scan_repos.py"]
            if target:
                cmd.extend(["--target", target])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600 * 4  # 4 hour timeout
            )
            
            if result.returncode == 0:
                logger.info("Scan completed successfully")
                return {"status": "success", "output": result.stdout[-1000:]}
            else:
                logger.error(f"Scan failed: {result.stderr[-500:]}")
                raise RuntimeError(result.stderr[-500:])
                
        except subprocess.TimeoutExpired:
            logger.error("Scan timed out after 4 hours")
            raise
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
    
    async def _run_backup(self):
        """Execute organization backup."""
        logger.info("=" * 60)
        logger.info("SCHEDULED: Organization Backup")
        logger.info("=" * 60)
        
        backup_all = os.getenv("BACKUP_ALL_ORGS", "true").lower() == "true"
        
        try:
            cmd = ["python", "scripts/backup_organization.py"]
            if backup_all:
                cmd.append("--all")
            cmd.extend(["--output", "backups/"])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minute timeout
            )
            
            if result.returncode == 0:
                logger.info("Backup completed successfully")
                return {"status": "success", "output": result.stdout[-1000:]}
            else:
                logger.error(f"Backup failed: {result.stderr[-500:]}")
                raise RuntimeError(result.stderr[-500:])
                
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            raise

    async def _run_scan_new_repos(self):
        """Execute scan for new repositories that have never been scanned."""
        logger.info("=" * 60)
        logger.info("SCHEDULED: Auto-scan New Repositories")
        logger.info("=" * 60)

        try:
            cmd = ["python", "scan_repos.py", "--new-repos-only"]

            # Optional: Add target organization if configured
            target = os.getenv("SCAN_TARGET", "").strip()
            if target:
                cmd.extend(["--target", target])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600 * 2  # 2 hour timeout (shorter than full scan)
            )

            if result.returncode == 0:
                logger.info("New repo scan completed successfully")
                return {"status": "success", "output": result.stdout[-1000:]}
            else:
                logger.error(f"New repo scan failed: {result.stderr[-500:]}")
                raise RuntimeError(result.stderr[-500:])

        except subprocess.TimeoutExpired:
            logger.error("New repo scan timed out after 2 hours")
            raise
        except Exception as e:
            logger.error(f"New repo scan failed: {e}")
            raise

    # -------------------------------------------------------------------------
    # Manual Triggers
    # -------------------------------------------------------------------------
    
    async def trigger_job(self, job_name: str) -> Dict[str, Any]:
        """Manually trigger a job."""
        if job_name not in self.jobs:
            raise ValueError(f"Unknown job: {job_name}")
        
        job = self.jobs[job_name]
        logger.info(f"Manually triggering job: {job_name}")
        
        try:
            result = await job.handler()
            job.last_run = datetime.now(timezone.utc)
            job.last_status = "success"
            job.run_count += 1
            return {"status": "success", "result": result}
        except Exception as e:
            job.last_run = datetime.now(timezone.utc)
            job.last_status = "error"
            job.last_error = str(e)
            job.error_count += 1
            return {"status": "error", "error": str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """Get scheduler status and job information."""
        return {
            "enabled": self.enabled,
            "running": self._running,
            "jobs": {
                name: {
                    "description": job.description,
                    "cron": job.cron_expression,
                    "enabled": job.enabled,
                    "last_run": job.last_run.isoformat() if job.last_run else None,
                    "last_status": job.last_status,
                    "last_error": job.last_error,
                    "run_count": job.run_count,
                    "error_count": job.error_count
                }
                for name, job in self.jobs.items()
            }
        }


# Global scheduler instance
scheduler_service = SchedulerService()


def get_scheduler() -> SchedulerService:
    """Get the global scheduler instance."""
    return scheduler_service
