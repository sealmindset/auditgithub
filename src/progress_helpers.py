"""
Helper functions for progress-aware subprocess monitoring.

These functions wrap subprocess execution with intelligent progress monitoring
to avoid killing scans that are actively working.
"""

import time
import logging
import threading
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# Global registry to track active subprocess PIDs for progress monitoring
_active_processes: Dict[str, Any] = {}
_process_lock = threading.Lock()


def register_process(repo_name: str, process_info: Dict[str, Any]):
    """Register an active process for progress monitoring."""
    with _process_lock:
        _active_processes[repo_name] = process_info


def unregister_process(repo_name: str):
    """Unregister a completed process."""
    with _process_lock:
        _active_processes.pop(repo_name, None)


def get_process_info(repo_name: str) -> Optional[Dict[str, Any]]:
    """Get information about an active process."""
    with _process_lock:
        return _active_processes.get(repo_name)


def monitor_repo_progress(
    repo_name: str,
    timeout_minutes: int,
    check_interval: int = 30,
    max_idle_time: int = 180,
    min_cpu_threshold: float = 5.0
) -> Dict[str, Any]:
    """
    Monitor repository scan progress with intelligent timeout.
    
    Instead of a hard timeout, this monitors for actual progress:
    - New output from scanners
    - CPU activity
    - File I/O
    
    Only times out if no progress detected for max_idle_time seconds.
    
    Args:
        repo_name: Name of repository being scanned
        timeout_minutes: Initial timeout in minutes
        check_interval: Seconds between progress checks
        max_idle_time: Seconds of no progress before timeout
        min_cpu_threshold: Minimum CPU % to consider active
        
    Returns:
        Dict with monitoring results
    """
    start_time = time.time()
    initial_timeout = timeout_minutes * 60
    last_check = start_time
    total_checks = 0
    progress_extensions = 0
    
    logger.info(
        f"Progress monitoring started for {repo_name}: "
        f"initial_timeout={timeout_minutes}m, check_interval={check_interval}s, "
        f"max_idle={max_idle_time}s"
    )
    
    while True:
        elapsed = time.time() - start_time
        
        # Check if process is still registered (completed or failed)
        process_info = get_process_info(repo_name)
        if not process_info:
            logger.info(f"Process {repo_name} completed or terminated")
            return {
                "status": "completed",
                "elapsed": elapsed,
                "checks": total_checks,
                "extensions": progress_extensions
            }
        
        # Check if we've exceeded initial timeout
        if elapsed > initial_timeout:
            # Check for progress
            if "progress_monitor" in process_info:
                monitor = process_info["progress_monitor"]
                metrics = monitor.check_progress()
                
                if metrics.is_progressing:
                    # Scan is making progress, extend timeout
                    progress_extensions += 1
                    logger.info(
                        f"✓ Progress detected for {repo_name}: {metrics.progress_reason} "
                        f"(extension #{progress_extensions})"
                    )
                    # Extend by another timeout period
                    initial_timeout = elapsed + (timeout_minutes * 60)
                elif monitor.is_stuck():
                    # No progress for max_idle_time
                    idle_time = monitor.get_idle_time()
                    logger.warning(
                        f"⚠️  No progress for {repo_name}: {idle_time:.0f}s idle "
                        f"(threshold: {max_idle_time}s)"
                    )
                    return {
                        "status": "timeout",
                        "reason": "no_progress",
                        "elapsed": elapsed,
                        "idle_time": idle_time,
                        "checks": total_checks,
                        "extensions": progress_extensions,
                        "progress_summary": monitor.get_summary()
                    }
        
        # Sleep until next check
        time.sleep(check_interval)
        total_checks += 1
        last_check = time.time()
