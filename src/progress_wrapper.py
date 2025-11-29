"""
Reusable progress monitoring wrapper for subprocess execution.

This module provides a simple decorator/wrapper that adds intelligent progress
monitoring to any subprocess call with minimal code changes.
"""

import subprocess
import logging
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Try to import progress monitoring dependencies
try:
    import psutil
    from src.progress_monitor import ProgressMonitor
    from src.progress_helpers import register_process, unregister_process
    PROGRESS_AVAILABLE = True
except ImportError:
    PROGRESS_AVAILABLE = False
    logger.debug("Progress monitoring not available - install psutil to enable")


@dataclass
class ProgressConfig:
    """Configuration for progress monitoring."""
    enabled: bool = True
    min_cpu_threshold: float = 1.0
    check_interval: int = 30
    max_idle_time: int = 180


def run_with_progress_monitoring(
    cmd: List[str],
    repo_name: str,
    scanner_name: str,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    timeout: int = 600,
    progress_config: Optional[ProgressConfig] = None
) -> subprocess.CompletedProcess:
    """
    Run a subprocess with intelligent progress monitoring.
    
    This is a drop-in replacement for subprocess.run() that adds progress monitoring.
    
    Args:
        cmd: Command to run (list of strings)
        repo_name: Repository name (for process registry)
        scanner_name: Scanner name (for keyword detection)
        cwd: Working directory
        env: Environment variables
        timeout: Timeout in seconds
        progress_config: Progress monitoring configuration (None = use defaults)
        
    Returns:
        subprocess.CompletedProcess object
        
    Example:
        >>> result = run_with_progress_monitoring(
        ...     cmd=["semgrep", "scan", "--config", "auto"],
        ...     repo_name="my-repo",
        ...     scanner_name="semgrep",
        ...     cwd="/path/to/repo",
        ...     timeout=600
        ... )
    """
    if progress_config is None:
        progress_config = ProgressConfig()
    
    # Start subprocess
    process = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env
    )
    
    # Register for progress monitoring (if available and enabled)
    progress_monitor = None
    if PROGRESS_AVAILABLE and progress_config.enabled:
        try:
            ps_process = psutil.Process(process.pid)
            progress_monitor = ProgressMonitor(
                process=ps_process,
                scanner_name=scanner_name,
                min_cpu_threshold=progress_config.min_cpu_threshold,
                check_interval=progress_config.check_interval,
                max_idle_time=progress_config.max_idle_time
            )
            register_process(repo_name, {
                "pid": process.pid,
                "progress_monitor": progress_monitor,
                "scanner": scanner_name
            })
            logger.debug(f"Registered {scanner_name} process {process.pid} for progress monitoring")
        except Exception as monitor_err:
            logger.debug(f"Could not register progress monitor: {monitor_err}")
            progress_monitor = None
    
    try:
        # Read output with timeout
        stdout, stderr = process.communicate(timeout=timeout)
        
        # Feed output to progress monitor
        if progress_monitor:
            for line in (stdout + stderr).splitlines():
                progress_monitor.add_output(line)
        
        # Create CompletedProcess object
        result = subprocess.CompletedProcess(
            args=cmd,
            returncode=process.returncode,
            stdout=stdout if stdout else "",
            stderr=stderr if stderr else ""
        )
        
        return result
        
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise
        
    finally:
        # Unregister process
        if PROGRESS_AVAILABLE and progress_config.enabled:
            unregister_process(repo_name)


def progress_monitored(scanner_name: str, timeout: int = 600):
    """
    Decorator to add progress monitoring to scanner functions.
    
    The decorated function should accept (repo_path, repo_name, report_dir)
    and return a subprocess.CompletedProcess.
    
    Example:
        @progress_monitored(scanner_name="semgrep", timeout=600)
        def run_semgrep_scan(repo_path, repo_name, report_dir):
            cmd = ["semgrep", "scan", "--config", "auto"]
            # Function will automatically get progress monitoring
            return cmd, repo_path  # Return cmd and cwd
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(repo_path: str, repo_name: str, report_dir: str, **kwargs):
            # Call original function to get command and setup
            cmd, cwd = func(repo_path, repo_name, report_dir, **kwargs)
            
            # Run with progress monitoring
            return run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name=scanner_name,
                cwd=cwd,
                timeout=timeout,
                progress_config=kwargs.get('progress_config')
            )
        return wrapper
    return decorator


# Example usage:
"""
# Option 1: Direct wrapper
result = run_with_progress_monitoring(
    cmd=["semgrep", "scan", "--config", "auto"],
    repo_name="my-repo",
    scanner_name="semgrep",
    cwd="/path/to/repo",
    timeout=600
)

# Option 2: Decorator
@progress_monitored(scanner_name="trivy", timeout=1200)
def run_trivy_scan(repo_path, repo_name, report_dir):
    cmd = ["trivy", "fs", "--format", "json", repo_path]
    return cmd, repo_path

# Option 3: Disable progress monitoring
config = ProgressConfig(enabled=False)
result = run_with_progress_monitoring(
    cmd=["bandit", "-r", "."],
    repo_name="my-repo",
    scanner_name="bandit",
    cwd="/path/to/repo",
    progress_config=config
)
"""
