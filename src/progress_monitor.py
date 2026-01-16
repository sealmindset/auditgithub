"""
Progress monitoring for long-running security scans.

Monitors subprocess progress to implement intelligent timeouts that only kill
truly stuck processes, not slow-but-working scans.
"""

import time
import logging
import psutil
import threading
from typing import Optional, Dict, Any, Callable, List
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ProgressMetrics:
    """Metrics about scan progress."""
    last_output_time: float
    total_output_lines: int
    cpu_percent: float
    memory_mb: float
    io_counters: Optional[Dict[str, int]]
    elapsed_time: float
    is_progressing: bool
    progress_reason: str


class ProgressMonitor:
    """
    Monitors subprocess progress to detect if it's stuck or actively working.
    
    Progress indicators:
    - New stdout/stderr output
    - CPU usage above threshold
    - File I/O activity
    - Scanner-specific keywords in output
    """
    
    # Scanner-specific progress keywords
    PROGRESS_KEYWORDS = {
        "semgrep": ["Scanning", "rules", "files", "findings", "Ran"],
        "trivy": ["Scanning", "Analyzing", "Detected", "Total"],
        "dependency-check": ["Checking", "Analyzing", "dependencies", "Processing"],
        "npm": ["npm", "vulnerabilities", "packages"],
        "pip-audit": ["Auditing", "Found", "vulnerabilities"],
        "safety": ["Scanning", "packages", "vulnerabilities"],
        "bandit": ["Run", "Test", "Issue"],
        "gitleaks": ["Finding", "commits", "secrets"],
        "grype": ["Cataloging", "Scanning", "Discovered"],
        "syft": ["Cataloging", "Discovered", "packages"],
    }
    
    def __init__(
        self,
        process: psutil.Process,
        scanner_name: str = "unknown",
        min_cpu_threshold: float = 1.0,
        check_interval: int = 30,
        max_idle_time: int = 180
    ):
        """
        Initialize progress monitor.
        
        Args:
            process: psutil.Process to monitor
            scanner_name: Name of scanner (for keyword detection)
            min_cpu_threshold: Minimum CPU % to consider active
            check_interval: Seconds between progress checks
            max_idle_time: Seconds of no progress before considering stuck
        """
        self.process = process
        self.scanner_name = scanner_name.lower()
        self.min_cpu_threshold = min_cpu_threshold
        self.check_interval = check_interval
        self.max_idle_time = max_idle_time
        
        # Progress tracking
        self.start_time = time.time()
        self.last_progress_time = self.start_time
        self.last_output_time = self.start_time
        self.output_lines = 0
        self.last_output_count = 0
        self.last_io_counters = None
        
        # Output buffer for keyword detection
        self.recent_output: List[str] = []
        self.max_buffer_size = 100
        
        logger.info(
            f"Progress monitor initialized for {scanner_name}: "
            f"check_interval={check_interval}s, max_idle={max_idle_time}s, "
            f"cpu_threshold={min_cpu_threshold}%"
        )
    
    def add_output(self, line: str):
        """
        Record new output line from subprocess.
        
        Args:
            line: Output line from subprocess
        """
        self.output_lines += 1
        self.last_output_time = time.time()
        
        # Keep recent output for keyword detection
        self.recent_output.append(line)
        if len(self.recent_output) > self.max_buffer_size:
            self.recent_output.pop(0)
    
    def check_progress(self) -> ProgressMetrics:
        """
        Check if subprocess is making progress.
        
        Returns:
            ProgressMetrics with current status
        """
        now = time.time()
        elapsed = now - self.start_time
        
        try:
            # Get process stats
            if not self.process.is_running():
                return ProgressMetrics(
                    last_output_time=self.last_output_time,
                    total_output_lines=self.output_lines,
                    cpu_percent=0.0,
                    memory_mb=0.0,
                    io_counters=None,
                    elapsed_time=elapsed,
                    is_progressing=False,
                    progress_reason="Process not running"
                )
            
            cpu_percent = self.process.cpu_percent(interval=0.1)
            memory_mb = self.process.memory_info().rss / 1024 / 1024
            
            # Get I/O counters if available
            io_counters = None
            try:
                io = self.process.io_counters()
                io_counters = {
                    "read_bytes": io.read_bytes,
                    "write_bytes": io.write_bytes
                }
            except (AttributeError, psutil.AccessDenied):
                pass
            
            # Check various progress indicators
            is_progressing, reason = self._detect_progress(
                cpu_percent, io_counters, now
            )
            
            if is_progressing:
                self.last_progress_time = now
            
            metrics = ProgressMetrics(
                last_output_time=self.last_output_time,
                total_output_lines=self.output_lines,
                cpu_percent=cpu_percent,
                memory_mb=memory_mb,
                io_counters=io_counters,
                elapsed_time=elapsed,
                is_progressing=is_progressing,
                progress_reason=reason
            )
            
            logger.debug(
                f"Progress check: {reason} | "
                f"CPU={cpu_percent:.1f}% | "
                f"Output={self.output_lines} lines | "
                f"Idle={(now - self.last_progress_time):.0f}s"
            )
            
            return metrics
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.warning(f"Error checking progress: {e}")
            return ProgressMetrics(
                last_output_time=self.last_output_time,
                total_output_lines=self.output_lines,
                cpu_percent=0.0,
                memory_mb=0.0,
                io_counters=None,
                elapsed_time=elapsed,
                is_progressing=False,
                progress_reason=f"Error: {str(e)}"
            )
    
    def _detect_progress(
        self,
        cpu_percent: float,
        io_counters: Optional[Dict[str, int]],
        now: float
    ) -> tuple[bool, str]:
        """
        Detect if process is making progress.
        
        Returns:
            (is_progressing, reason)
        """
        # Check 1: New output since last check
        if self.output_lines > self.last_output_count:
            new_lines = self.output_lines - self.last_output_count
            self.last_output_count = self.output_lines
            return (True, f"New output ({new_lines} lines)")
        
        # Check 2: CPU usage above threshold
        if cpu_percent > self.min_cpu_threshold:
            return (True, f"Active CPU ({cpu_percent:.1f}%)")
        
        # Check 3: File I/O activity
        if io_counters and self.last_io_counters:
            read_delta = io_counters["read_bytes"] - self.last_io_counters["read_bytes"]
            write_delta = io_counters["write_bytes"] - self.last_io_counters["write_bytes"]
            
            if read_delta > 1024 or write_delta > 1024:  # > 1KB
                self.last_io_counters = io_counters
                return (True, f"File I/O ({(read_delta + write_delta) / 1024:.1f} KB)")
        
        if io_counters:
            self.last_io_counters = io_counters
        
        # Check 4: Network activity (established connections)
        try:
            connections = self.process.connections()
            if connections:
                # If we have active connections, we're likely waiting on network I/O
                # This is common for scanners downloading databases (e.g. Dependency-Check NVD)
                return (True, f"Network activity ({len(connections)} connections)")
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        # Check 5: Scanner-specific keywords in recent output
        if self._has_progress_keywords():
            return (True, "Scanner progress keywords detected")
        
        # No progress detected
        idle_time = now - self.last_progress_time
        return (False, f"No progress ({idle_time:.0f}s idle)")
    
    def _has_progress_keywords(self) -> bool:
        """Check if recent output contains scanner-specific progress keywords."""
        keywords = self.PROGRESS_KEYWORDS.get(self.scanner_name, [])
        if not keywords or not self.recent_output:
            return False
        
        # Check last few output lines for keywords
        recent_text = " ".join(self.recent_output[-10:]).lower()
        return any(keyword.lower() in recent_text for keyword in keywords)
    
    def is_stuck(self) -> bool:
        """
        Check if process appears stuck (no progress for max_idle_time).
        
        Returns:
            True if stuck, False if still making progress
        """
        idle_time = time.time() - self.last_progress_time
        return idle_time >= self.max_idle_time
    
    def get_idle_time(self) -> float:
        """Get seconds since last progress was detected."""
        return time.time() - self.last_progress_time
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of progress monitoring session.
        
        Returns:
            Dictionary with progress summary
        """
        now = time.time()
        return {
            "scanner": self.scanner_name,
            "total_time": now - self.start_time,
            "idle_time": now - self.last_progress_time,
            "output_lines": self.output_lines,
            "last_output_age": now - self.last_output_time,
            "is_stuck": self.is_stuck()
        }
