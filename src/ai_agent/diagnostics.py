"""
Diagnostic data collector for stuck scans.

Collects comprehensive diagnostic information when a scan times out,
including repository metadata, system metrics, scanner progress, and logs.
"""

import logging
import os
import psutil
import time
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class DiagnosticCollector:
    """Collects diagnostic data for AI analysis of stuck scans."""
    
    def __init__(self, report_dir: str = "vulnerability_reports"):
        """
        Initialize the diagnostic collector.
        
        Args:
            report_dir: Directory where reports and logs are stored
        """
        self.report_dir = report_dir
        self.start_time = time.time()
    
    def collect(
        self,
        repo_name: str,
        scanner: str,
        phase: str,
        timeout_duration: int,
        repo_metadata: Optional[Dict[str, Any]] = None,
        scanner_progress: Optional[Dict[str, Any]] = None,
        recent_logs: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Collect comprehensive diagnostic data.
        
        Args:
            repo_name: Name of the repository
            scanner: Scanner that was running
            phase: Current phase of the scan
            timeout_duration: How long before timeout (seconds)
            repo_metadata: Optional repository metadata
            scanner_progress: Optional scanner progress information
            recent_logs: Optional recent log entries
            
        Returns:
            Dictionary of diagnostic data
        """
        try:
            diagnostic_data = {
                "repo_name": repo_name,
                "scanner": scanner,
                "phase": phase,
                "timeout_duration": timeout_duration,
                "timestamp": time.time(),
                "repo_metadata": repo_metadata or self._collect_repo_metadata(repo_name),
                "system_metrics": self._collect_system_metrics(),
                "scanner_progress": scanner_progress or {},
                "recent_logs": recent_logs or self._collect_recent_logs(repo_name, scanner),
                "historical_timeouts": self._count_historical_timeouts(repo_name),
                "environment": self._collect_environment_info()
            }
            
            logger.debug(f"Collected diagnostic data for {repo_name}")
            return diagnostic_data
            
        except Exception as e:
            logger.error(f"Failed to collect diagnostic data: {e}", exc_info=True)
            # Return minimal diagnostic data
            return {
                "repo_name": repo_name,
                "scanner": scanner,
                "phase": phase,
                "timeout_duration": timeout_duration,
                "error": str(e)
            }
    
    def _collect_repo_metadata(self, repo_name: str) -> Dict[str, Any]:
        """
        Collect repository metadata.
        
        Args:
            repo_name: Name of the repository
            
        Returns:
            Dictionary of repository metadata
        """
        try:
            repo_report_dir = Path(self.report_dir) / repo_name
            
            # Try to get repository size
            size_mb = 0
            file_count = 0
            if repo_report_dir.exists():
                for root, dirs, files in os.walk(repo_report_dir):
                    file_count += len(files)
                    for file in files:
                        try:
                            size_mb += os.path.getsize(os.path.join(root, file)) / (1024 * 1024)
                        except:
                            pass
            
            return {
                "size_mb": round(size_mb, 2),
                "file_count": file_count,
                "primary_language": "unknown",  # Could be enhanced with language detection
                "loc": 0  # Could be enhanced with line counting
            }
        except Exception as e:
            logger.warning(f"Failed to collect repo metadata: {e}")
            return {"error": str(e)}
    
    def _collect_system_metrics(self) -> Dict[str, Any]:
        """
        Collect current system resource metrics.
        
        Returns:
            Dictionary of system metrics
        """
        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_io_wait": psutil.cpu_times_percent(interval=0.1).iowait if hasattr(psutil.cpu_times_percent(interval=0.1), 'iowait') else 0,
                "available_memory_mb": round(psutil.virtual_memory().available / (1024 * 1024), 2),
                "disk_usage_percent": psutil.disk_usage('/').percent
            }
        except Exception as e:
            logger.warning(f"Failed to collect system metrics: {e}")
            return {"error": str(e)}
    
    def _collect_recent_logs(self, repo_name: str, scanner: str, max_lines: int = 100) -> List[str]:
        """
        Collect recent log entries for the scanner.
        
        Args:
            repo_name: Name of the repository
            scanner: Scanner name
            max_lines: Maximum number of log lines to collect
            
        Returns:
            List of recent log lines
        """
        try:
            log_file = Path(self.report_dir) / repo_name / f"{repo_name}_{scanner}.log"
            
            if not log_file.exists():
                return []
            
            # Read last N lines
            with open(log_file, 'r') as f:
                lines = f.readlines()
                return [line.strip() for line in lines[-max_lines:]]
                
        except Exception as e:
            logger.warning(f"Failed to collect recent logs: {e}")
            return []
    
    def _count_historical_timeouts(self, repo_name: str) -> int:
        """
        Count how many times this repository has timed out before.
        
        Args:
            repo_name: Name of the repository
            
        Returns:
            Number of historical timeouts
        """
        try:
            stuck_log = Path(self.report_dir) / "stuck_repos.log"
            
            if not stuck_log.exists():
                return 0
            
            count = 0
            with open(stuck_log, 'r') as f:
                for line in f:
                    if repo_name in line:
                        count += 1
            
            return count
            
        except Exception as e:
            logger.warning(f"Failed to count historical timeouts: {e}")
            return 0
    
    def _collect_environment_info(self) -> Dict[str, Any]:
        """
        Collect environment information.
        
        Returns:
            Dictionary of environment info
        """
        try:
            return {
                "python_version": os.sys.version.split()[0],
                "platform": os.sys.platform,
                "cpu_count": psutil.cpu_count(),
                "total_memory_gb": round(psutil.virtual_memory().total / (1024**3), 2)
            }
        except Exception as e:
            logger.warning(f"Failed to collect environment info: {e}")
            return {"error": str(e)}
