"""
Safe Subprocess Execution - Enhanced subprocess handling with strict timeouts.

Provides reliable subprocess execution that:
- Never hangs indefinitely
- Properly kills process trees on timeout
- Handles edge cases with problematic inputs
- Provides detailed error information
"""
import subprocess
import signal
import os
import sys
import logging
import time
from typing import List, Optional, Dict, Any, Union
from contextlib import contextmanager
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class SubprocessTimeout(Exception):
    """Raised when a subprocess exceeds its timeout."""

    def __init__(self, message: str, cmd: List[str], timeout: int, partial_output: str = ""):
        super().__init__(message)
        self.cmd = cmd
        self.timeout = timeout
        self.partial_output = partial_output


class SubprocessError(Exception):
    """Raised when a subprocess fails with an error."""

    def __init__(self, message: str, cmd: List[str], returncode: int, stderr: str = ""):
        super().__init__(message)
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr


@dataclass
class SafeProcessResult:
    """Result from safe subprocess execution."""
    args: List[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_seconds: float = 0.0

    def to_completed_process(self) -> subprocess.CompletedProcess:
        """Convert to standard CompletedProcess for compatibility."""
        return subprocess.CompletedProcess(
            args=self.args,
            returncode=self.returncode,
            stdout=self.stdout,
            stderr=self.stderr
        )


def _kill_process_tree(pid: int) -> None:
    """
    Kill a process and all its children.

    Uses process group on Unix, taskkill on Windows.
    """
    try:
        if os.name == 'nt':
            # Windows: use taskkill to kill process tree
            subprocess.run(
                ['taskkill', '/F', '/T', '/PID', str(pid)],
                capture_output=True,
                timeout=10
            )
        else:
            # Unix: kill the process group
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except ProcessLookupError:
                pass  # Process already dead
            except PermissionError:
                # Fallback to just killing the process
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    except Exception as e:
        logger.debug(f"Error killing process tree {pid}: {e}")


def run_safe(
    cmd: List[str],
    timeout: int = 300,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    check: bool = False,
    capture_output: bool = True,
    stdin_data: Optional[str] = None,
    kill_on_timeout: bool = True
) -> SafeProcessResult:
    """
    Run a subprocess with strict timeout handling.

    This function ensures:
    - Process never runs longer than timeout
    - Process tree is killed on timeout (not just the parent)
    - stdin is closed to prevent hanging on input
    - Partial output is captured even on timeout

    Args:
        cmd: Command and arguments as list (never use shell=True)
        timeout: Maximum seconds to wait (default 5 minutes)
        cwd: Working directory
        env: Environment variables (merged with current)
        check: Raise SubprocessError on non-zero exit
        capture_output: Capture stdout/stderr (default True)
        stdin_data: Data to send to stdin (closes stdin after)
        kill_on_timeout: Kill process on timeout (default True)

    Returns:
        SafeProcessResult with execution results

    Raises:
        SubprocessTimeout: If process exceeds timeout and kill_on_timeout=True
        SubprocessError: If check=True and returncode != 0
    """
    start_time = time.time()

    # Merge environment
    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    # Prepare Popen kwargs
    popen_kwargs = {
        'stdout': subprocess.PIPE if capture_output else subprocess.DEVNULL,
        'stderr': subprocess.PIPE if capture_output else subprocess.DEVNULL,
        'stdin': subprocess.PIPE if stdin_data else subprocess.DEVNULL,
        'cwd': cwd,
        'env': full_env,
    }

    # On Unix, create a new process group for clean termination
    if os.name != 'nt':
        popen_kwargs['preexec_fn'] = os.setsid

    # Start process
    try:
        process = subprocess.Popen(cmd, **popen_kwargs)
    except FileNotFoundError as e:
        return SafeProcessResult(
            args=cmd,
            returncode=127,
            stdout="",
            stderr=f"Command not found: {cmd[0]}",
            timed_out=False,
            duration_seconds=0
        )
    except PermissionError as e:
        return SafeProcessResult(
            args=cmd,
            returncode=126,
            stdout="",
            stderr=f"Permission denied: {cmd[0]}",
            timed_out=False,
            duration_seconds=0
        )

    stdout = ""
    stderr = ""
    timed_out = False

    try:
        # Send stdin data if provided
        stdin_bytes = stdin_data.encode() if stdin_data else None

        # Wait with timeout
        stdout_bytes, stderr_bytes = process.communicate(
            input=stdin_bytes,
            timeout=timeout
        )

        stdout = stdout_bytes.decode('utf-8', errors='replace') if stdout_bytes else ""
        stderr = stderr_bytes.decode('utf-8', errors='replace') if stderr_bytes else ""

    except subprocess.TimeoutExpired:
        timed_out = True
        logger.warning(f"Process timed out after {timeout}s: {' '.join(cmd[:3])}...")

        if kill_on_timeout:
            # Kill the entire process tree
            _kill_process_tree(process.pid)

            # Wait for process to actually terminate
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Force kill if still alive
                try:
                    process.kill()
                    process.wait(timeout=5)
                except (ProcessLookupError, PermissionError, OSError) as e:
                    logger.warning(f"Failed to force kill process {process.pid}: {str(e)}")

        # Try to get any partial output
        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=1)
            stdout = stdout_bytes.decode('utf-8', errors='replace') if stdout_bytes else ""
            stderr = stderr_bytes.decode('utf-8', errors='replace') if stderr_bytes else ""
        except (subprocess.TimeoutExpired, ValueError, OSError) as e:
            logger.debug(f"Failed to get partial output from process {process.pid}: {str(e)}")

    except Exception as e:
        # Ensure process is killed on any error
        try:
            _kill_process_tree(process.pid)
            process.wait(timeout=5)
        except (ProcessLookupError, PermissionError, OSError, subprocess.TimeoutExpired) as cleanup_error:
            logger.warning(f"Failed to cleanup process {process.pid} after error: {str(cleanup_error)}")
        raise

    duration = time.time() - start_time

    result = SafeProcessResult(
        args=cmd,
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        duration_seconds=duration
    )

    # Handle timeout exception
    if timed_out and kill_on_timeout:
        raise SubprocessTimeout(
            f"Command timed out after {timeout}s: {cmd[0]}",
            cmd=cmd,
            timeout=timeout,
            partial_output=stdout[:1000] if stdout else ""
        )

    # Handle check for non-zero exit
    if check and result.returncode != 0:
        raise SubprocessError(
            f"Command failed with exit code {result.returncode}: {cmd[0]}",
            cmd=cmd,
            returncode=result.returncode,
            stderr=stderr[:1000] if stderr else ""
        )

    return result


def run_with_timeout(
    cmd: List[str],
    timeout: int = 300,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    check: bool = False,
    capture_output: bool = True,
    stdin_data: Optional[str] = None
) -> subprocess.CompletedProcess:
    """
    Compatibility wrapper that returns subprocess.CompletedProcess.

    Use this as a drop-in replacement for subprocess.run() with timeout.
    """
    try:
        result = run_safe(
            cmd=cmd,
            timeout=timeout,
            cwd=cwd,
            env=env,
            check=check,
            capture_output=capture_output,
            stdin_data=stdin_data,
            kill_on_timeout=True
        )
        return result.to_completed_process()
    except SubprocessTimeout as e:
        # Return a CompletedProcess with error state
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=-9,  # SIGKILL
            stdout=e.partial_output,
            stderr=f"Process timed out after {timeout}s"
        )


@contextmanager
def timeout_context(seconds: int, message: str = "Operation timed out"):
    """
    Context manager for timing out operations (Unix only).

    Usage:
        with timeout_context(30, "Git clone timed out"):
            subprocess.run(["git", "clone", url])

    Note: Only works on Unix systems. On Windows, this is a no-op.
    """
    if os.name == 'nt':
        # Windows doesn't support SIGALRM
        yield
        return

    def timeout_handler(signum, frame):
        raise SubprocessTimeout(message, cmd=[], timeout=seconds)

    # Set the signal handler
    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)

    try:
        yield
    finally:
        # Restore the old handler and cancel the alarm
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def run_scanner_safe(
    cmd: List[str],
    repo_name: str,
    scanner_name: str,
    cwd: Optional[str] = None,
    timeout: int = 3600
) -> subprocess.CompletedProcess:
    """
    Run a security scanner with safe handling for problematic repo names.

    This is a convenience wrapper specifically for security scanners.

    Args:
        cmd: Scanner command and arguments
        repo_name: Repository name (for logging)
        scanner_name: Scanner name (for logging)
        cwd: Working directory
        timeout: Timeout in seconds (default 1 hour)

    Returns:
        CompletedProcess with results
    """
    logger.info(f"Running {scanner_name} for {repo_name}...")

    try:
        result = run_safe(
            cmd=cmd,
            timeout=timeout,
            cwd=cwd,
            capture_output=True,
            kill_on_timeout=True
        )

        if result.timed_out:
            logger.warning(f"{scanner_name} timed out for {repo_name} after {timeout}s")
        elif result.returncode != 0:
            logger.debug(f"{scanner_name} returned {result.returncode} for {repo_name}")

        return result.to_completed_process()

    except SubprocessTimeout as e:
        logger.error(f"{scanner_name} timed out for {repo_name}: {e}")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=-9,
            stdout="",
            stderr=f"Scanner timed out after {timeout}s"
        )
    except Exception as e:
        logger.error(f"{scanner_name} failed for {repo_name}: {e}")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=1,
            stdout="",
            stderr=str(e)
        )
