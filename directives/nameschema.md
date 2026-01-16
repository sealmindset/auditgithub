# Repository Name Schema Handling

## Problem Statement

Repositories with problematic names (e.g., `-EBS-F-7005-AP-UPD-PYMT-METHOD`) cause scan processes to hang indefinitely, even when scans appear to complete successfully. The issues stem from:

1. **CLI Flag Interpretation**: Names starting with `-` are interpreted as command-line flags
2. **Shell Escaping**: Special characters (`$`, `(`, `)`, `|`, `&`, etc.) break shell commands
3. **Subprocess Hangs**: Even with safe argument handling, subprocesses may hang waiting for input or on edge cases
4. **Incomplete Error Handling**: Timeouts and errors don't always propagate correctly

### Observed Behavior

```
INFO:root:Completed processing repository: -EBS-F-7005-AP-UPD-PYMT-METHOD
[Process hangs indefinitely despite "Completed" message]
```

---

## Solution Architecture

### 1. Repository Name Sanitization Layer

Create a dedicated `RepoNameHandler` class that centralizes all name handling:

**File**: `src/repo_name_handler.py`

```python
import re
import os
from typing import Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class NameRisk(Enum):
    SAFE = "safe"
    NEEDS_QUOTING = "needs_quoting"
    NEEDS_ESCAPING = "needs_escaping"
    DANGEROUS = "dangerous"

@dataclass
class RepoNameInfo:
    """Complete information about a repository name."""
    original: str
    safe_filesystem: str  # For file/directory names
    safe_cli: str         # For CLI arguments (quoted if needed)
    safe_git: str         # For git commands
    risk_level: NameRisk
    warnings: list

class RepoNameHandler:
    """Centralized handler for repository name sanitization."""

    # Characters that are problematic in different contexts
    CLI_FLAG_CHARS = {'-'}  # At start
    SHELL_SPECIAL = {'`', '$', '(', ')', '{', '}', '|', '&', ';', '<', '>', '!', '*', '?', ' ', '"', "'", '\\', '\n', '\t'}
    HIDDEN_PREFIX = {'.'}
    FILESYSTEM_UNSAFE = {'/', '\\', '\0', ':', '*', '?', '"', '<', '>', '|'}

    @classmethod
    def analyze(cls, repo_name: str) -> RepoNameInfo:
        """Analyze a repository name and return safe versions for all contexts."""
        warnings = []
        risk_level = NameRisk.SAFE

        if not repo_name:
            return RepoNameInfo(
                original="",
                safe_filesystem="_empty_",
                safe_cli="'_empty_'",
                safe_git="_empty_",
                risk_level=NameRisk.DANGEROUS,
                warnings=["Empty repository name"]
            )

        # Check for CLI flag interpretation
        if repo_name[0] in cls.CLI_FLAG_CHARS:
            warnings.append(f"Starts with '{repo_name[0]}' - may be interpreted as CLI flag")
            risk_level = NameRisk.NEEDS_QUOTING

        # Check for hidden file prefix
        if repo_name[0] in cls.HIDDEN_PREFIX:
            warnings.append(f"Starts with '{repo_name[0]}' - may be hidden on Unix systems")
            risk_level = max(risk_level, NameRisk.NEEDS_QUOTING, key=lambda x: list(NameRisk).index(x))

        # Check for shell special characters
        shell_chars_found = cls.SHELL_SPECIAL.intersection(set(repo_name))
        if shell_chars_found:
            warnings.append(f"Contains shell special characters: {shell_chars_found}")
            risk_level = NameRisk.NEEDS_ESCAPING

        # Generate safe versions
        safe_filesystem = cls._make_filesystem_safe(repo_name)
        safe_cli = cls._make_cli_safe(repo_name)
        safe_git = cls._make_git_safe(repo_name)

        return RepoNameInfo(
            original=repo_name,
            safe_filesystem=safe_filesystem,
            safe_cli=safe_cli,
            safe_git=safe_git,
            risk_level=risk_level,
            warnings=warnings
        )

    @classmethod
    def _make_filesystem_safe(cls, name: str) -> str:
        """Create a filesystem-safe version of the name."""
        # Replace unsafe characters with underscores
        safe = "".join(c if c.isalnum() or c in '._-' else '_' for c in name)
        # Ensure doesn't start with hyphen (causes issues with some tools)
        if safe.startswith('-'):
            safe = '_' + safe[1:]
        return safe or '_empty_'

    @classmethod
    def _make_cli_safe(cls, name: str) -> str:
        """Create a CLI-safe version (properly quoted)."""
        # Use single quotes and escape any single quotes within
        escaped = name.replace("'", "'\\''")
        return f"'{escaped}'"

    @classmethod
    def _make_git_safe(cls, name: str) -> str:
        """Create a git-safe version for clone URLs."""
        # URL-encode special characters
        import urllib.parse
        return urllib.parse.quote(name, safe='')

    @classmethod
    def wrap_for_subprocess(cls, args: list, repo_name_index: int = None) -> list:
        """
        Prepare arguments for subprocess, handling problematic repo names.

        If repo_name_index is provided, that argument will be specially handled.
        """
        # subprocess.run with list arguments handles escaping automatically
        # But we need to ensure the repo name doesn't look like a flag
        if repo_name_index is not None and len(args) > repo_name_index:
            name = args[repo_name_index]
            if name.startswith('-'):
                # Use -- to signal end of options if the command supports it
                # Or prefix with ./ for paths
                args[repo_name_index] = './' + name if '/' not in name else name
        return args
```

---

### 2. Enhanced Subprocess Execution with Timeouts

**File**: `src/safe_subprocess.py`

```python
import subprocess
import signal
import os
import logging
from typing import List, Optional, Dict, Any
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class SubprocessTimeout(Exception):
    """Raised when a subprocess times out."""
    pass

class SubprocessHang(Exception):
    """Raised when a subprocess appears to be hanging."""
    pass

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
    Run a subprocess with strict timeout handling.

    Args:
        cmd: Command and arguments as list
        timeout: Maximum seconds to wait (default 5 minutes)
        cwd: Working directory
        env: Environment variables (merged with current)
        check: Raise on non-zero exit
        capture_output: Capture stdout/stderr
        stdin_data: Data to send to stdin (closes stdin after)

    Returns:
        CompletedProcess with results

    Raises:
        SubprocessTimeout: If process exceeds timeout
        subprocess.CalledProcessError: If check=True and returncode != 0
    """
    # Merge environment
    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    # Start process
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
        stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
        cwd=cwd,
        env=full_env,
        # Ensure process is in its own group for clean termination
        preexec_fn=os.setsid if os.name != 'nt' else None
    )

    try:
        # Send stdin data if provided
        stdin_bytes = stdin_data.encode() if stdin_data else None

        # Wait with timeout
        stdout, stderr = process.communicate(input=stdin_bytes, timeout=timeout)

        result = subprocess.CompletedProcess(
            args=cmd,
            returncode=process.returncode,
            stdout=stdout.decode() if stdout else "",
            stderr=stderr.decode() if stderr else ""
        )

        if check and process.returncode != 0:
            raise subprocess.CalledProcessError(
                process.returncode, cmd, result.stdout, result.stderr
            )

        return result

    except subprocess.TimeoutExpired:
        logger.warning(f"Process timed out after {timeout}s: {' '.join(cmd[:3])}...")

        # Kill the entire process group
        try:
            if os.name != 'nt':
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass  # Process already dead

        # Clean up
        process.wait()

        raise SubprocessTimeout(f"Command timed out after {timeout}s: {cmd[0]}")

    except Exception as e:
        # Ensure process is killed on any error
        try:
            process.kill()
            process.wait()
        except:
            pass
        raise
```

---

### 3. AI Agent Self-Annealing for Problematic Repos

**File**: `src/ai_agent/repo_name_analyzer.py`

```python
"""
AI-powered analysis and remediation for problematic repository names.
"""
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class RepoNameAnalyzer:
    """Uses AI to analyze and suggest fixes for repo name issues."""

    def __init__(self, ai_provider):
        self.ai_provider = ai_provider

    async def analyze_stuck_repo(
        self,
        repo_name: str,
        error_logs: str,
        scan_phase: str,
        timeout_duration: int
    ) -> Dict[str, Any]:
        """
        Analyze why a repo with a problematic name got stuck.

        Returns remediation suggestions and configuration changes.
        """
        prompt = f"""Analyze this stuck repository scan and provide remediation:

**Repository Name**: `{repo_name}`
**Scan Phase**: {scan_phase}
**Timeout After**: {timeout_duration} seconds

**Error Logs**:
```
{error_logs[-2000:]}
```

**Known Issues with this name**:
- Starts with hyphen: {repo_name.startswith('-')}
- Contains spaces: {' ' in repo_name}
- Contains shell special chars: {any(c in repo_name for c in '`$(){}|&;<>!*?')}

Provide a JSON response with:
1. "root_cause": Why did the scan hang/fail?
2. "name_issues": List of specific issues with this repo name
3. "remediation": {{
     "cli_handling": How to safely pass this name to CLI tools,
     "git_handling": How to safely clone/fetch this repo,
     "subprocess_handling": Safe subprocess execution approach
   }}
4. "skip_recommendation": Should this repo be skipped? (true/false)
5. "confidence": 0.0-1.0

Focus on practical solutions that don't require renaming the repository."""

        try:
            response = await self.ai_provider.execute_prompt(prompt)
            # Parse JSON response
            import json
            return json.loads(response)
        except Exception as e:
            logger.error(f"AI analysis failed for {repo_name}: {e}")
            return {
                "root_cause": "AI analysis unavailable",
                "remediation": {"cli_handling": "Use -- to end options"},
                "skip_recommendation": False,
                "confidence": 0
            }

    async def suggest_scan_strategy(
        self,
        repo_name: str,
        repo_metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Suggest the best scanning strategy for a problematic repo.
        """
        prompt = f"""Suggest scanning strategy for this problematic repository:

**Repository**: `{repo_name}`
**Size**: {repo_metadata.get('size_kb', 'unknown')} KB
**Languages**: {repo_metadata.get('languages', [])}
**Last Updated**: {repo_metadata.get('updated_at', 'unknown')}

The repository name has these issues:
- May be interpreted as CLI flag
- Needs special quoting/escaping

Provide JSON with:
1. "scan_order": Recommended order of scanners (safest first)
2. "skip_scanners": Scanners that are likely to fail with this name
3. "timeout_multiplier": Suggested timeout multiplier (1.0-3.0)
4. "special_handling": Any special flags or approaches needed
5. "fallback_strategy": What to do if scans fail"""

        try:
            response = await self.ai_provider.execute_prompt(prompt)
            import json
            return json.loads(response)
        except Exception as e:
            logger.error(f"Strategy suggestion failed: {e}")
            return {
                "scan_order": ["trivy", "semgrep", "grype"],
                "skip_scanners": [],
                "timeout_multiplier": 1.5,
                "special_handling": "Use named arguments only"
            }
```

---

### 4. Integration into scan_repos.py

Add the following changes to `scan_repos.py`:

```python
# At top of file, add import
from src.repo_name_handler import RepoNameHandler, NameRisk
from src.safe_subprocess import run_with_timeout, SubprocessTimeout

# In process_repo_with_timeout function, replace current name handling:
def process_repo_with_timeout(...):
    repo_name = repo.get('name', 'unknown')

    # Analyze repo name for safety
    name_info = RepoNameHandler.analyze(repo_name)

    if name_info.warnings:
        for warning in name_info.warnings:
            logging.warning(f"⚠️  {repo_name}: {warning}")

    # Use safe versions throughout
    safe_fs_name = name_info.safe_filesystem
    safe_cli_name = name_info.safe_cli

    # For subprocess calls, always use list form (never shell=True)
    # and use named arguments for scripts that accept them

    # Example for ingest script:
    cmd = [
        sys.executable,
        ingest_script,
        "--repo-name", repo_name,  # Original name for database
        "--repo-dir", repo_report_dir
    ]

    try:
        result = run_with_timeout(cmd, timeout=300)
    except SubprocessTimeout:
        logging.error(f"Ingest timed out for {repo_name}")
        record_failure(repo_name, "ingest_timeout")
```

---

### 5. Self-Annealing Integration

When a repo fails due to name issues, the AI Agent analyzes and learns:

```python
async def handle_problematic_repo_failure(
    repo_name: str,
    phase: str,
    error: str,
    ai_agent
) -> Dict[str, Any]:
    """
    Called when a repo with problematic name fails.
    Uses AI to analyze and suggest future handling.
    """
    analyzer = RepoNameAnalyzer(ai_agent.provider)

    # Get AI analysis
    analysis = await analyzer.analyze_stuck_repo(
        repo_name=repo_name,
        error_logs=error,
        scan_phase=phase,
        timeout_duration=300
    )

    # Record in database for future reference
    if DATABASE_AVAILABLE:
        db = SessionLocal()
        try:
            repo = db.query(models.Repository).filter(
                models.Repository.name == repo_name
            ).first()

            if repo:
                repo.failure_count = (repo.failure_count or 0) + 1
                repo.last_failure_reason = analysis.get('root_cause', 'Unknown')[:255]
                repo.last_failure_at = datetime.utcnow()

                # Store AI remediation suggestion
                repo.metadata = repo.metadata or {}
                repo.metadata['ai_remediation'] = analysis.get('remediation', {})

                db.commit()
        finally:
            db.close()

    return analysis
```

---

## Run Migration

If database changes are needed for storing AI remediation data:

```bash
cat migrations/add_repo_metadata.sql | docker-compose exec -T db psql -U auditgh -d auditgh_kb
```

---

## Testing

Test with known problematic repo names:

```bash
# Test CLI flag interpretation - use = syntax to prevent argparse confusion
docker-compose run --rm auditgh --repo="-EBS-F-7005-AP-UPD-PYMT-METHOD" --overridescan

# Alternative: use quotes with =
docker-compose run --rm auditgh --repo='-EBS-F-7005-AP-UPD-PYMT-METHOD' --overridescan

# Test shell special characters
docker-compose run --rm auditgh --repo="repo-test" --overridescan

# Test hidden file prefix
docker-compose run --rm auditgh --repo=".hidden-repo" --overridescan
```

**Important**: For repos starting with `-`, always use the `--repo="-name"` syntax (with `=`),
not `--repo "-name"` (with space). The space syntax causes argparse to interpret the repo name as a flag.

---

## Verification

After implementation, these scenarios should complete without hanging:

| Repo Name | Expected Behavior |
|-----------|-------------------|
| `-EBS-F-7005-AP-UPD-PYMT-METHOD` | Scans complete, results ingested |
| `repo$name` | Warning logged, scans complete |
| `.hidden-repo` | Warning logged, scans complete |
| `repo (test)` | Escaping applied, scans complete |

The key indicators of success:
1. No indefinite hangs after "Completed processing" message
2. All subprocess calls terminate within timeout
3. AI analysis available for failed repos
4. Self-annealing prevents repeated failures on known problematic repos
