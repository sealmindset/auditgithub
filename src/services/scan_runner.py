"""
One place that knows how to launch scan_repos.py.

Every caller used to build the command by hand as ``["python",
"scan_repos.py", ...]`` and let the process working directory find the script.
The script lives at ``scripts/scanning/scan_repos.py`` and every container that
runs the API has ``WORKDIR /app``, so each of those commands died on the spot
with::

    python: can't open file '/app/scan_repos.py': [Errno 2] No such file or directory

and the caller recorded it as a failed *scan*. A scan that never started and a
scan that ran and found nothing look identical in the schedule table, which is
why this survived a move of the script: the UI said "failed", and the operator
blamed the repository. Resolving the path once, here, is what keeps the call
sites from drifting apart again.

Two execution modes, because where the scan runs changes what it finds:

``local``
    Subprocess inside the API container. Dockerfile.api installs syft and
    semgrep and nothing else -- trivy, grype, trufflehog, checkov and the rest
    are absent, and scan_repos.py skips a missing tool rather than failing. The
    run reports success having executed a fraction of the scanners.
``docker``
    A one-shot container from the scanner image, which is the image that
    actually carries the tools. Needs the docker SDK and the mounted docker
    socket.

``auto`` (the default) prefers docker and falls back to local with a warning,
never silently.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shlex
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

# src/services/scan_runner.py -> src/services -> src -> repo root
REPO_ROOT = Path(__file__).resolve().parents[2]

# Relative to the repo root, and to WORKDIR inside the scanner image.
SCAN_SCRIPT_RELPATH = Path("scripts") / "scanning" / "scan_repos.py"

# An org-wide scan is long, but not unbounded. Without a ceiling a wedged scan
# leaves the organization row reading 'scanning' forever, and the UI offers no
# way to start another one.
ORG_SCAN_TIMEOUT_SECONDS = int(os.environ.get("ORG_SCAN_TIMEOUT_SECONDS", str(6 * 3600)))

# Arguments implied by each scan_type the API accepts. The names on the right
# are scan_repos.py flags; --overridescan defeats every skip heuristic, which is
# what "full" has to mean for an operator who just pressed the button.
SCAN_TYPE_ARGS: Dict[str, List[str]] = {
    "full": ["--overridescan"],
    "incremental": ["--skipscan"],
    # scan_repos.py has no gitleaks; its secret scanners are these two.
    "secrets": ["--scanners", "trufflehog,whispers"],
}


class ScanScriptNotFound(RuntimeError):
    """scan_repos.py is not where this process can reach it."""


def scan_script_path() -> Path:
    """Absolute path to scan_repos.py, or raise saying where we looked."""
    override = os.environ.get("SCAN_REPOS_SCRIPT", "").strip()
    candidate = Path(override) if override else REPO_ROOT / SCAN_SCRIPT_RELPATH
    if not candidate.is_file():
        raise ScanScriptNotFound(
            f"scan_repos.py not found at {candidate}. "
            "Set SCAN_REPOS_SCRIPT if the repository is mounted elsewhere."
        )
    return candidate


def build_scan_command(
    *,
    org: Optional[str] = None,
    repo: Optional[str] = None,
    scan_type: Optional[str] = None,
    extra: Optional[Sequence[str]] = None,
) -> List[str]:
    """
    Build an argv for a local scan_repos.py run.

    ``org`` maps to --target (the multi-org flag that loads per-org credentials
    and database), not --org. ``repo`` omitted means every repository in the
    organization -- that single difference is what separates a repo scan from an
    org scan.
    """
    cmd = [sys.executable, str(scan_script_path())]
    if org:
        cmd += ["--target", org]
    if repo:
        # --repo=value, not --repo value: a repository whose name starts with a
        # dash is parsed as a flag otherwise.
        cmd += [f"--repo={repo}"]
    if scan_type:
        try:
            cmd += SCAN_TYPE_ARGS[scan_type]
        except KeyError:
            raise ValueError(
                f"Unknown scan_type {scan_type!r}; expected one of "
                f"{', '.join(sorted(SCAN_TYPE_ARGS))}"
            ) from None
    if extra:
        cmd += list(extra)
    return cmd


def scan_script_args(
    *,
    org: Optional[str] = None,
    repo: Optional[str] = None,
    scan_type: Optional[str] = None,
    extra: Optional[Sequence[str]] = None,
) -> List[str]:
    """The same arguments without the interpreter or script path.

    The scanner image's ENTRYPOINT is already ``python
    scripts/scanning/scan_repos.py``, so a container run passes only these.
    """
    return build_scan_command(org=org, repo=repo, scan_type=scan_type, extra=extra)[2:]


# =============================================================================
# Execution mode
# =============================================================================

def _docker_sdk():
    try:
        import docker  # type: ignore
    except ImportError:
        return None
    return docker


def _docker_available() -> bool:
    docker = _docker_sdk()
    if docker is None:
        return False
    return Path(os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")).exists()


def resolve_execution_mode() -> str:
    """Return 'docker' or 'local'. Never raises; logs why it chose local."""
    requested = os.environ.get("SCAN_EXECUTION_MODE", "auto").strip().lower()
    if requested == "local":
        return "local"
    if requested == "docker":
        if not _docker_available():
            raise RuntimeError(
                "SCAN_EXECUTION_MODE=docker but the docker SDK or "
                "/var/run/docker.sock is unavailable in this container."
            )
        return "docker"
    if requested != "auto":
        logger.warning("Unknown SCAN_EXECUTION_MODE=%r; treating as auto", requested)
    if _docker_available():
        return "docker"
    logger.warning(
        "Falling back to SCAN_EXECUTION_MODE=local: the docker SDK or socket is "
        "unavailable. Scanners not installed in this container (trivy, grype, "
        "trufflehog and others) will be skipped, and the scan will still report "
        "success."
    )
    return "local"


def host_project_dir() -> str:
    """
    Host path to mount at /app in a scanner container.

    A container cannot bind-mount its own filesystem into a sibling: the daemon
    resolves the source on the *host*. Ask the daemon what this container's /app
    is bound to rather than trusting HOST_PROJECT_DIR, which is hand-maintained
    in .env and goes stale the moment the checkout moves.
    """
    docker = _docker_sdk()
    if docker is not None:
        try:
            client = docker.from_env()
            me = client.containers.get(socket.gethostname())
            for mount in me.attrs.get("Mounts", []):
                if mount.get("Destination") == "/app" and mount.get("Source"):
                    return mount["Source"]
        except Exception as exc:  # container id unknown, daemon unreachable, ...
            logger.debug("Could not inspect own container for /app mount: %s", exc)
    configured = os.environ.get("HOST_PROJECT_DIR", "").strip()
    if configured and configured != ".":
        return configured
    return str(REPO_ROOT)


# =============================================================================
# Organization-wide scans
# =============================================================================

@dataclass
class OrgScanRun:
    """A single press of Start Full Scan."""

    org_name: str
    scan_type: str
    repos: Optional[List[str]]
    mode: str
    log_path: Path
    started_at: datetime
    repos_total: Optional[int]
    repos_completed: int = 0
    finished_at: Optional[datetime] = None
    returncode: Optional[int] = None
    error: Optional[str] = None
    cancelled: bool = False
    _task: Optional[asyncio.Task] = field(default=None, repr=False)
    _proc: Optional[asyncio.subprocess.Process] = field(default=None, repr=False)
    _container: object = field(default=None, repr=False)
    _on_complete: object = field(default=None, repr=False)

    @property
    def is_running(self) -> bool:
        return self.finished_at is None

    @property
    def status(self) -> str:
        if self.is_running:
            return "scanning"
        if self.cancelled:
            return "cancelled"
        return "error" if self.error else "idle"

    @property
    def progress(self) -> Optional[int]:
        """
        Percent complete, or None when it genuinely cannot be known.

        A whole-org run is one scan_repos.py process that reports per-repo
        progress only to its log; there is no honest percentage to give, and
        inventing one is worse than an indeterminate bar. A run over an explicit
        list of repositories is one process per repository, so that one counts.
        """
        if not self.is_running:
            return 100
        if not self.repos_total:
            return None
        return int(100 * self.repos_completed / self.repos_total)

    def to_dict(self) -> Dict[str, object]:
        finished = self.finished_at or datetime.now(timezone.utc)
        return {
            "status": self.status,
            "mode": self.mode,
            "scan_type": self.scan_type,
            "repos": self.repos,
            "repos_total": self.repos_total,
            "repos_completed": self.repos_completed,
            "progress": self.progress,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "elapsed_seconds": int((finished - self.started_at).total_seconds()),
            "returncode": self.returncode,
            "error": self.error,
            "log_path": str(self.log_path),
        }


class OrgScanAlreadyRunning(RuntimeError):
    def __init__(self, run: OrgScanRun):
        self.run = run
        super().__init__(
            f"A scan of '{run.org_name}' started at "
            f"{run.started_at.isoformat()} is still running."
        )


class OrgScanRunner:
    """Owns the org-wide scan processes for this API process.

    State lives in memory. The API runs a single uvicorn worker, so one runner
    sees every run; a restart loses the handles, which
    :meth:`reconcile_stale` exists to detect rather than paper over.
    """

    def __init__(self) -> None:
        self._runs: Dict[str, OrgScanRun] = {}

    # -- queries ---------------------------------------------------------

    def get(self, org_name: str) -> Optional[OrgScanRun]:
        """Most recent run for the org, running or finished."""
        return self._runs.get(org_name.lower())

    def active(self, org_name: str) -> Optional[OrgScanRun]:
        run = self.get(org_name)
        return run if run is not None and run.is_running else None

    # -- lifecycle -------------------------------------------------------

    async def start(
        self,
        org_name: str,
        *,
        repos: Optional[Sequence[str]] = None,
        scan_type: str = "full",
        on_progress: Optional[Callable[[OrgScanRun], Awaitable[None]]] = None,
        on_complete: Optional[Callable[[OrgScanRun], Awaitable[None]]] = None,
    ) -> OrgScanRun:
        existing = self.active(org_name)
        if existing is not None:
            raise OrgScanAlreadyRunning(existing)

        if scan_type not in SCAN_TYPE_ARGS:
            raise ValueError(
                f"Unknown scan_type {scan_type!r}; expected one of "
                f"{', '.join(sorted(SCAN_TYPE_ARGS))}"
            )

        mode = resolve_execution_mode()
        # Fail here, before anything is marked 'scanning', if the script is
        # missing: an operator needs to see "no scan started", not a scan that
        # reports failure a second later.
        if mode == "local":
            scan_script_path()

        repo_list = [r for r in (repos or []) if r] or None
        started = datetime.now(timezone.utc)
        log_dir = REPO_ROOT / "logs" / "org-scans"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{org_name}-{started.strftime('%Y%m%dT%H%M%SZ')}.log"

        run = OrgScanRun(
            org_name=org_name,
            scan_type=scan_type,
            repos=repo_list,
            mode=mode,
            log_path=log_path,
            started_at=started,
            repos_total=len(repo_list) if repo_list else None,
        )
        run._on_complete = on_complete
        self._runs[org_name.lower()] = run
        run._task = asyncio.create_task(
            self._execute(run, on_progress),
            name=f"org-scan:{org_name}",
        )
        logger.info(
            "Org scan started: org=%s mode=%s scan_type=%s repos=%s log=%s",
            org_name, mode, scan_type,
            len(repo_list) if repo_list else "all", log_path,
        )
        return run

    async def cancel(self, org_name: str) -> bool:
        """Stop a running scan. Returns False if nothing was running."""
        run = self.active(org_name)
        if run is None or run._task is None:
            return False
        run.cancelled = True
        run._task.cancel()
        try:
            await run._task
        except asyncio.CancelledError:
            pass
        if run.is_running:
            # Cancelled before the event loop ever entered _execute, so its
            # finally block never ran. Close the run out here: otherwise it
            # stays marked running for the life of the process, the database
            # row stays 'scanning', and every later start is refused with 409.
            run.error = "Scan cancelled by operator"
            await self._finalize(run)
        return True

    def reconcile_stale(self, org_name: str, db_status: Optional[str]) -> bool:
        """
        True when the database claims a scan is running and this process has no
        such run.

        That combination means the API restarted while a scan was in flight. The
        subprocess died with it, so the row is stale rather than the scan being
        slow -- a distinction worth making to whoever is watching the spinner.
        """
        return db_status == "scanning" and self.active(org_name) is None

    # -- internals -------------------------------------------------------

    async def _finalize(self, run: OrgScanRun) -> None:
        """Close a run out exactly once and tell the caller it ended."""
        if run.finished_at is None:
            run.finished_at = datetime.now(timezone.utc)
        run._proc = None
        run._container = None
        logger.info(
            "Org scan finished: org=%s status=%s rc=%s error=%s",
            run.org_name, run.status, run.returncode, run.error,
        )
        on_complete = run._on_complete
        run._on_complete = None
        if on_complete is not None:
            await _safe_callback(on_complete, run)

    async def _execute(
        self,
        run: OrgScanRun,
        on_progress: Optional[Callable[[OrgScanRun], Awaitable[None]]],
    ) -> None:
        # One target of None means "the whole org in one process"; a list means
        # one process per repository, because scan_repos.py takes a single
        # --repo.
        targets: List[Optional[str]] = list(run.repos) if run.repos else [None]
        try:
            with run.log_path.open("ab", buffering=0) as log:
                for target in targets:
                    rc = await self._run_one(run, target, log)
                    run.returncode = rc
                    if rc != 0:
                        run.error = (
                            f"scan_repos.py exited {rc}"
                            + (f" for {target}" if target else "")
                            + f"; see {run.log_path}"
                        )
                        break
                    run.repos_completed += 1
                    if on_progress is not None:
                        await _safe_callback(on_progress, run)
        except asyncio.CancelledError:
            run.cancelled = True
            run.error = "Scan cancelled by operator"
            raise
        except asyncio.TimeoutError:
            run.error = (
                f"Scan exceeded ORG_SCAN_TIMEOUT_SECONDS "
                f"({ORG_SCAN_TIMEOUT_SECONDS}s) and was killed"
            )
        except Exception as exc:
            logger.exception("Org scan failed: %s", run.org_name)
            run.error = str(exc)
        finally:
            await self._finalize(run)

    async def _run_one(self, run: OrgScanRun, repo: Optional[str], log) -> int:
        if run.mode == "docker":
            return await self._run_in_scanner_container(run, repo, log)
        return await self._run_subprocess(run, repo, log)

    async def _run_subprocess(self, run: OrgScanRun, repo: Optional[str], log) -> int:
        cmd = build_scan_command(org=run.org_name, repo=repo, scan_type=run.scan_type)
        log.write(f"$ {shlex.join(cmd)}\n".encode())
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(REPO_ROOT),
            stdout=log,
            stderr=asyncio.subprocess.STDOUT,
        )
        run._proc = proc
        try:
            return await asyncio.wait_for(proc.wait(), timeout=ORG_SCAN_TIMEOUT_SECONDS)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            proc.kill()
            await proc.wait()
            raise

    async def _run_in_scanner_container(
        self, run: OrgScanRun, repo: Optional[str], log
    ) -> int:
        """
        Run the scan in a one-shot container from the scanner image.

        Blocking docker SDK calls go to a thread: the whole API shares this
        event loop, and `container.wait()` blocks for as long as the scan runs.
        """
        docker = _docker_sdk()
        assert docker is not None  # resolve_execution_mode() checked
        args = scan_script_args(org=run.org_name, repo=repo, scan_type=run.scan_type)
        image = os.environ.get("SCANNER_IMAGE", "auditgithub-scanner:latest")
        network = os.environ.get("DOCKER_NETWORK", "auditgithub_default")
        project_dir = host_project_dir()
        log.write(f"$ docker run --rm {image} {shlex.join(args)}\n".encode())

        def _start():
            client = docker.from_env()
            return client.containers.run(
                image,
                args,
                detach=True,
                network=network,
                working_dir="/app",
                volumes={project_dir: {"bind": "/app", "mode": "rw"}},
                environment=_scanner_environment(),
            )

        container = await asyncio.to_thread(_start)
        run._container = container
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(container.wait), timeout=ORG_SCAN_TIMEOUT_SECONDS
            )
        except (asyncio.CancelledError, asyncio.TimeoutError):
            await asyncio.to_thread(_kill_container, container)
            await asyncio.to_thread(_drain_logs, container, log)
            await asyncio.to_thread(_remove_container, container)
            raise
        await asyncio.to_thread(_drain_logs, container, log)
        await asyncio.to_thread(_remove_container, container)
        return int(result.get("StatusCode", 1))


def _scanner_environment() -> Dict[str, str]:
    """
    Environment handed to the scanner container.

    Copied from this process rather than read from .env: the API already holds
    the resolved values, including the database host rewritten to the compose
    service name. Only variables the scanner needs are passed -- the API's
    AuditBoard and SMTP credentials have no business in a scanner.
    """
    env = {
        # The scanner image sets no PYTHONPATH and its ENTRYPOINT runs
        # scripts/scanning/scan_repos.py, so sys.path[0] is that script's own
        # directory and /app is not on the path at all. --target then dies with
        # "No module named 'execution'" -- multi-org mode is exactly the mode
        # this runner uses. Dockerfile.scanner carries the same line for the
        # compose service and the CLI; this one makes it true without a rebuild.
        "PYTHONPATH": "/app",
    }
    wanted = (
        "GITHUB_TOKEN", "GITHUB_API", "GITHUB_ORG",
        "POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_USER",
        "POSTGRES_PASSWORD", "POSTGRES_DB",
        "SECRETS_MASTER_KEY",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "AWS_DEFAULT_REGION", "AWS_SESSION_TOKEN",
        "AI_PROVIDER", "ANTHROPIC_MODEL",
        "AZURE_AI_FOUNDRY_ENDPOINT", "AZURE_AI_FOUNDRY_API_KEY",
        "REPORT_DIR",
    )
    env.update({k: os.environ[k] for k in wanted if os.environ.get(k)})
    return env


def _kill_container(container) -> None:
    try:
        container.kill()
    except Exception as exc:
        logger.debug("Could not kill scanner container: %s", exc)


def _drain_logs(container, log) -> None:
    try:
        log.write(container.logs(stdout=True, stderr=True))
    except Exception as exc:
        logger.debug("Could not read scanner container logs: %s", exc)


def _remove_container(container) -> None:
    try:
        container.remove(force=True)
    except Exception as exc:
        logger.debug("Could not remove scanner container: %s", exc)


async def _safe_callback(cb: Callable[[OrgScanRun], Awaitable[None]], run: OrgScanRun) -> None:
    """A failing status callback must not change the outcome of the scan."""
    try:
        await cb(run)
    except Exception:
        logger.exception("Org scan callback failed for %s", run.org_name)


_runner: Optional[OrgScanRunner] = None


def get_org_scan_runner() -> OrgScanRunner:
    global _runner
    if _runner is None:
        _runner = OrgScanRunner()
    return _runner
