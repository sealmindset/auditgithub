"""
Tests for src/services/scan_runner.py.

The defect these cover: four call sites built ["python", "scan_repos.py", ...]
and relied on the process CWD. The script lives under scripts/scanning/ and the
containers run with WORKDIR /app, so every one of them failed with ENOENT and
recorded it as a failed scan. Nothing asserted that the path the callers used
pointed at a file that exists -- so these tests do.
"""
import asyncio
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.services import scan_runner
from src.services.scan_runner import (
    REPO_ROOT,
    SCAN_TYPE_ARGS,
    OrgScanAlreadyRunning,
    OrgScanRunner,
    ScanScriptNotFound,
    build_scan_command,
    scan_script_args,
    scan_script_path,
)


# =============================================================================
# Path resolution -- the actual bug
# =============================================================================

def test_scan_script_path_points_at_a_real_file():
    assert scan_script_path().is_file()


def test_scan_script_path_is_under_scripts_scanning():
    """Pin the location. If the script moves again this fails here, loudly,
    instead of at 3am as a scan that 'failed'."""
    assert scan_script_path() == REPO_ROOT / "scripts" / "scanning" / "scan_repos.py"


def test_command_is_absolute_so_cwd_cannot_break_it():
    cmd = build_scan_command(org="acme")
    assert Path(cmd[1]).is_absolute()
    assert Path(cmd[1]).is_file()


def test_command_uses_this_interpreter():
    assert build_scan_command()[0] == sys.executable


def test_override_env_is_honoured(monkeypatch, tmp_path):
    script = tmp_path / "elsewhere.py"
    script.write_text("")
    monkeypatch.setenv("SCAN_REPOS_SCRIPT", str(script))
    assert scan_script_path() == script


def test_missing_script_names_where_it_looked(monkeypatch, tmp_path):
    monkeypatch.setenv("SCAN_REPOS_SCRIPT", str(tmp_path / "nope.py"))
    with pytest.raises(ScanScriptNotFound) as exc:
        scan_script_path()
    assert "nope.py" in str(exc.value)


# =============================================================================
# Command construction
# =============================================================================

def test_org_scan_uses_target_not_org():
    """--target loads per-org credentials and the org database; --org does not."""
    cmd = build_scan_command(org="acme")
    assert "--target" in cmd
    assert cmd[cmd.index("--target") + 1] == "acme"
    assert "--org" not in cmd


def test_omitting_repo_is_what_makes_it_an_org_scan():
    assert not any(a.startswith("--repo") for a in build_scan_command(org="acme"))


def test_repo_is_passed_as_one_token():
    """A repository whose name starts with '-' is parsed as a flag when passed
    as two tokens."""
    cmd = build_scan_command(org="acme", repo="-leading-dash")
    assert "--repo=-leading-dash" in cmd
    assert "-leading-dash" not in cmd


@pytest.mark.parametrize("scan_type", sorted(SCAN_TYPE_ARGS))
def test_each_scan_type_contributes_its_flags(scan_type):
    cmd = build_scan_command(org="acme", scan_type=scan_type)
    for arg in SCAN_TYPE_ARGS[scan_type]:
        assert arg in cmd


def test_secrets_scan_names_scanners_that_exist():
    """scan_repos.py has no gitleaks; trufflehog and whispers are its secret
    scanners. A name it does not know is silently ignored, producing a scan
    that runs nothing and reports success."""
    source = (REPO_ROOT / "scripts" / "scanning" / "scan_repos.py").read_text()
    names = SCAN_TYPE_ARGS["secrets"][1].split(",")
    assert names
    for name in names:
        assert f"is_scanner_enabled('{name}')" in source


def test_unknown_scan_type_rejected():
    with pytest.raises(ValueError) as exc:
        build_scan_command(org="acme", scan_type="deep")
    assert "deep" in str(exc.value)


def test_extra_args_are_appended():
    cmd = build_scan_command(org="acme", extra=["--new-repos-only"])
    assert cmd[-1] == "--new-repos-only"


def test_scan_script_args_drops_interpreter_and_script():
    """The scanner image ENTRYPOINT already is the interpreter and the script."""
    args = scan_script_args(org="acme", scan_type="full")
    assert args[0] == "--target"
    assert sys.executable not in args
    assert not any(a.endswith("scan_repos.py") for a in args)


def test_scanner_image_entrypoint_matches_scan_script_args():
    """scan_script_args() is only correct while the image's ENTRYPOINT is the
    script itself."""
    dockerfile = (REPO_ROOT / "Dockerfile.scanner").read_text()
    assert 'ENTRYPOINT ["python", "scripts/scanning/scan_repos.py"]' in dockerfile


# =============================================================================
# Execution mode
# =============================================================================

def test_explicit_local_mode_never_probes_docker(monkeypatch):
    monkeypatch.setenv("SCAN_EXECUTION_MODE", "local")
    monkeypatch.setattr(scan_runner, "_docker_available", lambda: True)
    assert scan_runner.resolve_execution_mode() == "local"


def test_explicit_docker_mode_fails_loudly_when_unavailable(monkeypatch):
    monkeypatch.setenv("SCAN_EXECUTION_MODE", "docker")
    monkeypatch.setattr(scan_runner, "_docker_available", lambda: False)
    with pytest.raises(RuntimeError):
        scan_runner.resolve_execution_mode()


def test_auto_prefers_docker(monkeypatch):
    monkeypatch.setenv("SCAN_EXECUTION_MODE", "auto")
    monkeypatch.setattr(scan_runner, "_docker_available", lambda: True)
    assert scan_runner.resolve_execution_mode() == "docker"


def test_auto_falls_back_to_local(monkeypatch):
    monkeypatch.setenv("SCAN_EXECUTION_MODE", "auto")
    monkeypatch.setattr(scan_runner, "_docker_available", lambda: False)
    assert scan_runner.resolve_execution_mode() == "local"


def test_scanner_environment_sets_pythonpath():
    """The scanner image's sys.path[0] is scripts/scanning/, not /app, so
    --target fails with "No module named 'execution'" -- and --target is the
    only mode an org scan uses."""
    assert scan_runner._scanner_environment()["PYTHONPATH"] == "/app"


def test_scanner_image_also_sets_pythonpath():
    """Runtime env covers this runner; the image has to cover the compose
    scanner service and the CLI too."""
    dockerfile = (REPO_ROOT / "Dockerfile.scanner").read_text()
    assert "ENV PYTHONPATH=/app" in dockerfile


def test_scanner_environment_excludes_api_only_secrets(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("AUDITBOARD_TOKEN", "ab_secret")
    monkeypatch.setenv("SMTP_PASSWORD", "smtp_secret")
    env = scan_runner._scanner_environment()
    assert env["GITHUB_TOKEN"] == "ghp_x"
    assert "AUDITBOARD_TOKEN" not in env
    assert "SMTP_PASSWORD" not in env


# =============================================================================
# OrgScanRunner
# =============================================================================

@pytest.fixture
def local_mode(monkeypatch):
    monkeypatch.setenv("SCAN_EXECUTION_MODE", "local")
    return monkeypatch


def _stub_script(monkeypatch, tmp_path, body: str) -> Path:
    script = tmp_path / "fake_scan.py"
    script.write_text(body)
    monkeypatch.setenv("SCAN_REPOS_SCRIPT", str(script))
    return script


@pytest.mark.asyncio
async def test_successful_run_reports_idle(local_mode, tmp_path):
    _stub_script(local_mode, tmp_path, "import sys; sys.exit(0)")
    runner = OrgScanRunner()
    run = await runner.start("acme")
    await run._task
    assert run.status == "idle"
    assert run.returncode == 0
    assert run.error is None
    assert run.progress == 100


@pytest.mark.asyncio
async def test_nonzero_exit_is_an_error_naming_the_log(local_mode, tmp_path):
    _stub_script(local_mode, tmp_path, "import sys; sys.exit(3)")
    runner = OrgScanRunner()
    run = await runner.start("acme")
    await run._task
    assert run.status == "error"
    assert run.returncode == 3
    assert str(run.log_path) in run.error


@pytest.mark.asyncio
async def test_scanner_output_is_captured_to_the_log(local_mode, tmp_path):
    _stub_script(local_mode, tmp_path, "print('scanning repo one')")
    runner = OrgScanRunner()
    run = await runner.start("acme")
    await run._task
    assert "scanning repo one" in run.log_path.read_text()


@pytest.mark.asyncio
async def test_second_start_while_running_is_refused(local_mode, tmp_path):
    _stub_script(local_mode, tmp_path, "import time; time.sleep(30)")
    runner = OrgScanRunner()
    run = await runner.start("acme")
    try:
        with pytest.raises(OrgScanAlreadyRunning):
            await runner.start("acme")
    finally:
        await runner.cancel("acme")


@pytest.mark.asyncio
async def test_start_is_refused_case_insensitively(local_mode, tmp_path):
    _stub_script(local_mode, tmp_path, "import time; time.sleep(30)")
    runner = OrgScanRunner()
    await runner.start("Acme")
    try:
        with pytest.raises(OrgScanAlreadyRunning):
            await runner.start("acme")
    finally:
        await runner.cancel("acme")


@pytest.mark.asyncio
async def test_different_orgs_run_concurrently(local_mode, tmp_path):
    _stub_script(local_mode, tmp_path, "import time; time.sleep(30)")
    runner = OrgScanRunner()
    await runner.start("acme")
    await runner.start("globex")
    try:
        assert runner.active("acme") is not None
        assert runner.active("globex") is not None
    finally:
        await runner.cancel("acme")
        await runner.cancel("globex")


@pytest.mark.asyncio
async def test_cancel_kills_the_process_and_marks_cancelled(local_mode, tmp_path):
    _stub_script(local_mode, tmp_path, "import time; time.sleep(30)")
    runner = OrgScanRunner()
    run = await runner.start("acme")
    assert await runner.cancel("acme") is True
    assert run.cancelled is True
    assert run.status == "cancelled"
    assert run.is_running is False


@pytest.mark.asyncio
async def test_cancel_before_the_task_starts_still_closes_the_run(
    local_mode, tmp_path
):
    """asyncio.create_task() does not run the coroutine until the loop yields.
    Cancelling in that window skips _execute entirely, so its finally block
    never fires -- the run would stay 'scanning' forever and block every later
    start with a 409."""
    _stub_script(local_mode, tmp_path, "import time; time.sleep(30)")
    runner = OrgScanRunner()
    seen = []

    async def on_complete(run):
        seen.append(run.status)

    run = await runner.start("acme", on_complete=on_complete)
    # No await between start and cancel: the task has not been scheduled yet.
    assert await runner.cancel("acme") is True
    assert run.is_running is False
    assert run.status == "cancelled"
    assert seen == ["cancelled"]
    assert runner.active("acme") is None


@pytest.mark.asyncio
async def test_on_complete_fires_once_when_cancelled_after_starting(
    local_mode, tmp_path
):
    _stub_script(local_mode, tmp_path, "import time; time.sleep(30)")
    runner = OrgScanRunner()
    seen = []

    async def on_complete(run):
        seen.append(run.status)

    await runner.start("acme", on_complete=on_complete)
    await asyncio.sleep(0.2)  # let _execute get as far as the subprocess
    await runner.cancel("acme")
    assert seen == ["cancelled"]


@pytest.mark.asyncio
async def test_a_cancelled_org_can_be_started_again(local_mode, tmp_path):
    _stub_script(local_mode, tmp_path, "import time; time.sleep(30)")
    runner = OrgScanRunner()
    await runner.start("acme")
    await runner.cancel("acme")
    second = await runner.start("acme")
    try:
        assert second.is_running
    finally:
        await runner.cancel("acme")


@pytest.mark.asyncio
async def test_cancel_with_nothing_running_returns_false(local_mode, tmp_path):
    runner = OrgScanRunner()
    assert await runner.cancel("acme") is False


@pytest.mark.asyncio
async def test_missing_script_raises_before_anything_is_marked_running(
    local_mode, tmp_path
):
    local_mode.setenv("SCAN_REPOS_SCRIPT", str(tmp_path / "gone.py"))
    runner = OrgScanRunner()
    with pytest.raises(ScanScriptNotFound):
        await runner.start("acme")
    assert runner.active("acme") is None


@pytest.mark.asyncio
async def test_unknown_scan_type_rejected_before_launch(local_mode, tmp_path):
    _stub_script(local_mode, tmp_path, "pass")
    runner = OrgScanRunner()
    with pytest.raises(ValueError):
        await runner.start("acme", scan_type="deep")
    assert runner.active("acme") is None


@pytest.mark.asyncio
async def test_whole_org_progress_is_indeterminate_not_zero(local_mode, tmp_path):
    """One process scanning every repo reports progress only to its log. None
    means 'unknown'; 0 would read as 'nothing done yet', which is a claim."""
    _stub_script(local_mode, tmp_path, "import time; time.sleep(30)")
    runner = OrgScanRunner()
    run = await runner.start("acme")
    try:
        assert run.repos_total is None
        assert run.progress is None
    finally:
        await runner.cancel("acme")


@pytest.mark.asyncio
async def test_explicit_repo_list_runs_one_process_each_and_counts(
    local_mode, tmp_path
):
    marker = tmp_path / "invocations"
    _stub_script(
        local_mode,
        tmp_path,
        f"open({str(marker)!r}, 'a').write('x')",
    )
    runner = OrgScanRunner()
    progress_seen = []

    async def on_progress(run):
        progress_seen.append(run.progress)

    run = await runner.start(
        "acme", repos=["one", "two", "three"], on_progress=on_progress
    )
    await run._task
    assert marker.read_text() == "xxx"
    assert run.repos_completed == 3
    assert progress_seen == [33, 66, 100]


@pytest.mark.asyncio
async def test_repo_list_stops_at_the_first_failure(local_mode, tmp_path):
    marker = tmp_path / "invocations"
    _stub_script(
        local_mode,
        tmp_path,
        f"import sys; open({str(marker)!r}, 'a').write('x'); sys.exit(1)",
    )
    runner = OrgScanRunner()
    run = await runner.start("acme", repos=["one", "two", "three"])
    await run._task
    assert marker.read_text() == "x"
    assert run.status == "error"
    assert run.repos_completed == 0


@pytest.mark.asyncio
async def test_on_complete_runs_for_success_and_failure(local_mode, tmp_path):
    for body, expected in [("import sys; sys.exit(0)", "idle"),
                           ("import sys; sys.exit(9)", "error")]:
        _stub_script(local_mode, tmp_path, body)
        runner = OrgScanRunner()
        seen = []

        async def on_complete(run):
            seen.append(run.status)

        run = await runner.start("acme", on_complete=on_complete)
        await run._task
        assert seen == [expected]


@pytest.mark.asyncio
async def test_failing_callback_does_not_change_the_outcome(local_mode, tmp_path):
    """A status write that fails must not turn a successful scan into a failed
    one -- the scan already happened."""
    _stub_script(local_mode, tmp_path, "import sys; sys.exit(0)")
    runner = OrgScanRunner()

    async def on_complete(run):
        raise RuntimeError("database down")

    run = await runner.start("acme", on_complete=on_complete)
    await run._task
    assert run.status == "idle"
    assert run.error is None


@pytest.mark.asyncio
async def test_timeout_kills_the_scan_and_says_so(local_mode, tmp_path, monkeypatch):
    _stub_script(local_mode, tmp_path, "import time; time.sleep(30)")
    monkeypatch.setattr(scan_runner, "ORG_SCAN_TIMEOUT_SECONDS", 1)
    runner = OrgScanRunner()
    run = await runner.start("acme")
    await run._task
    assert run.status == "error"
    assert "ORG_SCAN_TIMEOUT_SECONDS" in run.error


@pytest.mark.asyncio
async def test_reconcile_stale_detects_a_lost_process(local_mode, tmp_path):
    """After an API restart the row still says 'scanning' but no run exists."""
    runner = OrgScanRunner()
    assert runner.reconcile_stale("acme", "scanning") is True
    assert runner.reconcile_stale("acme", "idle") is False


@pytest.mark.asyncio
async def test_a_live_run_is_not_stale(local_mode, tmp_path):
    _stub_script(local_mode, tmp_path, "import time; time.sleep(30)")
    runner = OrgScanRunner()
    await runner.start("acme")
    try:
        assert runner.reconcile_stale("acme", "scanning") is False
    finally:
        await runner.cancel("acme")


@pytest.mark.asyncio
async def test_to_dict_is_json_safe(local_mode, tmp_path):
    import json

    _stub_script(local_mode, tmp_path, "import sys; sys.exit(0)")
    runner = OrgScanRunner()
    run = await runner.start("acme")
    await run._task
    json.dumps(run.to_dict())
