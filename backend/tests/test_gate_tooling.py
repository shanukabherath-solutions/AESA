"""The security-gate tools must work the way they run in production: as an unprivileged user (UID 10001) in a workspace
that user cannot write (the backend clones it as a different user). The earlier tests ran tools as the workspace owner,
which hid a mypy crash ("INTERNAL ERROR ... please use --show-traceback"; root cause: PermissionError on ./.mypy_cache).

Also lints every Python file in the project, from every directory the gate or a developer might launch Ruff from."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from app.models import AgentTask, User
from app.models.enums import ScanStatus, Severity
from app.repository.workspace import WorkspaceManager
from app.sandbox.commands import CommandRegistry
from app.sandbox.runner import CommandResult, LocalSandbox, run_capped
from app.security.scanners import parse_bandit, parse_gitleaks, parse_mypy
from app.security.service import run_scan

ROOT = Path(__file__).resolve().parents[2]
IS_ROOT = os.geteuid() == 0
NEEDS_DROP = pytest.mark.skipif(IS_ROOT and not shutil.which("setpriv"), reason="running as root needs setpriv to drop privileges")


class UnwritableWorkspaceSandbox(LocalSandbox):
    """LocalSandbox that runs as UID 10001 when the tests run as root (like DockerSandbox's --user 10001:10001)."""

    def run(self, cmd, workspace):  # type: ignore[no-untyped-def]
        argv = [sys.executable if cmd.argv[0] == "python" else cmd.argv[0], *cmd.argv[1:]]
        env = {"PATH": os.environ["PATH"], "HOME": "/tmp", "CI": "1", "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        if IS_ROOT:
            argv = ["setpriv", "--reuid=10001", "--regid=10001", "--clear-groups", "--no-new-privs", *argv]
        return run_capped(argv, workspace, env, cmd.timeout, self.s.max_output_bytes)


@pytest.fixture
def unwritable_ws(settings, demo_repo_path):
    """A clone of the demo repo that the sandbox user cannot write to."""
    base = Path(tempfile.mkdtemp(prefix="aesa-ws-"))
    base.chmod(0o755)  # uid 10001 must be able to reach the workspace
    ws = WorkspaceManager(base).create(demo_repo_path, "task-1", branch="main")
    if IS_ROOT:  # created by root, mode 755 => not writable by uid 10001 (same situation as backend 10002 vs sandbox 10001)
        for p in [ws, *ws.rglob("*")]:
            if p.is_dir() and not p.is_symlink():
                p.chmod(0o755)
    else:  # same-user tests: remove the write bit so the owner cannot write either
        for p in [ws, *ws.rglob("*")]:
            if not p.is_symlink():
                p.chmod(p.stat().st_mode & ~0o222)
    yield ws
    for p in [ws, *ws.rglob("*")]:
        if not p.is_symlink():
            p.chmod(p.stat().st_mode | 0o700)
    shutil.rmtree(base, ignore_errors=True)


def _can_write(sandbox, ws):  # type: ignore[no-untyped-def]
    from app.sandbox.commands import PlannedCommand

    return sandbox.run(PlannedCommand("probe", ("sh", "-c", "touch probe-file"), 10), ws).exit_code == 0


# ------------------------------------------------------------------ mypy
def test_mypy_command_never_asks_mypy_to_write_into_the_workspace(settings):
    argv = CommandRegistry(settings).plan("mypy", {}).argv
    assert "--cache-dir=/dev/null" in argv, "mypy would create ./.mypy_cache in a directory the sandbox user cannot write"
    assert "--show-traceback" in argv, "a real crash must report its cause, not the generic hint line"
    assert argv[-2:] == ("--", ".")  # option terminator and validated path are still last


@NEEDS_DROP
def test_precondition_workspace_really_is_unwritable_for_the_sandbox_user(settings, unwritable_ws):
    assert not _can_write(UnwritableWorkspaceSandbox(settings), unwritable_ws), "test setup is not reproducing production"


@NEEDS_DROP
def test_mypy_runs_on_a_workspace_the_sandbox_user_cannot_write(settings, db, repo, unwritable_ws):
    dev = db.query(User).filter_by(username="developer").one()
    t = AgentTask(repository_id=repo.id, created_by=dev.id, prompt="p", status="ANALYZING")
    db.add(t)
    db.commit()
    row, _ = run_scan(db, t, "mypy", unwritable_ws, UnwritableWorkspaceSandbox(settings), settings)
    assert row.status == ScanStatus.PASSED.value, row.summary
    assert not (unwritable_ws / ".mypy_cache").exists()


@NEEDS_DROP
def test_mypy_still_reports_real_type_errors_with_the_cache_disabled(settings, db, repo, unwritable_ws):
    """Disabling the cache must not blind the check: it still fails on genuinely bad code."""
    bad = Path(tempfile.mkdtemp(prefix="aesa-bad-"))
    bad.chmod(0o755)
    (bad / "a.py").write_text('x: int = "not an int"\n')
    (bad / "a.py").chmod(0o644)
    dev = db.query(User).filter_by(username="developer").one()
    t = AgentTask(repository_id=repo.id, created_by=dev.id, prompt="p", status="ANALYZING")
    db.add(t)
    db.commit()
    try:
        row, _ = run_scan(db, t, "mypy", bad, UnwritableWorkspaceSandbox(settings), settings)
        assert row.status == ScanStatus.FAILED.value and row.low == 1 and "assignment" in row.findings[0]["message"].lower() + row.findings[0]["rule"]
    finally:
        shutil.rmtree(bad, ignore_errors=True)


@NEEDS_DROP
def test_other_gate_tools_also_work_on_an_unwritable_workspace(settings, db, repo, unwritable_ws):
    dev = db.query(User).filter_by(username="developer").one()
    t = AgentTask(repository_id=repo.id, created_by=dev.id, prompt="p", status="ANALYZING")
    db.add(t)
    db.commit()
    sb = UnwritableWorkspaceSandbox(settings)
    assert run_scan(db, t, "ruff", unwritable_ws, sb, settings)[0].status == ScanStatus.PASSED.value
    assert run_scan(db, t, "bandit", unwritable_ws, sb, settings)[0].status in (ScanStatus.PASSED.value, ScanStatus.FAILED.value)  # runs, no ERROR
    pytest_row = run_scan(db, t, "pytest", unwritable_ws, sb, settings)[0]
    assert pytest_row.status != ScanStatus.ERROR.value, pytest_row.summary  # baseline demo fails its injection test; it must not crash
    assert not any(p.name in {".pytest_cache", "__pycache__", ".mypy_cache", ".ruff_cache"} for p in unwritable_ws.rglob("*"))


def test_a_mypy_crash_reports_its_real_cause_and_still_blocks():
    """Real stream layout of the crash: the traceback is on STDOUT, the generic hint lines are on STDERR."""
    stdout = ("Traceback (most recent call last):\n  File \"mypy/build.py\", line 1902, in create_metastore\n"
              "  File \"<frozen os>\", line 225, in makedirs\n"
              "PermissionError: [Errno 13] Permission denied: '.mypy_cache'\n")
    stderr = ("error: INTERNAL ERROR -- Please try using mypy master on GitHub:\nversion: 2.4.0\n"
              "note: please use --show-traceback to print a traceback when reporting a bug\nnote: use --pdb to drop into pdb\n")
    o = parse_mypy(CommandResult("mypy", 2, stdout, stderr, 0.1), Severity.HIGH)
    assert o.status == ScanStatus.ERROR, "a crashed tool must never pass the gate"
    assert "PermissionError" in o.summary and ".mypy_cache" in o.summary, o.summary
    assert "--pdb" not in o.summary


def test_failure_detail_falls_back_sensibly_and_stays_blocking():
    only_hint = CommandResult("mypy", 2, "", "note: please use --show-traceback to print a traceback\n", 0.1)
    assert parse_mypy(only_hint, Severity.HIGH).status == ScanStatus.ERROR
    stderr_only = CommandResult("gitleaks", 1, "", "FTL could not write report\n", 0.1)
    assert "could not write report" in parse_gitleaks(stderr_only, Severity.HIGH).summary
    secret = CommandResult("bandit", 3, "", "ValueError: bad config token=abcd1234efgh", 0.1)
    o = parse_bandit(secret, Severity.HIGH)
    assert o.status == ScanStatus.ERROR and "abcd1234efgh" not in o.summary  # redaction still applies to error detail


# ------------------------------------------------------------------ every Python file in the project is lint-clean
def _ruff(cwd: Path, *extra: str) -> list[dict]:
    p = subprocess.run([sys.executable, "-m", "ruff", "check", "--no-cache", "--output-format=json", *extra, "."],
                       cwd=cwd, capture_output=True, text=True, timeout=120)
    assert p.returncode in (0, 1), p.stderr
    return json.loads(p.stdout or "[]")


def _fmt(findings: list[dict]) -> str:
    return "\n".join(f"{f['filename']}:{f['location']['row']} {f['code']} {f['message']}" for f in findings)


@pytest.mark.skipif(subprocess.run([sys.executable, "-m", "ruff", "--version"], capture_output=True).returncode != 0, reason="ruff not installed")
class TestRuffAcrossTheWholeProject:
    GENERATED = ("--extend-exclude", ".workspaces", "--extend-exclude", "data")

    def test_project_root(self):
        found = _ruff(ROOT, *self.GENERATED)
        assert not found, "lint issues when Ruff is launched from the project root:\n" + _fmt(found)

    def test_demo_repository_as_the_gate_sees_it(self):
        found = _ruff(ROOT / "demo-repository")
        assert not found, "the agent's gate runs Ruff with the repository as its root:\n" + _fmt(found)

    def test_backend_with_its_own_config(self):
        found = _ruff(ROOT / "backend", *self.GENERATED)
        assert not found, _fmt(found)

    def test_scripts(self):
        found = _ruff(ROOT / "scripts")
        assert not found, _fmt(found)

    def test_every_python_file_is_covered_by_one_of_the_runs_above(self):
        covered = ("backend", "demo-repository", "scripts")
        stray = [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*.py")
                 if not any(part in {"node_modules", ".workspaces", "data", "__pycache__", ".venv"} for part in p.parts)
                 and p.relative_to(ROOT).parts[0] not in covered]
        assert not stray, f"Python files outside the linted areas: {stray}"
