"""Real-Docker checks through the PRODUCTION code path (DockerSandbox.run -> build_args -> docker run).

Skipped unless a Docker daemon is reachable AND the sandbox image is built:  docker build -t aesa-sandbox:latest sandbox/
Run:  cd backend && pytest -q tests/test_docker_sandbox_integration.py -rs
"""
import json
import shutil
import subprocess

import pytest

from app.models.enums import ScanStatus, Severity
from app.sandbox.commands import CommandRegistry, PlannedCommand
from app.sandbox.runner import DockerSandbox
from app.security.scanners import parse_trivy

IMAGE = "aesa-sandbox:latest"


def _docker_ready() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = pytest.mark.skipif(not _docker_ready(), reason=f"needs a running Docker daemon and the {IMAGE} image")


@pytest.fixture
def sandbox(settings, tmp_path):
    s = settings.model_copy(update={"sandbox_backend": "docker", "workspace_root": str(tmp_path)})
    ws = tmp_path / "ws"
    ws.mkdir()
    ws.chmod(0o777)  # the container user is 10001
    return DockerSandbox(s), ws, CommandRegistry(s), s


def sh(sandbox_tuple, script):
    sb, ws, _reg, _s = sandbox_tuple
    return sb.run(PlannedCommand("selftest", ("sh", "-c", script), 60), ws)


def test_trivy_fs_succeeds_under_production_restrictions_with_the_baked_db(sandbox):
    sb, ws, reg, s = sandbox
    (ws / "requirements.txt").write_text("requests==2.19.0\n")  # old release with published CVEs: proves the DB is really used
    res = sb.run(reg.plan("trivy_fs", {}), ws)
    assert res.exit_code == 0, res.stderr[-800:]
    assert "read-only file system" not in (res.stderr + res.stdout).lower()
    assert not res.timed_out and not res.truncated
    json.loads(res.stdout)  # valid JSON
    outcome = parse_trivy(res, Severity.HIGH)
    assert outcome.status == ScanStatus.FAILED and sum(outcome.counts.values()) > 0, outcome.summary


def test_trivy_scan_of_a_clean_workspace_passes(sandbox):
    sb, ws, reg, _s = sandbox
    (ws / "app.py").write_text("print('hello')\n")
    res = sb.run(reg.plan("trivy_fs", {}), ws)
    assert res.exit_code == 0, res.stderr[-800:]
    assert parse_trivy(res, Severity.HIGH).status == ScanStatus.PASSED


def test_root_filesystem_and_baked_db_stay_immutable(sandbox):
    assert sh(sandbox, "touch /etc/pwned").exit_code != 0
    assert sh(sandbox, "touch /opt/trivy-db/db/pwned").exit_code != 0
    assert sh(sandbox, "echo x >> /opt/trivy-db/db/trivy.db").exit_code != 0
    assert sh(sandbox, "touch /tmp/ok && touch /workspace/ok").exit_code == 0  # only the tmpfs and the workspace are writable


def test_sandbox_stays_non_root_capless_and_offline(sandbox):
    assert sh(sandbox, "test \"$(id -u)\" = 10001").exit_code == 0
    assert sh(sandbox, "grep -q '^CapEff:.0000000000000000' /proc/self/status").exit_code == 0
    assert sh(sandbox, "grep -q '^NoNewPrivs:.1' /proc/self/status").exit_code == 0
    r = sh(sandbox, "python -c \"import socket; socket.create_connection(('1.1.1.1', 53), 3)\"")
    assert r.exit_code != 0, "the sandbox must have no network"
    assert sh(sandbox, "test ! -e /var/run/docker.sock").exit_code == 0


def test_trivy_wrapper_is_what_runs_and_real_binary_is_off_path(sandbox):
    assert "/usr/local/bin/trivy" in sh(sandbox, "command -v trivy").stdout
    assert sh(sandbox, "test -x /opt/trivy/bin/trivy && test ! -w /opt/trivy/bin/trivy").exit_code == 0
