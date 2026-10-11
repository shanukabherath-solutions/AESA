"""Sandbox backends. `docker` is the real isolation boundary; `local` is dev/test only."""
from __future__ import annotations

import logging
import os
import resource
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings
from app.repository.git import GitError, run_git
from app.sandbox.commands import PlannedCommand

log = logging.getLogger(__name__)


class SandboxUnavailable(Exception):
    """Raised when the configured sandbox cannot be used. Callers must FAIL CLOSED (never fall back)."""


@dataclass
class CommandResult:
    command: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def run_capped(
    argv: list[str], cwd: str | Path, env: dict[str, str], timeout: int, max_bytes: int,
    on_timeout: Callable[[], None] | None = None, limit_cpu: int | None = None,
) -> CommandResult:
    """Run without a shell, capture output with a hard cap, kill the whole process group on timeout."""
    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True, shell=False,
        )
    except FileNotFoundError:
        return CommandResult(" ".join(argv), 127, "", f"executable not found: {argv[0]}", 0.0)
    if limit_cpu:
        try:
            resource.prlimit(proc.pid, resource.RLIMIT_CPU, (limit_cpu, limit_cpu))
            resource.prlimit(proc.pid, resource.RLIMIT_FSIZE, (100 * 1024 * 1024, 100 * 1024 * 1024))
        except (OSError, ValueError, AttributeError):  # best effort; non-Linux
            pass

    bufs = {"out": bytearray(), "err": bytearray()}
    state = {"truncated": False}

    def pump(stream, key: str) -> None:  # type: ignore[no-untyped-def]
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            buf = bufs[key]
            room = max_bytes - len(buf)
            if room > 0:
                buf.extend(chunk[:room])
            if len(chunk) > room:
                state["truncated"] = True
                _kill_group(proc)
                return

    threads = [threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True)]
    for t in threads:
        t.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if on_timeout:
            on_timeout()
        _kill_group(proc)
        proc.wait(timeout=10)
    for t in threads:
        t.join(timeout=5)
    return CommandResult(
        " ".join(argv), proc.returncode, bufs["out"].decode("utf-8", "replace"),
        bufs["err"].decode("utf-8", "replace"), time.monotonic() - start, timed_out, state["truncated"],
    )


class SandboxBackend(ABC):
    name: str

    @abstractmethod
    def run(self, cmd: PlannedCommand, workspace: Path) -> CommandResult: ...


class LocalSandbox(SandboxBackend):
    """Subprocess with scrubbed env, rlimits, timeout and output cap. NOT isolated: no FS/network boundary."""

    name = "local"

    def __init__(self, settings: Settings):
        self.s = settings
        log.warning("Using LOCAL sandbox backend: development/testing only, not a security boundary")

    def run(self, cmd: PlannedCommand, workspace: Path) -> CommandResult:
        argv = list(cmd.argv)
        if argv[0] == "python":
            argv[0] = sys.executable
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(workspace), "LANG": "C.UTF-8",
            "TMPDIR": str(workspace), "PYTHONDONTWRITEBYTECODE": "1", "CI": "1", "NO_COLOR": "1",
            "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        }
        return run_capped(argv, workspace, env, cmd.timeout, self.s.max_output_bytes,
                          limit_cpu=cmd.timeout * 2)


class DockerSandbox(SandboxBackend):
    name = "docker"

    def __init__(self, settings: Settings):
        self.s = settings
        if shutil.which("docker") is None:
            raise SandboxUnavailable("docker CLI not found; refusing to fall back to an unisolated sandbox")

    def _host_path(self, workspace: Path) -> str:
        if not self.s.workspace_host_root:
            return str(workspace)
        rel = workspace.resolve().relative_to(Path(self.s.workspace_root).resolve())
        return str(Path(self.s.workspace_host_root) / rel)

    def build_args(self, cmd: PlannedCommand, workspace: Path, name: str) -> list[str]:
        network = self.s.sandbox_egress_network if (cmd.network and self.s.sandbox_egress_network) else "none"
        memory = cmd.memory or self.s.sandbox_memory
        tmpfs = cmd.tmpfs_size or self.s.sandbox_tmpfs_size
        return [
            "docker", "run", "--rm", "--pull", "never", "--init", "--name", name, "--label", "aesa=sandbox",
            "--user", "10001:10001", "--network", network,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.s.sandbox_pids_limit),
            "--memory", memory, "--memory-swap", memory,
            "--cpus", str(self.s.sandbox_cpus), "--ulimit", "nofile=1024:1024",
            # /tmp below is a tmpfs INSIDE the container, not the host /tmp
            "--read-only", "--tmpfs", f"/tmp:rw,nosuid,size={tmpfs}",  # noqa: S108  # nosec B108
            "--mount", f"type=bind,src={self._host_path(workspace)},dst=/workspace",
            "-w", "/workspace",
            "-e", "HOME=/tmp", "-e", "CI=1", "-e", "NO_COLOR=1", "-e", "PYTHONDONTWRITEBYTECODE=1",
            self.s.sandbox_image, *cmd.argv,
        ]

    def run(self, cmd: PlannedCommand, workspace: Path) -> CommandResult:
        name = f"aesa-{uuid.uuid4().hex[:10]}"
        args = self.build_args(cmd, workspace, name)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        if os.environ.get("DOCKER_HOST"):  # talk to the socket proxy; never forwarded into the container
            env["DOCKER_HOST"] = os.environ["DOCKER_HOST"]

        def kill_container() -> None:
            subprocess.run(["docker", "kill", name], env=env, capture_output=True, timeout=15, check=False)

        return run_capped(args, workspace, env, cmd.timeout, self.s.max_output_bytes, on_timeout=kill_container)


def get_sandbox(settings: Settings) -> SandboxBackend:
    if settings.sandbox_backend == "docker":
        return DockerSandbox(settings)
    if settings.sandbox_backend == "local":
        return LocalSandbox(settings)
    raise SandboxUnavailable(f"unknown sandbox backend {settings.sandbox_backend!r}")


def execute(cmd: PlannedCommand, workspace: Path, sandbox: SandboxBackend, settings: Settings) -> CommandResult:
    """Run a planned command: git on the task workspace via hardened host git, everything else sandboxed."""
    if cmd.host:
        start = time.monotonic()
        try:
            p = run_git(workspace, *cmd.argv[1:], timeout=cmd.timeout, check=False)
        except GitError as exc:
            return CommandResult(cmd.display, exc.returncode, "", str(exc), time.monotonic() - start,
                                 timed_out=exc.returncode == 124)
        out = p.stdout[: settings.max_output_bytes]
        return CommandResult(cmd.display, p.returncode, out, p.stderr[-4000:], time.monotonic() - start,
                             truncated=len(p.stdout) > settings.max_output_bytes)
    return sandbox.run(cmd, workspace)
