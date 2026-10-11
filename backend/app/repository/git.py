"""Hardened Git CLI wrapper. Arguments are always built by backend code, never by the model."""
from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path

HARDENING = [
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.pager=cat",
    "-c", "protocol.ext.allow=never",
    "-c", "credential.helper=",
    "-c", "advice.detachedHead=false",
]
IDENTITY = ["-c", "user.name=AESA", "-c", "user.email=aesa@users.noreply.local"]


class GitError(Exception):
    def __init__(self, message: str, returncode: int = 1, stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


def _env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
    }
    if extra:
        env.update(extra)
    return env


def run_git(
    cwd: str | Path | None,
    *args: str,
    input_text: str | None = None,
    timeout: int = 60,
    env_extra: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    cmd = ["git", *HARDENING, *args]
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, env=_env(env_extra), input=input_text,
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {args[0]} timed out after {timeout}s", 124) from exc
    if check and proc.returncode != 0:
        raise GitError(f"git {args[0]} failed (exit {proc.returncode})", proc.returncode, proc.stderr[-2000:])
    return proc


def github_auth_env(token: str) -> dict[str, str]:
    """Pass the token via env-config (not argv, which is visible in `ps`)."""
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
    }


def is_git_repo(path: str | Path) -> bool:
    p = run_git(path, "rev-parse", "--is-inside-work-tree", check=False)
    return p.returncode == 0 and p.stdout.strip() == "true"


def current_branch(path: str | Path) -> str:
    return run_git(path, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
