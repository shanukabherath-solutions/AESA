"""Command registry: the model never supplies a command line, only validated structured arguments.

Primary control  : allowlist of structured command specs (argv templates + Pydantic argument models).
Secondary control: denylist/metacharacter checks (defence in depth, never the only control).
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

from app.config import Settings
from app.repository.paths import PathViolation, check_relative


class CommandRejected(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PlannedCommand:
    key: str
    argv: tuple[str, ...]
    timeout: int
    network: bool = False
    host: bool = False  # True => hardened host-side git against the task workspace
    tmpfs_size: str | None = None  # None => the sandbox default (SANDBOX_TMPFS_SIZE)
    memory: str | None = None  # None => the sandbox default (SANDBOX_MEMORY)

    @property
    def display(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)


# ---------------------------------------------------------------- argument models
class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _validated_path(v: str | None) -> str | None:
    if v is None:
        return None
    try:
        return check_relative(v).as_posix()
    except PathViolation as exc:
        raise ValueError(f"{exc.code}: {exc.detail}") from exc


class PathArgs(_Args):
    path: str | None = None
    _p = field_validator("path")(_validated_path)


class PytestArgs(PathArgs):
    keyword: str | None = None

    @field_validator("keyword")
    @classmethod
    def _kw(cls, v: str | None) -> str | None:
        if v is not None and not re.fullmatch(r"[A-Za-z0-9_ ()]{1,100}", v):
            raise ValueError("keyword may only contain letters, digits, underscore, space and parentheses")
        return v


class GitDiffArgs(PathArgs):
    staged: bool = False


class NoArgs(_Args):
    pass


# ---------------------------------------------------------------- denylist (secondary)
_DENY_PATTERNS = [
    r"\brm\s+(-[a-z]*[rf][a-z]*\s+)+", r"\bsudo\b", r"\bsu\s+-?\b", r"\bchmod\s+(-R\s+)?[0-7]*7[0-7]*7\b",
    r"\bchown\b", r"\bmkfs\b", r"\bformat\b", r"\bshutdown\b", r"\breboot\b", r"\bdd\s+if=",
    r"\b(curl|wget)\b", r"\|\s*(sh|bash|zsh)\b", r"--privileged", r"docker\s+run", r"/var/run/docker\.sock",
    r"git\s+push\b.*(--force|-f\b|--force-with-lease)", r"git\s+push\b", r"\bnc\b|\bncat\b|\bnetcat\b",
    r":\(\)\s*\{", r">\s*/dev/", r"\beval\b", r"\bbase64\s+-d\b",
]
_DENY_RE = [re.compile(p, re.I) for p in _DENY_PATTERNS]
_SHELL_META = re.compile(r"[;&|`$<>\n\r(){}\\]")


def assert_not_dangerous(raw: str) -> None:
    for rx in _DENY_RE:
        if rx.search(raw):
            raise CommandRejected("dangerous_command", f"matches deny rule {rx.pattern!r}")
    if _SHELL_META.search(raw):
        raise CommandRejected("shell_metacharacters", "shell metacharacters are not allowed")


# ---------------------------------------------------------------- registry
@dataclass(frozen=True)
class CommandSpec:
    key: str
    model: type[_Args]
    timeout: int
    network: bool = False
    host: bool = False


SPECS: dict[str, CommandSpec] = {
    "pytest": CommandSpec("pytest", PytestArgs, 300),
    "npm_test": CommandSpec("npm_test", NoArgs, 300),
    "npm_build": CommandSpec("npm_build", NoArgs, 300),
    "npm_audit": CommandSpec("npm_audit", NoArgs, 120, network=True),
    "ruff_check": CommandSpec("ruff_check", PathArgs, 120),
    "mypy": CommandSpec("mypy", PathArgs, 300),
    "bandit": CommandSpec("bandit", PathArgs, 180),
    "trivy_fs": CommandSpec("trivy_fs", PathArgs, 300),  # offline by default: see CommandRegistry.plan
    "gitleaks": CommandSpec("gitleaks", PathArgs, 120),
    "git_status": CommandSpec("git_status", NoArgs, 30, host=True),
    "git_diff": CommandSpec("git_diff", GitDiffArgs, 30, host=True),
    "git_branch": CommandSpec("git_branch", NoArgs, 30, host=True),
}


class CommandRegistry:
    def __init__(self, settings: Settings):
        self.s = settings

    def plan(self, key: str, args: dict[str, Any] | None = None) -> PlannedCommand:
        spec = SPECS.get(key)
        if spec is None:
            raise CommandRejected("not_allowlisted", f"'{key}' is not an allowlisted command")
        try:
            a = spec.model.model_validate(args or {})
        except ValueError as exc:
            raise CommandRejected("invalid_arguments", str(exc).splitlines()[0][:200]) from exc
        path = getattr(a, "path", None) or "."
        timeout = min(spec.timeout, self.s.default_command_timeout * 3)
        argv: list[str]
        if key == "pytest":
            argv = ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-header", "--tb=short"]
            if a.keyword:  # type: ignore[attr-defined]
                argv += ["-k", a.keyword]  # type: ignore[attr-defined]
            if getattr(a, "path", None):
                argv += ["--", path]
        elif key == "npm_test":
            argv = ["npm", "test", "--silent"]
        elif key == "npm_build":
            argv = ["npm", "run", "build", "--silent"]
        elif key == "npm_audit":
            argv = ["npm", "audit", "--json"]
        elif key == "ruff_check":
            argv = ["ruff", "check", "--output-format=json", "--no-cache", "--", path]
        elif key == "mypy":
            # --cache-dir=/dev/null: mypy otherwise writes ./.mypy_cache into the workspace, which the sandbox user
            # (UID 10001) cannot write (the backend clones it as another user) and mypy then dies with an INTERNAL ERROR.
            # No cache means nothing is written anywhere and no state leaks between runs. --show-traceback makes a
            # genuine crash report its real cause instead of the generic "use --show-traceback" line.
            argv = ["mypy", "--show-traceback", "--cache-dir=/dev/null", "--show-error-codes", "--no-color-output",
                    "--no-error-summary", "--", path]
        elif key == "bandit":
            argv = ["bandit", "-r", "-f", "json", "-q", "-x", "*/tests/*,*/node_modules/*,*/.venv/*", "--", path]
        elif key == "trivy_fs":
            argv = ["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig",
                    "--skip-dirs", "node_modules"]
            if self.s.trivy_skip_db_update:
                argv += ["--skip-db-update", "--offline-scan"]
            argv += [path]
        elif key == "gitleaks":
            argv = ["gitleaks", "detect", "--no-git", "--no-banner", "--redact", "--exit-code", "0",
                    "--report-format", "json", "--report-path", "/dev/stdout", "--source", path]
        elif key == "git_status":
            argv = ["git", "status", "--porcelain=v1", "--branch"]
        elif key == "git_diff":
            argv = ["git", "diff", "--no-color", "--no-ext-diff", "--no-textconv"]
            argv.append("--cached" if a.staged else "HEAD")  # type: ignore[attr-defined]
            if getattr(a, "path", None):
                argv += ["--", path]
        else:  # git_branch
            argv = ["git", "branch", "--list", "--no-color"]
        if key == "trivy_fs":
            # Offline scan against the DB baked into the image: no network, ever, unless an operator explicitly
            # disables TRIVY_SKIP_DB_UPDATE (then the DB must be fetched, so the egress network is allowed).
            return PlannedCommand(key, tuple(argv), timeout, network=not self.s.trivy_skip_db_update, host=False,
                                  tmpfs_size=self.s.sandbox_trivy_tmpfs, memory=self.s.sandbox_trivy_memory)
        return PlannedCommand(key, tuple(argv), timeout, spec.network, spec.host)

    def resolve_raw(self, raw: str) -> PlannedCommand:
        """Map a raw command string onto an allowlisted structured command, or reject it.

        Not used by the agent (which never sends command strings); used by tests and any future
        operator console so that raw strings can never reach a shell.
        """
        assert_not_dangerous(raw)
        try:
            tok = shlex.split(raw)
        except ValueError as exc:
            raise CommandRejected("unparseable", str(exc)) from exc
        if not tok:
            raise CommandRejected("empty", "empty command")
        head, rest = tok[0], tok[1:]
        one = lambda k, extra=None: self.plan(k, extra)  # noqa: E731

        def opt_path(items: list[str]) -> dict[str, Any]:
            if len(items) > 1:
                raise CommandRejected("invalid_arguments", "too many arguments")
            return {"path": items[0]} if items else {}

        if head == "pytest":
            return one("pytest", opt_path(rest))
        if head == "npm" and rest == ["test"]:
            return one("npm_test")
        if head == "npm" and rest == ["run", "build"]:
            return one("npm_build")
        if head == "npm" and rest == ["audit"]:
            return one("npm_audit")
        if head == "ruff" and rest[:1] == ["check"]:
            return one("ruff_check", opt_path(rest[1:]))
        if head == "mypy":
            return one("mypy", opt_path(rest))
        if head == "bandit":
            return one("bandit", opt_path([r for r in rest if r != "-r"]))
        if head == "trivy":
            return one("trivy_fs", opt_path([r for r in rest if r != "fs"]))
        if head == "gitleaks":
            return one("gitleaks", opt_path([r for r in rest if r != "detect"]))
        if head == "git" and rest == ["status"]:
            return one("git_status")
        if head == "git" and rest[:1] == ["diff"]:
            return one("git_diff", opt_path(rest[1:]))
        if head == "git" and rest == ["branch"]:
            return one("git_branch")
        raise CommandRejected("not_allowlisted", f"'{head}' with these arguments is not allowlisted")
