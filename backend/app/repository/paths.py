"""Canonical path validation: the only way tools may touch repository files."""
from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

BLOCKED_DIR_NAMES = {".git", ".ssh", ".aws", ".gnupg", ".kube", "credentials", "secrets", "private_keys"}
BLOCKED_FILE_GLOBS = [
    ".env", ".env.*", "id_rsa", "id_rsa.*", "id_dsa", "id_ecdsa", "id_ed25519", "*.pem", "*.key",
    "*.p12", "*.pfx", "*.jks", ".netrc", ".npmrc", ".pypirc", "*.kdbx", "credentials.json",
]
DEFAULT_ALLOWED = [
    "src/", "app/", "lib/", "tests/", "test/", "docs/", ".github/", "README.md", "*.md",
    "package.json", "package-lock.json", "requirements*.txt", "pyproject.toml", "setup.py",
    "setup.cfg", "tox.ini", "Dockerfile", "*.toml", "*.cfg", "*.ini", "*.yml", "*.yaml",
]
DEFAULT_PROTECTED = [
    ".github/", "sandbox/", "Dockerfile*", "docker-compose*.yml", "CODEOWNERS", ".gitleaks.toml",
    "backend/app/policy/", "backend/app/sandbox/",
]
SAFE_BRANCH_RE = re.compile(r"^agent/proposal-\d+$")


class PathViolation(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _is_blocked_name(name: str, is_dir_hint: bool = False) -> bool:
    low = name.lower()
    if low in BLOCKED_DIR_NAMES:
        return True
    return any(fnmatch.fnmatch(low, g) for g in BLOCKED_FILE_GLOBS)


def check_relative(rel: str) -> PurePosixPath:
    """Pure/syntactic validation of a repo-relative path. No filesystem access."""
    if not isinstance(rel, str) or not rel:
        raise PathViolation("invalid_path", "path must be a non-empty string")
    if len(rel) > 512 or "\x00" in rel:
        raise PathViolation("invalid_path", "path too long or contains NUL")
    if "\\" in rel:
        raise PathViolation("invalid_path", "backslashes are not allowed")
    if rel.startswith("/") or re.match(r"^[A-Za-z]:", rel) or rel.startswith("~"):
        raise PathViolation("absolute_path", "absolute paths are not allowed")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise PathViolation("path_traversal", "'..' segments are not allowed")
    if any(p.startswith("-") for p in parts[:1]):
        raise PathViolation("invalid_path", "paths may not start with '-'")
    for p in parts:
        if _is_blocked_name(p):
            raise PathViolation("blocked_path", f"'{p}' is a sensitive path")
    return PurePosixPath(*parts) if parts else PurePosixPath(".")


def matches_any(rel: str, patterns: list[str]) -> bool:
    rel = rel.strip("/")
    for pat in patterns:
        if pat.endswith("/"):
            base = pat.rstrip("/")
            if rel == base or rel.startswith(base + "/"):
                return True
        elif fnmatch.fnmatch(rel, pat):
            return True
    return False


def is_protected_path(rel: str, protected: list[str]) -> bool:
    return matches_any(rel, protected)


def is_protected_branch(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


class PathGuard:
    """Resolves paths against a single root, following symlinks, and enforces allow/block rules."""

    def __init__(self, root: str | Path, allowed: list[str] | None = None, protected: list[str] | None = None):
        self.root = Path(os.path.realpath(root))
        self.allowed = allowed if allowed else DEFAULT_ALLOWED
        self.protected = protected if protected is not None else DEFAULT_PROTECTED
        if not self.root.is_dir():
            raise PathViolation("invalid_root", f"{self.root} is not a directory")

    def is_allowed(self, rel: str) -> bool:
        return matches_any(rel, self.allowed)

    def resolve(self, rel: str, *, for_write: bool = False, must_exist: bool = True) -> Path:
        clean = check_relative(rel)
        rel_s = clean.as_posix()
        if rel_s != "." and not self.is_allowed(rel_s):
            raise PathViolation("not_allowed", f"'{rel_s}' is outside the allowed paths")
        if for_write and rel_s != "." and is_protected_path(rel_s, self.protected):
            raise PathViolation("protected_path", f"'{rel_s}' is protected and cannot be modified by the agent")
        candidate = self.root / clean
        real = Path(os.path.realpath(candidate))
        if real != self.root and self.root not in real.parents:
            raise PathViolation("escapes_root", "resolved path is outside the repository root")
        real_rel = real.relative_to(self.root).as_posix()
        if real_rel != ".":
            check_relative(real_rel)  # symlink to a blocked name
            if not self.is_allowed(real_rel):
                raise PathViolation("not_allowed", "symlink target is outside the allowed paths")
        if must_exist and not real.exists():
            raise PathViolation("not_found", f"'{rel_s}' does not exist")
        return real

    def iter_files(self, base: str = ".", max_files: int = 5000) -> Iterator[str]:
        start = self.resolve(base)
        if start.is_file():
            yield start.relative_to(self.root).as_posix()
            return
        count = 0
        for dirpath, dirnames, filenames in os.walk(start, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if not _is_blocked_name(d) and d not in {"node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".ruff_cache", ".pytest_cache"})
            for fn in sorted(filenames):
                full = Path(dirpath) / fn
                if full.is_symlink() or _is_blocked_name(fn):
                    continue
                rel = full.relative_to(self.root).as_posix()
                if not self.is_allowed(rel):
                    continue
                yield rel
                count += 1
                if count >= max_files:
                    return

    def read_text(self, rel: str, max_bytes: int) -> str:
        p = self.resolve(rel)
        if not p.is_file():
            raise PathViolation("not_a_file", f"'{rel}' is not a regular file")
        if p.stat().st_size > max_bytes:
            raise PathViolation("too_large", f"file exceeds {max_bytes} bytes")
        data = p.read_bytes()
        if b"\x00" in data[:8192]:
            raise PathViolation("binary_file", "binary files cannot be read")
        return data.decode("utf-8", errors="replace")

    def write_text(self, rel: str, content: str) -> Path:
        if (self.root / check_relative(rel)).is_symlink():
            raise PathViolation("symlink_write", "refusing to write through a symlink")
        p = self.resolve(rel, for_write=True, must_exist=False)
        if p.exists() and not p.is_file():
            raise PathViolation("not_a_file", "target is not a regular file")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p
