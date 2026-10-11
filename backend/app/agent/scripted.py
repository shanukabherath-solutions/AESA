"""Offline, rule-based provider so the demo works with no API key.

It is NOT an LLM: it plays the role of one by emitting the same structured tool calls, which then pass
through the same validation / policy / sandbox / audit path as any real model's calls. Its code fixers
recognise a few classic insecure idioms (weak password hashing, hard-coded secrets, SQL built with f-strings).
"""
from __future__ import annotations

import re
from typing import Any

from app.agent.provider import AIProvider, Message, ModelAction

AUTH_HINT = re.compile(r"auth|login|password|security|session|token", re.I)

PBKDF2_BLOCK = '''PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    """Hash a password with salted PBKDF2-HMAC-SHA256 (format: scheme$iterations$salt$digest)."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password in constant time."""
    try:
        scheme, iterations, salt_hex, digest_hex = stored_hash.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
    except ValueError:
        return False
    return hmac.compare_digest(candidate.hex(), digest_hex)
'''

SECRET_BLOCK = '''def get_secret_key() -> str:
    """Read the signing key from the environment instead of source code."""
    key = os.environ.get("APP_SECRET_KEY")
    if not key:
        raise RuntimeError("APP_SECRET_KEY environment variable must be set")
    return key
'''


def _ensure_imports(text: str, modules: list[str]) -> str:
    """Add `import x` lines, keeping the leading run of plain imports sorted (ruff isort-clean)."""
    lines = text.split("\n")
    present = {ln.strip() for ln in lines if ln.startswith("import ")}
    wanted = [f"import {m}" for m in modules if f"import {m}" not in present]
    if not wanted:
        return text
    idx = [i for i, ln in enumerate(lines) if ln.startswith("import ")]
    if not idx:
        return "\n".join(wanted) + "\n\n\n" + text.lstrip("\n")
    first = idx[0]
    last = first
    while last + 1 < len(lines) and lines[last + 1].startswith("import "):
        last += 1
    block = sorted(set(lines[first : last + 1] + wanted), key=lambda ln: ln.split()[1])
    return "\n".join(lines[:first] + block + lines[last + 1 :])


def fix_weak_hashing(text: str) -> tuple[str, str | None]:
    pat = re.compile(r"def hash_password\([^)]*\)[^\n]*:\n(?:    [^\n]*\n|\n(?=    ))+", re.M)
    m = pat.search(text)
    if not m or not re.search(r"hashlib\.(md5|sha1)\(", m.group(0)):
        return text, None
    new = text[: m.start()].rstrip("\n") + "\n\n\n" + PBKDF2_BLOCK.split("\n\n\ndef verify_password")[0] + "\n\n\n" + text[m.end():].lstrip("\n")
    ver = re.compile(r"def verify_password\([^)]*\)[^\n]*:\n(?:    [^\n]*\n|\n(?=    ))+", re.M)
    vm = ver.search(new)
    verify_src = "def verify_password" + PBKDF2_BLOCK.split("def verify_password", 1)[1]
    if vm:
        new = new[: vm.start()] + verify_src + new[vm.end():]
    else:
        new = new.rstrip("\n") + "\n\n\n" + verify_src
    new = _ensure_imports(new, ["hashlib", "hmac", "secrets"])
    return new, "Passwords were hashed with unsalted MD5/SHA-1 and compared with ==; replaced with salted PBKDF2-HMAC-SHA256 and constant-time comparison."


def fix_hardcoded_secret(text: str) -> tuple[str, str | None]:
    m = re.search(r'^(SECRET_KEY|JWT_SECRET|APP_SECRET)[ \t]*=[ \t]*["\'][^"\']{4,}["\'][ \t]*$', text, re.M)
    if not m:
        return text, None
    name = m.group(1)
    body = text[: m.start()].rstrip("\n") + "\n\n\n" + SECRET_BLOCK.rstrip("\n") + text[m.end():]
    body = re.sub(rf"\b{name}\b(?!\s*=)", "get_secret_key()", body)
    return _ensure_imports(body, ["os"]), f"A signing secret ({name}) was hard-coded in source; it is now read from the APP_SECRET_KEY environment variable."


def fix_sql_injection(text: str) -> tuple[str, str | None]:
    n = 0

    def repl(m: re.Match[str]) -> str:
        nonlocal n
        sql = m.group(2)
        if re.search(r"\{(?!\w+\})", sql) or re.search(r"(?<!')\{\w+\}", sql):  # only quoted {var} placeholders
            return m.group(0)
        names = re.findall(r"'\{(\w+)\}'", sql)
        if not names or "{" in re.sub(r"'\{\w+\}'", "", sql):
            return m.group(0)
        n += 1
        param_sql = re.sub(r"'\{\w+\}'", "?", sql)
        params = ", ".join(names) + ("," if len(names) == 1 else "")
        return f'{m.group(1)}.execute("{param_sql}", ({params}))'

    new = re.sub(r'(\w+)\.execute\(f"([^"\n]*)"\)', repl, text)
    return (new, f"{n} SQL statement(s) were built with string interpolation (SQL injection); converted to parameterised queries.") if n else (text, None)


def fix_timing_compare(text: str) -> tuple[str, str | None]:
    pat = re.compile(r"if (sig|signature|digest|mac|token_hash) != (expected\w*|computed\w*):")
    new, n = pat.subn(lambda m: f"if not hmac.compare_digest({m.group(1)}, {m.group(2)}):", text)
    if not n:
        return text, None
    return _ensure_imports(new, ["hmac"]), "A signature was compared with != (timing side channel); now uses hmac.compare_digest."


FIXERS = [fix_weak_hashing, fix_hardcoded_secret, fix_sql_injection, fix_timing_compare]


class ScriptedProvider(AIProvider):
    name = "scripted"

    def __init__(self) -> None:
        self.phase = "list"
        self.queue: list[str] = []
        self.contents: dict[str, str] = {}
        self.new_files: list[dict[str, str]] = []
        self.issues: list[str] = []

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _obs(messages: list[Message]) -> dict[str, Any] | None:
        last = messages[-1] if messages else {}
        return last.get("data") if last.get("role") == "user" else None

    def _call(self, tool: str, reason: str, **args: Any) -> ModelAction:
        return ModelAction(tool=tool, arguments=args, reason=reason)

    def next_action(self, messages: list[Message], tools: list[dict[str, Any]]) -> ModelAction:
        obs = self._obs(messages)
        if self.phase == "list":
            self.phase = "search"
            return self._call("list_files", "Inspect the repository structure and detect languages", path=".")
        if self.phase == "search":
            self.phase = "pick"
            return self._call("search_code", "Locate authentication-related code",
                              query="auth|login|password|hash|secret|token|execute(")
        if self.phase == "pick":
            matches = ((obs or {}).get("data") or {}).get("matches", [])
            score: dict[str, int] = {}
            for m in matches:
                score[m["file"]] = score.get(m["file"], 0) + (5 if AUTH_HINT.search(m["file"]) else 1)
            ranked = [f for f, _ in sorted(score.items(), key=lambda kv: -kv[1]) if f.endswith(".py") and not f.startswith("tests/")]
            self.queue = ranked[:3]
            self.phase = "read"
        if self.phase == "read":
            if obs and obs.get("tool") == "read_file" and obs.get("status") == "ok":
                d = obs["data"]
                self.contents[d["path"]] = d["content"] if d["start_line"] == 1 else self.contents.get(d["path"], "")
            if self.queue:
                path = self.queue.pop(0)
                return self._call("read_file", f"Review {path} for security weaknesses", path=path, max_lines=2000)
            self.phase = "analyze"
        if self.phase == "analyze":
            for path, text in self.contents.items():
                new, notes = text, []
                for fixer in FIXERS:
                    new, note = fixer(new)
                    if note:
                        notes.append(note)
                if notes and new != text:
                    self.new_files.append({"path": path, "new_content": new if new.endswith("\n") else new + "\n"})
                    self.issues += [f"{path}: {n}" for n in notes]
            if not self.new_files:
                self.phase = "done"
                return ModelAction(final="Reviewed the authentication-related code and found no issue I can fix automatically.")
            self.phase = "branch"
        if self.phase == "branch":
            self.phase = "patch"
            return self._call("create_branch", "Create an isolated proposal branch for the fix")
        if self.phase == "patch":
            self.phase = "tests"
            return self._call(
                "create_patch", "Propose a minimal fix for the identified issues", files=self.new_files,
                summary="Fix insecure authentication code", explanation="\n".join(f"- {i}" for i in self.issues) +
                "\nNote: if existing stored password hashes use the old format they will need to be re-hashed (e.g. on next login).",
                risk_level="MEDIUM")
        if self.phase == "tests":
            self.phase = "lint"
            return self._call("run_tests", "Verify behaviour is preserved")
        if self.phase == "lint":
            self.phase = "scan"
            return self._call("run_linter", "Check style and types", linter="all")
        if self.phase == "scan":
            self.phase = "approve"
            return self._call("run_security_scan", "Validate the patch with the security scanners", scanner="all")
        if self.phase == "approve":
            self.phase = "done"
            return self._call("request_approval", "Ask a human to review the proposed fix",
                              summary="Proposed fix for insecure authentication code; checks completed.")
        return ModelAction(final="Finished.")
