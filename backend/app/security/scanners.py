"""Parsers that turn raw scanner output into normalised outcomes. Unparseable output => ERROR (fail closed)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.audit.redaction import redact_text
from app.models.enums import SEVERITY_ORDER, ScanStatus, Severity
from app.sandbox.runner import CommandResult

SECURITY_TOOLS = {"bandit", "gitleaks", "trivy", "npm_audit"}
QUALITY_TOOLS = {"pytest", "ruff", "mypy", "npm_test"}
TOOL_COMMAND = {
    "pytest": "pytest", "ruff": "ruff_check", "mypy": "mypy", "bandit": "bandit", "trivy": "trivy_fs",
    "gitleaks": "gitleaks", "npm_test": "npm_test", "npm_audit": "npm_audit",
}
MAX_FINDINGS = 100


@dataclass
class ScanOutcome:
    status: ScanStatus
    summary: str
    counts: dict[str, int] = field(default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    findings: list[dict[str, Any]] = field(default_factory=list)


def _finding(sev: str, rule: str, msg: str, file: str | None = None, line: int | None = None) -> dict[str, Any]:
    return {"severity": sev, "rule": rule, "message": redact_text(msg, aggressive=True)[:300], "file": file, "line": line}


def _threshold_hit(counts: dict[str, int], block: Severity) -> bool:
    return any(counts[s.value] > 0 and SEVERITY_ORDER[s] >= SEVERITY_ORDER[block] for s in Severity)


_EXCEPTION_LINE = re.compile(r"^(?:[A-Za-z_][\w.]*\.)?[A-Z]\w*(?:Error|Exception|Interrupt)\b.*$")


def _failure_detail(res: CommandResult) -> str:
    """The most informative single line of a failed tool run.

    A crashing Python tool prints its traceback on one stream and boilerplate hints ("please use --show-traceback",
    "use --pdb") on the other, so "the last line of stderr" is often the least useful line. Prefer the final exception
    line of a traceback from either stream, then fall back to the last non-empty line of stderr, then stdout."""
    lines = [ln.strip() for stream in (res.stdout, res.stderr) for ln in (stream or "").splitlines() if ln.strip()]
    for ln in reversed(lines):
        if _EXCEPTION_LINE.match(ln):
            return ln
    for stream in (res.stderr, res.stdout):
        tail = [ln.strip() for ln in (stream or "").splitlines() if ln.strip()]
        if tail:
            return tail[-1]
    return ""


def _error(res: CommandResult, why: str) -> ScanOutcome:
    return ScanOutcome(ScanStatus.ERROR, f"{why}: {redact_text(_failure_detail(res), aggressive=True)[:200]}")


def _precheck(res: CommandResult) -> ScanOutcome | None:
    if res.timed_out:
        return ScanOutcome(ScanStatus.ERROR, f"timed out after {res.duration_s:.0f}s")
    if res.exit_code == 127:
        return ScanOutcome(ScanStatus.ERROR, "tool is not installed in the sandbox")
    if res.truncated:
        return ScanOutcome(ScanStatus.ERROR, "output exceeded the size limit; scan aborted")
    return None


def _json(res: CommandResult) -> Any:
    return json.loads(res.stdout) if res.stdout.strip() else None


def parse_bandit(res: CommandResult, block: Severity) -> ScanOutcome:
    if (pre := _precheck(res)) or res.exit_code not in (0, 1):
        return pre or _error(res, "bandit failed")
    try:
        data = _json(res) or {}
    except ValueError:
        return _error(res, "bandit output was not valid JSON")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings = []
    for r in data.get("results", []):
        sev = str(r.get("issue_severity", "LOW")).lower()
        sev = sev if sev in counts else "low"
        counts[sev] += 1
        findings.append(_finding(sev, r.get("test_id", ""), r.get("issue_text", ""), r.get("filename"), r.get("line_number")))
    status = ScanStatus.FAILED if _threshold_hit(counts, block) else ScanStatus.PASSED
    return ScanOutcome(status, f"{len(findings)} finding(s): {counts['high']} high, {counts['medium']} medium, {counts['low']} low",
                       counts, findings[:MAX_FINDINGS])


def parse_gitleaks(res: CommandResult, block: Severity) -> ScanOutcome:
    if (pre := _precheck(res)) or res.exit_code != 0:
        return pre or _error(res, "gitleaks failed")
    try:
        data = _json(res) or []
    except ValueError:
        return _error(res, "gitleaks output was not valid JSON")
    findings = [_finding("critical", f.get("RuleID", "secret"), f.get("Description", "secret detected"),
                         f.get("File"), f.get("StartLine")) for f in data]
    counts = {"critical": len(findings), "high": 0, "medium": 0, "low": 0}
    return ScanOutcome(ScanStatus.FAILED if findings else ScanStatus.PASSED,
                       f"{len(findings)} secret(s) detected" if findings else "no secrets detected", counts,
                       findings[:MAX_FINDINGS])


def parse_trivy(res: CommandResult, block: Severity) -> ScanOutcome:
    if (pre := _precheck(res)) or res.exit_code != 0:
        return pre or _error(res, "trivy failed")
    try:
        data = _json(res) or {}
    except ValueError:
        return _error(res, "trivy output was not valid JSON")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings = []
    for result in data.get("Results", []) or []:
        target = result.get("Target")
        items = [("vuln", v) for v in result.get("Vulnerabilities", []) or []]
        items += [("secret", v) for v in result.get("Secrets", []) or []]
        items += [("misconfig", v) for v in result.get("Misconfigurations", []) or []]
        for kind, v in items:
            sev = str(v.get("Severity", "LOW")).lower()
            sev = sev if sev in counts else "low"
            counts[sev] += 1
            rid = v.get("VulnerabilityID") or v.get("RuleID") or v.get("ID") or kind
            msg = v.get("Title") or f"{v.get('PkgName', '')} {v.get('InstalledVersion', '')}".strip() or kind
            findings.append(_finding(sev, rid, msg, target))
    status = ScanStatus.FAILED if _threshold_hit(counts, block) else ScanStatus.PASSED
    return ScanOutcome(status, f"{len(findings)} finding(s): {counts['critical']} critical, {counts['high']} high",
                       counts, findings[:MAX_FINDINGS])


def parse_npm_audit(res: CommandResult, block: Severity) -> ScanOutcome:
    if (pre := _precheck(res)) or res.exit_code not in (0, 1):
        return pre or _error(res, "npm audit failed")
    try:
        data = _json(res) or {}
    except ValueError:
        return _error(res, "npm audit output was not valid JSON")
    if "error" in data:
        return ScanOutcome(ScanStatus.ERROR, f"npm audit error: {str(data['error'].get('summary', ''))[:200]}")
    v = (data.get("metadata") or {}).get("vulnerabilities") or {}
    counts = {"critical": v.get("critical", 0), "high": v.get("high", 0),
              "medium": v.get("moderate", 0), "low": v.get("low", 0)}
    findings = [_finding({"moderate": "medium"}.get(x.get("severity", "low"), x.get("severity", "low")), name,
                         f"vulnerable dependency {name}") for name, x in (data.get("vulnerabilities") or {}).items()]
    status = ScanStatus.FAILED if _threshold_hit(counts, block) else ScanStatus.PASSED
    return ScanOutcome(status, f"{sum(counts.values())} vulnerable package(s): {counts['critical']} critical, {counts['high']} high",
                       counts, findings[:MAX_FINDINGS])


def parse_ruff(res: CommandResult, block: Severity) -> ScanOutcome:
    if (pre := _precheck(res)) or res.exit_code not in (0, 1):
        return pre or _error(res, "ruff failed")
    try:
        data = _json(res) or []
    except ValueError:
        return _error(res, "ruff output was not valid JSON")
    findings = [_finding("low", d.get("code") or "", d.get("message", ""), d.get("filename"),
                         (d.get("location") or {}).get("row")) for d in data]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": len(findings)}
    return ScanOutcome(ScanStatus.FAILED if findings else ScanStatus.PASSED,
                       f"{len(findings)} lint issue(s)" if findings else "no lint issues", counts, findings[:MAX_FINDINGS])


_MYPY_LINE = re.compile(r"^(?P<file>[^:\n]+):(?P<line>\d+):(?:\d+:)? error: (?P<msg>.*)$", re.M)


def parse_mypy(res: CommandResult, block: Severity) -> ScanOutcome:
    if (pre := _precheck(res)) or res.exit_code not in (0, 1):
        return pre or _error(res, "mypy failed")
    findings = [_finding("low", "mypy", m["msg"], m["file"], int(m["line"])) for m in _MYPY_LINE.finditer(res.stdout)]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": len(findings)}
    failed = res.exit_code == 1 or bool(findings)
    return ScanOutcome(ScanStatus.FAILED if failed else ScanStatus.PASSED,
                       f"{len(findings)} type error(s)" if failed else "no type errors", counts, findings[:MAX_FINDINGS])


def parse_pytest(res: CommandResult, block: Severity) -> ScanOutcome:
    if pre := _precheck(res):
        return pre
    tail = [ln for ln in res.stdout.strip().splitlines() if ln.strip()][-1:] or [""]
    if res.exit_code == 0:
        return ScanOutcome(ScanStatus.PASSED, tail[0][:200] or "tests passed")
    if res.exit_code == 1:
        fails = [_finding("high", "pytest", ln, None) for ln in res.stdout.splitlines() if ln.startswith("FAILED")]
        return ScanOutcome(ScanStatus.FAILED, tail[0][:200] or "tests failed", {"critical": 0, "high": 0, "medium": 0, "low": len(fails)},
                           fails[:MAX_FINDINGS])
    if res.exit_code == 5:
        return ScanOutcome(ScanStatus.ERROR, "no tests were collected")
    return _error(res, f"pytest could not run (exit {res.exit_code})")


def parse_npm_test(res: CommandResult, block: Severity) -> ScanOutcome:
    if pre := _precheck(res):
        return pre
    return ScanOutcome(ScanStatus.PASSED if res.exit_code == 0 else ScanStatus.FAILED,
                       "npm test passed" if res.exit_code == 0 else f"npm test failed (exit {res.exit_code})")


PARSERS = {
    "bandit": parse_bandit, "gitleaks": parse_gitleaks, "trivy": parse_trivy, "npm_audit": parse_npm_audit,
    "ruff": parse_ruff, "mypy": parse_mypy, "pytest": parse_pytest, "npm_test": parse_npm_test,
}
