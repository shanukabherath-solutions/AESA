"""Approval gate: a patch may only be approved when every required check passed for THAT patch."""
from __future__ import annotations

from dataclasses import dataclass, field

from app.config import Settings
from app.models import SecurityScan
from app.models.enums import ScanStatus


def derive_required_scans(settings: Settings, inspection: dict[str, object]) -> list[str]:
    if settings.required_scan_list:
        return settings.required_scan_list
    req: list[str] = ["gitleaks", "trivy"]
    if inspection.get("has_python"):
        req += ["pytest", "ruff", "mypy", "bandit"]
    if inspection.get("has_node"):
        req += ["npm_test", "npm_audit"]
    return req


def applicable_security_tools(inspection: dict[str, object]) -> list[str]:
    tools = ["gitleaks", "trivy"]
    if inspection.get("has_python"):
        tools.insert(0, "bandit")
    if inspection.get("has_node"):
        tools.append("npm_audit")
    return tools


@dataclass
class GateResult:
    passed: bool
    required: list[str]
    missing: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def latest_for_patch(scans: list[SecurityScan], patch_sha: str | None, phase: str = "proposal") -> dict[str, SecurityScan]:
    latest: dict[str, SecurityScan] = {}
    for s in sorted(scans, key=lambda x: x.id):
        if s.patch_sha256 == patch_sha and s.phase == phase:
            latest[s.tool] = s
    return latest


def evaluate_gate(scans: list[SecurityScan], patch_sha: str | None, required: list[str]) -> GateResult:
    if not patch_sha:
        return GateResult(False, required, list(required), ["no patch has been proposed"])
    latest = latest_for_patch(scans, patch_sha)
    res = GateResult(True, required)
    for tool in required:
        s = latest.get(tool)
        if s is None:
            res.missing.append(tool)
            res.reasons.append(f"{tool}: not run against the current patch")
        elif s.status != ScanStatus.PASSED.value:
            res.reasons.append(f"{tool}: {s.status} ({s.summary})")
    res.passed = not res.reasons
    return res
