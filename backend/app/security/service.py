from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.config import Settings
from app.models import AgentTask, SecurityScan
from app.models.enums import ScanStatus, Severity
from app.sandbox.commands import CommandRegistry, CommandRejected
from app.sandbox.runner import SandboxBackend, execute
from app.security.scanners import PARSERS, TOOL_COMMAND, ScanOutcome


def run_scan(
    db: Session, task: AgentTask, tool: str, workspace: Path, sandbox: SandboxBackend,
    settings: Settings, *, extra_args: dict | None = None, phase: str = "proposal",
    patch_sha: str | None = None,
) -> tuple[SecurityScan, str]:
    """Run one scanner/test tool in the sandbox, persist the normalised result, return (row, raw tail)."""
    registry = CommandRegistry(settings)
    sha = patch_sha if patch_sha is not None else task.patch_sha256
    try:
        cmd = registry.plan(TOOL_COMMAND[tool], extra_args or {})
        res = execute(cmd, workspace, sandbox, settings)
        outcome = PARSERS[tool](res, Severity(settings.security_block_severity))
        tail = (res.stdout[-2500:] + ("\n" + res.stderr[-1200:] if res.stderr else "")).strip()
        exit_code, duration = res.exit_code, res.duration_s
    except CommandRejected as exc:
        outcome = ScanOutcome(ScanStatus.ERROR, f"command rejected: {exc.code}")
        tail, exit_code, duration = "", None, 0.0
    row = SecurityScan(
        task_id=task.id, tool=tool, status=outcome.status.value, summary=outcome.summary,
        critical=outcome.counts["critical"], high=outcome.counts["high"], medium=outcome.counts["medium"],
        low=outcome.counts["low"], findings=outcome.findings, patch_sha256=sha, exit_code=exit_code,
        duration_s=round(duration, 2), phase=phase,
    )
    db.add(row)
    db.commit()
    return row, tail
