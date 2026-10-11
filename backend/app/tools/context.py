from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.config import Settings
from app.models import AgentTask, Repository
from app.models.enums import PermissionLevel
from app.policy.engine import PolicyContext, PolicyEngine
from app.repository.paths import PathGuard
from app.sandbox.commands import CommandRegistry
from app.sandbox.runner import SandboxBackend


@dataclass
class ToolResult:
    ok: bool
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    exit_code: int | None = None
    affected_files: list[str] = field(default_factory=list)
    terminal: bool = False  # True => the agent loop should stop (e.g. approval requested)


@dataclass
class ToolContext:
    db: Session
    settings: Settings
    task: AgentTask
    repo: Repository
    workspace: Path
    guard: PathGuard
    sandbox: SandboxBackend
    registry: CommandRegistry
    policy: PolicyEngine
    username: str
    step: int = 0
    ip: str | None = None
    session_id: str | None = None

    def policy_context(self) -> PolicyContext:
        return PolicyContext.for_agent(
            self.task.id, PermissionLevel(self.task.permission_level), self.task.branch_name,
            self.repo.protected_branches or self.settings.protected_branch_list,
            self.repo.protected_paths, self.settings.max_patch_files,
        )
