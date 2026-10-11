"""Central policy engine. Every tool/action is evaluated here BEFORE execution.

Design rules:
* default deny: unknown tools are refused;
* the permission context is built by backend code from trusted state (task row, approval rows),
  never from model output;
* the agent actor is clamped to PROPOSE_CHANGE and can never use human/system-only actions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.enums import LEVEL_ORDER, PermissionLevel
from app.repository.paths import (
    SAFE_BRANCH_RE,
    PathViolation,
    check_relative,
    is_protected_branch,
    is_protected_path,
)

AGENT = "agent"
SYSTEM = "system"
HUMAN = "human"


@dataclass(frozen=True)
class ToolPolicy:
    level: PermissionLevel
    agent_allowed: bool = True  # False => only backend/system code may perform it
    description: str = ""


TOOL_POLICIES: dict[str, ToolPolicy] = {
    # READ_ONLY
    "list_files": ToolPolicy(PermissionLevel.READ_ONLY),
    "read_file": ToolPolicy(PermissionLevel.READ_ONLY),
    "search_code": ToolPolicy(PermissionLevel.READ_ONLY),
    "git_status": ToolPolicy(PermissionLevel.READ_ONLY),
    "git_diff": ToolPolicy(PermissionLevel.READ_ONLY),
    # PROPOSE_CHANGE (acts only inside the isolated sandbox workspace)
    "run_tests": ToolPolicy(PermissionLevel.PROPOSE_CHANGE),
    "run_linter": ToolPolicy(PermissionLevel.PROPOSE_CHANGE),
    "run_security_scan": ToolPolicy(PermissionLevel.PROPOSE_CHANGE),
    "create_patch": ToolPolicy(PermissionLevel.PROPOSE_CHANGE),
    "create_branch": ToolPolicy(PermissionLevel.PROPOSE_CHANGE),
    "request_approval": ToolPolicy(PermissionLevel.PROPOSE_CHANGE),
    # APPROVED_CHANGE (requires a human approval record)
    "create_pull_request": ToolPolicy(PermissionLevel.APPROVED_CHANGE),
    "apply_patch": ToolPolicy(PermissionLevel.APPROVED_CHANGE, agent_allowed=False),
    "git_commit": ToolPolicy(PermissionLevel.APPROVED_CHANGE, agent_allowed=False),
    "git_push": ToolPolicy(PermissionLevel.APPROVED_CHANGE, agent_allowed=False),
    # DEPLOY (requires a separate human deployment approval)
    "deploy": ToolPolicy(PermissionLevel.DEPLOY, agent_allowed=False),
}

# Tools the model is told about. Everything else is invisible AND denied.
MODEL_TOOLS = [
    "list_files", "read_file", "search_code", "git_status", "git_diff", "run_tests", "run_linter",
    "run_security_scan", "create_patch", "create_branch", "request_approval", "create_pull_request",
]
AGENT_MAX_LEVEL = PermissionLevel.PROPOSE_CHANGE


@dataclass(frozen=True)
class PolicyContext:
    actor: str
    max_level: PermissionLevel
    task_id: int | None = None
    approved_change: bool = False
    deploy_approved: bool = False
    task_branch: str | None = None
    protected_branches: tuple[str, ...] = ()
    protected_paths: tuple[str, ...] = ()
    max_patch_files: int = 20

    @staticmethod
    def for_agent(
        task_id: int, requested: PermissionLevel, branch: str | None,
        protected_branches: list[str], protected_paths: list[str], max_patch_files: int = 20,
    ) -> PolicyContext:
        level = requested if LEVEL_ORDER[requested] <= LEVEL_ORDER[AGENT_MAX_LEVEL] else AGENT_MAX_LEVEL
        return PolicyContext(AGENT, level, task_id, False, False, branch, tuple(protected_branches),
                             tuple(protected_paths), max_patch_files)

    @staticmethod
    def for_approved_change(
        task_id: int, branch: str, protected_branches: list[str], protected_paths: list[str],
    ) -> PolicyContext:
        return PolicyContext(SYSTEM, PermissionLevel.APPROVED_CHANGE, task_id, True, False, branch,
                             tuple(protected_branches), tuple(protected_paths))

    @staticmethod
    def for_deploy(task_id: int, branch: str | None) -> PolicyContext:
        return PolicyContext(HUMAN, PermissionLevel.DEPLOY, task_id, True, True, branch)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule: str
    reason: str
    required_level: PermissionLevel | None = None
    granted_level: PermissionLevel | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return "ALLOWED" if self.allowed else "DENIED"


class PolicyEngine:
    def evaluate(self, ctx: PolicyContext, tool: str, args: dict[str, Any] | None = None) -> Decision:
        args = args or {}
        pol = TOOL_POLICIES.get(tool)
        if pol is None:
            return Decision(False, "default_deny", f"'{tool}' is not a recognised tool; unknown actions are denied",
                            None, ctx.max_level)

        def deny(rule: str, reason: str) -> Decision:
            return Decision(False, rule, reason, pol.level, ctx.max_level)

        if ctx.actor == AGENT and not pol.agent_allowed:
            return deny("agent_forbidden", f"'{tool}' can only be performed by backend code after human approval")
        if LEVEL_ORDER[pol.level] > LEVEL_ORDER[ctx.max_level]:
            return deny("insufficient_level",
                        f"'{tool}' needs {pol.level.value}; this context only has {ctx.max_level.value}")
        if LEVEL_ORDER[pol.level] >= LEVEL_ORDER[PermissionLevel.APPROVED_CHANGE] and not ctx.approved_change:
            return deny("approval_required", f"'{tool}' requires an explicit human approval for this task")
        if pol.level == PermissionLevel.DEPLOY and (not ctx.deploy_approved or ctx.actor == AGENT):
            return deny("deploy_approval_required", "deployment requires a separate explicit deployment approval")

        arg_denial = self._check_args(ctx, tool, args)
        if arg_denial is not None:
            rule, reason = arg_denial
            return deny(rule, reason)
        return Decision(True, "allowed", "permitted by policy", pol.level, ctx.max_level)

    # ------------------------------------------------------------------ argument rules
    def _check_args(self, ctx: PolicyContext, tool: str, args: dict[str, Any]) -> tuple[str, str] | None:
        if args.get("force"):
            return "force_forbidden", "forced operations are never allowed"
        branch = args.get("branch") or args.get("head")
        if branch is not None:
            if not isinstance(branch, str) or not SAFE_BRANCH_RE.match(branch):
                return "branch_not_allowed", "only agent/proposal-<id> branches may be targeted"
            if is_protected_branch(branch, list(ctx.protected_branches)):
                return "protected_branch", f"'{branch}' is a protected branch"
            if ctx.task_branch and branch != ctx.task_branch:
                return "branch_mismatch", "branch does not belong to this task"
        if tool == "git_push" and branch is None:
            return "branch_not_allowed", "git_push requires an explicit proposal branch"

        paths: list[str] = []
        if tool in {"list_files", "search_code", "git_diff"} and args.get("path"):
            paths.append(args["path"])
        if tool == "read_file":
            paths.append(args.get("path", ""))
        if tool in {"create_patch", "apply_patch"}:
            files = args.get("files") or []
            if len(files) > ctx.max_patch_files:
                return "too_many_files", f"a patch may modify at most {ctx.max_patch_files} files"
            paths += [f.get("path", "") if isinstance(f, dict) else getattr(f, "path", "") for f in files]
        for p in paths:
            try:
                clean = check_relative(p)
            except PathViolation as exc:
                return exc.code, exc.detail
            if tool in {"create_patch", "apply_patch"} and is_protected_path(clean.as_posix(), list(ctx.protected_paths)):
                return "protected_path", f"'{clean}' is protected and cannot be modified by the agent"
        return None
