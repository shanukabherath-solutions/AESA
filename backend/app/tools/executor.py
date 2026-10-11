"""ToolExecutor: the single choke point every model-requested action passes through.

    validate (Pydantic) -> policy decision (persisted) -> execute -> redact -> audit

Nothing else in the codebase lets the model touch the repository, the shell, or Git.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from app.audit import logger as audit
from app.audit.redaction import redact_obj, redact_text
from app.models import AgentAction, PolicyDecision
from app.models.enums import ActionStatus
from app.repository.git import GitError
from app.repository.paths import PathViolation
from app.sandbox.commands import CommandRejected
from app.tools.context import ToolContext, ToolResult
from app.tools.handlers import HANDLERS
from app.tools.schemas import TOOL_MODELS

log = logging.getLogger(__name__)
OBSERVATION_LIMIT = 14_000
AGENT_NAME = "AESA"


@dataclass
class ToolOutcome:
    status: ActionStatus
    observation: dict[str, Any]
    terminal: bool = False


def _cap(data: dict[str, Any]) -> dict[str, Any]:
    blob = json.dumps(data, default=str)
    if len(blob) <= OBSERVATION_LIMIT:
        return data
    return {"truncated": True, "preview": blob[:OBSERVATION_LIMIT]}


class ToolExecutor:
    def __init__(self, ctx: ToolContext):
        self.ctx = ctx

    # -- persistence helpers -------------------------------------------------
    def _record(self, tool: str, args: dict[str, Any], reason: str, status: ActionStatus, summary: str,
                exit_code: int | None, t0: float, affected: list[str], perm: str) -> None:
        c = self.ctx
        ms = int((time.monotonic() - t0) * 1000)
        safe_args = redact_obj(args)
        c.db.add(AgentAction(task_id=c.task.id, step=c.step, tool=tool[:64], arguments=safe_args,
                             reason=redact_text(reason, aggressive=True)[:300], status=status.value,
                             result_summary=redact_text(summary, aggressive=True)[:2000],
                             exit_code=exit_code, duration_ms=ms))
        c.db.commit()
        audit.record(
            c.db, action="tool_call", user=c.username, agent=AGENT_NAME, repository=c.repo.name,
            task_id=c.task.id, tool=tool[:64], arguments=safe_args, permission_decision=perm,
            result=summary, status=status.value, exit_code=exit_code, duration_ms=ms,
            affected_files=affected, approval_state=c.task.status, ip=c.ip, session_id=c.session_id,
        )

    def _persist_decision(self, tool: str, d: Any, actor: str) -> None:
        c = self.ctx
        c.db.add(PolicyDecision(
            task_id=c.task.id, actor=actor, tool=tool[:64], decision="ALLOW" if d.allowed else "DENY",
            rule=d.rule, reason=d.reason[:500],
            required_level=d.required_level.value if d.required_level else None,
            granted_level=d.granted_level.value if d.granted_level else None,
        ))
        c.db.commit()

    # -- main entry point ----------------------------------------------------
    def execute(self, tool: str, raw_args: Any, reason: str = "") -> ToolOutcome:
        c, t0 = self.ctx, time.monotonic()
        tool = str(tool)[:64]
        pctx = c.policy_context()
        args_for_log: dict[str, Any] = raw_args if isinstance(raw_args, dict) else {"_raw": str(raw_args)[:200]}
        parsed = None
        model = TOOL_MODELS.get(tool)

        if model is not None:  # known tool: schema-validate before anything else looks at the arguments
            try:
                parsed = model.model_validate(raw_args if isinstance(raw_args, dict) else None)
            except ValidationError as exc:
                msg = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:4])
                self._record(tool, args_for_log, reason, ActionStatus.REJECTED, f"invalid arguments: {msg}", None, t0, [], "REJECTED")
                return ToolOutcome(ActionStatus.REJECTED, {"tool": tool, "status": "rejected",
                                                           "summary": f"invalid arguments: {msg}"})
        args_dict = parsed.model_dump() if parsed else args_for_log

        decision = c.policy.evaluate(pctx, tool, args_dict)
        self._persist_decision(tool, decision, pctx.actor)
        if not decision.allowed:
            summary = f"denied by policy ({decision.rule}): {decision.reason}"
            self._record(tool, args_dict, reason, ActionStatus.DENIED, summary, None, t0, [], "DENIED")
            return ToolOutcome(ActionStatus.DENIED, {"tool": tool, "status": "denied", "summary": summary})

        if parsed is None or tool not in HANDLERS:  # unreachable unless policy and registry drift apart: fail closed
            raise RuntimeError(f"no handler registered for {tool}")
        result: ToolResult
        status = ActionStatus.EXECUTED
        try:
            result = HANDLERS[tool](c, parsed)  # type: ignore[operator]
            if not result.ok:
                status = ActionStatus.FAILED
        except PathViolation as exc:
            result, status = ToolResult(False, f"path rejected ({exc.code}): {exc.detail}"), ActionStatus.REJECTED
        except CommandRejected as exc:
            result, status = ToolResult(False, f"command rejected ({exc.code}): {exc.detail}"), ActionStatus.REJECTED
        except GitError as exc:
            result, status = ToolResult(False, f"git operation failed: {exc}"), ActionStatus.FAILED
        except Exception:  # noqa: BLE001 - never leak internals to the model
            log.exception("tool %s crashed", tool)
            result, status = ToolResult(False, "internal error while running the tool"), ActionStatus.FAILED

        self._record(tool, args_dict, reason, status, result.summary, result.exit_code, t0,
                     result.affected_files, "ALLOWED")
        obs = {"tool": tool, "status": "ok" if result.ok else "failed", "summary": result.summary,
               "data": _cap(redact_obj_light(result.data))}
        return ToolOutcome(status, obs, terminal=result.terminal and result.ok)


def redact_obj_light(data: dict[str, Any]) -> dict[str, Any]:
    """Credential-format redaction of tool output before it reaches the model/UI."""
    def walk(v: Any) -> Any:
        if isinstance(v, str):
            return redact_text(v)
        if isinstance(v, list):
            return [walk(i) for i in v]
        if isinstance(v, dict):
            return {k: walk(i) for k, i in v.items()}
        return v

    return walk(data)  # type: ignore[no-any-return]
